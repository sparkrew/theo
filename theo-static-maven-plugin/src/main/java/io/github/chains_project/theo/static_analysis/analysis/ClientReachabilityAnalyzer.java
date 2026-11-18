package io.github.chains_project.theo.static_analysis.analysis;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.chains_project.theo.theo_commons.APILoader;
import io.github.chains_project.theo.theo_commons.PackageMatcher;
import io.github.chains_project.theo.theo_commons.SensitiveAPIDescriptor;
import io.github.chains_project.theo.static_analysis.model.BoundaryInteraction;
import io.github.chains_project.theo.static_analysis.model.PathMethod;
import io.github.chains_project.theo.static_analysis.model.SensitiveApiEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sootup.callgraph.CallGraph;
import sootup.callgraph.RapidTypeAnalysisAlgorithm;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.core.model.SootMethod;
import sootup.core.signatures.MethodSignature;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.core.views.JavaView;

import java.io.File;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Analyzes which sensitive APIs in dependencies are reachable from a client project's code.
 *
 * This class loads a JAR, discovers entry points (public methods in specified packages),
 * builds a call graph with SootUp's rapid type analysis, and then walks paths from each
 * entry point to any sensitive API. When a path passes through a third-party dependency
 * method, the dependency's Maven GAV and the sensitive API identifier are recorded.
 *
 * The result is a set of strings in the format "depGav::sensitiveApi", where depGav is the
 * Maven coordinate of the dependency and sensitiveApi is "className.methodName".
 */
public class ClientReachabilityAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(ClientReachabilityAnalyzer.class);

    public ClientReachabilityAnalyzer() {
        // No state needed; each analysis call is self-contained.
    }

    /**
     * Finds which sensitive APIs are reachable from the client project's code, and through
     * which dependency they are reached.
     *
     * @param pathToJar      path to the fat JAR containing the project and its dependencies
     * @param packageNames   base package names of the client project (e.g. ["org.example.app"])
     * @param packageMapPath path to the JSON file mapping package names to Maven coordinates
     * @return a set of "depGav::className.methodName" strings for each reachable sensitive API
     */
    public Set<String> findReachableSensitiveApis(String pathToJar, List<String> packageNames, Path packageMapPath) {
        return findReachableSensitiveApis(pathToJar, packageNames, packageMapPath, null);
    }

    public Set<String> findReachableSensitiveApis(String pathToJar, List<String> packageNames, Path packageMapPath, Path depsDir) {
        FullReachabilityResult full = analyzeReachability(pathToJar, packageNames, packageMapPath, depsDir);
        return full.reachableKeys;
    }

    /**
     * Returns the full reachable sensitive API data grouped by dependency GAV.
     * Each entry has the path, access type, and category info — enough to build
     * the reachable report without running per-dependency analysis.
     *
     * @param depsDir directory containing dependency JARs for SootUp classpath
     */
    public Map<String, List<SensitiveApiEntry>> findReachableEntries(String pathToJar, List<String> packageNames, Path packageMapPath, Path depsDir) {
        FullReachabilityResult full = analyzeReachability(pathToJar, packageNames, packageMapPath, depsDir);
        return full.entriesByDep;
    }

    /**
     * Returns the complete analysis result including boundary interactions.
     * Use this when attribution data is needed alongside reachability.
     */
    public FullReachabilityResult analyzeReachabilityFull(String pathToJar, List<String> packageNames, Path packageMapPath, Path depsDir) {
        return analyzeReachability(pathToJar, packageNames, packageMapPath, depsDir);
    }

    /**
     * Core analysis logic. Walks the call graph, collects reachable sensitive APIs
     * and all client-to-dependency boundary crossings for attribution.
     */
    private FullReachabilityResult analyzeReachability(String pathToJar, List<String> packageNames, Path packageMapPath, Path depsDir) {
        List<SensitiveAPIDescriptor> sensitiveApiList = APILoader.loadFromClasspath(
                "sensitive_apis.json", new TypeReference<>() {}
        );
        Set<String> sensitiveApiIdentifiers = sensitiveApiList.stream()
                .map(desc -> desc.className() + "." + desc.method())
                .collect(Collectors.toSet());

        // Build a lookup for category/subcategory by "className.method"
        Map<String, String[]> categoryLookup = new HashMap<>();
        for (SensitiveAPIDescriptor desc : sensitiveApiList) {
            categoryLookup.put(desc.className() + "." + desc.method(),
                    new String[]{desc.category(), desc.subcategory()});
        }

        Set<String> ignoredPrefixes = PackageMatcher.loadIgnoredPrefixes(packageNames);

        JavaView view = createJavaView(pathToJar, depsDir);
        Set<MethodSignature> entryPoints = detectEntryPoints(view, packageNames);
        log.info("Found {} public methods as entry points.", entryPoints.size());

        Set<String> reachableKeys = new HashSet<>();
        Map<String, List<SensitiveApiEntry>> entriesByDep = new HashMap<>();
        Set<String> seenPairs = new HashSet<>();
        List<BoundaryInteraction> boundaryInteractions = new ArrayList<>();
        Set<String> seenBoundaries = new HashSet<>();

        try {
            CallGraph cg = new RapidTypeAnalysisAlgorithm(view).initialize(new ArrayList<>(entryPoints));
            view = null;

            for (MethodSignature entryPoint : entryPoints) {
                Set<MethodSignature> reachable = getAllReachableMethodsWithBoundaries(
                        cg, entryPoint, packageNames, ignoredPrefixes,
                        packageMapPath, boundaryInteractions, seenBoundaries);

                Set<MethodSignature> reachableSensitive = reachable.stream()
                        .filter(method -> isSensitiveAPI(method, sensitiveApiIdentifiers))
                        .collect(Collectors.toSet());

                for (MethodSignature sensitiveMethod : reachableSensitive) {
                    List<List<MethodSignature>> allPaths = findPaths(cg, entryPoint, sensitiveMethod);

                    for (List<MethodSignature> path : allPaths) {
                        MethodSignature firstThirdParty = null;
                        int firstThirdPartyIndex = -1;
                        for (int i = 0; i < path.size(); i++) {
                            MethodSignature method = path.get(i);
                            if (!method.equals(sensitiveMethod) && isThirdPartyMethod(method, ignoredPrefixes)) {
                                firstThirdParty = method;
                                firstThirdPartyIndex = i;
                                break;
                            }
                        }

                        if (firstThirdParty != null) {
                            String thirdPartyFormatted = formatMethodSignature(firstThirdParty);
                            String pkgName = extractPackageName(thirdPartyFormatted, ignoredPrefixes);
                            String depGav = PackageMatcher.getDependencyName(pkgName, packageMapPath);
                            if (depGav != null) {
                                String sensitiveApiName = formatMethodSignature(sensitiveMethod);
                                reachableKeys.add(depGav + "::" + sensitiveApiName);

                                // Direct: the dependency reaches the sensitive API through
                                // its own code only. Indirect: the path goes through a
                                // different dependency before reaching the sensitive API.
                                boolean isDirect = true;
                                for (int j = firstThirdPartyIndex + 1; j < path.size() - 1; j++) {
                                    MethodSignature intermediate = path.get(j);
                                    String intermediatePkg = extractPackageName(
                                            formatMethodSignature(intermediate), ignoredPrefixes);
                                    if (intermediatePkg != null) {
                                        String intermediateGav = PackageMatcher.getDependencyName(
                                                intermediatePkg, packageMapPath);
                                        if (intermediateGav != null && !intermediateGav.equals(depGav)) {
                                            isDirect = false;
                                            break;
                                        }
                                    }
                                }
                                String accessType = isDirect ? "DIRECT" : "INDIRECT";

                                // Keep only the client caller and the dep caller of the
                                // sensitive API, deduplicated across all paths.
                                String clientCaller = firstThirdPartyIndex > 0
                                        ? formatMethodSignature(path.get(firstThirdPartyIndex - 1))
                                        : formatMethodSignature(entryPoint);
                                String depCaller = thirdPartyFormatted;
                                for (int k = path.size() - 2; k >= firstThirdPartyIndex; k--) {
                                    if (isThirdPartyMethod(path.get(k), ignoredPrefixes)) {
                                        depCaller = formatMethodSignature(path.get(k));
                                        break;
                                    }
                                }

                                String pairKey = depGav + "::" + sensitiveApiName + "::" + clientCaller + "::" + depCaller;
                                if (!seenPairs.add(pairKey)) {
                                    continue;
                                }

                                String clientGa = resolveArtifactGa(clientCaller, ignoredPrefixes, packageMapPath);
                                String depCallerGa = resolveArtifactGa(depCaller, ignoredPrefixes, packageMapPath);
                                List<PathMethod> fullPath = List.of(
                                        new PathMethod(clientCaller, clientGa),
                                        new PathMethod(depCaller, depCallerGa)
                                );

                                String[] catInfo = categoryLookup.get(stripParams(sensitiveApiName));
                                String category = catInfo != null ? catInfo[0] : null;
                                String subcategory = catInfo != null ? catInfo[1] : null;

                                SensitiveApiEntry apiEntry = new SensitiveApiEntry(
                                        sensitiveApiName,
                                        thirdPartyFormatted,
                                        accessType,
                                        List.of(depGav),
                                        fullPath,
                                        category,
                                        subcategory
                                );

                                entriesByDep.computeIfAbsent(depGav, k -> new ArrayList<>()).add(apiEntry);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error("Failed to initialize call graph or analyze reachability.", e);
        }

        log.info("Collected {} boundary interactions.", boundaryInteractions.size());
        return new FullReachabilityResult(reachableKeys, entriesByDep, boundaryInteractions);
    }

    /** Complete result of the reachability analysis including boundary interactions. */
    public record FullReachabilityResult(
            Set<String> reachableKeys,
            Map<String, List<SensitiveApiEntry>> entriesByDep,
            List<BoundaryInteraction> boundaryInteractions
    ) {}

    // -- Private helpers (same algorithms as MethodExtractor) --------------------------------

    private JavaView createJavaView(String pathToJar, Path depsDir) {
        // SootUp needs all dependency JARs on the classpath to resolve call graph
        // edges that cross from the project into dependency code.
        String classpath = pathToJar;
        if (depsDir != null && Files.isDirectory(depsDir)) {
            StringBuilder sb = new StringBuilder(pathToJar);
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(depsDir, "*.jar")) {
                for (Path jar : stream) {
                    sb.append(File.pathSeparator).append(jar.toAbsolutePath());
                }
            } catch (IOException e) {
                log.warn("Failed to list dependency JARs in {}: {}", depsDir, e.getMessage());
            }
            classpath = sb.toString();
            log.info("SootUp classpath: {} entries", classpath.split(File.pathSeparator).length);
        }
        AnalysisInputLocation inputLocation = new JavaClassPathAnalysisInputLocation(classpath);
        return new JavaView(inputLocation);
    }

    /**
     * Finds all public methods whose declaring class belongs to one of the given packages.
     * These serve as the entry points for the call graph traversal.
     */
    private Set<MethodSignature> detectEntryPoints(JavaView view, List<String> packageNames) {
        return view.getClasses()
                .flatMap(c -> c.getMethods().stream())
                .filter(SootMethod::isPublic)
                .filter(method -> {
                    String methodPkg = method.getDeclaringClassType().getPackageName().getName();
                    return packageNames.stream().anyMatch(methodPkg::startsWith);
                })
                .map(SootMethod::getSignature)
                .collect(Collectors.toSet());
    }

    /**
     * BFS from an entry point that also collects client→dep boundary crossings.
     * A boundary is recorded whenever a client method calls a third-party method.
     */
    private Set<MethodSignature> getAllReachableMethodsWithBoundaries(
            CallGraph cg, MethodSignature start,
            List<String> clientPackageNames, Set<String> ignoredPrefixes,
            Path packageMapPath,
            List<BoundaryInteraction> boundaries, Set<String> seenBoundaryKeys) {

        Set<MethodSignature> reachable = new HashSet<>();
        Deque<MethodSignature> queue = new ArrayDeque<>();
        queue.add(start);
        reachable.add(start);

        while (!queue.isEmpty()) {
            MethodSignature current = queue.poll();
            boolean sourceIsClient = isClientMethod(current, clientPackageNames);

            for (CallGraph.Call call : cg.callsFrom(current)) {
                MethodSignature target = call.getTargetMethodSignature();

                if (sourceIsClient && isThirdPartyMethod(target, ignoredPrefixes)) {
                    String clientFormatted = formatMethodSignature(current);
                    String depFormatted = formatMethodSignature(target);
                    String key = clientFormatted + "::" + depFormatted;
                    if (seenBoundaryKeys.add(key)) {
                        String depGa = resolveArtifactGa(depFormatted, ignoredPrefixes, packageMapPath);
                        if (depGa != null) {
                            boundaries.add(new BoundaryInteraction(clientFormatted, depFormatted, depGa));
                        }
                    }
                }

                if (reachable.add(target)) {
                    queue.add(target);
                }
            }
        }
        return reachable;
    }

    /**
     * Depth-first search for all paths from {@code start} to {@code target} in the call graph.
     * Uses a visited set to avoid cycles.
     */
    private List<List<MethodSignature>> findPaths(CallGraph cg, MethodSignature start, MethodSignature target) {
        List<List<MethodSignature>> results = new ArrayList<>();
        Deque<List<MethodSignature>> stack = new ArrayDeque<>();
        Set<MethodSignature> visited = new HashSet<>();
        stack.push(List.of(start));

        while (!stack.isEmpty()) {
            List<MethodSignature> path = stack.pop();
            MethodSignature last = path.get(path.size() - 1);

            if (last.equals(target)) {
                results.add(path);
                continue;
            }
            if (!visited.add(last)) {
                continue;
            }

            for (CallGraph.Call call : cg.callsFrom(last)) {
                MethodSignature next = call.getTargetMethodSignature();
                List<MethodSignature> newPath = new ArrayList<>(path);
                newPath.add(next);
                stack.push(newPath);
            }
        }
        return results;
    }

    /**
     * Checks whether a method signature matches one of the known sensitive API identifiers.
     * Matching is by className.methodName (without params) since the sensitive API catalog
     * does not distinguish overloads.
     */
    private boolean isSensitiveAPI(MethodSignature sig, Set<String> identifiers) {
        String nameOnly = formatName(sig.getDeclClassType().getFullyQualifiedName())
                + "." + formatName(sig.getName());
        return identifiers.contains(nameOnly);
    }

    /** True if the method belongs to the client project (its package starts with a client prefix). */
    private boolean isClientMethod(MethodSignature method, List<String> clientPackageNames) {
        String packageName = method.getDeclClassType().getPackageName().getName();
        return clientPackageNames.stream().anyMatch(packageName::startsWith);
    }

    /**
     * A method is considered third-party if its package does not start with any of the
     * ignored prefixes (which include JDK packages, test frameworks, and the project's own packages).
     */
    private boolean isThirdPartyMethod(MethodSignature method, Set<String> ignoredPrefixes) {
        String packageName = method.getDeclClassType().getPackageName().getName();
        return ignoredPrefixes.stream().noneMatch(packageName::startsWith);
    }

    /**
     * Produces a "className.methodName(paramType1,paramType2)" string for a method
     * signature, with inner-class separators cleaned up and full parameter types.
     */
    private String formatMethodSignature(MethodSignature method) {
        String className = formatName(method.getDeclClassType().getFullyQualifiedName());
        String methodName = formatName(method.getName());
        String params = method.getParameterTypes().stream()
                .map(t -> formatName(t.toString()))
                .collect(Collectors.joining(","));
        return className + "." + methodName + "(" + params + ")";
    }

    /**
     * Cleans up names that use dollar signs for inner classes or anonymous classes.
     * "$1234" (anonymous class indices) are removed; "$Foo" becomes ".Foo".
     */
    private String formatName(String name) {
        // Strip dollar-digit suffixes (anonymous/synthetic classes like $1, $23).
        name = name.replaceAll("\\$\\d+", "");
        // Turn dollar-letter boundaries into dots (inner classes like Outer$Inner -> Outer.Inner).
        name = name.replaceAll("\\$(?=[A-Za-z])", ".");
        return name;
    }

    /**
     * Strips the parameter list from a formatted method signature, returning
     * just "className.methodName" for use in lookups that don't distinguish overloads.
     */
    private String stripParams(String formattedSignature) {
        int parenIdx = formattedSignature.indexOf('(');
        return parenIdx >= 0 ? formattedSignature.substring(0, parenIdx) : formattedSignature;
    }

    /**
     * Extracts the package name from a fully qualified method signature string
     * (with or without parameter list), returning null if the package belongs
     * to an ignored prefix.
     */
    private String extractPackageName(String methodSignature, Set<String> ignoredPrefixes) {
        // Strip parameter list if present: "pkg.Class.method(params)" → "pkg.Class.method"
        String sig = methodSignature;
        int parenIdx = sig.indexOf('(');
        if (parenIdx >= 0) {
            sig = sig.substring(0, parenIdx);
        }
        int methodDot = sig.lastIndexOf('.');
        if (methodDot == -1) {
            return null;
        }
        String className = sig.substring(0, methodDot);
        int classDot = className.lastIndexOf('.');
        if (classDot == -1) {
            return null;
        }
        String packageName = className.substring(0, classDot);
        for (String prefix : ignoredPrefixes) {
            if (packageName.startsWith(prefix)) {
                return null;
            }
        }
        return packageName;
    }

    /**
     * Resolves the artifact GA (groupId.artifactId) for a formatted method signature.
     * Returns null for client-project or JDK methods (those in ignored prefixes).
     */
    private String resolveArtifactGa(String formattedMethod, Set<String> ignoredPrefixes, Path packageMapPath) {
        String pkg = extractPackageName(formattedMethod, ignoredPrefixes);
        if (pkg == null) {
            return null;
        }
        String gavWithVersion = PackageMatcher.getDependencyName(pkg, packageMapPath);
        if (gavWithVersion == null) {
            return null;
        }
        int lastColon = gavWithVersion.lastIndexOf(':');
        return lastColon > 0 ? gavWithVersion.substring(0, lastColon) : gavWithVersion;
    }
}
