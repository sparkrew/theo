package io.github.chains_project.theo.static_analysis.analysis;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.chains_project.theo.theo_commons.APILoader;
import io.github.chains_project.theo.theo_commons.PackageMatcher;
import io.github.chains_project.theo.theo_commons.SensitiveAPIDescriptor;
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
     * Core analysis logic shared by both public methods. Walks the client project's
     * call graph and collects both the identifier set (for highlighting) and the full
     * SensitiveApiEntry objects (for building reports).
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

        try {
            RapidTypeAnalysisAlgorithm rta = new RapidTypeAnalysisAlgorithm(view);
            CallGraph cg = rta.initialize(new ArrayList<>(entryPoints));

            Map<MethodSignature, Set<MethodSignature>> reachableMap = new HashMap<>();
            for (MethodSignature entryPoint : entryPoints) {
                reachableMap.put(entryPoint, getAllReachableMethods(cg, entryPoint));
            }

            for (Map.Entry<MethodSignature, Set<MethodSignature>> entry : reachableMap.entrySet()) {
                MethodSignature entryPoint = entry.getKey();
                Set<MethodSignature> reachable = entry.getValue();

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

                                List<String> fullPath = path.stream()
                                        .map(this::formatMethodSignature)
                                        .collect(Collectors.toList());

                                String[] catInfo = categoryLookup.get(sensitiveApiName);
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

        return new FullReachabilityResult(reachableKeys, entriesByDep);
    }

    private record FullReachabilityResult(
            Set<String> reachableKeys,
            Map<String, List<SensitiveApiEntry>> entriesByDep
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
     * Breadth-first traversal of the call graph starting from {@code start}.
     * Returns every method signature reachable from the starting point.
     */
    private Set<MethodSignature> getAllReachableMethods(CallGraph cg, MethodSignature start) {
        Set<MethodSignature> reachable = new HashSet<>();
        Deque<MethodSignature> queue = new ArrayDeque<>();
        queue.add(start);
        reachable.add(start);

        while (!queue.isEmpty()) {
            MethodSignature current = queue.poll();
            for (CallGraph.Call call : cg.callsFrom(current)) {
                MethodSignature target = call.getTargetMethodSignature();
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
     */
    private boolean isSensitiveAPI(MethodSignature sig, Set<String> identifiers) {
        String formatted = formatName(sig.getDeclClassType().getFullyQualifiedName())
                + "." + formatName(sig.getName());
        return identifiers.contains(formatted);
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
     * Produces a human-readable "className.methodName" string for a method signature,
     * with inner-class separators cleaned up.
     */
    private String formatMethodSignature(MethodSignature method) {
        String className = formatName(method.getDeclClassType().getFullyQualifiedName());
        String methodName = formatName(method.getName());
        return className + "." + methodName;
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
     * Extracts the package name from a fully qualified "className.methodName" string,
     * returning null if the package belongs to an ignored prefix.
     */
    private String extractPackageName(String methodSignature, Set<String> ignoredPrefixes) {
        int methodDot = methodSignature.lastIndexOf('.');
        if (methodDot == -1) {
            return null;
        }
        String className = methodSignature.substring(0, methodDot);
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
     * Splits a comma-separated package name string into individual package names.
     * Handles both single values and multiple comma-separated values.
     */
    private List<String> parsePackageNames(String packageName) {
        if (packageName == null || packageName.isBlank()) {
            return List.of();
        }
        return Arrays.stream(packageName.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }
}
