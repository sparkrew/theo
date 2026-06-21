package io.github.chains_project.theo.package_static_analyzer;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.chains_project.theo.theo_commons.APILoader;
import io.github.chains_project.theo.theo_commons.PackageMatcher;
import io.github.chains_project.theo.theo_commons.SensitiveAPIDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sootup.callgraph.CallGraph;
import sootup.callgraph.RapidTypeAnalysisAlgorithm;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.core.model.SootMethod;
import sootup.core.signatures.MethodSignature;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.core.views.JavaView;

import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Analyzes whether a package reaches sensitive Java APIs, either directly or through dependencies.
 *
 * How this differs from theo-static's MethodExtractor:
 * - theo-static asks: "does a dependency of my project use sensitive APIs?"
 *   It only records paths that go through a third-party dependency.
 * - This analyzer asks: "does this package use sensitive APIs?"
 *   It records ALL paths to sensitive APIs — both direct calls (the package's own
 *   code directly invokes a sensitive API) and indirect ones (the package calls a
 *   dependency which eventually reaches a sensitive API).
 *
 * The call graph construction and path-finding algorithms are the same as theo-static
 * (SootUp with Rapid Type Analysis). The difference is in what gets recorded.
 */
public class PackageStaticAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(PackageStaticAnalyzer.class);

    // The project's own package prefixes — methods in these packages are "ours"
    private static List<String> projectPackages;

    /**
     * Runs the analysis on a bytecode JAR.
     *
     * @param pathToJar      path to the bytecode JAR
     * @param reportPath     where to write the JSON report
     * @param packageName    comma-separated package name(s) of the package being analyzed
     * @param packageMapPath path to the package map JSON (package → Maven coordinate)
     */
    public static void process(String pathToJar, String reportPath, String packageName, Path packageMapPath) {
        projectPackages = parsePackageNames(packageName);
        log.info("Analyzing package(s): {}", projectPackages);

        // Load the 219 sensitive API identifiers
        List<SensitiveAPIDescriptor> sensitiveAPIList = APILoader.loadFromClasspath(
                "sensitive_apis.json", new TypeReference<>() {}
        );
        Set<String> sensitiveAPIIdentifiers = sensitiveAPIList.stream()
                .map(desc -> desc.className() + "." + desc.method())
                .collect(Collectors.toSet());

        // Build the call graph from the JAR
        JavaView view = createJavaView(pathToJar);

        // Entry points are all public methods belonging to the package's own code.
        // We use all public methods (not just main) because when a package is used as
        // a library, any of its public methods could be called.
        Set<MethodSignature> entryPoints = view.getClasses()
                .flatMap(c -> c.getMethods().stream())
                .filter(m -> m.isPublic() || m.isProtected())
                .map(SootMethod::getSignature)
                .collect(Collectors.toSet());
        log.info("Found {} public methods as entry points.", entryPoints.size());

        // Analyze: find all paths from entry points to sensitive APIs
        List<SensitiveApiPath> results = analyzeReachability(view, entryPoints, sensitiveAPIIdentifiers, packageMapPath);
        log.info("Found {} paths to sensitive APIs.", results.size());

        // Write the report
        ReportWriter.write(results, pathToJar, entryPoints.size(), reportPath);
        log.info("Report written to: {}", reportPath);
    }

    /**
     * For each entry point, finds all reachable sensitive APIs and classifies
     * each path as "direct" (no dependency code involved) or "indirect" (goes
     * through one or more dependencies).
     */
    private static List<SensitiveApiPath> analyzeReachability(
            JavaView view,
            Set<MethodSignature> entryPoints,
            Set<String> sensitiveAPIIdentifiers,
            Path packageMapPath) {

        List<SensitiveApiPath> results = new ArrayList<>();

        try {
            RapidTypeAnalysisAlgorithm rta = new RapidTypeAnalysisAlgorithm(view);
            CallGraph cg = rta.initialize(new ArrayList<>(entryPoints));

            for (MethodSignature entryPoint : entryPoints) {
                // Find all methods reachable from this entry point
                Set<MethodSignature> reachable = getAllReachableMethods(cg, entryPoint);

                // Filter to just the sensitive APIs among them
                Set<MethodSignature> reachableSensitive = reachable.stream()
                        .filter(m -> isSensitiveAPI(m, sensitiveAPIIdentifiers))
                        .collect(Collectors.toSet());

                for (MethodSignature sensitiveMethod : reachableSensitive) {
                    List<List<MethodSignature>> allPaths = findPaths(cg, entryPoint, sensitiveMethod);

                    for (List<MethodSignature> path : allPaths) {
                        List<String> pathStrings = path.stream()
                                .map(PackageStaticAnalyzer::formatMethodSignature)
                                .collect(Collectors.toList());

                        // Classify: find which dependencies (if any) sit along the path
                        Set<String> intermediaryDependencies = new LinkedHashSet<>();
                        boolean directAccess = true;

                        // Walk the path between the entry point and the sensitive API.
                        // Any method that is NOT project code and NOT the sensitive API itself
                        // means the access goes through a dependency.
                        for (int i = 1; i < path.size() - 1; i++) {
                            MethodSignature method = path.get(i);
                            String methodPkg = method.getDeclClassType().getPackageName().getName();

                            if (!isProjectMethod(methodPkg) && !isSensitiveAPI(method, sensitiveAPIIdentifiers)) {
                                directAccess = false;
                                // Look up which Maven dependency this method belongs to
                                String dep = PackageMatcher.getDependencyName(methodPkg, packageMapPath);
                                if (dep != null) {
                                    intermediaryDependencies.add(dep);
                                } else {
                                    // Package not in the map — use the package name as identifier
                                    intermediaryDependencies.add(methodPkg);
                                }
                            }
                        }

                        // Also check: if the path has only 2 nodes (entry → sensitive API),
                        // it's a direct call by definition
                        if (path.size() <= 2) {
                            directAccess = true;
                        }

                        results.add(new SensitiveApiPath(
                                entryPoint.toString(),
                                formatMethodSignature(sensitiveMethod),
                                directAccess ? "DIRECT" : "INDIRECT",
                                new ArrayList<>(intermediaryDependencies),
                                pathStrings
                        ));
                    }
                }
            }
        } catch (Exception e) {
            log.error("Failed during call graph analysis.", e);
        }

        return results;
    }

    /** Checks if a method's package belongs to the project being analyzed. */
    private static boolean isProjectMethod(String packageName) {
        return projectPackages.stream().anyMatch(packageName::startsWith);
    }

    private static JavaView createJavaView(String pathToJar) {
        AnalysisInputLocation inputLocation = new JavaClassPathAnalysisInputLocation(pathToJar);
        return new JavaView(inputLocation);
    }

    private static boolean isSensitiveAPI(MethodSignature sig, Set<String> identifiers) {
        return identifiers.contains(
                formatName(sig.getDeclClassType().getFullyQualifiedName()) + "." + formatName(sig.getName())
        );
    }

    /** BFS to find all methods reachable from a starting method in the call graph. */
    private static Set<MethodSignature> getAllReachableMethods(CallGraph cg, MethodSignature start) {
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
     * DFS to find paths from start to target in the call graph.
     * Uses a visited set to avoid infinite loops in recursive call chains.
     */
    private static List<List<MethodSignature>> findPaths(CallGraph cg, MethodSignature start, MethodSignature target) {
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
            if (!visited.add(last)) continue;
            for (CallGraph.Call call : cg.callsFrom(last)) {
                MethodSignature next = call.getTargetMethodSignature();
                List<MethodSignature> newPath = new ArrayList<>(path);
                newPath.add(next);
                stack.push(newPath);
            }
        }
        return results;
    }

    /** Cleans up SootUp's internal naming ($ separators) into readable dot notation. */
    static String formatMethodSignature(MethodSignature method) {
        String className = formatName(method.getDeclClassType().getFullyQualifiedName());
        String methodName = formatName(method.getName());
        return className + "." + methodName;
    }

    static String formatName(String name) {
        name = name.replaceAll("\\$\\d+", "");
        name = name.replaceAll("\\$(?=[A-Za-z])", ".");
        return name;
    }

    private static List<String> parsePackageNames(String packageName) {
        if (packageName == null || packageName.isBlank()) return List.of();
        return Arrays.stream(packageName.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    /**
     * A single path from an entry point to a sensitive API.
     *
     * @param entryPoint       the public method where the path starts
     * @param sensitiveAPI     the sensitive API that is reached
     * @param accessType       "DIRECT" if project code calls the API directly,
     *                         "INDIRECT" if the call goes through dependency code
     * @param dependencies     the dependencies involved in an indirect path (empty for direct)
     * @param fullPath         the complete method call chain from entry point to sensitive API
     */
    public record SensitiveApiPath(
            String entryPoint,
            String sensitiveAPI,
            String accessType,
            List<String> dependencies,
            List<String> fullPath
    ) {}
}
