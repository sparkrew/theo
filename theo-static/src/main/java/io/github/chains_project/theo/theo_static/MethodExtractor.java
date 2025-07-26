package io.github.chains_project.theo.theo_static;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.github.chains_project.theo.theo_commons.PackageMatcher;
import io.github.chains_project.theo.theo_commons.SensitiveAPIDescriptor;
import io.github.chains_project.theo.theo_commons.APILoader;
import io.github.chains_project.theo.theo_static.utils.AnalysisMetadata;
import io.github.chains_project.theo.theo_static.utils.SensitivePathAnalysisResult;
import io.github.chains_project.theo.theo_static.utils.SensitivePathResult;
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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

import static io.github.chains_project.theo.theo_commons.PackageMatcher.loadIgnoredPrefixes;

public class MethodExtractor {

    static final Logger log = LoggerFactory.getLogger(MethodExtractor.class);
    static Set<String> ignoredPrefixes;

    /**
     * This method processes the JAR file to extract sensitive API calls and their paths.
     * It reads a set of sensitive APIs from a JSON resource, initializes the call graph,
     * and finds paths to sensitive APIs that involve third-party method calls.
     *
     * @param pathToJar    Path to the JAR file to analyze.
     * @param reportPath   Path where the analysis report will be written.
     * @param packageName  The package name of the project under consideration to filter the events.
     * @param packageMapPath Path to the package map file that contains the mapping of package names to Maven coordinates.
     */
    public static void process(String pathToJar, String reportPath, String packageName, Path packageMapPath) {
        ignoredPrefixes = loadIgnoredPrefixes(packageName);
        List<SensitiveAPIDescriptor> sensitiveAPIList = APILoader.loadFromClasspath(
                "sensitive_apis.json", new TypeReference<>() {
                }
        );
        Set<String> sensitiveAPIIdentifiers = getSensitiveAPIIdentifiers(sensitiveAPIList);

        // Start reading the jar with sootup. Here we only use the main methods as the entry points.
        JavaView view = createJavaView(pathToJar);
        Set<MethodSignature> entryPoints = detectEntryPoints(view, packageName);
        log.info("Found " + entryPoints.size() + " public methods as entry points.");

        AnalysisResult result = analyzeReachability(view, entryPoints, sensitiveAPIIdentifiers, packageMapPath);

        AnalysisMetadata metadata = new AnalysisMetadata(
                pathToJar,
                entryPoints.size(),
                result.sensitivePathResults().size(),
                result.thirdPartyCalls().size(),
                System.currentTimeMillis()
        );

        SensitivePathAnalysisResult analysisResult = new SensitivePathAnalysisResult(metadata, result.sensitivePathResults());
//        Path projectRoot = Paths.get("").toAbsolutePath().getParent();
//        Path thirdPartyMethodsJsonPath = projectRoot.resolve("theo-commons/src/main/resources/third_party_methods.json");
//        writeThirdPartyMethodsToJson(result.thirdPartyCalls(), thirdPartyMethodsJsonPath.toFile());
//        log.info("Third party calls written to: " + thirdPartyMethodsJsonPath);
        OutputFormatter.process(analysisResult, reportPath);
        log.info("Dependency-wise output written to: " + reportPath);
    }

    private static JavaView createJavaView(String pathToJar) {
        AnalysisInputLocation inputLocation = new JavaClassPathAnalysisInputLocation(pathToJar);
        return new JavaView(inputLocation);
    }

    private static AnalysisResult analyzeReachability(JavaView view, Set<MethodSignature> entryPoints,
                                                      Set<String> sensitiveAPIIdentifiers, Path packageMapPath) {
        Set<String> thirdPartyCalls = new HashSet<>();
        List<SensitivePathResult> sensitivePathResults = new ArrayList<>();
        try {
            RapidTypeAnalysisAlgorithm cha = new RapidTypeAnalysisAlgorithm(view);
            CallGraph cg = cha.initialize(new ArrayList<>(entryPoints));

            Map<MethodSignature, Set<MethodSignature>> reachableMap = new HashMap<>();
            // We first find all reachable methods from the entry point.
            for (MethodSignature entryPoint : entryPoints) {
                Set<MethodSignature> reachable = getAllReachableMethods(cg, entryPoint);
                reachableMap.put(entryPoint, reachable);
            }
            // Then we check if sensitive APIs are accessed anywhere in those reachable paths from entry points.
            for (Map.Entry<MethodSignature, Set<MethodSignature>> entry : reachableMap.entrySet()) {
                MethodSignature entryPoint = entry.getKey();
                Set<MethodSignature> reachable = entry.getValue();
                Set<MethodSignature> reachableSensitive = reachable.stream()
                        .filter(method -> isSensitiveAPI(method, sensitiveAPIIdentifiers))
                        .collect(Collectors.toSet());
                // Here we check if any third party methods are there along the paths to sensitive APIs.
                for (MethodSignature sensitiveMethod : reachableSensitive) {
                    List<List<MethodSignature>> allPaths = findPaths(cg, entryPoint, sensitiveMethod);
                    for (List<MethodSignature> path : allPaths) {
                        MethodSignature firstThirdParty = null;
                        for (MethodSignature method : path) {
                            if (isThirdPartyMethod(method)) {
                                thirdPartyCalls.add(getFilteredMethodSignature(method));
                                if (firstThirdParty == null) {
                                    firstThirdParty = method;
                                }
                            }
                        }
                        // If there are any third party methods accessed among the way to sensitive APIs, we record them.
                        if (firstThirdParty != null) {
                            List<String> pathStrings = path.stream()
                                    .map(MethodExtractor::getFilteredMethodSignature)
                                    .collect(Collectors.toList());
                            Map<String, Map<String, String>> depPosMap = computeDependencyPositions(pathStrings,
                                    packageMapPath);
                            sensitivePathResults.add(new SensitivePathResult(
                                    entryPoint.toString(),
                                    firstThirdParty.toString(),
                                    getFilteredMethodSignature(sensitiveMethod),
                                    pathStrings,
                                    depPosMap
                            ));

                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error("Failed to initialize call graph.", e);
        }
        return new AnalysisResult(thirdPartyCalls, sensitivePathResults);
    }

    private static Map<String, Map<String, String>> computeDependencyPositions(List<String> path, Path packagePath) {
        Map<String, Integer> positionToIndex = new LinkedHashMap<>();
        for (int i = 0; i < path.size(); i++) {
            String method = path.get(i);
            String packageName = extractPackageName(method);
            if (packageName != null) {
                positionToIndex.put(packageName + "#" + i, i);
            }
        }
        List<String> orderedPackageNames = positionToIndex.keySet().stream()
                .map(s -> s.split("#")[0])
                .distinct()
                .toList();
        // A TreeMap to make sure the keys are sorted. So there won't be diffs for the same input.
        Map<String, Map<String, String>> dependencyMap = new TreeMap<>();
        int firstDepIndex = -1;
        int lastDepIndex = -1;
        // Get the dependency position. Later we assign "First" for the first method that has a non-null dependency.
        for (int i = 0; i < orderedPackageNames.size(); i++) {
            String dep = PackageMatcher.getDependencyName(orderedPackageNames.get(i), packagePath);
            if (dep != null) {
                if (firstDepIndex == -1) {
                    firstDepIndex = i;
                }
                lastDepIndex = i;
            }
        }
        // Here, we go again over the ordered package names and assign the positions based on the first and last
        // indices. If we can come up with a more optimized solution that does not need looping over twice, that would
        // be great. Now this works, so don't want to ruin it.
        for (int i = 0; i < orderedPackageNames.size(); i++) {
            String packageName = orderedPackageNames.get(i);
            String dep = PackageMatcher.getDependencyName(packageName, packagePath);
            if (dep == null) continue;
            String position;
            // If the same sensitive API is accessed multiple times, the position order will matter.
            if (i == firstDepIndex) {
                if (firstDepIndex == lastDepIndex)
                    position = "First, Last";
                else
                    position = "First";
            } else if (i == lastDepIndex) {
                position = "Last";
            } else {
                position = "Internal";
            }
            for (String method : path) {
                if (Objects.equals(extractPackageName(method), packageName)) {
                    String filtered = filterName(method);
                    dependencyMap.computeIfAbsent(dep, k -> new HashMap<>()).put(filtered, position);
                }
            }
        }
        return dependencyMap;
    }

    private static String extractPackageName(String method) {
        int methodDot = method.lastIndexOf('.');
        if (methodDot == -1) return null;
        String className = method.substring(0, methodDot);
        int classDot = className.lastIndexOf('.');
        if (classDot == -1) return null;
        String packageName = className.substring(0, classDot);
        // We reuse the ignored prefixes from MethodExtractor. The corresponding method is in the theo-commons module.
        for (String ignore : ignoredPrefixes) {
            if (packageName.startsWith(ignore)) return null;
        }
        return packageName;
    }

    private static String getFilteredMethodSignature(MethodSignature method) {
        String className = filterName(method.getDeclClassType().getFullyQualifiedName());
        String methodName = filterName(method.getName());
        return className + "." + methodName;
    }

    static String filterName(String name) {
        // Replace $ followed by digit (e.g., $Array1234) with nothing
        name = name.replaceAll("\\$\\d+", "");
        // Replace $ followed by letter (e.g. Java.ArrayInitializer) with a dot
        name = name.replaceAll("\\$(?=[A-Za-z])", ".");
        return name;
    }

    private static Set<String> getSensitiveAPIIdentifiers(List<SensitiveAPIDescriptor> list) {
        return list.stream()
                .map(desc -> desc.className() + "." + desc.method())
                .collect(Collectors.toSet());
    }

    // Using all public methods as entry points is not feasible either.
    private static Set<MethodSignature> detectEntryPoints(JavaView view, String packageName) {
        return view.getClasses()
                .flatMap(c -> c.getMethods().stream())
                .filter(SootMethod::isPublic)
                .filter(method -> "main".equals(method.getName()))
                .filter(method -> method.getDeclaringClassType().getPackageName().getName().startsWith(packageName))
                .map(SootMethod::getSignature)
                .collect(Collectors.toSet());
    }

    private static boolean isSensitiveAPI(MethodSignature sig, Set<String> identifiers) {
        return identifiers.contains(filterName(sig.getDeclClassType().getFullyQualifiedName()) + "." +
                filterName(sig.getName()));
    }

    private static boolean isThirdPartyMethod(MethodSignature method) {
        String packageName = method.getDeclClassType().getPackageName().getName();
        return ignoredPrefixes.stream().noneMatch(packageName::startsWith);
    }

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

    private static void writeThirdPartyMethodsToJson(Set<String> thirdPartyCalls, File outputFile) {
        List<ThirdPartyMethod> methodList = thirdPartyCalls.stream().map(fullMethod -> {
            int lastDot = fullMethod.lastIndexOf(".");
            String className = fullMethod.substring(0, lastDot);
            String method = fullMethod.substring(lastDot + 1);
            return new ThirdPartyMethod(className, method);
        }).collect(Collectors.toList());
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);
        try {
            mapper.writeValue(outputFile, methodList);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private record AnalysisResult(
            Set<String> thirdPartyCalls,
            List<SensitivePathResult> sensitivePathResults
    ) {
    }

    public record ThirdPartyMethod (
            String className,
            String method
    ){
    }
}
