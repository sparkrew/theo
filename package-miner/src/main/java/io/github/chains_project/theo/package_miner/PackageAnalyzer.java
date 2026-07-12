package io.github.chains_project.theo.package_miner;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.chains_project.theo.package_miner.model.PackageInfo;
import io.github.chains_project.theo.package_miner.util.PackageNameExtractor;
import io.github.chains_project.theo.theo_commons.APILoader;
import io.github.chains_project.theo.theo_commons.SensitiveAPIDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Runs the theo-static analyzer on individual package JARs and collects the results.
 *
 * For each package, this class:
 * 1. Downloads the POM and sets up a temporary Maven project directory
 * 2. Runs the theo-preprocessor-maven-plugin to resolve all dependencies and build the package map
 *    (the package map maps Java package names to their Maven coordinates)
 * 3. Invokes theo-static as a subprocess to analyze the JAR for sensitive API usage
 * 4. Parses the resulting report to extract which sensitive APIs were detected
 * 5. Writes a per-package paths JSON file listing the call paths from entry points to sensitive APIs
 *
 * If a report already exists on disk (from a previous run), we skip re-analyzing and just
 * parse the existing report. This works together with the checkpoint system for resumability.
 */
public class PackageAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(PackageAnalyzer.class);
    // Kill the analysis if it takes longer than 30 minutes — some packages can be very large
    private static final long ANALYSIS_TIMEOUT_MINUTES = 30;
    // Preprocessor should be much faster — it just resolves dependencies and scans JARs
    private static final long PREPROCESSOR_TIMEOUT_MINUTES = 10;
    private static final long DEPENDENCY_RESOLVE_TIMEOUT_MINUTES = 10;

    private final Path analyzerJar;
    private final Path outputDir;
    private final MavenCentralClient mavenClient;
    // The 219 sensitive API identifiers (e.g. "java.io.FileInputStream.<init>"), sorted
    // for consistent CSV column ordering
    private final List<String> sensitiveApiKeys;

    public PackageAnalyzer(Path analyzerJar, Path outputDir, MavenCentralClient mavenClient) {
        this.analyzerJar = analyzerJar;
        this.outputDir = outputDir;
        this.mavenClient = mavenClient;

        // Load the sensitive API list from theo-commons (same list used by theo-static)
        List<SensitiveAPIDescriptor> apis = APILoader.loadFromClasspath(
                "sensitive_apis.json", new TypeReference<>() {}
        );
        this.sensitiveApiKeys = apis.stream()
                .map(api -> api.className() + "." + api.method())
                .distinct()
                .sorted()
                .toList();
    }

    /**
     * Returns the sorted list of all 219 sensitive API identifiers.
     * This is used by the ResultWriter to create the CSV header.
     */
    public List<String> getSensitiveApiKeys() {
        return sensitiveApiKeys;
    }

    /**
     * Analyzes a single package for sensitive API usage.
     *
     * We need two JARs because they serve different purposes:
     * - bytecodeJarPath: the compiled JAR passed to theo-static (SootUp needs bytecode)
     * - sourceJarPath:   the sources JAR used for package name extraction (only contains
     *                    the project's own .java files, no bundled dependencies). Can be null
     *                    if the package doesn't publish a source JAR — we fall back to the
     *                    bytecode JAR with dependency filtering.
     *
     * @param pkg              the package metadata (groupId, artifactId, version)
     * @param bytecodeJarPath  path to the compiled/packaged JAR (for theo-static)
     * @param sourceJarPath    path to the sources JAR (for package name extraction), or null
     * @return which sensitive APIs were found, plus the path to the detailed paths JSON file
     */
    public AnalysisResult analyze(PackageInfo pkg, Path bytecodeJarPath, Path sourceJarPath) {
        String pkgKey = pkg.groupId() + "_" + pkg.artifactId() + "_" + pkg.latestVersion();
        Path reportFile = outputDir.resolve("reports").resolve(pkgKey + "-report.json");

        try {
            Files.createDirectories(reportFile.getParent());
        } catch (IOException e) {
            log.error("Failed to create report directory for {}", pkgKey, e);
            return new AnalysisResult(pkg, Collections.emptySet(), null, false, false, 0);
        }

        // If we already have a report from a previous run, just parse it instead of re-running.
        if (Files.exists(reportFile) && fileSize(reportFile) > 0) {
            log.info("Report already exists for {}, parsing...", pkgKey);
            return parseReport(pkg, reportFile, true, true);
        }

        // Step 1: Generate the package map and resolve dependencies.
        Path packageMapPath = generatePackageMap(pkg);
        if (packageMapPath == null) {
            log.warn("Could not generate package map for {}, skipping analysis.", pkgKey);
            return new AnalysisResult(pkg, Collections.emptySet(), null, false, false, 0);
        }

        // Step 1b: Resolve dependency JARs into a per-package folder
        Path depsDir = resolveDependencies(pkg);

        // Step 2: Extract the project's package name(s).
        // Prefer the source JAR since it only has the project's own .java files (no bundled deps).
        // If no source JAR is available, fall back to the bytecode JAR with dependency filtering
        // using the package map to subtract known dependency packages.
        List<String> packageNames;
        if (sourceJarPath != null) {
            // Source JARs are clean — they only contain the project's own source files
            packageNames = PackageNameExtractor.extractFromJar(sourceJarPath, Collections.emptySet());
        } else {
            // Bytecode JAR might be an uber JAR, so filter out dependency packages
            Set<String> dependencyPackages = loadPackageMapKeys(packageMapPath);
            packageNames = PackageNameExtractor.extractFromJar(bytecodeJarPath, dependencyPackages);
        }
        if (packageNames.isEmpty()) {
            log.warn("No package names found in JARs for {}, falling back to groupId.", pkgKey);
            packageNames = List.of(pkg.groupId());
        }
        String packageNameParam = String.join(",", packageNames);
        log.info("Using package name(s) for {}: {}", pkgKey, packageNameParam);

        // Step 3: Run the package-static-analyzer on the bytecode JAR
        try {
            List<String> cmd = new ArrayList<>(List.of(
                    "java", "-jar", analyzerJar.toAbsolutePath().toString(),
                    "analyze",
                    "-j", bytecodeJarPath.toAbsolutePath().toString(),
                    "-p", packageNameParam,
                    "-m", packageMapPath.toAbsolutePath().toString(),
                    "-r", reportFile.toAbsolutePath().toString()
            ));
            if (depsDir != null) {
                cmd.add("-d");
                cmd.add(depsDir.toAbsolutePath().toString());
            }
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            Process process = pb.start();

            // Read and log theo-static's output so it doesn't block on a full buffer
            boolean oomDetected = false;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    log.debug("[analyzer:{}] {}", pkg.artifactId(), line);
                    if (isOomMessage(line)) {
                        oomDetected = true;
                        log.warn("OOM detected in analyzer subprocess for {}, killing process.", pkgKey);
                        process.destroyForcibly();
                        break;
                    }
                }
            }

            if (oomDetected) {
                process.waitFor(10, TimeUnit.SECONDS);
                return new AnalysisResult(pkg, Collections.emptySet(), null, true, false, 0);
            }

            boolean finished = process.waitFor(ANALYSIS_TIMEOUT_MINUTES, TimeUnit.MINUTES);
            if (!finished) {
                process.destroyForcibly();
                log.warn("Analysis timed out for {}", pkgKey);
                return new AnalysisResult(pkg, Collections.emptySet(), null, true, false, 0);
            }

            if (process.exitValue() != 0) {
                log.warn("Analysis failed for {} (exit code {})", pkgKey, process.exitValue());
                return new AnalysisResult(pkg, Collections.emptySet(), null, true, false, 0);
            }

            return parseReport(pkg, reportFile, true, true);

        } catch (Exception e) {
            log.error("Error analyzing {}", pkgKey, e);
            return new AnalysisResult(pkg, Collections.emptySet(), null, true, false, 0);
        }
    }

    /**
     * Generates a proper package map by running the theo-preprocessor-maven-plugin.
     *
     * The preprocessor is a Maven plugin that needs to run inside a Maven project context.
     * It resolves all transitive dependencies of the project and scans each dependency JAR
     * to map Java package names to their Maven coordinates.
     *
     * To make this work for a standalone package from Maven Central, we:
     * 1. Download the package's POM file
     * 2. Create a temporary Maven project directory with that POM
     * 3. Run "mvn io.github.chains-project:theo-preprocessor-maven-plugin:preprocess"
     *    in that directory, which triggers Maven's dependency resolution and produces the map
     * 4. Return the path to the generated package-map.json
     */
    private Path generatePackageMap(PackageInfo pkg) {
        String pkgKey = pkg.groupId() + "_" + pkg.artifactId() + "_" + pkg.latestVersion();
        Path packageMapFile = outputDir.resolve("package-maps").resolve(pkgKey + "-package-map.json");

        // If we already generated this package map in a previous run, reuse it
        if (Files.exists(packageMapFile) && fileSize(packageMapFile) > 0) {
            log.info("Package map already exists for {}, reusing.", pkgKey);
            return packageMapFile;
        }

        try {
            Files.createDirectories(packageMapFile.getParent());

            // Download the POM from Maven Central
            Path pomDir = outputDir.resolve("poms");
            Path pomFile = mavenClient.downloadPom(pkg, pomDir);
            if (pomFile == null) {
                log.warn("Could not download POM for {}", pkgKey);
                return null;
            }

            // Create a temporary Maven project directory with the POM.
            // The preprocessor plugin needs to run in a directory that has a pom.xml
            // so Maven can resolve the project's dependencies.
            Path tempProjectDir = outputDir.resolve("temp-projects").resolve(pkgKey);
            Files.createDirectories(tempProjectDir);
            Path tempPom = tempProjectDir.resolve("pom.xml");
            Files.copy(pomFile, tempPom, StandardCopyOption.REPLACE_EXISTING);

            // Also create a minimal src directory so Maven doesn't complain
            Files.createDirectories(tempProjectDir.resolve("src/main/java"));

            // Run the preprocessor Maven plugin in the temp project directory.
            // This will resolve all dependencies declared in the POM, scan their JARs,
            // and write the package-to-dependency map to the output file.
            log.info("Running preprocessor for {} to generate package map...", pkgKey);
            ProcessBuilder pb = new ProcessBuilder(
                    "mvn",
                    "io.github.chains-project:theo-preprocessor-maven-plugin:1.0-SNAPSHOT:preprocess",
                    "-DoutputFile=" + packageMapFile.toAbsolutePath()
            );
            pb.directory(tempProjectDir.toFile());
            pb.redirectErrorStream(true);
            Process process = pb.start();

            // Read Maven's output so the process doesn't hang on a full buffer
            boolean oomDetected = false;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    log.debug("[preprocessor:{}] {}", pkg.artifactId(), line);
                    if (isOomMessage(line)) {
                        oomDetected = true;
                        log.warn("OOM detected in preprocessor subprocess for {}, killing process.", pkgKey);
                        process.destroyForcibly();
                        break;
                    }
                }
            }

            if (oomDetected) {
                process.waitFor(10, TimeUnit.SECONDS);
                return null;
            }

            boolean finished = process.waitFor(PREPROCESSOR_TIMEOUT_MINUTES, TimeUnit.MINUTES);
            if (!finished) {
                process.destroyForcibly();
                log.warn("Preprocessor timed out for {}", pkgKey);
                return null;
            }

            if (process.exitValue() != 0) {
                log.warn("Preprocessor failed for {} (exit code {})", pkgKey, process.exitValue());
                return null;
            }

            if (Files.exists(packageMapFile) && fileSize(packageMapFile) > 0) {
                log.info("Package map generated for {}", pkgKey);
                return packageMapFile;
            } else {
                log.warn("Preprocessor ran but no package map was generated for {}", pkgKey);
                return null;
            }

        } catch (Exception e) {
            log.error("Error generating package map for {}", pkgKey, e);
            return null;
        }
    }

    /**
     * Resolves all transitive dependency JARs for a package into a per-package directory.
     * Reuses the temp Maven project created by generatePackageMap().
     */
    private Path resolveDependencies(PackageInfo pkg) {
        String pkgKey = pkg.groupId() + "_" + pkg.artifactId() + "_" + pkg.latestVersion();
        Path depsDir = outputDir.resolve("deps").resolve(pkgKey);
        Path tempProjectDir = outputDir.resolve("temp-projects").resolve(pkgKey);

        if (Files.isDirectory(depsDir)) {
            try (var stream = Files.list(depsDir)) {
                if (stream.anyMatch(p -> p.toString().endsWith(".jar"))) {
                    log.debug("Dependencies already resolved for {}", pkgKey);
                    return depsDir;
                }
            } catch (IOException ignored) {}
        }

        if (!Files.isDirectory(tempProjectDir)) {
            log.debug("No temp project for {}, skipping dependency resolution.", pkgKey);
            return null;
        }

        try {
            Files.createDirectories(depsDir);
            ProcessBuilder pb = new ProcessBuilder(
                    "mvn", "dependency:copy-dependencies",
                    "-DoutputDirectory=" + depsDir.toAbsolutePath(),
                    "-DincludeScope=runtime",
                    "-B", "-q"
            );
            pb.directory(tempProjectDir.toFile());
            pb.redirectErrorStream(true);
            Process process = pb.start();

            boolean oomDetected = false;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (isOomMessage(line)) {
                        oomDetected = true;
                        log.warn("OOM detected in dependency resolution for {}, killing process.", pkgKey);
                        process.destroyForcibly();
                        break;
                    }
                }
            }

            if (oomDetected) {
                process.waitFor(10, TimeUnit.SECONDS);
                return null;
            }

            boolean finished = process.waitFor(DEPENDENCY_RESOLVE_TIMEOUT_MINUTES, TimeUnit.MINUTES);
            if (!finished) {
                process.destroyForcibly();
                log.warn("Dependency resolution timed out for {}", pkgKey);
                return null;
            }
            if (process.exitValue() != 0) {
                log.debug("Dependency resolution failed for {} (exit code {})", pkgKey, process.exitValue());
                return null;
            }
            return depsDir;
        } catch (Exception e) {
            log.debug("Error resolving dependencies for {}: {}", pkgKey, e.getMessage());
            return null;
        }
    }

    /**
     * Reads a package-static-analyzer report JSON and extracts:
     * - The set of sensitive API identifiers that were detected (for the CSV)
     * - The full call paths from entry points to sensitive APIs (for the per-package JSON)
     *
     * The report has "directAccesses" and "indirectAccesses" arrays, each with
     * entryPoint, sensitiveAPI, and fullPath fields.
     */
    private AnalysisResult parseReport(PackageInfo pkg, Path reportFile,
                                       boolean preprocessorOk, boolean analyzerOk) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> report = mapper.readValue(
                    reportFile.toFile(), new TypeReference<>() {}
            );

            Set<String> detectedApis = new HashSet<>();
            List<PathRecord> pathRecords = new ArrayList<>();

            // Extract the entry point count from the report metadata
            int entryPointCount = 0;
            Object metadataObj = report.get("metadata");
            if (metadataObj instanceof Map<?, ?> metaMap) {
                Object epCount = metaMap.get("entryPoints");
                if (epCount instanceof Number n) {
                    entryPointCount = n.intValue();
                }
            }

            // Parse both direct and indirect accesses from the report
            collectPaths(report.get("directAccesses"), detectedApis, pathRecords);
            collectPaths(report.get("indirectAccesses"), detectedApis, pathRecords);

            // Only write a paths JSON file if we actually found sensitive API accesses
            Path pathsJsonFile = null;
            if (!pathRecords.isEmpty()) {
                Path pathsDir = outputDir.resolve("paths");
                Files.createDirectories(pathsDir);
                String pkgKey = pkg.groupId() + "_" + pkg.artifactId() + "_" + pkg.latestVersion();
                pathsJsonFile = pathsDir.resolve(pkgKey + "-paths.json");
                mapper.writerWithDefaultPrettyPrinter().writeValue(pathsJsonFile.toFile(), pathRecords);
            }

            return new AnalysisResult(pkg, detectedApis, pathsJsonFile, preprocessorOk, analyzerOk, entryPointCount);

        } catch (IOException e) {
            log.error("Failed to parse report for {}", pkg.coordinate(), e);
            return new AnalysisResult(pkg, Collections.emptySet(), null, preprocessorOk, analyzerOk, 0);
        }
    }

    /**
     * Loads the keys (package names) from the preprocessor's package map JSON.
     * These represent packages that belong to dependencies — used to filter them out
     * when extracting the project's own package names from a potentially uber JAR.
     */
    private Set<String> loadPackageMapKeys(Path packageMapPath) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            Map<String, Object> map = mapper.readValue(
                    packageMapPath.toFile(), new TypeReference<>() {}
            );
            return map.keySet();
        } catch (IOException e) {
            log.warn("Could not read package map keys from {}, dependency filtering disabled.", packageMapPath);
            return Collections.emptySet();
        }
    }

    private static boolean isOomMessage(String line) {
        return line.contains("OutOfMemoryError")
                || line.contains("insufficient memory for the Java Runtime Environment")
                || line.contains("Native memory allocation (malloc) failed")
                || line.contains("Java heap space");
    }

    private long fileSize(Path file) {
        try {
            return Files.size(file);
        } catch (IOException e) {
            return 0;
        }
    }

    /**
     * Extracts paths from a "directAccesses" or "indirectAccesses" array in the report.
     */
    private void collectPaths(Object accessesObj, Set<String> detectedApis, List<PathRecord> pathRecords) {
        if (!(accessesObj instanceof List<?> accessesList)) return;
        for (Object item : accessesList) {
            if (!(item instanceof Map<?, ?> pathMap)) continue;
            String sensitiveApi = (String) pathMap.get("sensitiveAPI");
            String entryPoint = (String) pathMap.get("entryPoint");
            Object pathObj = pathMap.get("fullPath");

            if (sensitiveApi != null) {
                detectedApis.add(sensitiveApi);
            }

            List<String> pathSteps = new ArrayList<>();
            if (pathObj instanceof List<?> steps) {
                for (Object s : steps) {
                    pathSteps.add(String.valueOf(s));
                }
            }

            pathRecords.add(new PathRecord(
                    entryPoint != null ? entryPoint : "",
                    sensitiveApi != null ? sensitiveApi : "",
                    pathSteps
            ));
        }
    }

    /**
     * The result of analyzing a single package. Tracks whether each pipeline stage succeeded
     * so the orchestrator can count successes/failures at each step.
     *
     * @param packageInfo            the package that was analyzed
     * @param detectedSensitiveApis  the set of sensitive API identifiers found in this package
     * @param pathsJsonFile          path to the JSON file with detailed call paths (null if none found)
     * @param preprocessorSucceeded  true if the preprocessor ran successfully and produced a package map
     * @param analyzerSucceeded      true if the analyzer ran successfully and produced a report
     * @param entryPointCount        number of public entry point methods found in the package
     */
    public record AnalysisResult(
            PackageInfo packageInfo,
            Set<String> detectedSensitiveApis,
            Path pathsJsonFile,
            boolean preprocessorSucceeded,
            boolean analyzerSucceeded,
            int entryPointCount
    ) {}

    /**
     * Represents a single call path from an entry point to a sensitive API.
     * These get written to the per-package paths JSON files.
     */
    public record PathRecord(
            String entryPoint,
            String sensitiveAPI,
            List<String> path
    ) {}
}
