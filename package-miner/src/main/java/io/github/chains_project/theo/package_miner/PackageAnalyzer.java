package io.github.chains_project.theo.package_miner;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
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

    private final Path theoStaticJar;
    private final Path outputDir;
    private final MavenCentralClient mavenClient;
    // The 219 sensitive API identifiers (e.g. "java.io.FileInputStream.<init>"), sorted
    // for consistent CSV column ordering
    private final List<String> sensitiveApiKeys;

    public PackageAnalyzer(Path theoStaticJar, Path outputDir, MavenCentralClient mavenClient) {
        this.theoStaticJar = theoStaticJar;
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
     * Analyzes a single package JAR for sensitive API usage.
     *
     * @param pkg     the package metadata (groupId, artifactId, version)
     * @param jarPath path to the downloaded JAR file
     * @return which sensitive APIs were found, plus the path to the detailed paths JSON file
     */
    public AnalysisResult analyze(PackageInfo pkg, Path jarPath) {
        String pkgKey = pkg.groupId() + "_" + pkg.artifactId() + "_" + pkg.latestVersion();
        Path reportFile = outputDir.resolve("reports").resolve(pkgKey + "-report.json");

        try {
            Files.createDirectories(reportFile.getParent());
        } catch (IOException e) {
            log.error("Failed to create report directory for {}", pkgKey, e);
            return new AnalysisResult(pkg, Collections.emptySet(), null, false, false);
        }

        // If we already have a report from a previous run, just parse it instead of re-running.
        // We assume both preprocessor and analyzer succeeded if a valid report exists on disk.
        if (Files.exists(reportFile) && fileSize(reportFile) > 0) {
            log.info("Report already exists for {}, parsing...", pkgKey);
            return parseReport(pkg, reportFile, true, true);
        }

        // Step 1: Generate the package map by running the preprocessor.
        // This downloads the POM, creates a temp Maven project, and runs the preprocessor
        // plugin to resolve all transitive dependencies.
        Path packageMapPath = generatePackageMap(pkg);
        if (packageMapPath == null) {
            log.warn("Could not generate package map for {}, skipping analysis.", pkgKey);
            return new AnalysisResult(pkg, Collections.emptySet(), null, false, false);
        }

        // Step 2: Extract the project's package name(s) from the JAR's class files.
        // We use the package map (produced by the preprocessor) to filter out dependency
        // packages — this handles uber/fat JARs that bundle all dependencies inside.
        Set<String> dependencyPackages = loadPackageMapKeys(packageMapPath);
        List<String> packageNames = PackageNameExtractor.extractFromJar(jarPath, dependencyPackages);
        if (packageNames.isEmpty()) {
            log.warn("No package names found in JAR for {}, falling back to groupId.", pkgKey);
            packageNames = List.of(pkg.groupId());
        }
        // Pass as comma-separated string — theo-static now supports this format
        String packageNameParam = String.join(",", packageNames);
        log.info("Using package name(s) for {}: {}", pkgKey, packageNameParam);

        // Step 3: Run theo-static as a subprocess — same as running it from the command line
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "java", "-jar", theoStaticJar.toAbsolutePath().toString(),
                    "process",
                    "-j", jarPath.toAbsolutePath().toString(),
                    "-p", packageNameParam,
                    "-m", packageMapPath.toAbsolutePath().toString(),
                    "-r", reportFile.toAbsolutePath().toString()
            );
            pb.redirectErrorStream(true);
            Process process = pb.start();

            // Read and log theo-static's output so it doesn't block on a full buffer
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    log.debug("[theo-static:{}] {}", pkg.artifactId(), line);
                }
            }

            boolean finished = process.waitFor(ANALYSIS_TIMEOUT_MINUTES, TimeUnit.MINUTES);
            if (!finished) {
                process.destroyForcibly();
                log.warn("Analysis timed out for {}", pkgKey);
                return new AnalysisResult(pkg, Collections.emptySet(), null, true, false);
            }

            if (process.exitValue() != 0) {
                log.warn("Analysis failed for {} (exit code {})", pkgKey, process.exitValue());
                return new AnalysisResult(pkg, Collections.emptySet(), null, true, false);
            }

            return parseReport(pkg, reportFile, true, true);

        } catch (Exception e) {
            log.error("Error analyzing {}", pkgKey, e);
            return new AnalysisResult(pkg, Collections.emptySet(), null, true, false);
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
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    log.debug("[preprocessor:{}] {}", pkg.artifactId(), line);
                }
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
     * Reads a theo-static report JSON file and extracts:
     * - The set of sensitive API identifiers that were detected (for the CSV)
     * - The full call paths from entry points to sensitive APIs (for the per-package JSON)
     *
     * The report structure comes from theo-static's OutputFormatter and contains
     * a "sensitivePathResults" array where each entry has entryPoint, sensitiveAPI,
     * and the call path between them.
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

            // Walk through the sensitivePathResults array in the report
            Object pathsObj = report.get("sensitivePathResults");
            if (pathsObj instanceof List<?> pathsList) {
                for (Object item : pathsList) {
                    if (item instanceof Map<?, ?> pathMap) {
                        String sensitiveApi = (String) pathMap.get("sensitiveAPI");
                        String entryPoint = (String) pathMap.get("entryPoint");
                        Object pathObj = pathMap.get("path");

                        if (sensitiveApi != null) {
                            detectedApis.add(sensitiveApi);
                        }

                        // Collect the method call chain from entry point to sensitive API
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
            }

            // Only write a paths JSON file if we actually found sensitive API accesses
            Path pathsJsonFile = null;
            if (!pathRecords.isEmpty()) {
                Path pathsDir = outputDir.resolve("paths");
                Files.createDirectories(pathsDir);
                String pkgKey = pkg.groupId() + "_" + pkg.artifactId() + "_" + pkg.latestVersion();
                pathsJsonFile = pathsDir.resolve(pkgKey + "-paths.json");
                mapper.writerWithDefaultPrettyPrinter().writeValue(pathsJsonFile.toFile(), pathRecords);
            }

            return new AnalysisResult(pkg, detectedApis, pathsJsonFile, preprocessorOk, analyzerOk);

        } catch (IOException e) {
            log.error("Failed to parse report for {}", pkg.coordinate(), e);
            return new AnalysisResult(pkg, Collections.emptySet(), null, preprocessorOk, analyzerOk);
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

    private long fileSize(Path file) {
        try {
            return Files.size(file);
        } catch (IOException e) {
            return 0;
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
     * @param analyzerSucceeded      true if theo-static ran successfully and produced a report
     */
    public record AnalysisResult(
            PackageInfo packageInfo,
            Set<String> detectedSensitiveApis,
            Path pathsJsonFile,
            boolean preprocessorSucceeded,
            boolean analyzerSucceeded
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
