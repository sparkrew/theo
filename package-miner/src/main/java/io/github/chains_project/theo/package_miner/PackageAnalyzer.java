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
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Runs the theo-static analyzer on individual package JARs and collects the results.
 *
 * For each package, this class:
 * 1. Creates a minimal package map JSON (needed by theo-static to resolve Maven coordinates)
 * 2. Invokes theo-static as a subprocess (java -jar theo-static.jar process ...)
 * 3. Parses the resulting report JSON to extract which sensitive APIs were detected
 * 4. Writes a per-package paths JSON file listing the call paths from entry points to sensitive APIs
 *
 * If a report already exists on disk (from a previous run), we skip re-analyzing and just
 * parse the existing report. This works together with the checkpoint system for resumability.
 */
public class PackageAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(PackageAnalyzer.class);
    // Kill the analysis if it takes longer than 30 minutes — some packages can be very large
    private static final long ANALYSIS_TIMEOUT_MINUTES = 30;

    private final Path theoStaticJar;
    private final Path outputDir;
    // The 219 sensitive API identifiers (e.g. "java.io.FileInputStream.<init>"), sorted
    // for consistent CSV column ordering
    private final List<String> sensitiveApiKeys;

    public PackageAnalyzer(Path theoStaticJar, Path outputDir) {
        this.theoStaticJar = theoStaticJar;
        this.outputDir = outputDir;

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
            return new AnalysisResult(pkg, Collections.emptySet(), null);
        }

        // If we already have a report from a previous run, just parse it instead of re-running
        if (Files.exists(reportFile) && fileSize(reportFile) > 0) {
            log.info("Report already exists for {}, parsing...", pkgKey);
            return parseReport(pkg, reportFile);
        }

        // theo-static requires a package map file that maps package names to Maven coordinates.
        // Since we're analyzing packages in isolation, we create a minimal map with just this package.
        Path packageMapPath = createMinimalPackageMap(pkg);
        if (packageMapPath == null) {
            return new AnalysisResult(pkg, Collections.emptySet(), null);
        }

        // Run theo-static as a subprocess — same as running it from the command line
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "java", "-jar", theoStaticJar.toAbsolutePath().toString(),
                    "process",
                    "-j", jarPath.toAbsolutePath().toString(),
                    "-p", pkg.groupId(),
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
                return new AnalysisResult(pkg, Collections.emptySet(), null);
            }

            if (process.exitValue() != 0) {
                log.warn("Analysis failed for {} (exit code {})", pkgKey, process.exitValue());
                return new AnalysisResult(pkg, Collections.emptySet(), null);
            }

            return parseReport(pkg, reportFile);

        } catch (Exception e) {
            log.error("Error analyzing {}", pkgKey, e);
            return new AnalysisResult(pkg, Collections.emptySet(), null);
        }
    }

    /**
     * Creates a minimal package map JSON file for this single package.
     * theo-static needs this to map Java package names to Maven coordinates.
     * In our case, we just map the package's groupId to its full Maven coordinate.
     */
    private Path createMinimalPackageMap(PackageInfo pkg) {
        try {
            Path mapDir = outputDir.resolve("package-maps");
            Files.createDirectories(mapDir);
            Path mapFile = mapDir.resolve(
                    pkg.groupId() + "_" + pkg.artifactId() + "_map.json"
            );
            Map<String, List<String>> packageMap = new HashMap<>();
            packageMap.put(pkg.groupId(), List.of(pkg.coordinate()));

            ObjectMapper mapper = new ObjectMapper();
            mapper.writeValue(mapFile.toFile(), packageMap);
            return mapFile;
        } catch (IOException e) {
            log.error("Failed to create package map for {}", pkg.coordinate(), e);
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
    private AnalysisResult parseReport(PackageInfo pkg, Path reportFile) {
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

            return new AnalysisResult(pkg, detectedApis, pathsJsonFile);

        } catch (IOException e) {
            log.error("Failed to parse report for {}", pkg.coordinate(), e);
            return new AnalysisResult(pkg, Collections.emptySet(), null);
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
     * The result of analyzing a single package.
     *
     * @param packageInfo          the package that was analyzed
     * @param detectedSensitiveApis the set of sensitive API identifiers found in this package
     * @param pathsJsonFile        path to the JSON file with detailed call paths (null if none found)
     */
    public record AnalysisResult(
            PackageInfo packageInfo,
            Set<String> detectedSensitiveApis,
            Path pathsJsonFile
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
