package io.github.chains_project.theo.static_analysis.analysis;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.chains_project.theo.static_analysis.model.DependencyReport;
import io.github.chains_project.theo.static_analysis.model.SensitiveApiEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Invokes the package-static-analyzer CLI tool as a subprocess to analyze
 * a single dependency JAR for sensitive API usage. Each call produces a
 * {@link DependencyReport} that can be cached or aggregated upstream.
 */
public class DependencyAnalyzer {

    private static final Logger log = LoggerFactory.getLogger(DependencyAnalyzer.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    // Default timeout per dependency analysis (5 minutes).
    private static final long DEFAULT_TIMEOUT_MINUTES = 5;

    private final Path analyzerJarPath;
    private final Path packageMapPath;
    private final Path depsDir;
    private final long timeoutMinutes;

    /**
     * @param analyzerJarPath path to the package-static-analyzer jar-with-dependencies
     * @param packageMapPath  path to the theo-package-map.json file
     * @param depsDir         directory containing all dependency JARs (used for SootUp classpath)
     */
    public DependencyAnalyzer(Path analyzerJarPath, Path packageMapPath, Path depsDir) {
        this(analyzerJarPath, packageMapPath, depsDir, DEFAULT_TIMEOUT_MINUTES);
    }

    public DependencyAnalyzer(Path analyzerJarPath, Path packageMapPath, Path depsDir, long timeoutMinutes) {
        this.analyzerJarPath = analyzerJarPath;
        this.packageMapPath = packageMapPath;
        this.depsDir = depsDir;
        this.timeoutMinutes = timeoutMinutes;
    }

    /**
     * Runs the package-static-analyzer on a single JAR and returns the result
     * as a {@link DependencyReport}. If the subprocess fails for any reason
     * (non-zero exit, timeout, parse error), a warning is logged and an empty
     * report is returned so the overall build is not interrupted.
     *
     * @param groupId      Maven groupId of the dependency
     * @param artifactId   Maven artifactId of the dependency
     * @param version      Maven version of the dependency
     * @param type         packaging type (e.g. "jar")
     * @param jarPath      path to the dependency JAR file
     * @param packageNames top-level package names belonging to this dependency
     * @return the analysis report, possibly with an empty sensitive-API list on failure
     */
    public DependencyReport analyze(String groupId, String artifactId, String version,
                                    String type, Path jarPath, Set<String> packageNames) {
        String gav = groupId + ":" + artifactId + ":" + version;
        Path reportFile = null;

        try {
            // Temporary file for the analyzer's JSON output.
            reportFile = Files.createTempFile("theo-report-", ".json");

            String packages = String.join(",", packageNames);

            List<String> command = List.of(
                    "java", "-jar", analyzerJarPath.toAbsolutePath().toString(),
                    "analyze",
                    "-j", jarPath.toAbsolutePath().toString(),
                    "-p", packages,
                    "-m", packageMapPath.toAbsolutePath().toString(),
                    "-d", depsDir.toAbsolutePath().toString(),
                    "-r", reportFile.toAbsolutePath().toString()
            );

            log.info("Analyzing {}", gav);
            log.debug("Running command: {}", String.join(" ", command));

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(false);
            Process process = pb.start();

            // Capture stdout and stderr in parallel to avoid buffer deadlocks.
            String stdout = drainStream(process.getInputStream());
            String stderr = drainStream(process.getErrorStream());

            boolean finished = process.waitFor(timeoutMinutes, TimeUnit.MINUTES);
            if (!finished) {
                process.destroyForcibly();
                log.warn("Analyzer timed out after {} minutes for {}", timeoutMinutes, gav);
                return emptyReport(groupId, artifactId, version, type);
            }

            int exitCode = process.exitValue();
            if (exitCode != 0) {
                log.warn("Analyzer exited with code {} for {}. stderr: {}", exitCode, gav, stderr);
                return emptyReport(groupId, artifactId, version, type);
            }

            if (!Files.exists(reportFile) || Files.size(reportFile) == 0) {
                log.warn("Analyzer produced no report file for {}", gav);
                return emptyReport(groupId, artifactId, version, type);
            }

            return parseReport(reportFile, groupId, artifactId, version, type);

        } catch (IOException e) {
            log.warn("IO error while analyzing {}: {}", gav, e.getMessage(), e);
            return emptyReport(groupId, artifactId, version, type);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Interrupted while analyzing {}", gav);
            return emptyReport(groupId, artifactId, version, type);
        } finally {
            // Clean up the temp report file.
            if (reportFile != null) {
                try {
                    Files.deleteIfExists(reportFile);
                } catch (IOException e) {
                    log.debug("Could not delete temp report file: {}", reportFile, e);
                }
            }
        }
    }

    /**
     * Parses the JSON report produced by the package-static-analyzer and converts
     * it into a {@link DependencyReport}.
     */
    private DependencyReport parseReport(Path reportFile, String groupId, String artifactId,
                                         String version, String type) {
        try {
            JsonNode root = mapper.readTree(reportFile.toFile());

            // Extract metadata.
            JsonNode metadata = root.path("metadata");
            int entryPointCount = metadata.path("entryPointCount").asInt(0);
            long timestamp = metadata.path("timestamp").asLong(System.currentTimeMillis());

            // Collect entries from both direct and indirect accesses.
            List<SensitiveApiEntry> entries = new ArrayList<>();
            collectEntries(root.path("directAccesses"), entries);
            collectEntries(root.path("indirectAccesses"), entries);

            return new DependencyReport(groupId, artifactId, version, type,
                    entries, entryPointCount, timestamp);

        } catch (IOException e) {
            log.warn("Failed to parse report for {}:{}:{} - {}", groupId, artifactId, version, e.getMessage());
            return emptyReport(groupId, artifactId, version, type);
        }
    }

    /**
     * Iterates over a JSON array of access entries and converts each to a
     * {@link SensitiveApiEntry}.
     */
    private void collectEntries(JsonNode arrayNode, List<SensitiveApiEntry> target) {
        if (arrayNode == null || arrayNode.isMissingNode() || !arrayNode.isArray()) {
            return;
        }

        for (JsonNode node : arrayNode) {
            String sensitiveApi = node.path("sensitiveAPI").asText("");
            String entryPoint = node.path("entryPoint").asText("");
            String accessType = node.path("accessType").asText("UNKNOWN");

            List<String> dependencies = jsonArrayToList(node.path("dependencies"));
            List<String> fullPath = jsonArrayToList(node.path("fullPath"));

            // Category and subcategory may not be present in every report.
            String category = node.has("category") ? node.get("category").asText(null) : null;
            String subcategory = node.has("subcategory") ? node.get("subcategory").asText(null) : null;

            target.add(new SensitiveApiEntry(
                    sensitiveApi, entryPoint, accessType, dependencies, fullPath,
                    category, subcategory
            ));
        }
    }

    /**
     * Converts a JSON array of strings into a Java list.
     */
    private List<String> jsonArrayToList(JsonNode arrayNode) {
        if (arrayNode == null || !arrayNode.isArray()) {
            return Collections.emptyList();
        }
        List<String> result = new ArrayList<>(arrayNode.size());
        for (JsonNode element : arrayNode) {
            result.add(element.asText());
        }
        return result;
    }

    /**
     * Creates an empty report for cases where analysis failed. This keeps
     * the overall build running even when individual dependencies cannot
     * be analyzed.
     */
    private static DependencyReport emptyReport(String groupId, String artifactId,
                                                 String version, String type) {
        return new DependencyReport(groupId, artifactId, version, type,
                Collections.emptyList(), 0, System.currentTimeMillis());
    }

    /**
     * Reads all available bytes from an input stream into a string. Used to
     * capture stdout/stderr from the subprocess.
     */
    private static String drainStream(java.io.InputStream stream) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(stream))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append(System.lineSeparator());
            }
        }
        return sb.toString();
    }

    /**
     * Locates the package-static-analyzer jar-with-dependencies in a local Maven
     * repository. Looks under the standard path for the 1.0-SNAPSHOT artifact.
     *
     * @param localRepoPath path to the local Maven repository (e.g. ~/.m2/repository)
     * @return the path to the jar-with-dependencies
     * @throws IOException if the jar cannot be found
     */
    public static Path resolveAnalyzerJar(Path localRepoPath) throws IOException {
        Path artifactDir = localRepoPath.resolve(
                "io/github/sparkrew/package-static-analyzer/1.0-SNAPSHOT");

        if (!Files.isDirectory(artifactDir)) {
            throw new IOException("Analyzer artifact directory not found: " + artifactDir);
        }

        // Find the jar-with-dependencies file in the directory.
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(artifactDir,
                "package-static-analyzer-*-jar-with-dependencies.jar")) {
            for (Path jarFile : stream) {
                log.debug("Resolved analyzer jar: {}", jarFile);
                return jarFile;
            }
        }

        throw new IOException("No jar-with-dependencies found in " + artifactDir);
    }
}
