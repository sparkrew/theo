package io.github.chains_project.theo.package_miner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Set;

/**
 * Writes the main results CSV file: one row per module, one column per sensitive API.
 *
 * The CSV has this structure:
 *   groupId, artifactId, version, scmUrl, modulePath, java.io.FileInputStream.<init>, ...
 *   com.google.guava, guava, 32.1.3-jre, https://github.com/google/guava, ., True, False, ...
 *
 * There are 219 sensitive API columns (matching sensitive_apis.json), and each cell
 * is either "True" or "False" indicating whether that module uses that API.
 *
 * All writes go through a synchronized lock so that multiple worker threads can
 * safely append rows in parallel without corrupting the file.
 */
public class ResultWriter {

    private static final Logger log = LoggerFactory.getLogger(ResultWriter.class);

    private final Path csvFile;
    private final List<String> sensitiveApiKeys;
    private final Object writeLock = new Object();

    public ResultWriter(Path outputDir, List<String> sensitiveApiKeys) {
        this.csvFile = outputDir.resolve("sensitive_api_usage.csv");
        this.sensitiveApiKeys = sensitiveApiKeys;
    }

    /**
     * Writes the CSV header row. This should be called once at the start of a fresh run.
     */
    public void writeHeader() throws IOException {
        synchronized (writeLock) {
            try (BufferedWriter writer = Files.newBufferedWriter(csvFile,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                writer.write("groupId,artifactId,version,scmUrl,modulePath");
                for (String api : sensitiveApiKeys) {
                    writer.write(",");
                    writer.write(escapeCsv(api));
                }
                writer.newLine();
            }
        }
    }

    /**
     * Appends one row to the CSV for a single module.
     *
     * @param groupId      module groupId
     * @param artifactId   module artifactId
     * @param version      module version
     * @param scmUrl       GitHub URL (may be null)
     * @param modulePath   relative module path within the repo (e.g. "core" or ".")
     * @param detectedApis the set of sensitive API identifiers detected
     */
    public void appendResult(String groupId, String artifactId, String version,
                             String scmUrl, String modulePath, Set<String> detectedApis) {
        synchronized (writeLock) {
            try (BufferedWriter writer = Files.newBufferedWriter(csvFile,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                writer.write(escapeCsv(groupId));
                writer.write(",");
                writer.write(escapeCsv(artifactId));
                writer.write(",");
                writer.write(escapeCsv(version));
                writer.write(",");
                writer.write(escapeCsv(scmUrl != null ? scmUrl : ""));
                writer.write(",");
                writer.write(escapeCsv(modulePath != null ? modulePath : "."));

                for (String api : sensitiveApiKeys) {
                    writer.write(",");
                    writer.write(detectedApis.contains(api) ? "True" : "False");
                }
                writer.newLine();
            } catch (IOException e) {
                log.error("Failed to write CSV row for {}:{}", groupId, artifactId, e);
            }
        }
    }

    private String escapeCsv(String value) {
        if (value == null) return "";
        if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }
}
