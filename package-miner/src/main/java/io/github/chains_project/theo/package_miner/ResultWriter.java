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
 * Writes the main results CSV file: one row per package, one column per sensitive API.
 *
 * The CSV has this structure:
 *   groupId, artifactId, version, java.io.FileInputStream.<init>, java.io.FileReader.<init>, ...
 *   com.google.guava, guava, 32.1.3-jre, True, False, ...
 *
 * There are 219 sensitive API columns (matching sensitive_apis.json), and each cell
 * is either "True" or "False" indicating whether that package uses that API.
 *
 * All writes go through a synchronized lock so that multiple worker threads can
 * safely append rows in parallel without corrupting the file.
 */
public class ResultWriter {

    private static final Logger log = LoggerFactory.getLogger(ResultWriter.class);

    private final Path csvFile;
    private final List<String> sensitiveApiKeys;
    // Lock to ensure only one thread writes to the CSV at a time
    private final Object writeLock = new Object();

    public ResultWriter(Path outputDir, List<String> sensitiveApiKeys) {
        this.csvFile = outputDir.resolve("sensitive_api_usage.csv");
        this.sensitiveApiKeys = sensitiveApiKeys;
    }

    /**
     * Writes the CSV header row. This should be called once at the start of a fresh run.
     * On resume, we skip this since the CSV already has the header.
     */
    public void writeHeader() throws IOException {
        synchronized (writeLock) {
            try (BufferedWriter writer = Files.newBufferedWriter(csvFile,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                writer.write("groupId,artifactId,version");
                for (String api : sensitiveApiKeys) {
                    writer.write(",");
                    writer.write(escapeCsv(api));
                }
                writer.newLine();
            }
        }
    }

    /**
     * Appends one row to the CSV for a single package.
     * Each sensitive API column gets "True" if the analysis found that API in the package,
     * "False" otherwise.
     *
     * @param pkg          the package (provides groupId, artifactId, version for the first 3 columns)
     * @param detectedApis the set of sensitive API identifiers detected by theo-static
     */
    public void appendResult(PackageInfo pkg, Set<String> detectedApis) {
        synchronized (writeLock) {
            try (BufferedWriter writer = Files.newBufferedWriter(csvFile,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                writer.write(escapeCsv(pkg.groupId()));
                writer.write(",");
                writer.write(escapeCsv(pkg.artifactId()));
                writer.write(",");
                writer.write(escapeCsv(pkg.latestVersion()));

                for (String api : sensitiveApiKeys) {
                    writer.write(",");
                    writer.write(detectedApis.contains(api) ? "True" : "False");
                }
                writer.newLine();
            } catch (IOException e) {
                log.error("Failed to write CSV row for {}", pkg.coordinate(), e);
            }
        }
    }

    /**
     * Escapes a value for CSV: wraps it in quotes if it contains commas,
     * quotes, or newlines. Doubles any internal quotes.
     */
    private String escapeCsv(String value) {
        if (value == null) return "";
        if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }
}
