package io.github.chains_project.theo.package_miner.util;

import io.github.chains_project.theo.package_miner.model.PackageInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Set;

public class ResultWriter {

    private static final Logger log = LoggerFactory.getLogger(ResultWriter.class);

    private final Path csvFile;
    private final List<String> sensitiveApiKeys;
    private final Object writeLock = new Object();

    public ResultWriter(Path outputDir, List<String> sensitiveApiKeys) {
        this.csvFile = outputDir.resolve("sensitive_api_usage.csv");
        this.sensitiveApiKeys = sensitiveApiKeys;
    }

    public void writeHeader() throws IOException {
        synchronized (writeLock) {
            try (BufferedWriter writer = Files.newBufferedWriter(csvFile,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                writer.write("groupId,artifactId,version,scmUrl");
                for (String api : sensitiveApiKeys) {
                    writer.write(",");
                    writer.write(escapeCsv(api));
                }
                writer.newLine();
            }
        }
    }

    public void appendResult(PackageInfo pkg, Set<String> detectedApis) {
        synchronized (writeLock) {
            try (BufferedWriter writer = Files.newBufferedWriter(csvFile,
                    StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
                writer.write(escapeCsv(pkg.groupId()));
                writer.write(",");
                writer.write(escapeCsv(pkg.artifactId()));
                writer.write(",");
                writer.write(escapeCsv(pkg.latestVersion()));
                writer.write(",");
                writer.write(escapeCsv(pkg.scmUrl() != null ? pkg.scmUrl() : ""));

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

    private String escapeCsv(String value) {
        if (value == null) return "";
        if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }
}
