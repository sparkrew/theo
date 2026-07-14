package io.github.chains_project.theo.package_miner;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.chains_project.theo.package_miner.model.PackageInfo;
import io.github.chains_project.theo.package_miner.util.CheckpointManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.*;
import java.util.concurrent.*;

/**
 * Temporary recovery script — finds packages that were completed but have no report
 * (i.e. skipped in a previous run), re-runs the analysis to classify the failure reason,
 * and updates the CSV for packages that succeed on retry.
 * Safe to delete once recovery is done.
 */
@CommandLine.Command(name = "recover-skipped", mixinStandardHelpOptions = true,
        description = "Find and re-analyze previously skipped packages to classify failure reasons.")
public class RecoverSkippedCommand implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(RecoverSkippedCommand.class);
    private static final long SCAN_TIMEOUT_MINUTES = 20;

    @CommandLine.Option(names = {"-o", "--output-dir"}, paramLabel = "OUTPUT-DIR",
            description = "Directory with existing scan results.", required = true)
    Path outputDir;

    @CommandLine.Option(names = {"-j", "--analyzer-jar"}, paramLabel = "ANALYZER-JAR",
            description = "Path to the package-static-analyzer jar-with-dependencies JAR.", required = true)
    Path analyzerJar;

    @CommandLine.Option(names = {"--download-dir"}, paramLabel = "DOWNLOAD-DIR",
            description = "Directory for downloaded JARs. Defaults to <output-dir>/jars.")
    Path downloadDir;

    @Override
    public void run() {
        if (downloadDir == null) {
            downloadDir = outputDir.resolve("jars");
        }

        ObjectMapper mapper = new ObjectMapper();
        CheckpointManager checkpoint = new CheckpointManager(outputDir);

        List<PackageInfo> allPackages = checkpoint.loadPackageList();
        if (allPackages == null || allPackages.isEmpty()) {
            log.error("No selected_packages.json found in {}.", outputDir);
            return;
        }

        Path reportsDir = outputDir.resolve("reports");
        List<PackageInfo> skipped = new ArrayList<>();
        for (PackageInfo pkg : allPackages) {
            if (!checkpoint.isCompleted(pkg)) continue;
            String reportKey = pkg.groupId() + "_" + pkg.artifactId() + "_" + pkg.latestVersion();
            Path reportFile = reportsDir.resolve(reportKey + "-report.json");
            if (!Files.exists(reportFile) || fileSize(reportFile) == 0) {
                skipped.add(pkg);
            }
        }

        if (skipped.isEmpty()) {
            log.info("No skipped packages found — all completed packages have reports.");
            return;
        }

        log.info("Found {} skipped packages. Re-analyzing to classify failure reasons...", skipped.size());

        MavenCentralClient client = new MavenCentralClient();
        PackageAnalyzer analyzer = new PackageAnalyzer(analyzerJar, outputDir, client);

        List<PackageInfo> downloadFailed = new ArrayList<>();
        List<PackageInfo> scanFailed = new ArrayList<>();
        List<PackageInfo> timedOut = new ArrayList<>();
        List<PackageInfo> oomPackages = new ArrayList<>();
        Map<String, Set<String>> succeededOnRetry = new LinkedHashMap<>();

        for (int i = 0; i < skipped.size(); i++) {
            PackageInfo pkg = skipped.get(i);
            log.info("[{}/{}] Re-analyzing {}...", i + 1, skipped.size(), pkg.coordinate());

            try {
                Path bytecodeJar = client.downloadBytecodeJar(pkg, downloadDir);
                if (bytecodeJar == null) {
                    log.info("  -> download failed");
                    downloadFailed.add(pkg);
                    continue;
                }
                Path sourceJar = client.downloadSourceJar(pkg, downloadDir);

                ExecutorService timeoutExecutor = Executors.newSingleThreadExecutor();
                Future<PackageAnalyzer.AnalysisResult> analysisFuture =
                        timeoutExecutor.submit(() -> analyzer.analyze(pkg, bytecodeJar, sourceJar));

                PackageAnalyzer.AnalysisResult result;
                try {
                    result = analysisFuture.get(SCAN_TIMEOUT_MINUTES, TimeUnit.MINUTES);
                } catch (TimeoutException e) {
                    analysisFuture.cancel(true);
                    log.info("  -> timed out");
                    timedOut.add(pkg);
                    continue;
                } finally {
                    timeoutExecutor.shutdownNow();
                }

                if (!result.analyzerSucceeded()) {
                    log.info("  -> scan failed");
                    scanFailed.add(pkg);
                } else {
                    log.info("  -> succeeded ({} sensitive APIs)", result.detectedSensitiveApis().size());
                    succeededOnRetry.put(pkg.coordinate(), result.detectedSensitiveApis());
                }

            } catch (OutOfMemoryError e) {
                log.info("  -> OOM");
                oomPackages.add(pkg);
            } catch (Exception e) {
                log.info("  -> scan failed ({})", e.getMessage());
                scanFailed.add(pkg);
            }
        }

        if (!succeededOnRetry.isEmpty()) {
            updateCsv(succeededOnRetry, analyzer.getSensitiveApiKeys());
        }

        log.info("=============================================================");
        log.info("  RECOVERY RESULTS");
        log.info("  Total skipped:      {}", skipped.size());
        log.info("  Download failed:    {}", downloadFailed.size());
        log.info("  Scan failed:        {}", scanFailed.size());
        log.info("  Timed out:          {}", timedOut.size());
        log.info("  OOM:                {}", oomPackages.size());
        log.info("  Succeeded on retry: {}", succeededOnRetry.size());
        log.info("=============================================================");

        try {
            if (!downloadFailed.isEmpty())
                mapper.writerWithDefaultPrettyPrinter().writeValue(
                        outputDir.resolve("recovered_download_failed.json").toFile(), downloadFailed);
            if (!scanFailed.isEmpty())
                mapper.writerWithDefaultPrettyPrinter().writeValue(
                        outputDir.resolve("recovered_scan_failed.json").toFile(), scanFailed);
            if (!timedOut.isEmpty())
                mapper.writerWithDefaultPrettyPrinter().writeValue(
                        outputDir.resolve("recovered_timed_out.json").toFile(), timedOut);
            if (!oomPackages.isEmpty())
                mapper.writerWithDefaultPrettyPrinter().writeValue(
                        outputDir.resolve("recovered_oom.json").toFile(), oomPackages);
            log.info("Results saved to recovered_*.json files.");
        } catch (IOException e) {
            log.error("Failed to save recovery results.", e);
        }
    }

    private void updateCsv(Map<String, Set<String>> succeededOnRetry, List<String> sensitiveApiKeys) {
        Path csvFile = outputDir.resolve("sensitive_api_usage.csv");
        if (!Files.exists(csvFile)) {
            log.warn("CSV file not found, cannot update.");
            return;
        }

        try {
            List<String> lines = Files.readAllLines(csvFile);
            if (lines.isEmpty()) return;

            String header = lines.get(0);
            List<String> updatedLines = new ArrayList<>();
            updatedLines.add(header);

            for (int i = 1; i < lines.size(); i++) {
                String line = lines.get(i);
                String[] cols = line.split(",", 4);
                if (cols.length < 3) {
                    updatedLines.add(line);
                    continue;
                }

                String coordinate = cols[0] + ":" + cols[1] + ":" + cols[2];
                Set<String> newApis = succeededOnRetry.get(coordinate);
                if (newApis != null) {
                    StringBuilder sb = new StringBuilder();
                    sb.append(escapeCsv(cols[0]));
                    sb.append(",").append(escapeCsv(cols[1]));
                    sb.append(",").append(escapeCsv(cols[2]));
                    for (String api : sensitiveApiKeys) {
                        sb.append(",").append(newApis.contains(api) ? "True" : "False");
                    }
                    updatedLines.add(sb.toString());
                    log.info("Updated CSV row for {}", coordinate);
                } else {
                    updatedLines.add(line);
                }
            }

            try (BufferedWriter writer = Files.newBufferedWriter(csvFile,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
                for (String line : updatedLines) {
                    writer.write(line);
                    writer.newLine();
                }
            }
            log.info("CSV updated with {} recovered results.", succeededOnRetry.size());

        } catch (IOException e) {
            log.error("Failed to update CSV.", e);
        }
    }

    private String escapeCsv(String value) {
        if (value == null) return "";
        if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }

    private long fileSize(Path path) {
        try {
            return Files.size(path);
        } catch (IOException e) {
            return 0;
        }
    }
}
