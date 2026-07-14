package io.github.chains_project.theo.package_miner;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.chains_project.theo.package_miner.model.PackageInfo;
import io.github.chains_project.theo.package_miner.util.CheckpointManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.*;

/**
 * Temporary recovery script — finds packages that were completed but have no report
 * (i.e. skipped in a previous run), re-runs the analysis to classify the failure reason,
 * and writes the skipped_*.json files. Safe to delete once recovery is done.
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
                    log.info("  -> succeeded this time ({} sensitive APIs)", result.detectedSensitiveApis().size());
                }

            } catch (OutOfMemoryError e) {
                log.info("  -> OOM");
                oomPackages.add(pkg);
            } catch (Exception e) {
                log.info("  -> scan failed ({})", e.getMessage());
                scanFailed.add(pkg);
            }
        }

        log.info("=============================================================");
        log.info("  RECOVERY RESULTS");
        log.info("  Total skipped:    {}", skipped.size());
        log.info("  Download failed:  {}", downloadFailed.size());
        log.info("  Scan failed:      {}", scanFailed.size());
        log.info("  Timed out:        {}", timedOut.size());
        log.info("  OOM:              {}", oomPackages.size());
        log.info("  Succeeded on retry: {}",
                skipped.size() - downloadFailed.size() - scanFailed.size() - timedOut.size() - oomPackages.size());
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

    private long fileSize(Path path) {
        try {
            return Files.size(path);
        } catch (IOException e) {
            return 0;
        }
    }
}
