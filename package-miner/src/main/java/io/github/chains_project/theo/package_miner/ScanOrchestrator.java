package io.github.chains_project.theo.package_miner;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.chains_project.theo.package_miner.model.PackageInfo;
import io.github.chains_project.theo.package_miner.model.PackageScmInfo;
import io.github.chains_project.theo.package_miner.model.VersionHistory;
import io.github.chains_project.theo.package_miner.model.VersionInfo;
import io.github.chains_project.theo.package_miner.util.CheckpointManager;
import io.github.chains_project.theo.package_miner.util.MiningStats;
import io.github.chains_project.theo.package_miner.util.ResultWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

public class ScanOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(ScanOrchestrator.class);

    private static final Pattern PRERELEASE_PATTERN = Pattern.compile(
            "(?i).*(snapshot|alpha|beta|\\-rc|\\-m\\d|milestone|nightly|dev|preview|incubating).*"
    );

    private static final long SCAN_TIMEOUT_MINUTES = 30;
    private static final int MAX_VERSIONS_PER_PACKAGE = 4242;

    private final Path outputDir;
    private final Path downloadDir;
    private final Path analyzerJar;
    private final int workers;
    private final boolean analyzeAllVersions;
    private final int versionHistoryYears;
    private final int versionHistoryBatchSize;
    private final int limit;
    private final ObjectMapper mapper = new ObjectMapper();

    public ScanOrchestrator(Path outputDir, Path downloadDir, Path analyzerJar,
                            int workers, boolean analyzeAllVersions,
                            int versionHistoryYears, int versionHistoryBatchSize,
                            int limit) {
        this.outputDir = outputDir;
        this.downloadDir = downloadDir;
        this.analyzerJar = analyzerJar;
        this.workers = workers;
        this.analyzeAllVersions = analyzeAllVersions;
        this.versionHistoryYears = versionHistoryYears;
        this.versionHistoryBatchSize = versionHistoryBatchSize;
        this.limit = limit;
    }

    public void run() {
        try {
            Files.createDirectories(outputDir);
            Files.createDirectories(downloadDir);
        } catch (IOException e) {
            log.error("Failed to create output directories.", e);
            return;
        }

        MavenCentralClient client = new MavenCentralClient();
        CheckpointManager checkpoint = new CheckpointManager(outputDir);
        PackageAnalyzer analyzer = new PackageAnalyzer(analyzerJar, outputDir, client);
        ResultWriter resultWriter = new ResultWriter(outputDir, analyzer.getSensitiveApiKeys());
        MiningStats stats = new MiningStats();

        List<PackageInfo> allPackages = checkpoint.loadPackageList();
        if (allPackages == null || allPackages.isEmpty()) {
            log.error("No selected_packages.json found in {}. Run 'mine collect' first.", outputDir);
            return;
        }
        stats.setTotalSelected(allPackages.size());

        boolean csvExists = Files.exists(outputDir.resolve("sensitive_api_usage.csv"));
        if (!csvExists || checkpoint.completedCount() == 0) {
            try {
                resultWriter.writeHeader();
            } catch (IOException e) {
                log.error("Failed to write CSV header.", e);
                return;
            }
        }

        List<PackageWithApis> newPackagesWithApis = Collections.synchronizedList(new ArrayList<>());

        AtomicInteger processed = new AtomicInteger(checkpoint.completedCount());
        int total = allPackages.size();

        ExecutorService executor = Executors.newFixedThreadPool(workers);
        List<Future<?>> futures = new ArrayList<>();

        int queued = 0;
        for (PackageInfo pkg : allPackages) {
            if (checkpoint.isCompleted(pkg)) continue;
            if (limit > 0 && queued >= limit) break;
            queued++;

                futures.add(executor.submit(() -> {
                    try {
                        log.info("[{}/{}] Processing {}...", processed.get(), total, pkg.coordinate());

                        Path bytecodeJar = client.downloadBytecodeJar(pkg, downloadDir);
                        if (bytecodeJar == null) {
                            log.warn("Skipping {} — could not download bytecode JAR.", pkg.coordinate());
                            stats.recordDownloadFailure();
                            appendSkipped("skipped_download_failed.json", pkg);
                            checkpoint.markCompleted(pkg);
                            resultWriter.appendResult(pkg, Collections.emptySet());
                            processed.incrementAndGet();
                            return;
                        }
                        Path sourceJar = client.downloadSourceJar(pkg, downloadDir);
                        stats.recordDownloadSuccess();

                        ExecutorService timeoutExecutor = Executors.newSingleThreadExecutor();
                        Future<PackageAnalyzer.AnalysisResult> analysisFuture =
                                timeoutExecutor.submit(
                                        () -> analyzer.analyze(pkg, bytecodeJar, sourceJar));

                        PackageAnalyzer.AnalysisResult result;
                        try {
                            result = analysisFuture.get(SCAN_TIMEOUT_MINUTES, TimeUnit.MINUTES);
                        } catch (TimeoutException e) {
                            analysisFuture.cancel(true);
                            log.warn("Scan timed out after {} minutes for {}", SCAN_TIMEOUT_MINUTES, pkg.coordinate());
                            appendSkipped("skipped_timed_out.json", pkg);
                            stats.recordAnalyzerFailure();
                            checkpoint.markCompleted(pkg);
                            resultWriter.appendResult(pkg, Collections.emptySet());
                            processed.incrementAndGet();
                            return;
                        } finally {
                            timeoutExecutor.shutdownNow();
                        }

                        if (result.preprocessorSucceeded()) {
                            stats.recordPreprocessorSuccess();
                        } else {
                            stats.recordPreprocessorFailure();
                        }

                        if (result.analyzerSucceeded()) {
                            stats.recordAnalyzerSuccess();
                            stats.recordEntryPoints(result.entryPointCount());
                            if (!result.detectedSensitiveApis().isEmpty()) {
                                stats.recordWithSensitiveApis();
                                newPackagesWithApis.add(new PackageWithApis(pkg, result.detectedSensitiveApis()));
                            } else {
                                stats.recordWithoutSensitiveApis();
                            }
                        } else {
                            stats.recordAnalyzerFailure();
                            appendSkipped("skipped_scan_failed.json", pkg);
                        }

                        resultWriter.appendResult(pkg, result.detectedSensitiveApis());
                        checkpoint.markCompleted(pkg);

                        int done = processed.incrementAndGet();
                        log.info("[{}/{}] Completed {} — {} sensitive APIs detected.",
                                done, total, pkg.coordinate(), result.detectedSensitiveApis().size());

                    } catch (Exception e) {
                        log.error("Error processing {}: {}", pkg.coordinate(), e.getMessage(), e);
                        appendSkipped("skipped_scan_failed.json", pkg);
                        checkpoint.markCompleted(pkg);
                        resultWriter.appendResult(pkg, Collections.emptySet());
                        processed.incrementAndGet();
                    } catch (OutOfMemoryError e) {
                        log.error("OOM while processing {}, skipping.", pkg.coordinate());
                        appendSkipped("skipped_oom.json", pkg);
                        checkpoint.markCompleted(pkg);
                        resultWriter.appendResult(pkg, Collections.emptySet());
                        processed.incrementAndGet();
                    }
                }));
            }

        if (queued > 0) {
            log.info("Starting analysis of {} packages with {} workers. {} already completed.",
                    queued, workers, checkpoint.completedCount());

            for (Future<?> f : futures) {
                try {
                    f.get();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (ExecutionException e) {
                    log.error("Task failed.", e);
                }
            }
            checkpoint.save();

            stats.printSummary(outputDir);
        } else {
            log.info("All packages already analyzed. Proceeding to SCM tracking / version history.");
        }
        executor.shutdown();

        List<PackageWithApis> packagesWithApis = loadPackagesWithApis();

        if (!packagesWithApis.isEmpty()) {
            trackScmInfo(packagesWithApis, client);
        }

        if (analyzeAllVersions && !packagesWithApis.isEmpty()) {
            runVersionHistory(packagesWithApis, client, analyzer, checkpoint);
        }

        log.info("Results written to {}", outputDir);
        log.info("  CSV: {}", outputDir.resolve("sensitive_api_usage.csv"));
        log.info("  Paths: {}", outputDir.resolve("paths"));
        log.info("  Summary: {}", outputDir.resolve("mining_summary.json"));
        if (analyzeAllVersions) {
            log.info("  Version history: {}", outputDir.resolve("version-history"));
            log.info("  Visualization: {}", outputDir.resolve("permission_changes_report.html"));
        }
    }

    // Persistence for packagesWithApis

    private List<PackageWithApis> loadPackagesWithApis() {
        Path csvFile = outputDir.resolve("sensitive_api_usage.csv");
        if (Files.exists(csvFile)) {
            try {
                List<String> lines = Files.readAllLines(csvFile);
                if (lines.size() > 1) {
                    String[] header = lines.get(0).split(",");
                    List<String> apiColumns = new ArrayList<>();
                    for (int i = 3; i < header.length; i++) {
                        apiColumns.add(header[i]);
                    }

                    List<PackageWithApis> loaded = new ArrayList<>();
                    for (int row = 1; row < lines.size(); row++) {
                        String[] cols = lines.get(row).split(",");
                        if (cols.length < 3) continue;

                        String groupId = cols[0];
                        String artifactId = cols[1];
                        String version = cols[2];
                        Set<String> detectedApis = new HashSet<>();

                        for (int i = 3; i < cols.length && (i - 3) < apiColumns.size(); i++) {
                            if ("True".equals(cols[i])) {
                                detectedApis.add(apiColumns.get(i - 3));
                            }
                        }

                        if (!detectedApis.isEmpty()) {
                            loaded.add(new PackageWithApis(
                                    new PackageInfo(groupId, artifactId, version, 0), detectedApis));
                        }
                    }

                    if (!loaded.isEmpty()) {
                        log.info("Loaded {} packages with sensitive APIs from CSV.", loaded.size());
                        return Collections.synchronizedList(new ArrayList<>(loaded));
                    }
                }
            } catch (IOException e) {
                log.warn("Failed to read CSV.", e);
            }
        }

        return Collections.synchronizedList(new ArrayList<>());
    }

    // Skipped packages tracking

    private synchronized void appendSkipped(String filename, PackageInfo pkg) {
        Path file = outputDir.resolve(filename);
        try {
            List<PackageInfo> existing;
            if (Files.exists(file)) {
                existing = mapper.readValue(file.toFile(), new TypeReference<List<PackageInfo>>() {});
            } else {
                existing = new ArrayList<>();
            }
            existing.add(pkg);
            mapper.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), existing);
        } catch (IOException e) {
            log.error("Failed to append to {}.", filename, e);
        }
    }

    private synchronized void appendSkippedVersion(String filename, VersionInfo ver) {
        Path file = outputDir.resolve(filename);
        try {
            List<VersionInfo> existing;
            if (Files.exists(file)) {
                existing = mapper.readValue(file.toFile(), new TypeReference<List<VersionInfo>>() {});
            } else {
                existing = new ArrayList<>();
            }
            existing.add(ver);
            mapper.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), existing);
        } catch (IOException e) {
            log.error("Failed to append to {}.", filename, e);
        }
    }

    // SCM TRACKING

    private void trackScmInfo(List<PackageWithApis> packagesWithApis, MavenCentralClient client) {
        log.info("Extracting SCM info for {} packages with sensitive APIs...", packagesWithApis.size());

        List<PackageInfo> noScm = new ArrayList<>();
        List<PackageScmInfo> nonGitHub = new ArrayList<>();
        List<PackageScmInfo> withGitHub = new ArrayList<>();
        Path pomDir = outputDir.resolve("poms");

        for (PackageWithApis pwa : packagesWithApis) {
            PackageInfo pkg = pwa.pkg;
            try {
                Path pomFile = client.downloadPom(pkg, pomDir);
                if (pomFile == null) {
                    noScm.add(pkg);
                    continue;
                }

                ScmExtractor.ScmResult scm = ScmExtractor.extractScmInfo(pomFile);
                switch (scm.status()) {
                    case NO_SCM_TAG -> noScm.add(pkg);
                    case NON_GITHUB_SCM -> nonGitHub.add(PackageScmInfo.from(pkg, scm.rawScmUrl()));
                    case GITHUB -> withGitHub.add(PackageScmInfo.from(pkg, scm.githubUrl()));
                }
            } catch (Exception e) {
                log.debug("Failed to extract SCM for {}", pkg.coordinate());
                noScm.add(pkg);
            }
        }

        try {
            if (!noScm.isEmpty())
                mapper.writerWithDefaultPrettyPrinter().writeValue(
                        outputDir.resolve("packages_no_scm.json").toFile(), noScm);
            if (!nonGitHub.isEmpty())
                mapper.writerWithDefaultPrettyPrinter().writeValue(
                        outputDir.resolve("packages_non_github_scm.json").toFile(), nonGitHub);
            if (!withGitHub.isEmpty())
                mapper.writerWithDefaultPrettyPrinter().writeValue(
                        outputDir.resolve("packages_with_github_scm.json").toFile(), withGitHub);
            log.info("SCM tracking: {} no-SCM, {} non-GitHub, {} GitHub",
                    noScm.size(), nonGitHub.size(), withGitHub.size());
        } catch (IOException e) {
            log.error("Failed to save SCM tracking files.", e);
        }
    }

    // VERSION HISTORY

    private void runVersionHistory(List<PackageWithApis> packagesWithApis,
                                   MavenCentralClient client, PackageAnalyzer analyzer,
                                   CheckpointManager checkpoint) {
        log.info("=============================================================");
        log.info("  VERSION HISTORY — {} packages with sensitive APIs", packagesWithApis.size());
        log.info("  Batch size: {}, years: {}", versionHistoryBatchSize, versionHistoryYears);
        log.info("=============================================================");

        int startBatch = checkpoint.getVersionHistoryBatchIndex();
        int totalModules = packagesWithApis.size();
        VersionHistoryTracker tracker = new VersionHistoryTracker();

        for (int batchStart = startBatch * versionHistoryBatchSize;
             batchStart < totalModules;
             batchStart += versionHistoryBatchSize) {

            int batchEnd = Math.min(batchStart + versionHistoryBatchSize, totalModules);
            int batchIndex = batchStart / versionHistoryBatchSize;

            log.info("Processing version history batch {} (packages {}-{} of {})...",
                    batchIndex, batchStart + 1, batchEnd, totalModules);

            List<PackageWithApis> batch = packagesWithApis.subList(batchStart, batchEnd);

            for (PackageWithApis pwa : batch) {
                try {
                    processVersionHistory(pwa.pkg, client, analyzer, tracker);
                } catch (Exception e) {
                    log.error("Error processing version history for {}: {}",
                            pwa.pkg.coordinate(), e.getMessage());
                }
            }

            checkpoint.setVersionHistoryBatchIndex(batchIndex + 1);
            log.info("Batch {} complete.", batchIndex);
        }

        try {
            new VersionHistoryVisualizer().generateReport(outputDir);
        } catch (IOException e) {
            log.error("Failed to generate version history visualization.", e);
        }
    }

    private void processVersionHistory(PackageInfo pkg, MavenCentralClient client,
                                        PackageAnalyzer analyzer, VersionHistoryTracker tracker) {
        // TODO: remove this skip block once these packages are processed
        if (pkg.coordinate().startsWith("org.springframework.boot:spring-boot-starter-test:")
                || pkg.coordinate().startsWith("org.springframework.boot:spring-boot-starter-web:")) {
            log.info("  Skipping {} (temporary skip).", pkg.coordinate());
            return;
        }

        log.info("  Fetching versions for {}:{}...", pkg.groupId(), pkg.artifactId());

        List<VersionInfo> allVersions;
        try {
            allVersions = client.fetchVersions(pkg.groupId(), pkg.artifactId(), versionHistoryYears);
        } catch (Exception e) {
            log.warn("  Failed to fetch versions for {}: {}", pkg.coordinate(), e.getMessage());
            return;
        }

        List<VersionInfo> stableVersions = allVersions.stream()
                .filter(v -> isStableRelease(v.version()))
                .toList();

        if (stableVersions.size() <= 1) {
            log.info("  {}:{} has only {} stable version(s), skipping.", pkg.groupId(), pkg.artifactId(),
                    stableVersions.size());
            return;
        }

        if (stableVersions.size() > MAX_VERSIONS_PER_PACKAGE) {
            log.info("  {}:{} has {} stable versions, capping to {}.",
                    pkg.groupId(), pkg.artifactId(), stableVersions.size(), MAX_VERSIONS_PER_PACKAGE);
            stableVersions = stableVersions.subList(stableVersions.size() - MAX_VERSIONS_PER_PACKAGE, stableVersions.size());
        }

        log.info("  Analyzing {} stable versions of {}:{}...",
                stableVersions.size(), pkg.groupId(), pkg.artifactId());

        List<VersionHistoryTracker.VersionReportEntry> reportEntries = new ArrayList<>();

        for (VersionInfo ver : stableVersions) {
            try {
                PackageInfo versionPkg = ver.toPackageInfo();
                Path bytecodeJar = client.downloadBytecodeJarForVersion(ver, downloadDir);
                if (bytecodeJar == null) {
                    appendSkippedVersion("skipped_version_download_failed.json", ver);
                    continue;
                }

                Path sourceJar = client.downloadSourceJarForVersion(ver, downloadDir);

                ExecutorService timeoutExecutor = Executors.newSingleThreadExecutor();
                Future<PackageAnalyzer.AnalysisResult> analysisFuture =
                        timeoutExecutor.submit(() -> analyzer.analyze(versionPkg, bytecodeJar, sourceJar));

                PackageAnalyzer.AnalysisResult result;
                try {
                    result = analysisFuture.get(SCAN_TIMEOUT_MINUTES, TimeUnit.MINUTES);
                } catch (TimeoutException e) {
                    analysisFuture.cancel(true);
                    log.warn("  Version {} timed out after {} minutes, skipping.", ver.coordinate(), SCAN_TIMEOUT_MINUTES);
                    appendSkippedVersion("skipped_version_timed_out.json", ver);
                    continue;
                } finally {
                    timeoutExecutor.shutdownNow();
                }

                if (result.analyzerSucceeded()) {
                    String reportKey = ver.groupId() + "_" + ver.artifactId() + "_" + ver.version();
                    Path reportFile = outputDir.resolve("reports").resolve(reportKey + "-report.json");
                    if (Files.exists(reportFile)) {
                        reportEntries.add(new VersionHistoryTracker.VersionReportEntry(
                                ver.version(), ver.timestamp(), reportFile));
                    }
                } else {
                    appendSkippedVersion("skipped_version_scan_failed.json", ver);
                }
            } catch (OutOfMemoryError e) {
                log.warn("  OOM analyzing version {}, skipping.", ver.coordinate());
                appendSkippedVersion("skipped_version_oom.json", ver);
            } catch (Exception e) {
                log.debug("  Failed to analyze version {}: {}", ver.coordinate(), e.getMessage());
                appendSkippedVersion("skipped_version_scan_failed.json", ver);
            }
        }

        if (reportEntries.size() >= 2) {
            try {
                VersionHistory.PackageVersionHistory history =
                        tracker.buildHistory(pkg.groupId(), pkg.artifactId(), reportEntries);
                tracker.saveHistory(history, outputDir);
                log.info("  {}:{} — {} versions analyzed, changes: {}",
                        pkg.groupId(), pkg.artifactId(), reportEntries.size(), history.hasPermissionChanges());
            } catch (IOException e) {
                log.error("  Failed to save version history for {}:{}", pkg.groupId(), pkg.artifactId(), e);
            }
        }
    }

    static boolean isStableRelease(String version) {
        if (!version.matches("\\d+\\.\\d+.*")) return false;
        return !PRERELEASE_PATTERN.matcher(version).matches();
    }

    // Helper records

    record PackageWithApis(PackageInfo pkg, Set<String> detectedApis) {}
}
