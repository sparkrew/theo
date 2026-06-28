package io.github.chains_project.theo.package_miner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Coordinates the entire mining pipeline from start to finish.
 *
 * The pipeline has four phases:
 * 1. SELECT  — Pick 2000 packages from Maven Central (1000 popular + 1000 random)
 * 2. DOWNLOAD — Fetch the source JAR (or binary JAR) for each package
 * 3. PREPROCESS — Run the preprocessor to resolve dependencies and build the package map
 * 4. ANALYZE — Run theo-static on each JAR to find sensitive API usage
 *
 * Phases 2-4 happen together for each package, parallelized across worker threads.
 * The checkpoint system ensures we can resume after interruption without re-doing work.
 * At the end, a summary is printed showing how many packages made it through each stage.
 *
 * Output directory structure:
 *   output-dir/
 *     sensitive_api_usage.csv      — the main result: 2000 rows x 219 sensitive API columns
 *     mining_summary.json          — pipeline statistics (counts at each stage)
 *     selected_packages.json       — the 2000 selected packages (for reproducibility)
 *     checkpoint.json              — tracks completed packages (for resumability)
 *     jars/                        — downloaded JAR files
 *     poms/                        — downloaded POM files
 *     temp-projects/               — temporary Maven project dirs (for running preprocessor)
 *     package-maps/                — generated package maps (one per package)
 *     reports/                     — raw theo-static report JSONs (one per package)
 *     paths/                       — per-package call path JSONs (only for packages with sensitive API usage)
 */
public class MiningOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(MiningOrchestrator.class);

    private final Path outputDir;
    private final Path downloadDir;
    private final Path analyzerJar;
    private final int totalPackages;
    private final int workers;
    private final boolean analyzeAllVersions;
    private final int versionHistoryYears;

    public MiningOrchestrator(Path outputDir, Path downloadDir, Path analyzerJar,
                              int totalPackages, int workers,
                              boolean analyzeAllVersions, int versionHistoryYears) {
        this.outputDir = outputDir;
        this.downloadDir = downloadDir;
        this.analyzerJar = analyzerJar;
        this.totalPackages = totalPackages;
        this.workers = workers;
        this.analyzeAllVersions = analyzeAllVersions;
        this.versionHistoryYears = versionHistoryYears;
    }

    public void run() {
        try {
            Files.createDirectories(outputDir);
            Files.createDirectories(downloadDir);
        } catch (IOException e) {
            log.error("Failed to create output directories.", e);
            return;
        }

        // Set up the core components. The MavenCentralClient is shared between the
        // orchestrator (for downloading JARs) and the analyzer (for downloading POMs).
        MavenCentralClient client = new MavenCentralClient();
        CheckpointManager checkpoint = new CheckpointManager(outputDir);
        PackageAnalyzer analyzer = new PackageAnalyzer(analyzerJar, outputDir, client);
        ResultWriter resultWriter = new ResultWriter(outputDir, analyzer.getSensitiveApiKeys());
        MiningStats stats = new MiningStats();

        // Phase 1: Select packages (or load from a previous run's checkpoint)
        List<PackageInfo> allPackages = checkpoint.loadPackageList();
        if (allPackages == null) {
            allPackages = selectPackages();
            if (allPackages == null || allPackages.isEmpty()) {
                log.error("No packages selected. Exiting.");
                return;
            }
            // Save the list so we analyze the same packages on resume
            checkpoint.savePackageList(allPackages);
        }
        stats.setTotalSelected(allPackages.size());

        // Write the CSV header if this is a fresh run (not a resume)
        boolean csvExists = Files.exists(outputDir.resolve("sensitive_api_usage.csv"));
        if (!csvExists || checkpoint.completedCount() == 0) {
            try {
                resultWriter.writeHeader();
            } catch (IOException e) {
                log.error("Failed to write CSV header.", e);
                return;
            }
        }

        log.info("Starting analysis of {} packages with {} workers. {} already completed.",
                allPackages.size(), workers, checkpoint.completedCount());

        // Phase 2-4: Download, preprocess, analyze, and record results — in parallel across workers
        AtomicInteger processed = new AtomicInteger(checkpoint.completedCount());
        int total = allPackages.size();

        ExecutorService executor = Executors.newFixedThreadPool(workers);
        List<Future<?>> futures = new ArrayList<>();

        for (PackageInfo pkg : allPackages) {
            // Skip packages that were already completed in a previous run
            if (checkpoint.isCompleted(pkg)) {
                continue;
            }

            futures.add(executor.submit(() -> {
                try {
                    log.info("[{}/{}] Processing {}...",
                            processed.get(), total, pkg.coordinate());

                    // Step 1: Download both JARs.
                    // The bytecode JAR is required — theo-static (SootUp) needs compiled .class files.
                    // The source JAR is optional — used for cleaner package name extraction.
                    Path bytecodeJar = client.downloadBytecodeJar(pkg, downloadDir);
                    if (bytecodeJar == null) {
                        log.warn("Skipping {} — could not download bytecode JAR.", pkg.coordinate());
                        stats.recordDownloadFailure();
                        checkpoint.markCompleted(pkg);
                        resultWriter.appendResult(pkg, Collections.emptySet());
                        processed.incrementAndGet();
                        return;
                    }
                    // Source JAR may not exist for all packages — that's OK, we'll fall back
                    Path sourceJar = client.downloadSourceJar(pkg, downloadDir);
                    stats.recordDownloadSuccess();

                    // Step 2: Run preprocessor + theo-static analysis
                    PackageAnalyzer.AnalysisResult result = analyzer.analyze(pkg, bytecodeJar, sourceJar);

                    // Track preprocessor outcome
                    if (result.preprocessorSucceeded()) {
                        stats.recordPreprocessorSuccess();
                    } else {
                        stats.recordPreprocessorFailure();
                    }

                    // Track analyzer outcome
                    if (result.analyzerSucceeded()) {
                        stats.recordAnalyzerSuccess();
                    } else {
                        stats.recordAnalyzerFailure();
                    }

                    // Only track entry points and sensitive API counts for successful analyses.
                    // Failed analyses produce empty results that would skew the stats.
                    if (result.analyzerSucceeded()) {
                        stats.recordEntryPoints(result.entryPointCount());

                        if (!result.detectedSensitiveApis().isEmpty()) {
                            stats.recordWithSensitiveApis();
                        } else {
                            stats.recordWithoutSensitiveApis();
                        }
                    }

                    // Step 3: Write the True/False row to the CSV
                    resultWriter.appendResult(pkg, result.detectedSensitiveApis());
                    checkpoint.markCompleted(pkg);

                    int done = processed.incrementAndGet();
                    int apiCount = result.detectedSensitiveApis().size();
                    log.info("[{}/{}] Completed {} — {} sensitive APIs detected.",
                            done, total, pkg.coordinate(), apiCount);

                } catch (Exception e) {
                    // If anything goes wrong, log it and move on to the next package.
                    // We still mark it as completed to avoid retrying a broken package forever.
                    log.error("Error processing {}: {}", pkg.coordinate(), e.getMessage(), e);
                    checkpoint.markCompleted(pkg);
                    resultWriter.appendResult(pkg, Collections.emptySet());
                    processed.incrementAndGet();
                }
            }));
        }

        // Wait for all packages to finish
        for (Future<?> f : futures) {
            try {
                f.get();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.error("Interrupted while waiting for analysis tasks.", e);
                break;
            } catch (ExecutionException e) {
                log.error("Task failed.", e);
            }
        }

        executor.shutdown();
        checkpoint.save();

        // Phase 5 (optional): Version history analysis
        // For packages that have sensitive APIs, analyze all versions from the last N years
        // and track how permissions changed over time.
        if (analyzeAllVersions) {
            runVersionHistoryAnalysis(allPackages, client, analyzer);
        }

        // Print and save the final pipeline summary
        stats.printSummary(outputDir);

        log.info("Results written to {}", outputDir);
        log.info("  CSV: {}", outputDir.resolve("sensitive_api_usage.csv"));
        log.info("  Paths: {}", outputDir.resolve("paths"));
        log.info("  Summary: {}", outputDir.resolve("mining_summary.json"));
        if (analyzeAllVersions) {
            log.info("  Version history: {}", outputDir.resolve("version-history"));
            log.info("  Visualization: {}", outputDir.resolve("permission_changes_report.html"));
        }
    }

    /**
     * Selects packages from Maven Central: half popular (sorted by download count),
     * half random (using a fixed seed so the selection is reproducible).
     */
    private List<PackageInfo> selectPackages() {
        MavenCentralClient client = new MavenCentralClient();
        int half = totalPackages / 2;

        try {
            // First, get the most widely used packages
            List<PackageInfo> popular = client.fetchPopularPackages(half);
            log.info("Selected {} popular packages.", popular.size());

            // Then pick random packages from everything that's left
            List<PackageInfo> random = client.fetchRandomPackages(totalPackages - popular.size(), popular);
            log.info("Selected {} random packages.", random.size());

            List<PackageInfo> all = new ArrayList<>(popular);
            all.addAll(random);
            log.info("Total selected: {} packages.", all.size());
            return all;

        } catch (Exception e) {
            log.error("Failed to fetch packages from Maven Central.", e);
            return null;
        }
    }

    /**
     * Phase 5: For each package that had sensitive API usage, fetch all versions
     * from the last N years, analyze each version, and track permission changes.
     * Generates a per-package version history JSON and an HTML visualization.
     */
    private void runVersionHistoryAnalysis(List<PackageInfo> allPackages,
                                           MavenCentralClient client,
                                           PackageAnalyzer analyzer) {
        // Find packages that had sensitive APIs (they have a report with non-empty results)
        List<PackageInfo> packagesWithApis = new ArrayList<>();
        for (PackageInfo pkg : allPackages) {
            String pkgKey = pkg.groupId() + "_" + pkg.artifactId() + "_" + pkg.latestVersion();
            Path reportFile = outputDir.resolve("reports").resolve(pkgKey + "-report.json");
            if (java.nio.file.Files.exists(reportFile) && fileSize(reportFile) > 0) {
                Path pathsFile = outputDir.resolve("paths").resolve(pkgKey + "-paths.json");
                if (java.nio.file.Files.exists(pathsFile)) {
                    packagesWithApis.add(pkg);
                }
            }
        }

        if (packagesWithApis.isEmpty()) {
            log.info("No packages with sensitive APIs found. Skipping version history analysis.");
            return;
        }

        log.info("=============================================================");
        log.info("  VERSION HISTORY ANALYSIS: {} packages with sensitive APIs", packagesWithApis.size());
        log.info("  Looking back {} years for version history.", versionHistoryYears);
        log.info("=============================================================");

        VersionHistoryTracker tracker = new VersionHistoryTracker();
        AtomicInteger vhProcessed = new AtomicInteger(0);
        int vhTotal = packagesWithApis.size();

        ExecutorService vhExecutor = Executors.newFixedThreadPool(workers);
        List<Future<?>> vhFutures = new ArrayList<>();

        for (PackageInfo pkg : packagesWithApis) {
            vhFutures.add(vhExecutor.submit(() -> {
                try {
                    int done = vhProcessed.incrementAndGet();
                    log.info("[VH {}/{}] Fetching versions for {}:{}...",
                            done, vhTotal, pkg.groupId(), pkg.artifactId());

                    List<VersionInfo> versions = client.fetchVersions(
                            pkg.groupId(), pkg.artifactId(), versionHistoryYears);

                    if (versions.size() <= 1) {
                        log.info("[VH {}/{}] {}:{} has only {} version(s) in the last {} years, skipping.",
                                done, vhTotal, pkg.groupId(), pkg.artifactId(),
                                versions.size(), versionHistoryYears);
                        return;
                    }

                    log.info("[VH {}/{}] Analyzing {} versions of {}:{}...",
                            done, vhTotal, versions.size(), pkg.groupId(), pkg.artifactId());

                    List<VersionHistoryTracker.VersionReportEntry> reportEntries = new ArrayList<>();

                    for (VersionInfo ver : versions) {
                        Path reportFile = analyzeVersion(ver, client, analyzer);
                        if (reportFile != null) {
                            reportEntries.add(new VersionHistoryTracker.VersionReportEntry(
                                    ver.version(), ver.timestamp(), reportFile));
                        }
                    }

                    if (reportEntries.size() >= 2) {
                        VersionHistory.PackageVersionHistory history =
                                tracker.buildHistory(pkg.groupId(), pkg.artifactId(), reportEntries);
                        tracker.saveHistory(history, outputDir);
                        log.info("[VH {}/{}] {}:{} — {} versions analyzed, changes: {}",
                                done, vhTotal, pkg.groupId(), pkg.artifactId(),
                                reportEntries.size(), history.hasPermissionChanges());
                    }
                } catch (Exception e) {
                    log.error("Error during version history analysis of {}:{}",
                            pkg.groupId(), pkg.artifactId(), e);
                }
            }));
        }

        for (Future<?> f : vhFutures) {
            try {
                f.get();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.error("Interrupted during version history analysis.", e);
                break;
            } catch (ExecutionException e) {
                log.error("Version history task failed.", e);
            }
        }
        vhExecutor.shutdown();

        // Generate the HTML visualization from all version-history JSONs
        try {
            new VersionHistoryVisualizer().generateReport(outputDir);
        } catch (IOException e) {
            log.error("Failed to generate version history visualization.", e);
        }

        log.info("Version history analysis complete.");
    }

    /**
     * Analyzes a specific version of a package and returns the report file path.
     * Reuses existing reports if available.
     */
    private Path analyzeVersion(VersionInfo ver, MavenCentralClient client, PackageAnalyzer analyzer) {
        String pkgKey = ver.groupId() + "_" + ver.artifactId() + "_" + ver.version();
        Path reportFile = outputDir.resolve("reports").resolve(pkgKey + "-report.json");

        if (java.nio.file.Files.exists(reportFile) && fileSize(reportFile) > 0) {
            return reportFile;
        }

        try {
            Path bytecodeJar = client.downloadBytecodeJarForVersion(ver, downloadDir);
            if (bytecodeJar == null) {
                log.debug("Could not download bytecode JAR for {}", ver.coordinate());
                return null;
            }
            Path sourceJar = client.downloadSourceJarForVersion(ver, downloadDir);

            PackageInfo versionAsPkg = ver.toPackageInfo();
            PackageAnalyzer.AnalysisResult result = analyzer.analyze(versionAsPkg, bytecodeJar, sourceJar);

            if (result.analyzerSucceeded() && java.nio.file.Files.exists(reportFile)) {
                return reportFile;
            }
        } catch (Exception e) {
            log.debug("Failed to analyze version {}: {}", ver.coordinate(), e.getMessage());
        }
        return null;
    }

    private long fileSize(Path file) {
        try {
            return java.nio.file.Files.size(file);
        } catch (IOException e) {
            return 0;
        }
    }
}
