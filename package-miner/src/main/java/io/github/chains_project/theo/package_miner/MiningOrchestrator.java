package io.github.chains_project.theo.package_miner;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * Coordinates the entire mining pipeline from start to finish.
 *
 * Pipeline phases:
 * 1. DISCOVER  — Find popular Java packages on Maven Central with GitHub SCM links
 * 2. CLONE & BUILD — Clone repos, build with Maven, run preprocessor
 * 3. ANALYZE  — Run package-static-analyzer on built JARs
 * 4. VERSION HISTORY — Track sensitive API changes across git commits (batched)
 *
 * Output directory structure:
 *   output-dir/
 *     sensitive_api_usage.csv        — main result: modules x sensitive APIs
 *     mining_summary.json            — pipeline statistics
 *     selected_packages.json         — discovered packages (phase 1 checkpoint)
 *     validated_repos.json           — cloned/built repos (phase 2 checkpoint)
 *     checkpoint.json                — completed module coordinates (phase 3)
 *     version_history_checkpoint.json — batch index (phase 4)
 *     poms/                          — cached POM files from Maven Central
 *     repos/                         — cloned GitHub repositories
 *     package-maps/                  — generated package maps
 *     reports/                       — analyzer report JSONs
 *     paths/                         — per-module call path JSONs
 *     version-history/               — per-module version history JSONs
 *     permission_changes_report.html — visualization
 */
public class MiningOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(MiningOrchestrator.class);

    private final Path outputDir;
    private final Path analyzerJar;
    private final int workers;
    private final Path tokensFile;
    private final Path reposDir;
    private final int targetRepos;
    private final boolean analyzeAllVersions;
    private final int versionHistoryYears;
    private final int versionHistoryBatchSize;
    private final int cutoffYear;

    public MiningOrchestrator(Path outputDir, Path analyzerJar, int workers,
                              Path tokensFile, Path reposDir, int targetRepos,
                              boolean analyzeAllVersions, int versionHistoryYears,
                              int versionHistoryBatchSize, int cutoffYear) {
        this.outputDir = outputDir;
        this.analyzerJar = analyzerJar;
        this.workers = workers;
        this.tokensFile = tokensFile;
        this.reposDir = reposDir;
        this.targetRepos = targetRepos;
        this.analyzeAllVersions = analyzeAllVersions;
        this.versionHistoryYears = versionHistoryYears;
        this.versionHistoryBatchSize = versionHistoryBatchSize;
        this.cutoffYear = cutoffYear;
    }

    public void run() {
        try {
            Files.createDirectories(outputDir);
            Files.createDirectories(reposDir);
        } catch (IOException e) {
            log.error("Failed to create output directories.", e);
            return;
        }

        GitHubTokenManager tokenMgr;
        try {
            tokenMgr = new GitHubTokenManager(tokensFile);
        } catch (IOException e) {
            log.error("Failed to read GitHub tokens from {}: {}", tokensFile, e.getMessage());
            return;
        }

        MavenCentralClient client = new MavenCentralClient();
        CheckpointManager checkpoint = new CheckpointManager(outputDir);
        PackageAnalyzer analyzer = new PackageAnalyzer(analyzerJar, outputDir, client);
        ResultWriter resultWriter = new ResultWriter(outputDir, analyzer.getSensitiveApiKeys());
        MiningStats stats = new MiningStats();
        ProjectBuilder builder = new ProjectBuilder();

        // ===== Phase 1: DISCOVER =====
        List<PackageInfo> selectedPackages = checkpoint.loadPackageList();
        if (selectedPackages == null) {
            MavenCentralClient.DiscoveryResult discovery = discoverPackages(client);
            if (discovery == null || discovery.packagesWithGitHub().isEmpty()) {
                log.error("No packages discovered. Exiting.");
                return;
            }
            selectedPackages = discovery.packagesWithGitHub();
            checkpoint.savePackageList(selectedPackages);
            saveTrackingLists(discovery);
        }
        log.info("Phase 1 complete: {} packages with GitHub SCM links.", selectedPackages.size());

        // ===== Phase 2: CLONE & BUILD =====
        List<GitHubProject.RepoInfo> validatedRepos = checkpoint.loadRepoList();
        if (validatedRepos == null) {
            validatedRepos = cloneAndBuildAll(selectedPackages, builder, tokenMgr);
            checkpoint.saveRepoList(validatedRepos);
        }
        log.info("Phase 2 complete: {} validated repos with {} total modules.",
                validatedRepos.size(),
                validatedRepos.stream().mapToLong(r -> r.modules().size()).sum());
        stats.setTotalSelected((int) validatedRepos.stream()
                .mapToLong(r -> r.modules().size()).sum());

        // ===== Phase 3: ANALYZE =====
        // Write CSV header if this is a fresh run
        boolean csvExists = Files.exists(outputDir.resolve("sensitive_api_usage.csv"));
        if (!csvExists || checkpoint.completedCount() == 0) {
            try {
                resultWriter.writeHeader();
            } catch (IOException e) {
                log.error("Failed to write CSV header.", e);
                return;
            }
        }

        log.info("Starting analysis with {} workers. {} modules already completed.",
                workers, checkpoint.completedCount());

        // Flatten repos into a list of analyzable modules
        List<AnalyzableModule> allModules = new ArrayList<>();
        for (GitHubProject.RepoInfo repo : validatedRepos) {
            for (GitHubProject.ModuleInfo module : repo.modules()) {
                if (module.buildSucceeded() && module.preprocessorSucceeded()
                        && module.jarPath() != null && module.packageMapPath() != null) {
                    allModules.add(new AnalyzableModule(repo, module));
                }
            }
        }

        AtomicInteger processed = new AtomicInteger(checkpoint.completedCount());
        int total = allModules.size();
        // Track modules with sensitive APIs for phase 4
        List<ModuleWithApis> modulesWithApis = Collections.synchronizedList(new ArrayList<>());

        ExecutorService executor = Executors.newFixedThreadPool(workers);
        List<Future<?>> futures = new ArrayList<>();

        for (AnalyzableModule am : allModules) {
            String coordinate = am.module.coordinate();
            if (checkpoint.isCompleted(coordinate)) {
                continue;
            }

            futures.add(executor.submit(() -> {
                try {
                    log.info("[{}/{}] Analyzing {}...", processed.get(), total, coordinate);

                    PackageAnalyzer.AnalysisResult result = analyzer.analyzeFromProject(
                            am.module.groupId(), am.module.artifactId(), am.module.version(),
                            Path.of(am.module.jarPath()), Path.of(am.module.packageMapPath())
                    );

                    if (result.analyzerSucceeded()) {
                        stats.recordAnalyzerSuccess();
                        stats.recordEntryPoints(result.entryPointCount());
                        if (!result.detectedSensitiveApis().isEmpty()) {
                            stats.recordWithSensitiveApis();
                            modulesWithApis.add(new ModuleWithApis(am, result.detectedSensitiveApis()));
                        } else {
                            stats.recordWithoutSensitiveApis();
                        }
                    } else {
                        stats.recordAnalyzerFailure();
                    }

                    resultWriter.appendResult(
                            am.module.groupId(), am.module.artifactId(), am.module.version(),
                            am.repo.githubUrl(), am.module.modulePath(),
                            result.detectedSensitiveApis()
                    );
                    checkpoint.markCompleted(coordinate);

                    int done = processed.incrementAndGet();
                    log.info("[{}/{}] Completed {} — {} sensitive APIs detected.",
                            done, total, coordinate, result.detectedSensitiveApis().size());

                } catch (Exception e) {
                    log.error("Error analyzing {}: {}", coordinate, e.getMessage(), e);
                    checkpoint.markCompleted(coordinate);
                    resultWriter.appendResult(
                            am.module.groupId(), am.module.artifactId(), am.module.version(),
                            am.repo.githubUrl(), am.module.modulePath(),
                            Collections.emptySet()
                    );
                    processed.incrementAndGet();
                }
            }));
        }

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
        executor.shutdown();
        checkpoint.save();

        // ===== Phase 4: VERSION HISTORY =====
        if (analyzeAllVersions && !modulesWithApis.isEmpty()) {
            runGitVersionHistory(modulesWithApis, builder, tokenMgr, analyzer, checkpoint);
        }

        stats.printSummary(outputDir);

        log.info("Results written to {}", outputDir);
        log.info("  CSV: {}", outputDir.resolve("sensitive_api_usage.csv"));
        log.info("  Reports: {}", outputDir.resolve("reports"));
        log.info("  Summary: {}", outputDir.resolve("mining_summary.json"));
        if (analyzeAllVersions) {
            log.info("  Version history: {}", outputDir.resolve("version-history"));
            log.info("  Visualization: {}", outputDir.resolve("permission_changes_report.html"));
        }
    }

    // ==================== Phase 1: DISCOVER ====================

    private MavenCentralClient.DiscoveryResult discoverPackages(MavenCentralClient client) {
        log.info("=============================================================");
        log.info("  Phase 1: DISCOVER — Finding packages with GitHub SCM");
        log.info("  Target: {} unique GitHub repos, cutoff year: {}", targetRepos, cutoffYear);
        log.info("=============================================================");

        try {
            Path pomCacheDir = outputDir.resolve("poms");
            int candidateTarget = (int) (targetRepos * 1.5);
            return client.fetchPopularJavaPackages(candidateTarget, pomCacheDir, cutoffYear);
        } catch (Exception e) {
            log.error("Failed to discover packages from Maven Central.", e);
            return null;
        }
    }

    /**
     * Saves the lists of packages without SCM and with non-GitHub SCM to JSON files
     * for tracking and later analysis.
     */
    private void saveTrackingLists(MavenCentralClient.DiscoveryResult discovery) {
        ObjectMapper mapper = new ObjectMapper();
        try {
            if (!discovery.packagesNoScm().isEmpty()) {
                mapper.writerWithDefaultPrettyPrinter().writeValue(
                        outputDir.resolve("packages_no_scm.json").toFile(),
                        discovery.packagesNoScm());
                log.info("Saved {} packages with no SCM tag to packages_no_scm.json",
                        discovery.packagesNoScm().size());
            }
            if (!discovery.packagesNonGitHubScm().isEmpty()) {
                mapper.writerWithDefaultPrettyPrinter().writeValue(
                        outputDir.resolve("packages_non_github_scm.json").toFile(),
                        discovery.packagesNonGitHubScm());
                log.info("Saved {} packages with non-GitHub SCM to packages_non_github_scm.json",
                        discovery.packagesNonGitHubScm().size());
            }
        } catch (IOException e) {
            log.error("Failed to save tracking lists.", e);
        }
    }

    // ==================== Phase 2: CLONE & BUILD ====================

    /**
     * A mismatch between the Maven Central coordinates and what the GitHub repo's pom.xml declares.
     */
    record CoordinateMismatch(
            String mavenCentralGroupId,
            String mavenCentralArtifactId,
            String githubGroupId,
            String githubArtifactId,
            String githubUrl
    ) {}

    private List<GitHubProject.RepoInfo> cloneAndBuildAll(
            List<PackageInfo> packages, ProjectBuilder builder, GitHubTokenManager tokenMgr) {

        log.info("=============================================================");
        log.info("  Phase 2: CLONE & BUILD — {} packages to process", packages.size());
        log.info("=============================================================");

        Map<String, List<PackageInfo>> byRepo = new LinkedHashMap<>();
        for (PackageInfo pkg : packages) {
            if (pkg.scmUrl() != null) {
                byRepo.computeIfAbsent(pkg.scmUrl().toLowerCase(), k -> new ArrayList<>()).add(pkg);
            }
        }
        log.info("Grouped into {} unique GitHub repos.", byRepo.size());

        List<GitHubProject.RepoInfo> results = Collections.synchronizedList(new ArrayList<>());
        List<CoordinateMismatch> mismatches = Collections.synchronizedList(new ArrayList<>());
        AtomicInteger repoProcessed = new AtomicInteger(0);
        int totalRepos = byRepo.size();

        ExecutorService executor = Executors.newFixedThreadPool(workers);
        List<Future<?>> futures = new ArrayList<>();

        for (Map.Entry<String, List<PackageInfo>> entry : byRepo.entrySet()) {
            String githubUrl = entry.getValue().get(0).scmUrl(); // use original casing
            List<PackageInfo> pkgsForRepo = entry.getValue();
            long popularity = pkgsForRepo.stream().mapToLong(PackageInfo::downloadCount).max().orElse(0);

            futures.add(executor.submit(() -> {
                int idx = repoProcessed.incrementAndGet();
                log.info("[{}/{}] Cloning {}...", idx, totalRepos, githubUrl);

                Path cloneDir = builder.cloneRepo(githubUrl, reposDir, tokenMgr);
                if (cloneDir == null) {
                    log.warn("[{}/{}] Clone failed for {}", idx, totalRepos, githubUrl);
                    return;
                }

                if (builder.isGradleProject(cloneDir)) {
                    log.info("[{}/{}] Skipping Gradle project: {}", idx, totalRepos, githubUrl);
                    return;
                }

                if (!Files.exists(cloneDir.resolve("pom.xml"))) {
                    log.info("[{}/{}] No pom.xml found in {}", idx, totalRepos, githubUrl);
                    return;
                }

                // Detect modules
                List<String> modulePaths = builder.detectModules(cloneDir);

                // Determine which modules to analyze and check for coordinate mismatches.
                // If any Maven Central package matches a specific child module, only analyze that one.
                // Otherwise (SCM points to parent or no match), analyze all modules.
                Set<String> targetModules = new LinkedHashSet<>();
                for (PackageInfo pkg : pkgsForRepo) {
                    String match = builder.matchModuleToArtifact(cloneDir, modulePaths,
                            pkg.groupId(), pkg.artifactId());
                    if (match != null) {
                        targetModules.add(match);
                    } else {
                        // No match — check if coordinates differ from root/first module
                        GitHubProject.ModuleInfo rootInfo = builder.readModuleInfo(cloneDir, ".");
                        if (rootInfo != null
                                && (!pkg.groupId().equals(rootInfo.groupId())
                                    || !pkg.artifactId().equals(rootInfo.artifactId()))) {
                            mismatches.add(new CoordinateMismatch(
                                    pkg.groupId(), pkg.artifactId(),
                                    rootInfo.groupId(), rootInfo.artifactId(),
                                    githubUrl
                            ));
                        }
                    }
                }
                if (targetModules.isEmpty()) {
                    targetModules.addAll(modulePaths);
                }

                // Build from root
                log.info("[{}/{}] Building {}...", idx, totalRepos, githubUrl);
                boolean buildOk = builder.buildProject(cloneDir);
                if (!buildOk) {
                    log.warn("[{}/{}] Build failed for {}", idx, totalRepos, githubUrl);
                    return;
                }

                // Process each target module
                String owner = ProjectBuilder.extractOwner(githubUrl);
                String repo = ProjectBuilder.extractRepo(githubUrl);
                List<GitHubProject.ModuleInfo> moduleInfos = new ArrayList<>();

                for (String modulePath : targetModules) {
                    Path moduleDir = modulePath.equals(".")
                            ? cloneDir : cloneDir.resolve(modulePath);
                    if (!Files.exists(moduleDir.resolve("pom.xml"))) continue;

                    GitHubProject.ModuleInfo baseInfo = builder.readModuleInfo(moduleDir, modulePath);
                    if (baseInfo == null) continue;

                    Path jarPath = builder.findModuleJar(moduleDir);
                    if (jarPath == null) {
                        log.debug("No JAR found for module {} in {}", modulePath, githubUrl);
                        moduleInfos.add(new GitHubProject.ModuleInfo(
                                baseInfo.groupId(), baseInfo.artifactId(), baseInfo.version(),
                                modulePath, null, null, true, false
                        ));
                        continue;
                    }

                    // Run preprocessor
                    String mapKey = baseInfo.groupId() + "_" + baseInfo.artifactId() + "_" + baseInfo.version();
                    Path packageMapFile = outputDir.resolve("package-maps").resolve(mapKey + "-package-map.json");
                    boolean preprocOk = builder.runPreprocessor(moduleDir, packageMapFile);

                    moduleInfos.add(new GitHubProject.ModuleInfo(
                            baseInfo.groupId(), baseInfo.artifactId(), baseInfo.version(),
                            modulePath,
                            jarPath.toAbsolutePath().toString(),
                            preprocOk ? packageMapFile.toAbsolutePath().toString() : null,
                            true, preprocOk
                    ));
                }

                if (!moduleInfos.isEmpty()) {
                    results.add(new GitHubProject.RepoInfo(
                            githubUrl, owner, repo,
                            cloneDir.toAbsolutePath().toString(),
                            moduleInfos, popularity
                    ));
                }

                log.info("[{}/{}] {} — {} modules processed.",
                        idx, totalRepos, githubUrl, moduleInfos.size());
            }));
        }

        for (Future<?> f : futures) {
            try {
                f.get();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (ExecutionException e) {
                log.error("Clone/build task failed.", e);
            }
        }
        executor.shutdown();

        // Save coordinate mismatches
        if (!mismatches.isEmpty()) {
            try {
                new ObjectMapper().writerWithDefaultPrettyPrinter().writeValue(
                        outputDir.resolve("coordinate_mismatches.json").toFile(), mismatches);
                log.info("Saved {} coordinate mismatches to coordinate_mismatches.json", mismatches.size());
            } catch (IOException e) {
                log.error("Failed to save coordinate mismatches.", e);
            }
        }

        // Sort by popularity and keep top targetRepos
        results.sort((a, b) -> Long.compare(b.popularity(), a.popularity()));
        if (results.size() > targetRepos) {
            log.info("Trimming from {} to {} repos by popularity.", results.size(), targetRepos);
            return new ArrayList<>(results.subList(0, targetRepos));
        }

        log.info("Phase 2 complete: {} validated repos.", results.size());
        return results;
    }

    // ==================== Phase 4: VERSION HISTORY ====================

    private void runGitVersionHistory(List<ModuleWithApis> modulesWithApis,
                                      ProjectBuilder builder, GitHubTokenManager tokenMgr,
                                      PackageAnalyzer analyzer, CheckpointManager checkpoint) {
        log.info("=============================================================");
        log.info("  Phase 4: VERSION HISTORY — {} modules with sensitive APIs", modulesWithApis.size());
        log.info("  Batch size: {}, years back: {}", versionHistoryBatchSize, versionHistoryYears);
        log.info("=============================================================");

        // Sort by number of sensitive APIs (descending)
        modulesWithApis.sort((a, b) -> Integer.compare(b.detectedApis.size(), a.detectedApis.size()));

        int startBatch = checkpoint.getVersionHistoryBatchIndex();
        int totalModules = modulesWithApis.size();
        CommitVersionScanner scanner = new CommitVersionScanner();
        VersionHistoryTracker tracker = new VersionHistoryTracker();

        for (int batchStart = startBatch * versionHistoryBatchSize;
             batchStart < totalModules;
             batchStart += versionHistoryBatchSize) {

            int batchEnd = Math.min(batchStart + versionHistoryBatchSize, totalModules);
            int batchIndex = batchStart / versionHistoryBatchSize;

            log.info("Processing version history batch {} (modules {}-{} of {})...",
                    batchIndex, batchStart + 1, batchEnd, totalModules);

            List<ModuleWithApis> batch = modulesWithApis.subList(batchStart, batchEnd);

            for (ModuleWithApis mwa : batch) {
                try {
                    processModuleVersionHistory(mwa, scanner, builder, tokenMgr, analyzer, tracker);
                } catch (Exception e) {
                    log.error("Error processing version history for {}:{}: {}",
                            mwa.am.module.groupId(), mwa.am.module.artifactId(), e.getMessage());
                }
            }

            checkpoint.setVersionHistoryBatchIndex(batchIndex + 1);
            log.info("Batch {} complete.", batchIndex);
        }

        // Generate visualization
        try {
            new VersionHistoryVisualizer().generateReport(outputDir);
        } catch (IOException e) {
            log.error("Failed to generate version history visualization.", e);
        }
    }

    private void processModuleVersionHistory(ModuleWithApis mwa,
                                              CommitVersionScanner scanner,
                                              ProjectBuilder builder,
                                              GitHubTokenManager tokenMgr,
                                              PackageAnalyzer analyzer,
                                              VersionHistoryTracker tracker) {
        GitHubProject.ModuleInfo module = mwa.am.module;
        GitHubProject.RepoInfo repo = mwa.am.repo;
        Path cloneDir = Path.of(repo.cloneDir());
        String modulePath = module.modulePath();
        String pomRelativePath = modulePath.equals(".")
                ? "pom.xml" : modulePath + "/pom.xml";

        log.info("  Analyzing version history for {}:{}...", module.groupId(), module.artifactId());

        // Deepen the clone to get full history
        if (!scanner.deepenClone(cloneDir)) {
            log.warn("  Failed to deepen clone for {}", repo.githubUrl());
            return;
        }

        // Find version-changing commits
        List<CommitVersionScanner.VersionCommit> versionCommits =
                scanner.findVersionChangingCommits(cloneDir, pomRelativePath, versionHistoryYears);

        if (versionCommits.size() <= 1) {
            log.info("  {}:{} has only {} version(s) in history, skipping.",
                    module.groupId(), module.artifactId(), versionCommits.size());
            return;
        }

        log.info("  Found {} version-changing commits for {}:{}",
                versionCommits.size(), module.groupId(), module.artifactId());

        List<VersionHistoryTracker.VersionReportEntry> reportEntries = new ArrayList<>();

        for (CommitVersionScanner.VersionCommit vc : versionCommits) {
            try {
                // Checkout the commit
                if (!scanner.checkoutCommit(cloneDir, vc.hash())) {
                    log.debug("  Failed to checkout {}", vc.hash());
                    continue;
                }

                // Build
                if (!builder.buildProject(cloneDir)) {
                    log.debug("  Build failed at commit {} (version {})", vc.hash(), vc.version());
                    continue;
                }

                // Find JAR and run preprocessor
                Path moduleDir = modulePath.equals(".") ? cloneDir : cloneDir.resolve(modulePath);
                Path jarPath = builder.findModuleJar(moduleDir);
                if (jarPath == null) continue;

                String mapKey = module.groupId() + "_" + module.artifactId() + "_" + vc.version();
                Path packageMapFile = outputDir.resolve("package-maps").resolve(mapKey + "-package-map.json");

                if (!builder.runPreprocessor(moduleDir, packageMapFile)) continue;

                // Run analyzer
                PackageAnalyzer.AnalysisResult result = analyzer.analyzeFromProject(
                        module.groupId(), module.artifactId(), vc.version(),
                        jarPath, packageMapFile
                );

                if (result.analyzerSucceeded()) {
                    String reportKey = module.groupId() + "_" + module.artifactId() + "_" + vc.version();
                    Path reportFile = outputDir.resolve("reports").resolve(reportKey + "-report.json");
                    if (Files.exists(reportFile)) {
                        long timestamp = java.time.Instant.parse(
                                vc.isoDate().length() > 10 ? vc.isoDate() : vc.isoDate() + "T00:00:00Z"
                        ).toEpochMilli();
                        reportEntries.add(new VersionHistoryTracker.VersionReportEntry(
                                vc.version(), timestamp, reportFile));
                    }
                }
            } catch (Exception e) {
                log.debug("  Error at commit {} (version {}): {}", vc.hash(), vc.version(), e.getMessage());
            }
        }

        // Restore HEAD
        scanner.restoreHead(cloneDir);

        if (reportEntries.size() >= 2) {
            try {
                VersionHistory.PackageVersionHistory history =
                        tracker.buildHistory(module.groupId(), module.artifactId(), reportEntries);
                tracker.saveHistory(history, outputDir);
                log.info("  {}:{} — {} versions analyzed, changes: {}",
                        module.groupId(), module.artifactId(),
                        reportEntries.size(), history.hasPermissionChanges());
            } catch (IOException e) {
                log.error("  Failed to save version history for {}:{}", module.groupId(), module.artifactId(), e);
            }
        }
    }

    // ==================== Helper records ====================

    private record AnalyzableModule(GitHubProject.RepoInfo repo, GitHubProject.ModuleInfo module) {}

    private record ModuleWithApis(AnalyzableModule am, Set<String> detectedApis) {}
}
