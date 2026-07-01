package io.github.chains_project.theo.package_miner;

import picocli.CommandLine;

import java.nio.file.Path;

/**
 * The "mine" subcommand that drives the whole mining pipeline.
 *
 * Pipeline phases:
 * 1. DISCOVER — Select popular Java packages from Maven Central that have GitHub SCM links
 * 2. CLONE & BUILD — Clone repos, build with Maven, run preprocessor
 * 3. ANALYZE — Run package-static-analyzer on built JARs
 * 4. VERSION HISTORY — Track sensitive API changes across git commits (optional, batched)
 *
 * The analysis can be parallelized with -w and will checkpoint progress,
 * so you can kill and resume without losing work.
 */
@CommandLine.Command(name = "mine", mixinStandardHelpOptions = true, version = "0.1",
        description = "Mine Maven Central packages for sensitive API usage via GitHub cloning.")
public class MineCommand implements Runnable {

    @CommandLine.Option(
            names = {"-o", "--output-dir"},
            paramLabel = "OUTPUT-DIR",
            description = "Directory where results (CSV, JSON reports) are written.",
            required = true
    )
    Path outputDir;

    @CommandLine.Option(
            names = {"-j", "--analyzer-jar"},
            paramLabel = "ANALYZER-JAR",
            description = "Path to the package-static-analyzer jar-with-dependencies JAR.",
            required = true
    )
    Path analyzerJar;

    @CommandLine.Option(
            names = {"-w", "--workers"},
            paramLabel = "WORKERS",
            description = "Number of parallel workers. Default: 1.",
            defaultValue = "1"
    )
    int workers;

    @CommandLine.Option(
            names = {"--tokens-file"},
            paramLabel = "TOKENS-FILE",
            description = "Path to GitHub tokens file (one token per line). Default: ./tokens.txt.",
            defaultValue = "tokens.txt"
    )
    Path tokensFile;

    @CommandLine.Option(
            names = {"--repos-dir"},
            paramLabel = "REPOS-DIR",
            description = "Directory for cloned GitHub repos. Defaults to <output-dir>/repos."
    )
    Path reposDir;

    @CommandLine.Option(
            names = {"--target-repos"},
            paramLabel = "TARGET",
            description = "Target number of valid GitHub repos to analyze. Default: 4200.",
            defaultValue = "4200"
    )
    int targetRepos;

    @CommandLine.Option(
            names = {"--analyze-all-versions"},
            paramLabel = "BOOL",
            description = "Analyze version history from git commits for packages with sensitive APIs. " +
                    "Default: true. Set to false to only analyze the latest version.",
            defaultValue = "true"
    )
    boolean analyzeAllVersions;

    @CommandLine.Option(
            names = {"--version-history-years"},
            paramLabel = "YEARS",
            description = "How many years back to scan git history for version changes. Default: 5.",
            defaultValue = "5"
    )
    int versionHistoryYears;

    @CommandLine.Option(
            names = {"--version-history-batch-size"},
            paramLabel = "BATCH",
            description = "Number of packages to process per version-history batch. Default: 100.",
            defaultValue = "100"
    )
    int versionHistoryBatchSize;

    @CommandLine.Option(
            names = {"--cutoff-year"},
            paramLabel = "YEAR",
            description = "Skip packages not updated since this year. Default: 2021.",
            defaultValue = "2021"
    )
    int cutoffYear;

    @Override
    public void run() {
        if (reposDir == null) {
            reposDir = outputDir.resolve("repos");
        }
        MiningOrchestrator orchestrator = new MiningOrchestrator(
                outputDir, analyzerJar, workers, tokensFile, reposDir,
                targetRepos, analyzeAllVersions, versionHistoryYears,
                versionHistoryBatchSize, cutoffYear
        );
        orchestrator.run();
    }
}
