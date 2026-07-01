package io.github.chains_project.theo.package_miner;

import picocli.CommandLine;

import java.nio.file.Path;

@CommandLine.Command(name = "mine", mixinStandardHelpOptions = true, version = "0.1",
        description = "Mine Maven Central packages for sensitive API usage.")
public class MineCommand implements Runnable {

    @CommandLine.Option(names = {"-o", "--output-dir"}, paramLabel = "OUTPUT-DIR",
            description = "Directory where results are written.", required = true)
    Path outputDir;

    @CommandLine.Option(names = {"-j", "--analyzer-jar"}, paramLabel = "ANALYZER-JAR",
            description = "Path to the package-static-analyzer jar-with-dependencies JAR.", required = true)
    Path analyzerJar;

    @CommandLine.Option(names = {"-t", "--total-packages"}, paramLabel = "TOTAL",
            description = "Total number of packages to analyze. Default: 4200.", defaultValue = "4200")
    int totalPackages;

    @CommandLine.Option(names = {"-w", "--workers"}, paramLabel = "WORKERS",
            description = "Number of parallel workers. Default: 1.", defaultValue = "1")
    int workers;

    @CommandLine.Option(names = {"--download-dir"}, paramLabel = "DOWNLOAD-DIR",
            description = "Directory for downloaded JARs. Defaults to <output-dir>/jars.")
    Path downloadDir;

    @CommandLine.Option(names = {"--analyze-all-versions"}, paramLabel = "BOOL",
            description = "Analyze version history for packages with sensitive APIs. Default: true.",
            defaultValue = "true")
    boolean analyzeAllVersions;

    @CommandLine.Option(names = {"--version-history-years"}, paramLabel = "YEARS",
            description = "How many years of version history to analyze. Default: 5.", defaultValue = "5")
    int versionHistoryYears;

    @CommandLine.Option(names = {"--version-history-batch-size"}, paramLabel = "BATCH",
            description = "Packages per version-history batch. Default: 100.", defaultValue = "100")
    int versionHistoryBatchSize;

    @CommandLine.Option(names = {"--cutoff-year"}, paramLabel = "YEAR",
            description = "Skip packages not updated since this year. Default: 2021.", defaultValue = "2021")
    int cutoffYear;

    @Override
    public void run() {
        if (downloadDir == null) {
            downloadDir = outputDir.resolve("jars");
        }
        MiningOrchestrator orchestrator = new MiningOrchestrator(
                outputDir, downloadDir, analyzerJar, totalPackages, workers,
                analyzeAllVersions, versionHistoryYears, versionHistoryBatchSize, cutoffYear
        );
        orchestrator.run();
    }
}
