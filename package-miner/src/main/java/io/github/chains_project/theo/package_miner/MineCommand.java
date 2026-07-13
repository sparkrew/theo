package io.github.chains_project.theo.package_miner;

import picocli.CommandLine;

import java.nio.file.Path;

@CommandLine.Command(name = "mine", mixinStandardHelpOptions = true, version = "0.1",
        description = "Mine Maven Central packages for sensitive API usage.",
        subcommands = {MineCommand.CollectCommand.class, MineCommand.ScanCommand.class})
public class MineCommand implements Runnable {

    @Override
    public void run() {
        CommandLine.usage(this, System.out);
    }

    @CommandLine.Command(name = "collect", mixinStandardHelpOptions = true,
            description = "Collect popular Java packages from ecosyste.ms and save the list.")
    public static class CollectCommand implements Runnable {

        @CommandLine.Option(names = {"-o", "--output-dir"}, paramLabel = "OUTPUT-DIR",
                description = "Directory where the package list is saved.", required = true)
        Path outputDir;

        @CommandLine.Option(names = {"-t", "--total-packages"}, paramLabel = "TOTAL",
                description = "Number of packages to collect. Use 0 to collect all. Default: 0.",
                defaultValue = "0")
        int totalPackages;

        @CommandLine.Option(names = {"--cutoff-year"}, paramLabel = "YEAR",
                description = "Skip packages not updated since this year. Default: 2021.",
                defaultValue = "2021")
        int cutoffYear;

        @Override
        public void run() {
            new CollectOrchestrator(outputDir, totalPackages, cutoffYear).run();
        }
    }

    @CommandLine.Command(name = "scan", mixinStandardHelpOptions = true,
            description = "Scan previously collected packages for sensitive API usage.")
    public static class ScanCommand implements Runnable {

        @CommandLine.Option(names = {"-o", "--output-dir"}, paramLabel = "OUTPUT-DIR",
                description = "Directory containing selected_packages.json and where results are written.",
                required = true)
        Path outputDir;

        @CommandLine.Option(names = {"-j", "--analyzer-jar"}, paramLabel = "ANALYZER-JAR",
                description = "Path to the package-static-analyzer jar-with-dependencies JAR.", required = true)
        Path analyzerJar;

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
                description = "How many years of version history to analyze. Default: 5.",
                defaultValue = "5")
        int versionHistoryYears;

        @CommandLine.Option(names = {"--version-history-batch-size"}, paramLabel = "BATCH",
                description = "Packages per version-history batch. Default: 20.", defaultValue = "20")
        int versionHistoryBatchSize;

        @Override
        public void run() {
            if (downloadDir == null) {
                downloadDir = outputDir.resolve("jars");
            }
            new ScanOrchestrator(outputDir, downloadDir, analyzerJar, workers,
                    analyzeAllVersions, versionHistoryYears, versionHistoryBatchSize).run();
        }
    }
}
