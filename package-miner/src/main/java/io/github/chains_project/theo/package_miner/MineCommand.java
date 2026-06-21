package io.github.chains_project.theo.package_miner;

import picocli.CommandLine;

import java.nio.file.Path;

/**
 * The "mine" subcommand that drives the whole mining pipeline.
 *
 * What it does:
 * 1. Selects packages from Maven Central (half most-popular, half random)
 * 2. Downloads their source JARs (falls back to binary JARs if source isn't available)
 * 3. Runs theo-static on each JAR to detect sensitive API usage
 * 4. Writes a CSV matrix (packages x sensitive APIs) and per-package path JSON files
 *
 * The analysis can be parallelized with -w and will checkpoint progress,
 * so you can kill and resume without losing work.
 */
@CommandLine.Command(name = "mine", mixinStandardHelpOptions = true, version = "0.1",
        description = "Mine Maven Central packages for sensitive API usage.")
public class MineCommand implements Runnable {

    @CommandLine.Option(
            names = {"-o", "--output-dir"},
            paramLabel = "OUTPUT-DIR",
            description = "Directory where results (CSV, JSON reports) are written.",
            required = true
    )
    Path outputDir;

    @CommandLine.Option(
            names = {"-t", "--total-packages"},
            paramLabel = "TOTAL",
            description = "Total number of packages to analyze (half popular, half random). Default: 2000.",
            defaultValue = "2000"
    )
    int totalPackages;

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
            description = "Number of parallel workers for analysis. Default: 1.",
            defaultValue = "1"
    )
    int workers;

    @CommandLine.Option(
            names = {"--download-dir"},
            paramLabel = "DOWNLOAD-DIR",
            description = "Directory to store downloaded source JARs. Defaults to <output-dir>/jars."
    )
    Path downloadDir;

    @Override
    public void run() {
        // If the user didn't specify a download directory, put JARs inside the output folder
        if (downloadDir == null) {
            downloadDir = outputDir.resolve("jars");
        }
        MiningOrchestrator orchestrator = new MiningOrchestrator(
                outputDir, downloadDir, analyzerJar, totalPackages, workers
        );
        orchestrator.run();
    }
}
