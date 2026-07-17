package io.github.chains_project.theo.package_miner;

import picocli.CommandLine;

import java.io.IOException;
import java.nio.file.Path;

@CommandLine.Command(name = "generate-report", mixinStandardHelpOptions = true,
        description = "Generate the permission_changes_report.html from existing version-history data.")
public class GenerateReportCommand implements Runnable {

    @CommandLine.Option(names = {"-o", "--output-dir"}, paramLabel = "OUTPUT-DIR",
            description = "Directory containing the version-history folder.", required = true)
    Path outputDir;

    @Override
    public void run() {
        try {
            new VersionHistoryVisualizer().generateReport(outputDir);
        } catch (IOException e) {
            System.err.println("Failed to generate report: " + e.getMessage());
        }
    }
}
