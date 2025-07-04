package io.github.chains_project.theo.theo_test_exec.detector;

import picocli.CommandLine;

import java.nio.file.Path;

/**
 * This class represents the main entry point to the Detector.
 */
public class Main {

    public static void main(String[] args) {
        int exitCode = new CommandLine(new CLIEntryPoint()).execute(args);
        System.exit(exitCode);
    }

    @CommandLine.Command(subcommands = {Offline.class}, mixinStandardHelpOptions = true, version = "0.1")
    public static class CLIEntryPoint implements Runnable {
        @Override
        public void run() {
            CommandLine.usage(this, System.out);
        }
    }

    @CommandLine.Command(name = "process", mixinStandardHelpOptions = true, version = "0.1")
    private static class Offline implements Runnable {
        @CommandLine.Option(
                names = {"-j", "--jfr-recording"},
                paramLabel = "RECORDING-FILE",
                description = "The path to the file containing the JFR recordings",
                required = true
        )
        Path recordingFile;

        @CommandLine.Option(
                names = {"-r", "--report-file"},
                paramLabel = "REPORT-FILE",
                description = "The path to the JSON file where the report should be written to. If not specified," +
                        " the report will be written to a file named test-report.json",
                defaultValue = "theo-test-report.json"
        )
        Path reportFile;

        @CommandLine.Option(
                names = {"-n", "--remove-noise"},
                paramLabel = "REMOVE-NOISE",
                description = "If set to true, the detector will remove noise from the report. " +
                        "This includes classloads and reflections.",
                defaultValue = "false"
        )
        String removeNoise;

        @CommandLine.Option(
                names = {"-p", "--package-name"},
                paramLabel = "PACKAGE-NAME",
                description = "The package name of the project under consideration to filter the events.",
                required = true
        )
        String packageName;

        @CommandLine.Option(
                names = {"-m", "--package-map"},
                paramLabel = "PACKAGE-MAP",
                description = "The path to the package map file. " +
                        "This file contains the mapping of package names to Maven coordinates.",
                required = true
        )
        String packageMapPath;

        @Override
        public void run() {
            BaseDetector baseDetector = new BaseDetector();
            baseDetector.trackJFREvents(recordingFile, reportFile, removeNoise, packageName, packageMapPath);
        }
    }
}
