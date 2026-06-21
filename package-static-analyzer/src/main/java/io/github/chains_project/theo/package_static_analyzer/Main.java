package io.github.chains_project.theo.package_static_analyzer;

import picocli.CommandLine;

import java.nio.file.Path;

/**
 * Entry point for the package-static-analyzer CLI tool.
 *
 * This analyzer checks whether a package itself reaches sensitive Java APIs,
 * either directly (its own code calls them) or indirectly (through a dependency).
 *
 * This differs from theo-static which checks whether a *dependency* of a given
 * project reaches sensitive APIs. Here we analyze the package as the subject,
 * not the project that depends on it.
 *
 * Usage:
 *   java -jar package-static-analyzer.jar analyze -j <jar> -p <packages> -m <map> -r <report>
 */
public class Main {
    public static void main(String[] args) {
        int exitCode = new CommandLine(new CLIEntryPoint()).execute(args);
        System.exit(exitCode);
    }

    @CommandLine.Command(
            name = "package-static-analyzer",
            subcommands = {AnalyzeCommand.class},
            mixinStandardHelpOptions = true,
            version = "0.1"
    )
    public static class CLIEntryPoint implements Runnable {
        @Override
        public void run() {
            CommandLine.usage(this, System.out);
        }
    }

    @CommandLine.Command(name = "analyze", mixinStandardHelpOptions = true, version = "0.1",
            description = "Analyze a package JAR for sensitive API usage (direct and indirect).")
    static class AnalyzeCommand implements Runnable {

        @CommandLine.Option(
                names = {"-j", "--jar-path"},
                paramLabel = "JAR-PATH",
                description = "Path to the bytecode JAR file to analyze.",
                required = true
        )
        String jarPath;

        @CommandLine.Option(
                names = {"-r", "--report-file"},
                paramLabel = "REPORT-FILE",
                description = "Path to the JSON report output file.",
                defaultValue = "package-static-report.json"
        )
        String reportFile;

        @CommandLine.Option(
                names = {"-p", "--package-name"},
                paramLabel = "PACKAGE-NAME",
                description = "The package name(s) of the package being analyzed (comma-separated).",
                required = true
        )
        String packageName;

        @CommandLine.Option(
                names = {"-m", "--package-map"},
                paramLabel = "PACKAGE-MAP",
                description = "Path to the package map JSON (maps package names to Maven coordinates).",
                required = true
        )
        Path packageMapPath;

        @Override
        public void run() {
            PackageStaticAnalyzer.process(jarPath, reportFile, packageName, packageMapPath);
        }
    }
}
