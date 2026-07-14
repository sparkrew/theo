package io.github.chains_project.theo.package_miner;

import picocli.CommandLine;

/**
 * Entry point for the package-miner CLI tool.
 * This tool mines Maven Central to find out which packages use sensitive Java APIs
 * (like file I/O, network sockets, reflection, etc.).
 *
 * It follows the same CLI pattern as theo-static: a top-level command that delegates
 * to subcommands via picocli.
 *
 * Usage:
 *   java -jar package-miner.jar mine -o /output -j /path/to/theo-static.jar
 */
public class Main {
    public static void main(String[] args) {
        int exitCode = new CommandLine(new CLIEntryPoint()).execute(args);
        System.exit(exitCode);
    }

    /**
     * The root command. If called without a subcommand, it just prints help text.
     * The actual work happens in the "mine" subcommand (see {@link MineCommand}).
     */
    @CommandLine.Command(
            name = "package-miner",
            subcommands = {MineCommand.class, RecoverSkippedCommand.class},
            mixinStandardHelpOptions = true,
            version = "0.1"
    )
    public static class CLIEntryPoint implements Runnable {
        @Override
        public void run() {
            CommandLine.usage(this, System.out);
        }
    }
}
