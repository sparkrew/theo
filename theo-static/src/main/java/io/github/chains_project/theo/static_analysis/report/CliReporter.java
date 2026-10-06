package io.github.chains_project.theo.static_analysis.report;

import io.github.chains_project.theo.static_analysis.cve.CveResult;
import io.github.chains_project.theo.static_analysis.model.AnalysisSummary;
import io.github.chains_project.theo.static_analysis.model.ChangeSet;
import io.github.chains_project.theo.static_analysis.model.DependencyReport;
import org.apache.maven.plugin.logging.Log;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * Formats analysis results for the Maven CLI output. Keeps the output concise --
 * the detailed information lives in the HTML reports. The CLI just highlights
 * what changed and where to find more info.
 */
public class CliReporter {

    private final Log log;

    public CliReporter(Log log) {
        this.log = log;
    }

    /**
     * Prints the analysis summary to the Maven log.
     *
     * @param summary    the full analysis result
     * @param changeSet  what changed since the last run
     * @param reportDir  where the HTML reports are
     * @param verbose    if true, shows changes across all deps; if false, only reachable changes
     */
    public void printSummary(AnalysisSummary summary, ChangeSet changeSet, Path reportDir, boolean verbose) {
        log.info("");
        log.info("=== Theo static analysis complete ===");
        log.info("");

        // Quick stats
        int totalDeps = summary.getDependencyReports().size();
        int depsWithApis = (int) summary.getDependencyReports().stream()
                .filter(DependencyReport::hasSensitiveApis).count();
        log.info("Analyzed " + totalDeps + " dependencies, " + depsWithApis + " have sensitive API access.");

        // Changes section
        if (!changeSet.hasPreviousRun()) {
            log.info("First analysis run — no previous data to compare against.");
        } else if (!changeSet.hasChanges()) {
            log.info("No changes detected since the last run.");
        } else {
            printChanges(changeSet, summary, verbose);
        }

        log.info("");
        printReportLinks(reportDir);
    }

    /**
     * Prints change details based on verbosity.
     * Verbose mode shows all changes; non-verbose only shows changes to client-reachable APIs.
     */
    private void printChanges(ChangeSet changeSet, AnalysisSummary summary, boolean verbose) {
        if (verbose) {
            printAllChanges(changeSet);
        } else {
            printReachableChanges(changeSet, summary);
        }
    }

    /**
     * Prints all changes across all dependencies.
     * Uses + for added, - for removed, ~ for modified.
     */
    private void printAllChanges(ChangeSet changeSet) {
        int total = changeSet.totalChanges();
        log.info("Changes detected in " + total + " dependencies:");

        for (DependencyReport added : changeSet.getAddedDependencies()) {
            log.info("  + " + added.gav() + " (new, " + added.sensitiveApiCount() + " sensitive APIs)");
        }

        for (ChangeSet.DependencyChange mod : changeSet.getModifiedDependencies()) {
            String versionInfo = mod.oldVersion().equals(mod.newVersion())
                    ? "" : " " + mod.oldVersion() + " -> " + mod.newVersion();
            int addedCount = mod.addedApis().size();
            int removedCount = mod.removedApis().size();
            log.info("  ~ " + mod.gav() + versionInfo
                    + " (" + addedCount + " added, " + removedCount + " removed)");
        }

        for (DependencyReport removed : changeSet.getRemovedDependencies()) {
            log.info("  - " + removed.gav() + " (removed)");
        }
    }

    /**
     * Only prints changes affecting APIs that the client project actually reaches.
     */
    private void printReachableChanges(ChangeSet changeSet, AnalysisSummary summary) {
        // Filter to only changes where the affected APIs are in the reachable set
        boolean anyReachableChange = false;

        for (DependencyReport added : changeSet.getAddedDependencies()) {
            long reachableCount = added.getSensitiveApis().stream()
                    .filter(api -> summary.isReachable(added.gav(), api.sensitiveApi()))
                    .count();
            if (reachableCount > 0) {
                if (!anyReachableChange) {
                    log.info("Changes to client-reachable APIs:");
                    anyReachableChange = true;
                }
                log.info("  + " + added.gav() + " (" + reachableCount + " reachable sensitive APIs)");
            }
        }

        for (ChangeSet.DependencyChange mod : changeSet.getModifiedDependencies()) {
            long addedReachable = mod.addedApis().stream()
                    .filter(api -> summary.isReachable(mod.gav(), api.sensitiveApi()))
                    .count();
            long removedReachable = mod.removedApis().stream()
                    .filter(api -> summary.isReachable(mod.gav(), api.sensitiveApi()))
                    .count();
            if (addedReachable > 0 || removedReachable > 0) {
                if (!anyReachableChange) {
                    log.info("Changes to client-reachable APIs:");
                    anyReachableChange = true;
                }
                log.info("  ~ " + mod.gav() + " (" + addedReachable + " added, " + removedReachable + " removed)");
            }
        }

        if (!anyReachableChange) {
            log.info("No changes to client-reachable APIs since the last run.");
        }
    }

    /**
     * Prints links to the HTML reports so users know where to dig in.
     */
    private void printReportLinks(Path reportDir) {
        log.info("Reports:");
        log.info("  All dependencies:       " + reportDir.resolve("all-dependencies.html"));
        log.info("  Client-reachable only:  " + reportDir.resolve("reachable.html"));
        log.info("  Changes since last run: " + reportDir.resolve("changes.html"));
    }

    /**
     * Prints CVE information to the CLI. Each affected dependency gets a line
     * listing its vulnerabilities with severity.
     */
    public void printCveSummary(Map<String, List<CveResult>> cveResults) {
        if (cveResults == null || cveResults.isEmpty()) {
            log.info("No known vulnerabilities found in any dependency.");
            return;
        }

        long totalVulns = cveResults.values().stream().mapToLong(List::size).sum();
        long affectedDeps = cveResults.values().stream().filter(l -> !l.isEmpty()).count();

        log.info("");
        log.info("Found " + totalVulns + " vulnerabilities across " + affectedDeps + " dependencies:");

        for (Map.Entry<String, List<CveResult>> entry : cveResults.entrySet()) {
            List<CveResult> cves = entry.getValue();
            if (cves.isEmpty()) {
                continue;
            }

            String cveList = cves.stream()
                    .map(c -> c.severity().isEmpty() ? c.id() : c.id() + " (" + c.severity() + ")")
                    .reduce((a, b) -> a + ", " + b)
                    .orElse("");

            log.info("  " + entry.getKey() + " — " + cveList);
        }
    }
}
