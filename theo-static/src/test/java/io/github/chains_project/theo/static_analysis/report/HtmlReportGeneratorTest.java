package io.github.chains_project.theo.static_analysis.report;

import io.github.chains_project.theo.static_analysis.model.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class HtmlReportGeneratorTest {

    @Test
    void generateReportsCreatesAllExpectedFiles(@TempDir Path reportDir) throws IOException {
        AnalysisSummary summary = buildMinimalSummary();
        ChangeSet changeSet = new ChangeSet(List.of(), List.of(), List.of(), false);
        HtmlReportGenerator generator = new HtmlReportGenerator();

        generator.generateReports(summary, changeSet, reportDir);

        assertTrue(Files.exists(reportDir.resolve("all-dependencies.html")),
            "all-dependencies.html should be created");
        assertTrue(Files.exists(reportDir.resolve("reachable.html")),
            "reachable.html should be created");
        assertTrue(Files.exists(reportDir.resolve("changes.html")),
            "changes.html should be created");
        assertFalse(Files.exists(reportDir.resolve("analysis-data.json")),
            "analysis-data.json should not be created (CVE check reads from summary directly)");
    }

    @Test
    void generatedHtmlContainsDepGavSpan(@TempDir Path reportDir) throws IOException {
        AnalysisSummary summary = buildMinimalSummary();
        ChangeSet changeSet = new ChangeSet(List.of(), List.of(), List.of(), false);
        HtmlReportGenerator generator = new HtmlReportGenerator();

        generator.generateReports(summary, changeSet, reportDir);

        String allDeps = Files.readString(reportDir.resolve("all-dependencies.html"));
        assertTrue(allDeps.contains("<span class=\"dep-gav\">"),
            "Report should contain dep-gav span elements");
        assertTrue(allDeps.contains("com.example:vulnerable-lib:1.0.0"),
            "Report should contain the dependency GAV");
    }

    @Test
    void generatedHtmlContainsDetailsElements(@TempDir Path reportDir) throws IOException {
        AnalysisSummary summary = buildMinimalSummary();
        ChangeSet changeSet = new ChangeSet(List.of(), List.of(), List.of(), false);
        HtmlReportGenerator generator = new HtmlReportGenerator();

        generator.generateReports(summary, changeSet, reportDir);

        String allDeps = Files.readString(reportDir.resolve("all-dependencies.html"));
        assertTrue(allDeps.contains("<details"), "Report should contain details elements");
        assertTrue(allDeps.contains("</details>"), "Report should contain closing details tags");
    }

    @Test
    void reachableSensitiveApisGetReachableClass(@TempDir Path reportDir) throws IOException {
        AnalysisSummary summary = buildMinimalSummary();
        ChangeSet changeSet = new ChangeSet(List.of(), List.of(), List.of(), false);
        HtmlReportGenerator generator = new HtmlReportGenerator();

        generator.generateReports(summary, changeSet, reportDir);

        String allDeps = Files.readString(reportDir.resolve("all-dependencies.html"));
        // The dependency with the reachable API should get the reachable class
        assertTrue(allDeps.contains("reachable"),
            "Report should mark reachable APIs with the reachable class");

        // The reachable.html should only contain reachable APIs
        String reachable = Files.readString(reportDir.resolve("reachable.html"));
        assertTrue(reachable.contains("java.io.FileInputStream"),
            "Reachable report should include the reachable sensitive API");
    }

    @Test
    void changesReportShowsFirstRunMessage(@TempDir Path reportDir) throws IOException {
        AnalysisSummary summary = buildMinimalSummary();
        // hasPreviousRun = false means this is the first run
        ChangeSet changeSet = new ChangeSet(List.of(), List.of(), List.of(), false);
        HtmlReportGenerator generator = new HtmlReportGenerator();

        generator.generateReports(summary, changeSet, reportDir);

        String changes = Files.readString(reportDir.resolve("changes.html"));
        assertTrue(changes.contains("First analysis run"),
            "Changes report should indicate first run when there is no previous data");
    }

    /**
     * Builds a minimal AnalysisSummary with:
     * - One dependency with a reachable sensitive API (java.io.FileInputStream)
     * - One dependency with a non-reachable sensitive API (java.lang.Runtime.exec)
     */
    private AnalysisSummary buildMinimalSummary() {
        SensitiveApiEntry reachableApi = new SensitiveApiEntry(
            "java.io.FileInputStream.<init>",
            "com.example.Util.readFile",
            "DIRECT",
            List.of(),
            List.of("com.example.Util.readFile", "java.io.FileInputStream.<init>"),
            "filesystem",
            "read"
        );

        SensitiveApiEntry nonReachableApi = new SensitiveApiEntry(
            "java.lang.Runtime.exec",
            "com.other.Helper.runCommand",
            "DIRECT",
            List.of(),
            List.of("com.other.Helper.runCommand", "java.lang.Runtime.exec"),
            "process",
            "execute"
        );

        DependencyReport depWithReachable = new DependencyReport(
            "com.example", "vulnerable-lib", "1.0.0", "jar",
            List.of(reachableApi), 10, System.currentTimeMillis()
        );

        DependencyReport depWithNonReachable = new DependencyReport(
            "com.other", "safe-lib", "2.0.0", "jar",
            List.of(nonReachableApi), 5, System.currentTimeMillis()
        );

        // Mark only the first API as reachable
        Set<String> reachableApis = Set.of(
            "com.example:vulnerable-lib:1.0.0::java.io.FileInputStream.<init>"
        );

        return new AnalysisSummary(
            "com.test", "test-project", "1.0-SNAPSHOT",
            List.of(depWithReachable, depWithNonReachable),
            reachableApis,
            System.currentTimeMillis()
        );
    }
}
