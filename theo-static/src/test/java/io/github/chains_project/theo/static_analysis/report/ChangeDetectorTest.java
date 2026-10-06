package io.github.chains_project.theo.static_analysis.report;

import io.github.chains_project.theo.static_analysis.model.*;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ChangeDetectorTest {

    private final ChangeDetector detector = new ChangeDetector();

    @Test
    void firstRunTreatsAllDependenciesAsAdded() {
        AnalysisSummary current = buildSummary(
                buildReport("com.example", "lib-a", "1.0"),
                buildReport("com.example", "lib-b", "2.0"));

        ChangeSet changes = detector.detectChanges(null, current);

        assertFalse(changes.hasPreviousRun());
        assertEquals(2, changes.getAddedDependencies().size());
        assertTrue(changes.getRemovedDependencies().isEmpty());
        assertTrue(changes.getModifiedDependencies().isEmpty());
    }

    @Test
    void identicalRunsProduceNoChanges() {
        DependencyReport dep = buildReport("com.example", "lib-a", "1.0");
        AnalysisSummary previous = buildSummary(dep);
        AnalysisSummary current = buildSummary(dep);

        ChangeSet changes = detector.detectChanges(previous, current);

        assertTrue(changes.hasPreviousRun());
        assertFalse(changes.hasChanges());
    }

    @Test
    void detectsAddedDependency() {
        DependencyReport existing = buildReport("com.example", "lib-a", "1.0");
        DependencyReport added = buildReport("com.example", "lib-b", "1.0");

        AnalysisSummary previous = buildSummary(existing);
        AnalysisSummary current = buildSummary(existing, added);

        ChangeSet changes = detector.detectChanges(previous, current);

        assertEquals(1, changes.getAddedDependencies().size());
        assertEquals("com.example:lib-b:1.0",
                changes.getAddedDependencies().get(0).gav());
        assertTrue(changes.getRemovedDependencies().isEmpty());
    }

    @Test
    void detectsRemovedDependency() {
        DependencyReport staying = buildReport("com.example", "lib-a", "1.0");
        DependencyReport leaving = buildReport("com.example", "lib-b", "1.0");

        AnalysisSummary previous = buildSummary(staying, leaving);
        AnalysisSummary current = buildSummary(staying);

        ChangeSet changes = detector.detectChanges(previous, current);

        assertTrue(changes.getAddedDependencies().isEmpty());
        assertEquals(1, changes.getRemovedDependencies().size());
        assertEquals("com.example:lib-b:1.0",
                changes.getRemovedDependencies().get(0).gav());
    }

    @Test
    void detectsModifiedDependency() {
        SensitiveApiEntry oldApi = new SensitiveApiEntry(
                "java.io.File.delete", "ep1", "DIRECT",
                List.of(), List.of(), "io", "file");
        SensitiveApiEntry newApi = new SensitiveApiEntry(
                "java.net.Socket.<init>", "ep2", "DIRECT",
                List.of(), List.of(), "network", "socket");

        DependencyReport oldVersion = new DependencyReport(
                "com.example", "lib-a", "1.0", "jar",
                List.of(oldApi), 1, 1000L);
        DependencyReport newVersion = new DependencyReport(
                "com.example", "lib-a", "2.0", "jar",
                List.of(newApi), 1, 2000L);

        AnalysisSummary previous = buildSummary(oldVersion);
        AnalysisSummary current = buildSummary(newVersion);

        ChangeSet changes = detector.detectChanges(previous, current);

        assertTrue(changes.getAddedDependencies().isEmpty());
        assertTrue(changes.getRemovedDependencies().isEmpty());
        assertEquals(1, changes.getModifiedDependencies().size());

        ChangeSet.DependencyChange mod = changes.getModifiedDependencies().get(0);
        assertEquals("com.example", mod.groupId());
        assertEquals("lib-a", mod.artifactId());
        assertEquals("1.0", mod.oldVersion());
        assertEquals("2.0", mod.newVersion());
        assertEquals(1, mod.addedApis().size());
        assertEquals("java.net.Socket.<init>", mod.addedApis().get(0).sensitiveApi());
        assertEquals(1, mod.removedApis().size());
        assertEquals("java.io.File.delete", mod.removedApis().get(0).sensitiveApi());
    }

    // -- helpers --

    private DependencyReport buildReport(String groupId, String artifactId, String version) {
        return new DependencyReport(groupId, artifactId, version, "jar",
                List.of(), 0, System.currentTimeMillis());
    }

    private AnalysisSummary buildSummary(DependencyReport... reports) {
        return new AnalysisSummary(
                "com.myapp", "web-service", "1.0.0",
                List.of(reports), new HashSet<>(), System.currentTimeMillis());
    }
}
