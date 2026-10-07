package io.github.chains_project.theo.static_analysis.cache;

import io.github.chains_project.theo.static_analysis.model.AnalysisSummary;
import io.github.chains_project.theo.static_analysis.model.CacheKey;
import io.github.chains_project.theo.static_analysis.model.DependencyReport;
import io.github.chains_project.theo.static_analysis.model.SensitiveApiEntry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class CacheManagerTest {

    @TempDir
    Path tempDir;

    private CacheManager cacheManager;

    @BeforeEach
    void setUp() {
        cacheManager = new CacheManager(tempDir);
    }

    @Test
    void isCachedReturnsFalseForUncachedKey() {
        CacheKey key = new CacheKey("com.example", "unknown", "1.0.0");
        assertFalse(cacheManager.isCached(key));
    }

    @Test
    void isCachedReturnsTrueAfterStore() {
        CacheKey key = new CacheKey("com.example", "my-lib", "1.0.0");
        DependencyReport report = new DependencyReport(
                "com.example", "my-lib", "1.0.0", "jar",
                null, 0, 1000L);

        cacheManager.storeDependencyReport(key, report);
        assertTrue(cacheManager.isCached(key));
    }

    @Test
    void loadDependencyReportReturnsStoredData() {
        CacheKey key = new CacheKey("com.example", "my-lib", "1.0.0");
        SensitiveApiEntry entry = new SensitiveApiEntry(
                "java.io.File.delete", "com.example.Util.cleanup",
                "DIRECT", List.of(), List.of("cleanup", "File.delete"),
                "io", "file");
        DependencyReport report = new DependencyReport(
                "com.example", "my-lib", "1.0.0", "jar",
                List.of(entry), 3, 1700000000L);

        cacheManager.storeDependencyReport(key, report);
        DependencyReport loaded = cacheManager.loadDependencyReport(key);

        assertNotNull(loaded);
        assertEquals("com.example:my-lib:1.0.0", loaded.gav());
        assertEquals("jar", loaded.getType());
        assertEquals(3, loaded.getEntryPointCount());
        assertEquals(1700000000L, loaded.getAnalyzedAt());
        assertEquals(1, loaded.sensitiveApiCount());
        assertEquals("java.io.File.delete",
                loaded.getSensitiveApis().get(0).sensitiveApi());
    }

    @Test
    void loadDependencyReportReturnsNullForUncachedKey() {
        CacheKey key = new CacheKey("com.example", "missing", "1.0.0");
        assertNull(cacheManager.loadDependencyReport(key));
    }

    @Test
    void storeAndLoadLastRunRoundTrip() {
        DependencyReport dep = new DependencyReport(
                "org.slf4j", "slf4j-api", "2.0.9", "jar",
                List.of(), 0, 1700000000L);

        Set<String> reachable = new HashSet<>();
        reachable.add("org.slf4j:slf4j-api:2.0.9::java.io.File.delete");

        AnalysisSummary summary = new AnalysisSummary(
                "com.myapp", "web-service", "3.0.0",
                List.of(dep), reachable, 1700000000L);

        cacheManager.storeLastRun(summary);
        AnalysisSummary loaded = cacheManager.loadLastRun(
                "com.myapp", "web-service");

        assertNotNull(loaded);
        assertEquals("com.myapp", loaded.getProjectGroupId());
        assertEquals("web-service", loaded.getProjectArtifactId());
        assertEquals("3.0.0", loaded.getProjectVersion());
        assertEquals(1, loaded.getDependencyReports().size());
        assertEquals("org.slf4j:slf4j-api:2.0.9",
                loaded.getDependencyReports().get(0).gav());
        assertEquals(1700000000L, loaded.getAnalyzedAt());
    }

    @Test
    void loadLastRunReturnsNullWhenNoPreviousRunExists() {
        assertNull(cacheManager.loadLastRun("com.myapp", "web-service"));
    }
}
