package io.github.chains_project.theo.static_analysis.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DependencyReportTest {

    @Test
    void gavReturnsCorrectString() {
        DependencyReport report = new DependencyReport(
                "com.example", "my-lib", "1.0.0", "jar",
                null, 0, 1000L);
        assertEquals("com.example:my-lib:1.0.0", report.gav());
    }

    @Test
    void hasSensitiveApisReturnsFalseForNull() {
        DependencyReport report = new DependencyReport(
                "g", "a", "v", "jar", null, 0, 0L);
        assertFalse(report.hasSensitiveApis());
    }

    @Test
    void hasSensitiveApisReturnsFalseForEmptyList() {
        DependencyReport report = new DependencyReport(
                "g", "a", "v", "jar", Collections.emptyList(), 0, 0L);
        assertFalse(report.hasSensitiveApis());
    }

    @Test
    void hasSensitiveApisReturnsTrueWhenPresent() {
        SensitiveApiEntry entry = new SensitiveApiEntry(
                "java.io.File.delete", "com.example.Util.cleanup",
                "DIRECT", List.of(), List.of(), "io", "file");
        DependencyReport report = new DependencyReport(
                "g", "a", "v", "jar", List.of(entry), 1, 0L);
        assertTrue(report.hasSensitiveApis());
    }

    @Test
    void sensitiveApiCountReturnsCorrectCount() {
        SensitiveApiEntry e1 = new SensitiveApiEntry(
                "java.io.File.delete", "ep1", "DIRECT",
                List.of(), List.of(), "io", "file");
        SensitiveApiEntry e2 = new SensitiveApiEntry(
                "java.net.Socket.<init>", "ep2", "INDIRECT",
                List.of("dep1"), List.of("ep2", "dep1.m", "Socket.<init>"),
                "network", "socket");
        DependencyReport report = new DependencyReport(
                "g", "a", "v", "jar", List.of(e1, e2), 2, 0L);
        assertEquals(2, report.sensitiveApiCount());
    }

    @Test
    void sensitiveApiCountReturnsZeroForNull() {
        DependencyReport report = new DependencyReport(
                "g", "a", "v", "jar", null, 0, 0L);
        assertEquals(0, report.sensitiveApiCount());
    }

    @Test
    void jacksonSerializationRoundTrip() throws Exception {
        SensitiveApiEntry e1 = new SensitiveApiEntry(
                "java.io.File.delete", "com.example.Util.cleanup",
                "DIRECT", List.of(), List.of("cleanup", "File.delete"),
                "io", "file");
        SensitiveApiEntry e2 = new SensitiveApiEntry(
                "java.net.Socket.<init>", "com.example.Net.connect",
                "INDIRECT", List.of("lib-x"),
                List.of("connect", "lib-x.open", "Socket.<init>"),
                "network", "socket");

        DependencyReport original = new DependencyReport(
                "com.example", "my-lib", "2.1.0", "jar",
                List.of(e1, e2), 5, 1700000000L);

        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(original);
        DependencyReport restored = mapper.readValue(json, DependencyReport.class);

        assertEquals(original.gav(), restored.gav());
        assertEquals(original.getType(), restored.getType());
        assertEquals(original.getEntryPointCount(), restored.getEntryPointCount());
        assertEquals(original.getAnalyzedAt(), restored.getAnalyzedAt());
        assertEquals(original.sensitiveApiCount(), restored.sensitiveApiCount());
        assertEquals(original.getSensitiveApis().get(0).sensitiveApi(),
                restored.getSensitiveApis().get(0).sensitiveApi());
        assertEquals(original.getSensitiveApis().get(1).category(),
                restored.getSensitiveApis().get(1).category());
    }
}
