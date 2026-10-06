package io.github.chains_project.theo.static_analysis.cve;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for OsvClient that hit the real OSV API.
 * These tests require network access and may fail if the API is unreachable.
 */
class OsvClientTest {

    private final OsvClient client = new OsvClient();

    @Test
    void queryKnownVulnerablePackageReturnsResults() {
        // log4j-core 2.14.1 is affected by Log4Shell (CVE-2021-44228)
        List<CveResult> results = client.query("org.apache.logging.log4j", "log4j-core", "2.14.1");

        assertFalse(results.isEmpty(), "Expected at least one vulnerability for log4j-core 2.14.1");
    }

    @Test
    void queryResultHasNonEmptyIdAndLink() {
        List<CveResult> results = client.query("org.apache.logging.log4j", "log4j-core", "2.14.1");

        assertFalse(results.isEmpty());
        CveResult first = results.get(0);
        assertNotNull(first.id());
        assertFalse(first.id().isBlank(), "CVE id should not be blank");
        assertNotNull(first.link());
        assertFalse(first.link().isBlank(), "CVE link should not be blank");
    }

    @Test
    void batchQueryReturnsResultsForVulnerableDependency() {
        List<String[]> deps = new java.util.ArrayList<>();
        deps.add(new String[]{"org.apache.logging.log4j", "log4j-core", "2.14.1"});

        Map<String, List<CveResult>> results = client.queryBatch(deps);

        // The batch endpoint only includes entries that have vulnerabilities
        assertTrue(results.containsKey("org.apache.logging.log4j:log4j-core:2.14.1"),
            "Expected batch results to contain log4j-core entry");
        assertFalse(results.get("org.apache.logging.log4j:log4j-core:2.14.1").isEmpty(),
            "Expected at least one vulnerability for log4j-core 2.14.1");
    }

    @Test
    void queryNonVulnerablePackageReturnsEmptyOrFewResults() {
        // junit 4.13.2 should be clean or have very few vulnerabilities
        List<CveResult> results = client.query("junit", "junit", "4.13.2");

        // We cannot assert strictly empty because the OSV database may evolve,
        // but we can assert a reasonable upper bound
        assertTrue(results.size() < 5,
            "Expected few or no vulnerabilities for junit 4.13.2, got " + results.size());
    }

    @Test
    void batchQueryWithEmptyListReturnsEmptyMap() {
        Map<String, List<CveResult>> results = client.queryBatch(List.of());

        assertTrue(results.isEmpty());
    }
}
