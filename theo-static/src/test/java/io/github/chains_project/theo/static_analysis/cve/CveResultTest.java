package io.github.chains_project.theo.static_analysis.cve;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class CveResultTest {

    @Test
    void allFieldsAreAccessible() {
        CveResult result = new CveResult(
            "CVE-2021-44228",
            "Log4Shell remote code execution",
            "CRITICAL",
            "https://osv.dev/vulnerability/CVE-2021-44228",
            List.of("CWE-502", "CWE-78"),
            Set.of("NETWORK", "PROCESS")
        );

        assertEquals("CVE-2021-44228", result.id());
        assertEquals("Log4Shell remote code execution", result.summary());
        assertEquals("CRITICAL", result.severity());
        assertEquals("https://osv.dev/vulnerability/CVE-2021-44228", result.link());
        assertEquals(List.of("CWE-502", "CWE-78"), result.cweIds());
        assertTrue(result.categories().contains("NETWORK"));
        assertTrue(result.categories().contains("PROCESS"));
    }

    @Test
    void recordEqualityWorks() {
        CveResult a = new CveResult("CVE-2021-44228", "Log4Shell", "CRITICAL",
            "https://osv.dev/vulnerability/CVE-2021-44228", List.of("CWE-502"), Set.of("NETWORK"));
        CveResult b = new CveResult("CVE-2021-44228", "Log4Shell", "CRITICAL",
            "https://osv.dev/vulnerability/CVE-2021-44228", List.of("CWE-502"), Set.of("NETWORK"));
        CveResult c = new CveResult("CVE-2021-99999", "Something else", "LOW",
            "https://osv.dev/vulnerability/CVE-2021-99999", List.of(), Set.of("OTHER"));

        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(a, c);
    }

    @Test
    void nullSummaryDoesNotCauseIssues() {
        CveResult result = new CveResult("CVE-2021-44228", null, "HIGH",
            "https://osv.dev/vulnerability/CVE-2021-44228", List.of(), Set.of("OTHER"));

        assertNull(result.summary());
        assertDoesNotThrow(result::toString);
        assertDoesNotThrow(result::hashCode);
    }
}
