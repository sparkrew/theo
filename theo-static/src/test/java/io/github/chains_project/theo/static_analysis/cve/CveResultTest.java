package io.github.chains_project.theo.static_analysis.cve;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CveResultTest {

    @Test
    void allFieldsAreAccessible() {
        CveResult result = new CveResult(
            "CVE-2021-44228",
            "Log4Shell remote code execution",
            "CRITICAL",
            "https://osv.dev/vulnerability/CVE-2021-44228"
        );

        assertEquals("CVE-2021-44228", result.id());
        assertEquals("Log4Shell remote code execution", result.summary());
        assertEquals("CRITICAL", result.severity());
        assertEquals("https://osv.dev/vulnerability/CVE-2021-44228", result.link());
    }

    @Test
    void recordEqualityWorks() {
        CveResult a = new CveResult("CVE-2021-44228", "Log4Shell", "CRITICAL", "https://osv.dev/vulnerability/CVE-2021-44228");
        CveResult b = new CveResult("CVE-2021-44228", "Log4Shell", "CRITICAL", "https://osv.dev/vulnerability/CVE-2021-44228");
        CveResult c = new CveResult("CVE-2021-99999", "Something else", "LOW", "https://osv.dev/vulnerability/CVE-2021-99999");

        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
        assertNotEquals(a, c);
    }

    @Test
    void nullSummaryDoesNotCauseIssues() {
        CveResult result = new CveResult("CVE-2021-44228", null, "HIGH", "https://osv.dev/vulnerability/CVE-2021-44228");

        assertNull(result.summary());
        assertDoesNotThrow(result::toString);
        assertDoesNotThrow(result::hashCode);
    }
}
