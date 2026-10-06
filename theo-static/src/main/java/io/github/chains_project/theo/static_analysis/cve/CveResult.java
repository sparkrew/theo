package io.github.chains_project.theo.static_analysis.cve;

/**
 * A single vulnerability finding from the OSV database. We only store
 * what we need for display — the full advisory is a click away.
 */
public record CveResult(
    String id,          // e.g. "GHSA-abcd-efgh-ijkl" or "CVE-2024-12345"
    String summary,     // brief description from the advisory
    String severity,    // "CRITICAL", "HIGH", "MEDIUM", "LOW", or empty if unavailable
    String link         // URL to the full advisory, e.g. "https://osv.dev/vulnerability/GHSA-..."
) {}
