package io.github.chains_project.theo.static_analysis.cve;

import java.util.List;
import java.util.Set;

/**
 * A single vulnerability finding from the OSV database. Includes the
 * CWE IDs from the advisory and the Theo categories they map to,
 * so CVEs can be grouped alongside sensitive APIs by category.
 */
public record CveResult(
    String id,
    String summary,
    String severity,
    String link,
    List<String> cweIds,       // e.g. ["CWE-22", "CWE-78"], empty if unavailable
    Set<String> categories     // e.g. {"FILESYSTEM", "PROCESS"}, derived from CWEs via CweCategoryMapper
) {}
