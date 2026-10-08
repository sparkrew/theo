package io.github.chains_project.theo.static_analysis.cve;

import io.github.chains_project.theo.static_analysis.model.DependencyReport;
import io.github.chains_project.theo.static_analysis.model.SensitiveApiEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * Augments existing HTML reports with CVE badge information. Reads each
 * HTML file, finds dependency entries by their GAV string, and injects
 * a badge span right after the dependency name.
 */
public class CveEnricher {

    private static final Logger log = LoggerFactory.getLogger(CveEnricher.class);

    /**
     * Fetches CVEs for all dependencies and augments the HTML reports.
     *
     * @param reports   the dependency reports from the analysis
     * @param reportDir the directory containing the HTML reports
     * @return map of "groupId:artifactId:version" -> list of CveResults (for CLI output)
     */
    public Map<String, List<CveResult>> enrichReports(List<DependencyReport> reports, Path reportDir) {
        OsvClient client = new OsvClient();

        // Build the batch query from the dependency reports
        List<String[]> deps = new ArrayList<>();
        for (DependencyReport report : reports) {
            deps.add(new String[]{report.getGroupId(), report.getArtifactId(), report.getVersion()});
        }

        log.info("Querying OSV.dev for CVEs across {} dependencies...", deps.size());
        Map<String, List<CveResult>> cveResults = client.queryBatch(deps);

        if (cveResults.isEmpty()) {
            log.info("No known vulnerabilities found in any dependency.");
            return cveResults;
        }

        // Count total vulnerabilities found
        long totalVulns = cveResults.values().stream().mapToLong(List::size).sum();
        log.info("Found {} vulnerabilities across {} dependencies.", totalVulns, cveResults.size());

        // Augment each HTML report file with CVE badges
        augmentHtmlFile(reportDir.resolve("all-dependencies.html"), cveResults);
        augmentHtmlFile(reportDir.resolve("reachable.html"), cveResults);
        augmentHtmlFile(reportDir.resolve("changes.html"), cveResults);

        // Add unaudited capability badges to the reachable report only.
        // These flag sensitive API categories where the dependency has no
        // known CVE — a gap worth noting for reachable code paths.
        addUnauditedBadges(reportDir.resolve("reachable.html"), reports, cveResults);

        return cveResults;
    }

    /**
     * Injects CVE badge HTML into an existing report file. Places badges next
     * to dependency GAV strings (existing behavior) and also under each
     * category header with relevant CVEs for that category.
     */
    private void augmentHtmlFile(Path htmlFile, Map<String, List<CveResult>> cveResults) {
        if (!Files.exists(htmlFile)) {
            return;
        }

        try {
            String content = Files.readString(htmlFile, StandardCharsets.UTF_8);

            // Step 1: inject badges next to dependency GAV names (existing behavior)
            for (Map.Entry<String, List<CveResult>> entry : cveResults.entrySet()) {
                String gav = entry.getKey();
                List<CveResult> cves = entry.getValue();
                if (cves.isEmpty()) {
                    continue;
                }

                // Build the badge HTML: one badge per CVE, styled by severity
                StringBuilder badges = new StringBuilder();
                for (CveResult cve : cves) {
                    String severityClass = cve.severity().isEmpty() ? "" : cve.severity().toLowerCase();
                    String label = cve.severity().isEmpty()
                        ? escapeHtml(cve.id())
                        : escapeHtml(cve.id()) + " (" + cve.severity() + ")";
                    badges.append(String.format(
                        " <span class=\"cve-badge %s\"><a href=\"%s\" target=\"_blank\">%s</a></span>",
                        severityClass,
                        escapeHtml(cve.link()),
                        label
                    ));
                }

                // Inject badges after every occurrence of this dependency's GAV span.
                // A dependency can appear under multiple categories, so we replace all.
                // To avoid doubling badges on repeated runs, check if badges are already there.
                String gavMarker = "<span class=\"dep-gav\">" + escapeHtml(gav) + "</span>";
                if (!content.contains(gavMarker + " <span class=\"cve-badge")) {
                    String gavWithBadges = gavMarker + badges.toString();
                    content = content.replace(gavMarker, gavWithBadges);
                }
            }

            // Step 2: inject CVE summary blocks under each category header.
            // Category headers are: <h2 class="category-header">FILESYSTEM</h2>
            for (String category : List.of("FILESYSTEM", "NETWORK", "PROCESS", "OTHER")) {
                String headerTag = "<h2 class=\"category-header\">" + escapeHtml(category) + "</h2>";
                if (!content.contains(headerTag)) continue;

                // Collect all CVEs that belong to this category
                StringBuilder categoryBadges = new StringBuilder();
                for (List<CveResult> cves : cveResults.values()) {
                    for (CveResult cve : cves) {
                        if (cve.categories() != null && cve.categories().contains(category)) {
                            String severityClass = cve.severity().isEmpty() ? "" : cve.severity().toLowerCase();
                            String label = cve.severity().isEmpty()
                                ? escapeHtml(cve.id())
                                : escapeHtml(cve.id()) + " (" + cve.severity() + ")";
                            categoryBadges.append(String.format(
                                " <span class=\"cve-badge %s\"><a href=\"%s\" target=\"_blank\">%s</a></span>",
                                severityClass,
                                escapeHtml(cve.link()),
                                label
                            ));
                        }
                    }
                }

                if (categoryBadges.length() > 0) {
                    String badgeBlock = "\n<div class=\"category-cves\">" + categoryBadges + "</div>";
                    content = content.replace(headerTag, headerTag + badgeBlock);
                }
            }

            Files.writeString(htmlFile, content, StandardCharsets.UTF_8);
            log.info("Augmented {} with CVE badges.", htmlFile.getFileName());

        } catch (IOException e) {
            log.warn("Could not augment {} with CVE data: {}", htmlFile.getFileName(), e.getMessage());
        }
    }

    /**
     * Adds "unaudited capability" badges to sensitive API entries in the reachable
     * report where the dependency has no CVE covering that API's category. This
     * highlights gaps in CVE coverage for code paths that are actually reachable
     * from the client project.
     */
    private void addUnauditedBadges(Path htmlFile, List<DependencyReport> reports,
                                     Map<String, List<CveResult>> cveResults) {
        if (!Files.exists(htmlFile)) return;

        log.info("Adding unaudited capability badges to {}...", htmlFile.getFileName());

        try {
            String content = Files.readString(htmlFile, StandardCharsets.UTF_8);

            // Build all replacements first, then apply them in one pass.
            // This avoids O(n * html_size) repeated string scans.
            Map<String, String> replacements = new LinkedHashMap<>();

            for (DependencyReport dep : reports) {
                List<CveResult> depCves = cveResults.getOrDefault(dep.gav(), List.of());

                Set<String> coveredCategories = new HashSet<>();
                for (CveResult cve : depCves) {
                    if (cve.categories() != null) {
                        coveredCategories.addAll(cve.categories());
                    }
                }

                Set<String> processed = new HashSet<>();
                for (SensitiveApiEntry entry : dep.getSensitiveApis()) {
                    String category = entry.category();
                    String subcategory = entry.subcategory();
                    if (category == null || category.isBlank()) continue;
                    if (coveredCategories.contains(category)) continue;
                    if (!processed.add(entry.sensitiveApi())) continue;

                    List<Integer> cwes = CweCategoryMapper.cwesForSubcategory(subcategory);
                    if (cwes.isEmpty()) continue;

                    String cweLabel = "CWE-" + cwes.get(0);
                    String tooltip = CweCategoryMapper.capabilityDescription(category, subcategory);
                    String badge = " <span class=\"unaudited-badge\" title=\""
                        + escapeHtml(tooltip) + "\">" + cweLabel + "</span>";

                    String apiMarker = "<summary>" + escapeHtml(entry.sensitiveApi());
                    replacements.putIfAbsent(apiMarker, apiMarker + badge);
                }
            }

            for (Map.Entry<String, String> r : replacements.entrySet()) {
                if (content.contains(r.getKey()) && !content.contains(r.getValue())) {
                    content = content.replace(r.getKey(), r.getValue());
                }
            }

            Files.writeString(htmlFile, content, StandardCharsets.UTF_8);
            log.info("Added {} unaudited badges to {}.", replacements.size(), htmlFile.getFileName());
        } catch (IOException e) {
            log.warn("Could not add unaudited badges to {}: {}", htmlFile.getFileName(), e.getMessage());
        }
    }

    /**
     * Escapes HTML special characters to prevent injection when we embed
     * user-controlled strings (like advisory IDs or URLs) into the report.
     */
    private static String escapeHtml(String text) {
        if (text == null) {
            return "";
        }
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;");
    }
}
