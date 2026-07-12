package io.github.chains_project.theo.package_miner;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.chains_project.theo.package_miner.model.VersionHistory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Generates an interactive HTML visualization of permission changes across package versions.
 *
 * The visualization includes:
 * - A summary table showing which packages had permission changes
 * - Per-package heatmap grids (versions x APIs) with direct/indirect distinction
 * - Highlighted cells where permissions were added or removed between versions
 */
public class VersionHistoryVisualizer {

    private static final Logger log = LoggerFactory.getLogger(VersionHistoryVisualizer.class);
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Reads all version-history JSON files from the output directory and generates
     * a single HTML report.
     */
    public void generateReport(Path outputDir) throws IOException {
        Path historyDir = outputDir.resolve("version-history");
        if (!Files.isDirectory(historyDir)) {
            log.info("No version-history directory found, skipping visualization.");
            return;
        }

        List<VersionHistory.PackageVersionHistory> allHistories = new ArrayList<>();
        try (Stream<Path> files = Files.list(historyDir)) {
            for (Path file : files.filter(f -> f.toString().endsWith("-history.json")).toList()) {
                try {
                    VersionHistory.PackageVersionHistory history = mapper.readValue(
                            file.toFile(), new TypeReference<>() {}
                    );
                    allHistories.add(history);
                } catch (IOException e) {
                    log.warn("Failed to read history file: {}", file, e);
                }
            }
        }

        if (allHistories.isEmpty()) {
            log.info("No version histories found to visualize.");
            return;
        }

        allHistories.sort(Comparator.comparing(
                (VersionHistory.PackageVersionHistory h) -> h.hasPermissionChanges() ? 0 : 1)
                .thenComparing(VersionHistory.PackageVersionHistory::groupId)
                .thenComparing(VersionHistory.PackageVersionHistory::artifactId));

        String html = buildHtml(allHistories);
        Path reportFile = outputDir.resolve("permission_changes_report.html");
        Files.writeString(reportFile, html);
        log.info("Version history visualization written to {}", reportFile);
    }

    private String buildHtml(List<VersionHistory.PackageVersionHistory> histories) {
        StringBuilder sb = new StringBuilder();
        sb.append("""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Sensitive API Permission Changes Across Versions</title>
                <style>
                  * { box-sizing: border-box; margin: 0; padding: 0; }
                  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                         background: #f5f6fa; color: #2d3436; padding: 24px; }
                  h1 { margin-bottom: 8px; }
                  .subtitle { color: #636e72; margin-bottom: 24px; }
                  .stats { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
                  .stat-card { background: #fff; border-radius: 8px; padding: 16px 24px;
                               box-shadow: 0 1px 3px rgba(0,0,0,0.1); min-width: 160px; }
                  .stat-card .number { font-size: 28px; font-weight: 700; }
                  .stat-card .label { font-size: 13px; color: #636e72; }
                  .stat-card.changed .number { color: #d63031; }
                  .stat-card.stable .number { color: #00b894; }
                  .filter-bar { margin-bottom: 20px; }
                  .filter-bar label { margin-right: 12px; cursor: pointer; }
                  .summary-table { width: 100%; border-collapse: collapse; background: #fff;
                                   border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                                   margin-bottom: 32px; }
                  .summary-table th { background: #2d3436; color: #fff; padding: 10px 14px;
                                      text-align: left; font-size: 13px; }
                  .summary-table td { padding: 8px 14px; border-bottom: 1px solid #eee; font-size: 13px; }
                  .summary-table tr:hover { background: #f0f0f0; }
                  .badge { display: inline-block; padding: 2px 8px; border-radius: 10px;
                           font-size: 11px; font-weight: 600; }
                  .badge.changed { background: #ffeaa7; color: #d63031; }
                  .badge.stable { background: #dfe6e9; color: #636e72; }
                  .badge.added { background: #55efc4; color: #00695c; }
                  .badge.removed { background: #fab1a0; color: #c0392b; }
                  .pkg-section { background: #fff; border-radius: 8px; padding: 20px;
                                 margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
                  .pkg-section h3 { margin-bottom: 4px; }
                  .pkg-section .coord { color: #636e72; font-size: 13px; margin-bottom: 12px; }
                  .heatmap { overflow-x: auto; }
                  .heatmap table { border-collapse: collapse; font-size: 12px; }
                  .heatmap th, .heatmap td { padding: 4px 6px; border: 1px solid #dfe6e9;
                                              white-space: nowrap; text-align: center; }
                  .heatmap th { background: #f5f6fa; font-weight: 600; }
                  .heatmap th.version-header { writing-mode: vertical-rl; text-orientation: mixed;
                                                min-width: 32px; }
                  .heatmap td.direct { background: #0984e3; color: #fff; }
                  .heatmap td.indirect { background: #74b9ff; color: #fff; }
                  .heatmap td.none { background: #f5f6fa; color: #b2bec3; }
                  .heatmap td.added-direct { background: #d63031; color: #fff; font-weight: 700; }
                  .heatmap td.added-indirect { background: #e17055; color: #fff; font-weight: 700; }
                  .heatmap td.removed { background: #ffeaa7; color: #636e72;
                                         text-decoration: line-through; }
                  .change-log { margin-top: 12px; font-size: 13px; }
                  .change-log .change-entry { padding: 6px 0; border-bottom: 1px solid #eee; }
                  .change-log .change-entry:last-child { border-bottom: none; }
                  .legend { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px; font-size: 12px; }
                  .legend-item { display: flex; align-items: center; gap: 4px; }
                  .legend-swatch { width: 16px; height: 16px; border-radius: 3px; border: 1px solid #dfe6e9; }
                  .collapsible { cursor: pointer; user-select: none; }
                  .collapsible::before { content: '\\25BC '; font-size: 10px; }
                  .collapsible.collapsed::before { content: '\\25B6 '; }
                  .collapse-content { overflow: hidden; }
                  .collapse-content.hidden { display: none; }
                  a { color: #0984e3; text-decoration: none; }
                  a:hover { text-decoration: underline; }
                </style>
                </head>
                <body>
                <h1>Sensitive API Permission Changes</h1>
                <p class="subtitle">Tracking how packages' sensitive API usage evolves across versions</p>
                """);

        long changedCount = histories.stream().filter(VersionHistory.PackageVersionHistory::hasPermissionChanges).count();
        long stableCount = histories.size() - changedCount;
        long totalVersions = histories.stream().mapToLong(h -> h.snapshots().size()).sum();

        sb.append("<div class=\"stats\">\n");
        sb.append(statCard("Total Packages", String.valueOf(histories.size()), ""));
        sb.append(statCard("With Changes", String.valueOf(changedCount), "changed"));
        sb.append(statCard("Stable", String.valueOf(stableCount), "stable"));
        sb.append(statCard("Total Versions Analyzed", String.valueOf(totalVersions), ""));
        sb.append("</div>\n");

        sb.append("""
                <div class="legend">
                  <div class="legend-item"><div class="legend-swatch" style="background:#0984e3"></div> Direct access</div>
                  <div class="legend-item"><div class="legend-swatch" style="background:#74b9ff"></div> Indirect access</div>
                  <div class="legend-item"><div class="legend-swatch" style="background:#d63031"></div> Newly added (direct)</div>
                  <div class="legend-item"><div class="legend-swatch" style="background:#e17055"></div> Newly added (indirect)</div>
                  <div class="legend-item"><div class="legend-swatch" style="background:#ffeaa7"></div> Removed</div>
                  <div class="legend-item"><div class="legend-swatch" style="background:#f5f6fa;border:1px solid #dfe6e9"></div> Not used</div>
                </div>
                """);

        // Summary table
        sb.append("<table class=\"summary-table\">\n");
        sb.append("<tr><th>#</th><th>Package</th><th>Versions</th><th>Status</th><th>Changes</th></tr>\n");
        int idx = 0;
        for (VersionHistory.PackageVersionHistory h : histories) {
            idx++;
            String status = h.hasPermissionChanges()
                    ? "<span class=\"badge changed\">CHANGED</span>"
                    : "<span class=\"badge stable\">STABLE</span>";
            long changeCount = h.changes().stream().filter(VersionHistory.PermissionChange::hasChanges).count();
            String changeText = changeCount > 0
                    ? changeCount + " version transition" + (changeCount > 1 ? "s" : "")
                    : "-";
            sb.append(String.format("<tr><td>%d</td><td><a href=\"#pkg-%d\">%s:%s</a></td><td>%d</td><td>%s</td><td>%s</td></tr>\n",
                    idx, idx, h.groupId(), h.artifactId(), h.snapshots().size(), status, changeText));
        }
        sb.append("</table>\n");

        // Per-package detail sections
        idx = 0;
        for (VersionHistory.PackageVersionHistory h : histories) {
            idx++;
            sb.append(String.format("<div class=\"pkg-section\" id=\"pkg-%d\">\n", idx));
            sb.append(String.format("<h3 class=\"collapsible\" onclick=\"toggleCollapse(this)\">%s:%s</h3>\n",
                    escapeHtml(h.groupId()), escapeHtml(h.artifactId())));
            sb.append(String.format("<div class=\"coord\">%d versions analyzed | %s</div>\n",
                    h.snapshots().size(),
                    h.hasPermissionChanges() ? "Permission changes detected" : "No permission changes"));
            sb.append("<div class=\"collapse-content\">\n");

            buildHeatmap(sb, h);
            buildChangeLog(sb, h);

            sb.append("</div></div>\n");
        }

        sb.append("""
                <script>
                function toggleCollapse(el) {
                  el.classList.toggle('collapsed');
                  el.parentElement.querySelector('.collapse-content').classList.toggle('hidden');
                }
                </script>
                </body>
                </html>
                """);
        return sb.toString();
    }

    private void buildHeatmap(StringBuilder sb, VersionHistory.PackageVersionHistory history) {
        if (history.snapshots().isEmpty()) return;

        Set<String> allApis = new TreeSet<>();
        for (VersionHistory.VersionSnapshot snap : history.snapshots()) {
            allApis.addAll(snap.directApis());
            allApis.addAll(snap.indirectApis());
        }
        if (allApis.isEmpty()) return;

        // Build change sets for highlighting
        Map<String, VersionHistory.PermissionChange> changeByToVersion = new HashMap<>();
        for (VersionHistory.PermissionChange c : history.changes()) {
            changeByToVersion.put(c.toVersion(), c);
        }

        sb.append("<div class=\"heatmap\"><table>\n<tr><th>Sensitive API</th>");
        for (VersionHistory.VersionSnapshot snap : history.snapshots()) {
            sb.append(String.format("<th class=\"version-header\">%s</th>", escapeHtml(snap.version())));
        }
        sb.append("</tr>\n");

        for (String api : allApis) {
            sb.append(String.format("<tr><td style=\"text-align:left\">%s</td>", escapeHtml(api)));
            for (VersionHistory.VersionSnapshot snap : history.snapshots()) {
                boolean isDirect = snap.directApis().contains(api);
                boolean isIndirect = snap.indirectApis().contains(api);
                VersionHistory.PermissionChange change = changeByToVersion.get(snap.version());

                String cssClass;
                String text;
                if (change != null && change.addedDirect().contains(api)) {
                    cssClass = "added-direct";
                    text = "+D";
                } else if (change != null && change.addedIndirect().contains(api)) {
                    cssClass = "added-indirect";
                    text = "+I";
                } else if (change != null && (change.removedDirect().contains(api) || change.removedIndirect().contains(api))) {
                    cssClass = "removed";
                    text = "-";
                } else if (isDirect) {
                    cssClass = "direct";
                    text = "D";
                } else if (isIndirect) {
                    cssClass = "indirect";
                    text = "I";
                } else {
                    cssClass = "none";
                    text = "";
                }
                sb.append(String.format("<td class=\"%s\" title=\"%s @ %s\">%s</td>",
                        cssClass, escapeHtml(api), escapeHtml(snap.version()), text));
            }
            sb.append("</tr>\n");
        }
        sb.append("</table></div>\n");
    }

    private void buildChangeLog(StringBuilder sb, VersionHistory.PackageVersionHistory history) {
        List<VersionHistory.PermissionChange> significantChanges = history.changes().stream()
                .filter(VersionHistory.PermissionChange::hasChanges)
                .toList();

        if (significantChanges.isEmpty()) return;

        sb.append("<div class=\"change-log\">\n<h4>Change Log</h4>\n");
        for (VersionHistory.PermissionChange c : significantChanges) {
            sb.append(String.format("<div class=\"change-entry\"><strong>%s &rarr; %s</strong><br>",
                    escapeHtml(c.fromVersion()), escapeHtml(c.toVersion())));
            for (String api : c.addedDirect()) {
                sb.append(String.format("<span class=\"badge added\">+ %s (direct)</span> ", escapeHtml(api)));
            }
            for (String api : c.addedIndirect()) {
                sb.append(String.format("<span class=\"badge added\">+ %s (indirect)</span> ", escapeHtml(api)));
            }
            for (String api : c.removedDirect()) {
                sb.append(String.format("<span class=\"badge removed\">- %s (direct)</span> ", escapeHtml(api)));
            }
            for (String api : c.removedIndirect()) {
                sb.append(String.format("<span class=\"badge removed\">- %s (indirect)</span> ", escapeHtml(api)));
            }
            sb.append("</div>\n");
        }
        sb.append("</div>\n");
    }

    private String statCard(String label, String number, String cssClass) {
        return String.format(
                "<div class=\"stat-card %s\"><div class=\"number\">%s</div><div class=\"label\">%s</div></div>\n",
                cssClass, number, label);
    }

    private String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
