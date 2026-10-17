package io.github.chains_project.theo.static_analysis.report;

import io.github.chains_project.theo.static_analysis.model.ReachableSnapshot;
import io.github.chains_project.theo.static_analysis.model.ReachableSnapshot.ReachableApiRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Generates a history.html table showing the presence of reachable sensitive
 * APIs across snapshots. Each row is a dependency + API, each column is a
 * snapshot, and cells show D (direct) or I (indirect) with the dependency
 * version in parentheses.
 */
public class HistoryReportGenerator {

    private static final Logger log = LoggerFactory.getLogger(HistoryReportGenerator.class);
    private static final DateTimeFormatter DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneId.systemDefault());

    /**
     * Generates history.html from a list of snapshots (newest first).
     */
    public void generateReport(List<ReachableSnapshot> snapshots, Path reportDir) throws IOException {
        Files.createDirectories(reportDir);

        if (snapshots.isEmpty()) {
            log.info("No snapshots available for history report.");
            return;
        }

        // Reverse so columns go left (oldest) to right (newest)
        List<ReachableSnapshot> ordered = new ArrayList<>(snapshots);
        Collections.reverse(ordered);

        // Collect all unique dep+api combinations across all snapshots
        // Grouped by category -> depGa -> set of api names
        Map<String, Map<String, Set<String>>> grouped = new TreeMap<>();
        for (ReachableSnapshot snap : ordered) {
            for (ReachableApiRecord rec : snap.getReachableApis()) {
                String cat = (rec.category() == null || rec.category().isBlank()) ? "OTHER" : rec.category().toUpperCase();
                grouped.computeIfAbsent(cat, k -> new TreeMap<>())
                        .computeIfAbsent(rec.depGa(), k -> new TreeSet<>())
                        .add(rec.sensitiveApi());
            }
        }

        // Build lookup: for each snapshot, map "depGa::api" -> record
        List<Map<String, ReachableApiRecord>> snapshotLookups = new ArrayList<>();
        for (ReachableSnapshot snap : ordered) {
            Map<String, ReachableApiRecord> lookup = new HashMap<>();
            for (ReachableApiRecord rec : snap.getReachableApis()) {
                lookup.put(rec.depGa() + "::" + rec.sensitiveApi(), rec);
            }
            snapshotLookups.add(lookup);
        }

        StringBuilder content = new StringBuilder();

        content.append("<p class=\"stats\">").append(snapshots.size())
                .append(" snapshots, ").append(ordered.get(ordered.size() - 1).getLabel())
                .append(" (newest) to ").append(ordered.get(0).getLabel())
                .append(" (oldest)</p>\n");

        // Render one table per category
        List<String> categoryOrder = List.of("FILESYSTEM", "NETWORK", "PROCESS", "OTHER");
        for (String category : categoryOrder) {
            Map<String, Set<String>> depsInCategory = grouped.get(category);
            if (depsInCategory == null || depsInCategory.isEmpty()) continue;

            content.append("<h2 class=\"category-header\">").append(escapeHtml(category)).append("</h2>\n");
            content.append("<div class=\"table-wrapper\"><table class=\"history-table\">\n");

            // Header row: dependency | API | snapshot1 | snapshot2 | ...
            content.append("<thead><tr>");
            content.append("<th>Dependency</th><th>Sensitive API</th>");
            for (ReachableSnapshot snap : ordered) {
                String date = DATE_FORMAT.format(Instant.ofEpochMilli(snap.getTimestamp()));
                content.append("<th>").append(escapeHtml(snap.getLabel()))
                        .append("<br><span class=\"snapshot-date\">").append(date).append("</span></th>");
            }
            content.append("</tr></thead>\n");

            // Data rows
            content.append("<tbody>\n");
            for (Map.Entry<String, Set<String>> depEntry : depsInCategory.entrySet()) {
                String depGa = depEntry.getKey();
                Set<String> apis = depEntry.getValue();
                boolean firstApi = true;

                for (String api : apis) {
                    // Check if this row has changes across snapshots — the API is
                    // present in some but not others, or the access type differs.
                    String key = depGa + "::" + api;
                    boolean hasChanges = false;
                    if (snapshotLookups.size() > 1) {
                        boolean firstPresent = snapshotLookups.get(0).containsKey(key);
                        String firstType = firstPresent ? snapshotLookups.get(0).get(key).accessType() : null;
                        for (int si = 1; si < snapshotLookups.size(); si++) {
                            boolean present = snapshotLookups.get(si).containsKey(key);
                            String type = present ? snapshotLookups.get(si).get(key).accessType() : null;
                            if (present != firstPresent || !Objects.equals(type, firstType)) {
                                hasChanges = true;
                                break;
                            }
                        }
                    }

                    String rowClass = hasChanges ? " class=\"row-changed\"" : "";
                    content.append("<tr").append(rowClass).append(">");

                    if (firstApi) {
                        content.append("<td class=\"dep-cell\">").append(escapeHtml(depGa)).append("</td>");
                        firstApi = false;
                    } else {
                        content.append("<td class=\"dep-cell continuation\"></td>");
                    }

                    content.append("<td class=\"api-cell\">").append(escapeHtml(api)).append("</td>");

                    for (Map<String, ReachableApiRecord> lookup : snapshotLookups) {
                        ReachableApiRecord rec = lookup.get(key);
                        if (rec == null) {
                            content.append("<td class=\"empty-cell\"></td>");
                        } else {
                            String marker = "DIRECT".equals(rec.accessType()) ? "D" : "I";
                            String cssClass = "DIRECT".equals(rec.accessType()) ? "cell-direct" : "cell-indirect";
                            content.append("<td class=\"").append(cssClass).append("\">")
                                    .append(marker)
                                    .append(" <span class=\"dep-ver\">(").append(escapeHtml(rec.depVersion())).append(")</span>")
                                    .append("</td>");
                        }
                    }

                    content.append("</tr>\n");
                }
            }
            content.append("</tbody></table></div>\n");
        }

        String template = loadTemplate();
        String html = template
                .replace("{{TITLE}}", "Theo — history")
                .replace("{{GENERATED_AT}}", DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
                        .withZone(ZoneId.systemDefault()).format(Instant.now()))
                .replace("{{CONTENT}}", content.toString())
                .replace("{{FOOTER_NOTE}}", "D = direct access, I = indirect access. Version in parentheses.");

        Files.writeString(reportDir.resolve("history.html"), html, StandardCharsets.UTF_8);
        log.info("History report written to {}", reportDir.resolve("history.html"));
    }

    private String loadTemplate() throws IOException {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream("report-template.html")) {
            if (is == null) throw new IOException("report-template.html not found on classpath");
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }
}
