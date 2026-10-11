package io.github.chains_project.theo.static_analysis.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.chains_project.theo.static_analysis.model.*;
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
 * Generates three HTML reports from the analysis results using a simple
 * template with placeholder replacement. No template engine dependency —
 * the reports are straightforward enough that string building works fine.
 */
public class HtmlReportGenerator {

    private static final Logger log = LoggerFactory.getLogger(HtmlReportGenerator.class);
    private static final DateTimeFormatter TIMESTAMP_FORMAT =
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());

    public HtmlReportGenerator() {
    }

    /**
     * Generates all three HTML reports.
     */
    public void generateReports(AnalysisSummary summary, ChangeSet changeSet, Path reportDir) throws IOException {
        generateReports(summary, changeSet, reportDir, false, null);
    }

    public void generateReports(AnalysisSummary summary, ChangeSet changeSet,
                                Path reportDir, boolean reachableOnly) throws IOException {
        generateReports(summary, changeSet, reportDir, reachableOnly, null);
    }

    /**
     * @param previousSummary the previous analysis run, used to check whether removed
     *                        APIs were reachable before. Null on first run.
     */
    public void generateReports(AnalysisSummary summary, ChangeSet changeSet,
                                Path reportDir, boolean reachableOnly,
                                AnalysisSummary previousSummary) throws IOException {
        Files.createDirectories(reportDir);

        String template = loadTemplate();

        generateReachableReport(summary, template, reportDir);
        generateChangesReport(summary, changeSet, template, reportDir, reachableOnly, previousSummary);

        if (!reachableOnly) {
            generateAllDependenciesReport(summary, template, reportDir);
        }

        writeStatsJson(summary, changeSet, reportDir, reachableOnly);
        log.info("Reports written to {}", reportDir);
    }

    private String loadTemplate() throws IOException {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream("report-template.html")) {
            if (is == null) throw new IOException("report-template.html not found on classpath");
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private String renderTemplate(String template, String title, String content, String footerNote) {
        return template
            .replace("{{TITLE}}", escapeHtml(title))
            .replace("{{GENERATED_AT}}", TIMESTAMP_FORMAT.format(Instant.now()))
            .replace("{{CONTENT}}", content)
            .replace("{{FOOTER_NOTE}}", footerNote != null ? escapeHtml(footerNote) : "");
    }

    // --- all-dependencies.html ---

    /** The fixed order in which categories appear in reports. */
    private static final List<String> CATEGORY_ORDER = List.of("FILESYSTEM", "NETWORK", "PROCESS", "OTHER");

    private void generateAllDependenciesReport(AnalysisSummary summary, String template, Path reportDir) throws IOException {
        StringBuilder content = new StringBuilder();

        int totalDeps = summary.getDependencyReports().size();
        int withApis = (int) summary.getDependencyReports().stream()
            .filter(DependencyReport::hasSensitiveApis).count();
        content.append("<p class=\"stats\">").append(totalDeps)
            .append(" dependencies analyzed, ").append(withApis)
            .append(" with sensitive API access</p>\n");

        Map<String, DependencyReport> reportsByGav = indexByGav(summary.getDependencyReports());

        // category -> subcategory -> depGav -> (apiName -> accessType)
        Map<String, Map<String, Map<String, Map<String, String>>>> grouped = new LinkedHashMap<>();
        for (String cat : CATEGORY_ORDER) {
            grouped.put(cat, new TreeMap<>());
        }

        // Per-category stats: deps with direct vs indirect access
        Map<String, Set<String>> directDepsByCategory = new LinkedHashMap<>();
        Map<String, Set<String>> indirectDepsByCategory = new LinkedHashMap<>();
        for (String cat : CATEGORY_ORDER) {
            directDepsByCategory.put(cat, new HashSet<>());
            indirectDepsByCategory.put(cat, new HashSet<>());
        }

        for (DependencyReport dep : summary.getDependencyReports()) {
            if (!dep.hasSensitiveApis()) continue;
            for (SensitiveApiEntry entry : dep.getSensitiveApis()) {
                String cat = (entry.category() == null || entry.category().isBlank()) ? "OTHER" : entry.category().toUpperCase();
                String sub = (entry.subcategory() == null || entry.subcategory().isBlank()) ? "General" : entry.subcategory();
                grouped.computeIfAbsent(cat, k -> new TreeMap<>())
                    .computeIfAbsent(sub, k -> new TreeMap<>())
                    .computeIfAbsent(dep.gav(), k -> new TreeMap<>())
                    .putIfAbsent(entry.sensitiveApi(), entry.accessType());

                if ("DIRECT".equals(entry.accessType())) {
                    directDepsByCategory.computeIfAbsent(cat, k -> new HashSet<>()).add(dep.gav());
                } else {
                    indirectDepsByCategory.computeIfAbsent(cat, k -> new HashSet<>()).add(dep.gav());
                }
            }
        }

        buildAllDepsStatsTable(content, directDepsByCategory, indirectDepsByCategory);

        for (String category : CATEGORY_ORDER) {
            Map<String, Map<String, Map<String, String>>> subcategories = grouped.get(category);
            if (subcategories == null || subcategories.isEmpty()) continue;

            content.append("<h2 class=\"category-header\">").append(escapeHtml(category)).append("</h2>\n");

            for (Map.Entry<String, Map<String, Map<String, String>>> subEntry : subcategories.entrySet()) {
                content.append("<h3 class=\"subcategory-header\">").append(escapeHtml(subEntry.getKey())).append("</h3>\n");

                for (Map.Entry<String, Map<String, String>> depEntry : subEntry.getValue().entrySet()) {
                    String gav = depEntry.getKey();
                    Map<String, String> apis = depEntry.getValue();

                    boolean isReachable = apis.keySet().stream().anyMatch(api -> summary.isReachable(gav, api));
                    String reachableClass = isReachable ? " reachable" : "";

                    content.append("<details class=\"dependency").append(reachableClass).append("\">\n");
                    content.append("  <summary><span class=\"dep-gav\">").append(escapeHtml(gav))
                        .append("</span>").append(depMetaHtml(reportsByGav.get(gav)))
                        .append(" <span class=\"count\">(").append(apis.size())
                        .append(" sensitive APIs)</span></summary>\n");

                    content.append("  <ul class=\"api-list\">\n");
                    for (Map.Entry<String, String> api : apis.entrySet()) {
                        boolean apiReachable = summary.isReachable(gav, api.getKey());
                        String apiClass = apiReachable ? " class=\"reachable\"" : "";
                        content.append("    <li").append(apiClass).append(">")
                            .append(escapeHtml(api.getKey()));
                        content.append(accessTypeSpan(api.getValue()));
                        content.append("</li>\n");
                    }
                    content.append("  </ul>\n");
                    content.append("</details>\n");
                }
            }
        }

        String html = renderTemplate(template, "Theo — all dependencies", content.toString(),
            "For full call paths, see reachable.html.");
        Files.writeString(reportDir.resolve("all-dependencies.html"), html, StandardCharsets.UTF_8);
    }

    // --- reachable.html ---

    private void generateReachableReport(AnalysisSummary summary, String template, Path reportDir) throws IOException {
        StringBuilder content = new StringBuilder();

        List<DependencyReport> reachableDeps = summary.getDependencyReports().stream()
            .filter(dep -> dep.getSensitiveApis().stream()
                .anyMatch(api -> summary.isReachable(dep.gav(), api.sensitiveApi())))
            .sorted(Comparator.comparing(DependencyReport::gav))
            .toList();

        Map<String, DependencyReport> reportsByGav = indexByGav(reachableDeps);

        content.append("<p class=\"stats\">").append(reachableDeps.size())
            .append(" dependencies with client-reachable sensitive APIs</p>\n");

        // Group: category -> subcategory -> depGav -> list of reachable entries
        Map<String, Map<String, Map<String, List<SensitiveApiEntry>>>> grouped = new LinkedHashMap<>();
        for (String cat : CATEGORY_ORDER) {
            grouped.put(cat, new TreeMap<>());
        }

        // Per-category stats: unique API names and unique dep GAVs
        Map<String, Set<String>> apisByCategory = new LinkedHashMap<>();
        Map<String, Set<String>> depsByCategory = new LinkedHashMap<>();
        for (String cat : CATEGORY_ORDER) {
            apisByCategory.put(cat, new HashSet<>());
            depsByCategory.put(cat, new HashSet<>());
        }

        for (DependencyReport dep : reachableDeps) {
            for (SensitiveApiEntry entry : dep.getSensitiveApis()) {
                if (!summary.isReachable(dep.gav(), entry.sensitiveApi())) continue;
                String cat = (entry.category() == null || entry.category().isBlank()) ? "OTHER" : entry.category().toUpperCase();
                String sub = (entry.subcategory() == null || entry.subcategory().isBlank()) ? "General" : entry.subcategory();
                grouped.computeIfAbsent(cat, k -> new TreeMap<>())
                    .computeIfAbsent(sub, k -> new TreeMap<>())
                    .computeIfAbsent(dep.gav(), k -> new ArrayList<>())
                    .add(entry);
                apisByCategory.computeIfAbsent(cat, k -> new HashSet<>()).add(entry.sensitiveApi());
                depsByCategory.computeIfAbsent(cat, k -> new HashSet<>()).add(dep.gav());
            }
        }

        buildCategoryStatsTable(content, apisByCategory, depsByCategory);

        for (String category : CATEGORY_ORDER) {
            Map<String, Map<String, List<SensitiveApiEntry>>> subcategories = grouped.get(category);
            if (subcategories == null || subcategories.isEmpty()) continue;

            content.append("<h2 class=\"category-header\">").append(escapeHtml(category)).append("</h2>\n");

            for (Map.Entry<String, Map<String, List<SensitiveApiEntry>>> subEntry : subcategories.entrySet()) {
                content.append("<h3 class=\"subcategory-header\">").append(escapeHtml(subEntry.getKey())).append("</h3>\n");

                for (Map.Entry<String, List<SensitiveApiEntry>> depEntry : subEntry.getValue().entrySet()) {
                    String gav = depEntry.getKey();
                    DependencyReport dep = reachableDeps.stream()
                        .filter(d -> d.gav().equals(gav)).findFirst().orElse(null);
                    if (dep == null) continue;

                    content.append("<details class=\"dependency reachable\">\n");
                    content.append("  <summary><span class=\"dep-gav\">").append(escapeHtml(gav))
                        .append("</span>").append(depMetaHtml(dep)).append("</summary>\n");

                    Map<String, List<SensitiveApiEntry>> byApi = groupBySensitiveApi(depEntry.getValue());
                    for (Map.Entry<String, List<SensitiveApiEntry>> apiGroup : byApi.entrySet()) {
                        content.append("  <details class=\"sensitive-api reachable\">\n");
                        content.append("    <summary>").append(escapeHtml(apiGroup.getKey()));
                        if (!apiGroup.getValue().isEmpty()) {
                            content.append(accessTypeSpan(apiGroup.getValue().get(0).accessType()));
                        }
                        content.append("</summary>\n");

                        for (SensitiveApiEntry apiEntry : apiGroup.getValue()) {
                            buildPathDetails(content, apiEntry);
                        }
                        content.append("  </details>\n");
                    }

                    content.append("</details>\n");
                }
            }
        }

        String html = renderTemplate(template, "Theo — client-reachable APIs", content.toString(),
            null);
        Files.writeString(reportDir.resolve("reachable.html"), html, StandardCharsets.UTF_8);
    }

    // --- changes.html ---

    private void generateChangesReport(AnalysisSummary summary, ChangeSet changeSet,
                                       String template, Path reportDir, boolean reachableOnly,
                                       AnalysisSummary previousSummary) throws IOException {
        StringBuilder content = new StringBuilder();

        if (!changeSet.hasPreviousRun()) {
            content.append("<p class=\"stats\">First analysis run — no previous data to compare against.</p>\n");
        } else if (!changeSet.hasChanges()) {
            content.append("<p class=\"stats\">No changes detected since the last run.</p>\n");
        } else if (reachableOnly) {
            content.append("<div class=\"reachable-section\">\n");
            content.append("<h2>Changes to client-reachable APIs</h2>\n");
            buildChangesSection(content, changeSet, summary, true, previousSummary);
            content.append("</div>\n");
        } else {
            content.append("<h2>Changes across all dependencies</h2>\n");
            buildChangesSection(content, changeSet, summary, false, previousSummary);

            content.append("<div class=\"reachable-section\">\n");
            content.append("<h2>Changes to client-reachable APIs</h2>\n");
            buildChangesSection(content, changeSet, summary, true, previousSummary);
            content.append("</div>\n");
        }

        String html = renderTemplate(template, "Theo — changes since last run", content.toString(), null);
        Files.writeString(reportDir.resolve("changes.html"), html, StandardCharsets.UTF_8);
    }

    private void buildChangesSection(StringBuilder content, ChangeSet changeSet,
                                     AnalysisSummary summary, boolean onlyReachable,
                                     AnalysisSummary previousSummary) {
        // Collect per-category stats before rendering the details
        Map<String, Integer> addedByCategory = new LinkedHashMap<>();
        Map<String, Integer> removedByCategory = new LinkedHashMap<>();
        Map<String, Set<String>> changedDepsByCategory = new LinkedHashMap<>();
        collectChangesStats(changeSet, summary, onlyReachable, previousSummary,
            addedByCategory, removedByCategory, changedDepsByCategory);
        buildChangesStatsTable(content, addedByCategory, removedByCategory, changedDepsByCategory);

        boolean anyChanges = false;

        // Version-changed dependencies first — these are the most important changes
        List<ChangeSet.DependencyChange> versionChanged = changeSet.getModifiedDependencies().stream()
            .filter(m -> !m.oldVersion().equals(m.newVersion()))
            .toList();
        List<ChangeSet.DependencyChange> sameVersion = changeSet.getModifiedDependencies().stream()
            .filter(m -> m.oldVersion().equals(m.newVersion()))
            .toList();

        for (ChangeSet.DependencyChange mod : versionChanged) {
            anyChanges |= renderModifiedDep(content, mod, summary, onlyReachable, true, previousSummary);
        }

        // Then same-version modifications (snapshot rebuilds, analyzer updates, etc.)
        for (ChangeSet.DependencyChange mod : sameVersion) {
            anyChanges |= renderModifiedDep(content, mod, summary, onlyReachable, false, previousSummary);
        }

        // Added dependencies
        for (DependencyReport added : changeSet.getAddedDependencies()) {
            List<SensitiveApiEntry> apis = onlyReachable
                ? added.getSensitiveApis().stream()
                    .filter(a -> summary.isReachable(added.gav(), a.sensitiveApi())).toList()
                : added.getSensitiveApis();
            if (apis.isEmpty() && onlyReachable) continue;

            anyChanges = true;
            content.append("<details class=\"dependency added\">\n");
            content.append("  <summary><span class=\"change-marker\">+</span> <span class=\"dep-gav\">")
                .append(escapeHtml(added.gav())).append("</span>")
                .append(depMetaHtml(added))
                .append(" (new)</summary>\n");
            buildCategorizedApiList(content, apis, "", onlyReachable && summary.hasReachableEntries());
            content.append("</details>\n");
        }

        // Removed dependencies — in reachable mode, only show if they had
        // reachable APIs in the previous run
        for (DependencyReport removed : changeSet.getRemovedDependencies()) {
            if (onlyReachable) {
                if (previousSummary == null) continue;
                boolean wasReachable = removed.getSensitiveApis().stream()
                    .anyMatch(a -> previousSummary.isReachable(removed.gav(), a.sensitiveApi()));
                if (!wasReachable) continue;
            }

            anyChanges = true;
            content.append("<details class=\"dependency removed\">\n");
            content.append("  <summary><span class=\"change-marker\">-</span> <span class=\"dep-gav\">")
                .append(escapeHtml(removed.gav())).append("</span>")
                .append(depMetaHtml(removed))
                .append(" (removed)</summary>\n");
            content.append("</details>\n");
        }

        if (!anyChanges) {
            content.append("<p class=\"no-changes\">No changes in this category.</p>\n");
        }
    }

    private boolean renderModifiedDep(StringBuilder content, ChangeSet.DependencyChange mod,
                                       AnalysisSummary summary, boolean onlyReachable,
                                       boolean versionChanged, AnalysisSummary previousSummary) {
        List<SensitiveApiEntry> addedApis = onlyReachable
            ? mod.addedApis().stream()
                .filter(a -> summary.isReachable(mod.gav(), a.sensitiveApi())).toList()
            : mod.addedApis();
        // Removed APIs can't be checked against the current reachable set (they
        // no longer exist). In reachable mode, check the previous run's
        // reachability data instead — only show APIs that were actually reachable.
        List<SensitiveApiEntry> removedApis;
        if (onlyReachable && previousSummary != null) {
            String prevGav = mod.groupId() + ":" + mod.artifactId() + ":" + mod.oldVersion();
            removedApis = mod.removedApis().stream()
                .filter(a -> previousSummary.isReachable(prevGav, a.sensitiveApi()))
                .toList();
        } else {
            removedApis = mod.removedApis();
        }

        if (addedApis.isEmpty() && removedApis.isEmpty()) return false;

        String depClass = versionChanged ? "dependency modified version-changed" : "dependency modified";
        String versionLabel = versionChanged
            ? " (" + mod.oldVersion() + " → " + mod.newVersion() + ")"
            : "";

        // Look up scope/depth from the current summary
        DependencyReport depReport = summary.getDependencyReports().stream()
            .filter(d -> d.getGroupId().equals(mod.groupId()) && d.getArtifactId().equals(mod.artifactId()))
            .findFirst().orElse(null);

        content.append("<details class=\"").append(depClass).append("\">\n");
        content.append("  <summary><span class=\"change-marker\">~</span> <span class=\"dep-gav\">")
            .append(escapeHtml(mod.gav())).append("</span>");
        if (depReport != null) {
            content.append(depMetaHtml(depReport));
        }
        content.append(escapeHtml(versionLabel)).append("</summary>\n");

        if (!addedApis.isEmpty()) {
            content.append("    <h3>Added</h3>\n");
            buildCategorizedApiList(content, addedApis, "+ ", onlyReachable && summary.hasReachableEntries());
        }
        if (!removedApis.isEmpty()) {
            // Removed APIs come from the previous run's per-dep data, so they
            // don't have client-rooted paths. Show them as a flat list.
            content.append("    <h3>Removed</h3>\n");
            buildCategorizedApiList(content, removedApis, "- ", false);
        }
        content.append("</details>\n");
        return true;
    }

    /**
     * Renders a deduplicated list of APIs grouped by category and subcategory.
     * Used in the changes report for the "all changes" section.
     */
    private void buildCategorizedApiList(StringBuilder content, List<SensitiveApiEntry> apis, String prefix) {
        buildCategorizedApiList(content, apis, prefix, false);
    }

    /**
     * Renders a deduplicated list of APIs grouped by category and subcategory.
     * When showPaths is true, each API gets expandable path details —
     * used in the changes report for reachable APIs.
     */
    private void buildCategorizedApiList(StringBuilder content, List<SensitiveApiEntry> apis,
                                         String prefix, boolean showPaths) {
        // category -> subcategory -> list of entries (deduplicated by API name)
        Map<String, Map<String, List<SensitiveApiEntry>>> grouped = new TreeMap<>();
        Set<String> seen = new HashSet<>();
        for (SensitiveApiEntry entry : apis) {
            if (!seen.add(entry.sensitiveApi())) continue;
            String cat = (entry.category() == null || entry.category().isBlank()) ? "OTHER" : entry.category().toUpperCase();
            String sub = (entry.subcategory() == null || entry.subcategory().isBlank()) ? "General" : entry.subcategory();
            grouped.computeIfAbsent(cat, k -> new TreeMap<>())
                .computeIfAbsent(sub, k -> new ArrayList<>())
                .add(entry);
        }

        for (Map.Entry<String, Map<String, List<SensitiveApiEntry>>> catEntry : grouped.entrySet()) {
            content.append("    <h3 class=\"subcategory-header\">").append(escapeHtml(catEntry.getKey())).append("</h3>\n");
            for (Map.Entry<String, List<SensitiveApiEntry>> subEntry : catEntry.getValue().entrySet()) {
                content.append("    <h3 class=\"subcategory-header\" style=\"margin-left:16px\">").append(escapeHtml(subEntry.getKey())).append("</h3>\n");

                for (SensitiveApiEntry entry : subEntry.getValue()) {
                    String changeType = prefix.startsWith("+") ? " added" : prefix.startsWith("-") ? " removed" : "";

                    if (showPaths) {
                        content.append("    <details class=\"sensitive-api").append(changeType).append("\">\n");
                        content.append("      <summary>").append(escapeHtml(prefix))
                            .append(escapeHtml(entry.sensitiveApi()))
                            .append(accessTypeSpan(entry.accessType()))
                            .append("</summary>\n");
                        buildPathDetails(content, entry);
                        content.append("    </details>\n");
                    } else {
                        content.append("    <div class=\"api-entry").append(changeType)
                            .append("\">").append(escapeHtml(prefix)).append(escapeHtml(entry.sensitiveApi()))
                            .append(accessTypeSpan(entry.accessType()))
                            .append("</div>\n");
                    }
                }
            }
        }
    }

    // --- Shared helpers ---

    /**
     * Builds the expandable call path for a single sensitive API entry.
     */
    private void buildPathDetails(StringBuilder content, SensitiveApiEntry entry) {
        content.append("    <details class=\"call-path\">\n");

        String pathSummary = entry.fullPath().isEmpty() ? entry.entryPoint() + " → " + entry.sensitiveApi()
            : entry.fullPath().get(0) + " → ... → " + entry.fullPath().get(entry.fullPath().size() - 1);
        content.append("      <summary>").append(escapeHtml(pathSummary)).append("</summary>\n");

        if (!entry.fullPath().isEmpty()) {
            content.append("      <ol class=\"path-list\">\n");
            for (String step : entry.fullPath()) {
                content.append("        <li>").append(escapeHtml(step)).append("</li>\n");
            }
            content.append("      </ol>\n");
        }

        content.append("    </details>\n");
    }

    private Map<String, List<SensitiveApiEntry>> groupBySensitiveApi(List<SensitiveApiEntry> entries) {
        Map<String, List<SensitiveApiEntry>> grouped = new TreeMap<>();
        for (SensitiveApiEntry entry : entries) {
            grouped.computeIfAbsent(entry.sensitiveApi(), k -> new ArrayList<>()).add(entry);
        }
        return grouped;
    }

    /**
     * Builds a lookup map from GAV string to DependencyReport for quick access
     * to metadata like scope and depth when rendering.
     */
    private Map<String, DependencyReport> indexByGav(List<DependencyReport> reports) {
        Map<String, DependencyReport> index = new HashMap<>();
        for (DependencyReport r : reports) {
            index.put(r.gav(), r);
        }
        return index;
    }

    /**
     * Renders scope and depth labels for a dependency. Returns an HTML string
     * like ' <span class="dep-meta">compile, depth 2</span>'.
     */
    private String depMetaHtml(DependencyReport dep) {
        if (dep == null) return "";
        StringBuilder sb = new StringBuilder();
        List<String> parts = new ArrayList<>();
        if (dep.getScope() != null && !dep.getScope().isEmpty()) {
            parts.add(dep.getScope());
        }
        if (dep.getDependencyDepth() > 0) {
            parts.add(dep.getDependencyDepth() == 1 ? "direct" : "depth " + dep.getDependencyDepth());
        }
        if (!parts.isEmpty()) {
            sb.append(" <span class=\"dep-meta\">").append(String.join(", ", parts)).append("</span>");
        }
        return sb.toString();
    }

    /**
     * Counts added/removed APIs and affected deps per category for the changes stats table.
     * Uses the same filtering logic as buildChangesSection so the numbers match the report.
     */
    private void collectChangesStats(ChangeSet changeSet, AnalysisSummary summary,
                                      boolean onlyReachable, AnalysisSummary previousSummary,
                                      Map<String, Integer> addedByCategory,
                                      Map<String, Integer> removedByCategory,
                                      Map<String, Set<String>> changedDepsByCategory) {
        Set<String> seenAdded = new HashSet<>();
        Set<String> seenRemoved = new HashSet<>();

        for (ChangeSet.DependencyChange mod : changeSet.getModifiedDependencies()) {
            List<SensitiveApiEntry> addedApis = onlyReachable
                ? mod.addedApis().stream()
                    .filter(a -> summary.isReachable(mod.gav(), a.sensitiveApi())).toList()
                : mod.addedApis();

            List<SensitiveApiEntry> removedApis;
            if (onlyReachable && previousSummary != null) {
                String prevGav = mod.groupId() + ":" + mod.artifactId() + ":" + mod.oldVersion();
                removedApis = mod.removedApis().stream()
                    .filter(a -> previousSummary.isReachable(prevGav, a.sensitiveApi())).toList();
            } else {
                removedApis = mod.removedApis();
            }

            String ga = mod.groupId() + ":" + mod.artifactId();
            countEntriesByCategory(addedApis, seenAdded, addedByCategory, changedDepsByCategory, ga);
            countEntriesByCategory(removedApis, seenRemoved, removedByCategory, changedDepsByCategory, ga);
        }

        for (DependencyReport added : changeSet.getAddedDependencies()) {
            List<SensitiveApiEntry> apis = onlyReachable
                ? added.getSensitiveApis().stream()
                    .filter(a -> summary.isReachable(added.gav(), a.sensitiveApi())).toList()
                : added.getSensitiveApis();
            String ga = added.getGroupId() + ":" + added.getArtifactId();
            countEntriesByCategory(apis, seenAdded, addedByCategory, changedDepsByCategory, ga);
        }

        for (DependencyReport removed : changeSet.getRemovedDependencies()) {
            if (onlyReachable) {
                if (previousSummary == null) continue;
                boolean wasReachable = removed.getSensitiveApis().stream()
                    .anyMatch(a -> previousSummary.isReachable(removed.gav(), a.sensitiveApi()));
                if (!wasReachable) continue;
            }
            List<SensitiveApiEntry> apis = removed.getSensitiveApis();
            String ga = removed.getGroupId() + ":" + removed.getArtifactId();
            countEntriesByCategory(apis, seenRemoved, removedByCategory, changedDepsByCategory, ga);
        }
    }

    private void countEntriesByCategory(List<SensitiveApiEntry> entries, Set<String> seen,
                                         Map<String, Integer> countMap,
                                         Map<String, Set<String>> depMap, String depGa) {
        for (SensitiveApiEntry entry : entries) {
            if (!seen.add(entry.sensitiveApi())) continue;
            String cat = (entry.category() == null || entry.category().isBlank()) ? "OTHER" : entry.category().toUpperCase();
            countMap.merge(cat, 1, Integer::sum);
            depMap.computeIfAbsent(cat, k -> new HashSet<>()).add(depGa);
        }
    }

    /**
     * Renders a compact table showing deps with direct/indirect access per category.
     */
    private void buildAllDepsStatsTable(StringBuilder content,
                                         Map<String, Set<String>> directDepsByCategory,
                                         Map<String, Set<String>> indirectDepsByCategory) {
        boolean hasAny = directDepsByCategory.values().stream().anyMatch(s -> !s.isEmpty())
            || indirectDepsByCategory.values().stream().anyMatch(s -> !s.isEmpty());
        if (!hasAny) return;

        content.append("<table class=\"stats-table\">\n");
        content.append("<tr><th></th><th>Direct</th><th>Indirect</th></tr>\n");
        int grandDirect = 0, grandIndirect = 0;
        for (String cat : CATEGORY_ORDER) {
            int direct = directDepsByCategory.getOrDefault(cat, Set.of()).size();
            int indirect = indirectDepsByCategory.getOrDefault(cat, Set.of()).size();
            if (direct == 0 && indirect == 0) continue;
            grandDirect += direct;
            grandIndirect += indirect;
            content.append("<tr><th>").append(escapeHtml(cat)).append("</th>")
                .append("<td class=\"num\">").append(direct).append("</td>")
                .append("<td class=\"num\">").append(indirect).append("</td></tr>\n");
        }
        content.append("<tr><th>Total</th>")
            .append("<td class=\"num\">").append(grandDirect).append("</td>")
            .append("<td class=\"num\">").append(grandIndirect).append("</td></tr>\n");
        content.append("</table>\n");
    }

    /**
     * Renders a compact table showing API count and dep count per category.
     */
    private void buildCategoryStatsTable(StringBuilder content,
                                          Map<String, Set<String>> apisByCategory,
                                          Map<String, Set<String>> depsByCategory) {
        boolean hasAny = apisByCategory.values().stream().anyMatch(s -> !s.isEmpty());
        if (!hasAny) return;

        content.append("<table class=\"stats-table\">\n");
        content.append("<tr><th></th><th>APIs</th><th>Deps</th></tr>\n");
        int totalApis = 0, totalDeps = 0;
        for (String cat : CATEGORY_ORDER) {
            int apis = apisByCategory.getOrDefault(cat, Set.of()).size();
            int deps = depsByCategory.getOrDefault(cat, Set.of()).size();
            if (apis == 0) continue;
            totalApis += apis;
            totalDeps += deps;
            content.append("<tr><th>").append(escapeHtml(cat)).append("</th>")
                .append("<td class=\"num\">").append(apis).append("</td>")
                .append("<td class=\"num\">").append(deps).append("</td></tr>\n");
        }
        content.append("<tr><th>Total</th>")
            .append("<td class=\"num\">").append(totalApis).append("</td>")
            .append("<td class=\"num\">").append(totalDeps).append("</td></tr>\n");
        content.append("</table>\n");
    }

    /**
     * Renders a compact table showing added/removed API counts and dep count per category.
     */
    private void buildChangesStatsTable(StringBuilder content,
                                         Map<String, Integer> addedByCategory,
                                         Map<String, Integer> removedByCategory,
                                         Map<String, Set<String>> changedDepsByCategory) {
        boolean hasAny = addedByCategory.values().stream().anyMatch(n -> n > 0)
            || removedByCategory.values().stream().anyMatch(n -> n > 0);
        if (!hasAny) return;

        content.append("<table class=\"stats-table\">\n");
        content.append("<tr><th></th><th>Added</th><th>Removed</th><th>Deps</th></tr>\n");
        int totalAdded = 0, totalRemoved = 0, totalDeps = 0;
        for (String cat : CATEGORY_ORDER) {
            int added = addedByCategory.getOrDefault(cat, 0);
            int removed = removedByCategory.getOrDefault(cat, 0);
            int deps = changedDepsByCategory.getOrDefault(cat, Set.of()).size();
            if (added == 0 && removed == 0) continue;
            totalAdded += added;
            totalRemoved += removed;
            totalDeps += deps;
            content.append("<tr><th>").append(escapeHtml(cat)).append("</th>")
                .append("<td class=\"num\">").append(added > 0 ? "+" + added : "0").append("</td>")
                .append("<td class=\"num\">").append(removed > 0 ? "-" + removed : "0").append("</td>")
                .append("<td class=\"num\">").append(deps).append("</td></tr>\n");
        }
        content.append("<tr><th>Total</th>")
            .append("<td class=\"num\">").append(totalAdded > 0 ? "+" + totalAdded : "0").append("</td>")
            .append("<td class=\"num\">").append(totalRemoved > 0 ? "-" + totalRemoved : "0").append("</td>")
            .append("<td class=\"num\">").append(totalDeps).append("</td></tr>\n");
        content.append("</table>\n");
    }

    /**
     * Writes a stats.json alongside the HTML reports with dep counts per category.
     */
    private void writeStatsJson(AnalysisSummary summary, ChangeSet changeSet,
                                 Path reportDir, boolean reachableOnly) throws IOException {
        Map<String, Object> stats = new LinkedHashMap<>();

        // all-deps: deps with direct/indirect access per category
        if (!reachableOnly) {
            Map<String, Object> allDeps = new LinkedHashMap<>();
            allDeps.put("totalAnalyzed", summary.getDependencyReports().size());
            long withApis = summary.getDependencyReports().stream()
                .filter(DependencyReport::hasSensitiveApis).count();
            allDeps.put("withSensitiveApis", withApis);

            Map<String, Set<String>> directDeps = new HashMap<>();
            Map<String, Set<String>> indirectDeps = new HashMap<>();
            for (DependencyReport dep : summary.getDependencyReports()) {
                if (!dep.hasSensitiveApis()) continue;
                for (SensitiveApiEntry e : dep.getSensitiveApis()) {
                    String cat = normCategory(e.category());
                    if ("DIRECT".equals(e.accessType())) {
                        directDeps.computeIfAbsent(cat, k -> new HashSet<>()).add(dep.gav());
                    } else {
                        indirectDeps.computeIfAbsent(cat, k -> new HashSet<>()).add(dep.gav());
                    }
                }
            }
            Map<String, Object> byCat = new LinkedHashMap<>();
            for (String cat : CATEGORY_ORDER) {
                int d = directDeps.getOrDefault(cat, Set.of()).size();
                int i = indirectDeps.getOrDefault(cat, Set.of()).size();
                if (d > 0 || i > 0) {
                    byCat.put(cat, Map.of("directDeps", d, "indirectDeps", i));
                }
            }
            allDeps.put("byCategory", byCat);
            stats.put("allDeps", allDeps);
        }

        // reachable: deps with reachable APIs per category
        Map<String, Set<String>> reachableDepsByCat = new HashMap<>();
        for (DependencyReport dep : summary.getDependencyReports()) {
            if (!dep.hasSensitiveApis()) continue;
            for (SensitiveApiEntry e : dep.getSensitiveApis()) {
                if (!summary.isReachable(dep.gav(), e.sensitiveApi())) continue;
                String cat = normCategory(e.category());
                reachableDepsByCat.computeIfAbsent(cat, k -> new HashSet<>()).add(dep.gav());
            }
        }
        Map<String, Object> reachable = new LinkedHashMap<>();
        Set<String> allReachable = new HashSet<>();
        reachableDepsByCat.values().forEach(allReachable::addAll);
        reachable.put("totalDeps", allReachable.size());
        Map<String, Object> reachableByCat = new LinkedHashMap<>();
        for (String cat : CATEGORY_ORDER) {
            int count = reachableDepsByCat.getOrDefault(cat, Set.of()).size();
            if (count > 0) reachableByCat.put(cat, Map.of("deps", count));
        }
        reachable.put("byCategory", reachableByCat);
        stats.put("reachable", reachable);

        // changes: added/removed/modified dep counts per category
        if (changeSet != null && changeSet.hasPreviousRun()) {
            Map<String, Object> changes = new LinkedHashMap<>();
            changes.put("addedDeps", changeSet.getAddedDependencies().size());
            changes.put("removedDeps", changeSet.getRemovedDependencies().size());
            changes.put("modifiedDeps", changeSet.getModifiedDependencies().size());
            long versionChanged = changeSet.getModifiedDependencies().stream()
                .filter(m -> !m.oldVersion().equals(m.newVersion())).count();
            changes.put("versionChangedDeps", versionChanged);

            Map<String, Set<String>> changedDepsByCat = new HashMap<>();
            for (ChangeSet.DependencyChange mod : changeSet.getModifiedDependencies()) {
                String ga = mod.groupId() + ":" + mod.artifactId();
                for (SensitiveApiEntry e : mod.addedApis()) {
                    changedDepsByCat.computeIfAbsent(normCategory(e.category()), k -> new HashSet<>()).add(ga);
                }
                for (SensitiveApiEntry e : mod.removedApis()) {
                    changedDepsByCat.computeIfAbsent(normCategory(e.category()), k -> new HashSet<>()).add(ga);
                }
            }
            for (DependencyReport added : changeSet.getAddedDependencies()) {
                String ga = added.getGroupId() + ":" + added.getArtifactId();
                for (SensitiveApiEntry e : added.getSensitiveApis()) {
                    changedDepsByCat.computeIfAbsent(normCategory(e.category()), k -> new HashSet<>()).add(ga);
                }
            }
            for (DependencyReport removed : changeSet.getRemovedDependencies()) {
                String ga = removed.getGroupId() + ":" + removed.getArtifactId();
                for (SensitiveApiEntry e : removed.getSensitiveApis()) {
                    changedDepsByCat.computeIfAbsent(normCategory(e.category()), k -> new HashSet<>()).add(ga);
                }
            }
            Map<String, Object> changesByCat = new LinkedHashMap<>();
            for (String cat : CATEGORY_ORDER) {
                int count = changedDepsByCat.getOrDefault(cat, Set.of()).size();
                if (count > 0) changesByCat.put(cat, Map.of("changedDeps", count));
            }
            changes.put("byCategory", changesByCat);
            stats.put("changes", changes);
        }

        new ObjectMapper().writerWithDefaultPrettyPrinter()
            .writeValue(reportDir.resolve("stats.json").toFile(), stats);
    }

    private static String normCategory(String category) {
        return (category == null || category.isBlank()) ? "OTHER" : category.toUpperCase();
    }

    private static String accessTypeSpan(String accessType) {
        if (accessType == null || accessType.isEmpty()) return "";
        String extraClass = "DIRECT".equals(accessType) ? " direct" : "";
        return " <span class=\"access-type" + extraClass + "\">" + accessType + "</span>";
    }

    private static String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;");
    }
}
