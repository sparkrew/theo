package io.github.chains_project.theo.static_analysis.report;

import io.github.chains_project.theo.static_analysis.decompile.MethodDecompiler;
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

    private final MethodDecompiler decompiler;

    // Map from dependency GAV to the Path of its JAR file,
    // needed for decompiling methods
    private final Map<String, Path> dependencyJarPaths;

    public HtmlReportGenerator(MethodDecompiler decompiler, Map<String, Path> dependencyJarPaths) {
        this.decompiler = decompiler;
        this.dependencyJarPaths = dependencyJarPaths;
    }

    /**
     * Generates all three HTML reports and writes an analysis-data.json file
     * for the CVE check goal to consume later.
     */
    public void generateReports(AnalysisSummary summary, ChangeSet changeSet, Path reportDir) throws IOException {
        Files.createDirectories(reportDir);

        String template = loadTemplate();

        // 1. all-dependencies.html — every sensitive API from every dep
        generateAllDependenciesReport(summary, template, reportDir);

        // 2. reachable.html — only client-reachable sensitive APIs
        generateReachableReport(summary, template, reportDir);

        // 3. changes.html — what changed since last run
        generateChangesReport(summary, changeSet, template, reportDir);

        // 4. analysis-data.json — machine-readable output for cve-check
        writeAnalysisData(summary, reportDir);

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

        // Build grouped structure: category -> depGav -> apiName -> accessType
        // A dependency can appear under multiple categories if its APIs span them.
        Map<String, Map<String, Map<String, String>>> byCategoryThenDep = new LinkedHashMap<>();
        for (String cat : CATEGORY_ORDER) {
            byCategoryThenDep.put(cat, new TreeMap<>());
        }

        for (DependencyReport dep : summary.getDependencyReports()) {
            if (!dep.hasSensitiveApis()) continue;
            for (SensitiveApiEntry entry : dep.getSensitiveApis()) {
                String cat = (entry.category() == null || entry.category().isBlank()) ? "OTHER" : entry.category();
                byCategoryThenDep.computeIfAbsent(cat, k -> new TreeMap<>())
                    .computeIfAbsent(dep.gav(), k -> new TreeMap<>())
                    .putIfAbsent(entry.sensitiveApi(), entry.accessType());
            }
        }

        // This report only lists which sensitive APIs each dependency accesses.
        // Full call paths and decompiled source are in reachable.html to keep
        // this overview compact when the project has many dependencies.
        for (String category : CATEGORY_ORDER) {
            Map<String, Map<String, String>> depsInCategory = byCategoryThenDep.get(category);
            if (depsInCategory == null || depsInCategory.isEmpty()) continue;

            content.append("<h2 class=\"category-header\">").append(escapeHtml(category)).append("</h2>\n");

            for (Map.Entry<String, Map<String, String>> depEntry : depsInCategory.entrySet()) {
                String gav = depEntry.getKey();
                Map<String, String> uniqueApis = depEntry.getValue();

                boolean isReachable = uniqueApis.keySet().stream()
                    .anyMatch(api -> summary.isReachable(gav, api));

                String reachableClass = isReachable ? " reachable" : "";
                content.append("<details class=\"dependency").append(reachableClass).append("\">\n");
                content.append("  <summary><span class=\"dep-gav\">").append(escapeHtml(gav))
                    .append("</span> <span class=\"count\">(").append(uniqueApis.size())
                    .append(" sensitive APIs)</span></summary>\n");

                content.append("  <ul class=\"api-list\">\n");
                for (Map.Entry<String, String> api : uniqueApis.entrySet()) {
                    boolean apiReachable = summary.isReachable(gav, api.getKey());
                    String apiClass = apiReachable ? " class=\"reachable\"" : "";
                    content.append("    <li").append(apiClass).append(">")
                        .append(escapeHtml(api.getKey()));
                    if (!api.getValue().isEmpty()) {
                        content.append(" <span class=\"access-type\">").append(api.getValue()).append("</span>");
                    }
                    content.append("</li>\n");
                }
                content.append("  </ul>\n");

                content.append("</details>\n");
            }
        }

        // Render any categories not in the standard order (shouldn't happen, but safe)
        for (Map.Entry<String, Map<String, Map<String, String>>> extra : byCategoryThenDep.entrySet()) {
            if (CATEGORY_ORDER.contains(extra.getKey()) || extra.getValue().isEmpty()) continue;
            content.append("<h2 class=\"category-header\">").append(escapeHtml(extra.getKey())).append("</h2>\n");
            for (Map.Entry<String, Map<String, String>> depEntry : extra.getValue().entrySet()) {
                String gav = depEntry.getKey();
                Map<String, String> uniqueApis = depEntry.getValue();
                boolean isReachable = uniqueApis.keySet().stream()
                    .anyMatch(api -> summary.isReachable(gav, api));
                String reachableClass = isReachable ? " reachable" : "";
                content.append("<details class=\"dependency").append(reachableClass).append("\">\n");
                content.append("  <summary><span class=\"dep-gav\">").append(escapeHtml(gav))
                    .append("</span> <span class=\"count\">(").append(uniqueApis.size())
                    .append(" sensitive APIs)</span></summary>\n");
                content.append("  <ul class=\"api-list\">\n");
                for (Map.Entry<String, String> api : uniqueApis.entrySet()) {
                    boolean apiReachable = summary.isReachable(gav, api.getKey());
                    String apiClass = apiReachable ? " class=\"reachable\"" : "";
                    content.append("    <li").append(apiClass).append(">")
                        .append(escapeHtml(api.getKey()));
                    if (!api.getValue().isEmpty()) {
                        content.append(" <span class=\"access-type\">").append(api.getValue()).append("</span>");
                    }
                    content.append("</li>\n");
                }
                content.append("  </ul>\n");
                content.append("</details>\n");
            }
        }

        String html = renderTemplate(template, "Theo — all dependencies", content.toString(),
            "For full call paths and decompiled source, see reachable.html.");
        Files.writeString(reportDir.resolve("all-dependencies.html"), html, StandardCharsets.UTF_8);
    }

    // --- reachable.html ---

    private void generateReachableReport(AnalysisSummary summary, String template, Path reportDir) throws IOException {
        StringBuilder content = new StringBuilder();

        // Filter to only deps with reachable APIs
        List<DependencyReport> reachableDeps = summary.getDependencyReports().stream()
            .filter(dep -> dep.getSensitiveApis().stream()
                .anyMatch(api -> summary.isReachable(dep.gav(), api.sensitiveApi())))
            .sorted(Comparator.comparing(DependencyReport::gav))
            .toList();

        content.append("<p class=\"stats\">").append(reachableDeps.size())
            .append(" dependencies with client-reachable sensitive APIs</p>\n");

        // Group reachable entries: category -> dep -> list of reachable API entries
        Map<String, Map<String, List<SensitiveApiEntry>>> byCategoryThenDep = new LinkedHashMap<>();
        for (String cat : CATEGORY_ORDER) {
            byCategoryThenDep.put(cat, new TreeMap<>());
        }

        for (DependencyReport dep : reachableDeps) {
            for (SensitiveApiEntry entry : dep.getSensitiveApis()) {
                if (!summary.isReachable(dep.gav(), entry.sensitiveApi())) continue;
                String cat = (entry.category() == null || entry.category().isBlank()) ? "OTHER" : entry.category();
                byCategoryThenDep.computeIfAbsent(cat, k -> new TreeMap<>())
                    .computeIfAbsent(dep.gav(), k -> new ArrayList<>())
                    .add(entry);
            }
        }

        for (String category : CATEGORY_ORDER) {
            Map<String, List<SensitiveApiEntry>> depsInCategory = byCategoryThenDep.get(category);
            if (depsInCategory == null || depsInCategory.isEmpty()) continue;

            content.append("<h2 class=\"category-header\">").append(escapeHtml(category)).append("</h2>\n");

            for (Map.Entry<String, List<SensitiveApiEntry>> depEntry : depsInCategory.entrySet()) {
                String gav = depEntry.getKey();
                DependencyReport dep = reachableDeps.stream()
                    .filter(d -> d.gav().equals(gav)).findFirst().orElse(null);
                if (dep == null) continue;

                content.append("<details class=\"dependency reachable\">\n");
                content.append("  <summary><span class=\"dep-gav\">").append(escapeHtml(gav))
                    .append("</span></summary>\n");

                // Group this dep's entries by sensitive API name
                Map<String, List<SensitiveApiEntry>> byApi = groupBySensitiveApi(depEntry.getValue());

                for (Map.Entry<String, List<SensitiveApiEntry>> apiGroup : byApi.entrySet()) {
                    content.append("  <details class=\"sensitive-api reachable\">\n");
                    content.append("    <summary>").append(escapeHtml(apiGroup.getKey()));
                    if (!apiGroup.getValue().isEmpty() && !apiGroup.getValue().get(0).accessType().isEmpty()) {
                        content.append(" <span class=\"access-type\">").append(apiGroup.getValue().get(0).accessType()).append("</span>");
                    }
                    content.append("</summary>\n");

                    for (SensitiveApiEntry apiEntry : apiGroup.getValue()) {
                        buildPathDetails(content, dep, apiEntry);
                    }

                    content.append("  </details>\n");
                }

                content.append("</details>\n");
            }
        }

        // Handle any unexpected categories not in the standard order
        for (Map.Entry<String, Map<String, List<SensitiveApiEntry>>> extra : byCategoryThenDep.entrySet()) {
            if (CATEGORY_ORDER.contains(extra.getKey()) || extra.getValue().isEmpty()) continue;
            content.append("<h2 class=\"category-header\">").append(escapeHtml(extra.getKey())).append("</h2>\n");
            for (Map.Entry<String, List<SensitiveApiEntry>> depEntry : extra.getValue().entrySet()) {
                String gav = depEntry.getKey();
                DependencyReport dep = reachableDeps.stream()
                    .filter(d -> d.gav().equals(gav)).findFirst().orElse(null);
                if (dep == null) continue;
                content.append("<details class=\"dependency reachable\">\n");
                content.append("  <summary><span class=\"dep-gav\">").append(escapeHtml(gav))
                    .append("</span></summary>\n");
                Map<String, List<SensitiveApiEntry>> byApi = groupBySensitiveApi(depEntry.getValue());
                for (Map.Entry<String, List<SensitiveApiEntry>> apiGroup : byApi.entrySet()) {
                    content.append("  <details class=\"sensitive-api reachable\">\n");
                    content.append("    <summary>").append(escapeHtml(apiGroup.getKey()));
                    if (!apiGroup.getValue().isEmpty() && !apiGroup.getValue().get(0).accessType().isEmpty()) {
                        content.append(" <span class=\"access-type\">").append(apiGroup.getValue().get(0).accessType()).append("</span>");
                    }
                    content.append("</summary>\n");
                    for (SensitiveApiEntry apiEntry : apiGroup.getValue()) {
                        buildPathDetails(content, dep, apiEntry);
                    }
                    content.append("  </details>\n");
                }
                content.append("</details>\n");
            }
        }

        String html = renderTemplate(template, "Theo — client-reachable APIs", content.toString(),
            "Decompiled code is produced by CFR and may not exactly match the original source.");
        Files.writeString(reportDir.resolve("reachable.html"), html, StandardCharsets.UTF_8);
    }

    // --- changes.html ---

    private void generateChangesReport(AnalysisSummary summary, ChangeSet changeSet,
                                       String template, Path reportDir) throws IOException {
        StringBuilder content = new StringBuilder();

        if (!changeSet.hasPreviousRun()) {
            content.append("<p class=\"stats\">First analysis run — no previous data to compare against.</p>\n");
        } else if (!changeSet.hasChanges()) {
            content.append("<p class=\"stats\">No changes detected since the last run.</p>\n");
        } else {
            // Section 1: Changes across all dependencies
            content.append("<h2>Changes across all dependencies</h2>\n");
            buildChangesSection(content, changeSet, summary, false);

            // Section 2: Changes to client-reachable APIs only
            content.append("<h2>Changes to client-reachable APIs</h2>\n");
            buildChangesSection(content, changeSet, summary, true);
        }

        String html = renderTemplate(template, "Theo — changes since last run", content.toString(), null);
        Files.writeString(reportDir.resolve("changes.html"), html, StandardCharsets.UTF_8);
    }

    private void buildChangesSection(StringBuilder content, ChangeSet changeSet,
                                     AnalysisSummary summary, boolean onlyReachable) {
        boolean anyChanges = false;

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
                .append(escapeHtml(added.gav())).append("</span> <span class=\"count\">(new, ")
                .append(apis.size()).append(" sensitive APIs)</span></summary>\n");

            for (SensitiveApiEntry api : apis) {
                content.append("    <div class=\"api-entry\">").append(escapeHtml(api.sensitiveApi()))
                    .append(" (").append(api.accessType()).append(")</div>\n");
            }
            content.append("</details>\n");
        }

        // Modified dependencies
        for (ChangeSet.DependencyChange mod : changeSet.getModifiedDependencies()) {
            List<SensitiveApiEntry> addedApis = onlyReachable
                ? mod.addedApis().stream()
                    .filter(a -> summary.isReachable(mod.gav(), a.sensitiveApi())).toList()
                : mod.addedApis();
            List<SensitiveApiEntry> removedApis = onlyReachable
                ? mod.removedApis().stream()
                    .filter(a -> summary.isReachable(mod.gav(), a.sensitiveApi())).toList()
                : mod.removedApis();

            if (addedApis.isEmpty() && removedApis.isEmpty()) continue;

            anyChanges = true;
            String versionChange = mod.oldVersion().equals(mod.newVersion()) ? ""
                : " (" + mod.oldVersion() + " → " + mod.newVersion() + ")";

            content.append("<details class=\"dependency modified\">\n");
            content.append("  <summary><span class=\"change-marker\">~</span> <span class=\"dep-gav\">")
                .append(escapeHtml(mod.gav())).append("</span>").append(escapeHtml(versionChange))
                .append("</summary>\n");

            if (!addedApis.isEmpty()) {
                content.append("    <h3>Added</h3>\n");
                for (SensitiveApiEntry api : addedApis) {
                    content.append("    <div class=\"api-entry added\">+ ").append(escapeHtml(api.sensitiveApi())).append("</div>\n");
                }
            }
            if (!removedApis.isEmpty()) {
                content.append("    <h3>Removed</h3>\n");
                for (SensitiveApiEntry api : removedApis) {
                    content.append("    <div class=\"api-entry removed\">- ").append(escapeHtml(api.sensitiveApi())).append("</div>\n");
                }
            }
            content.append("</details>\n");
        }

        // Removed dependencies
        for (DependencyReport removed : changeSet.getRemovedDependencies()) {
            anyChanges = true;
            content.append("<details class=\"dependency removed\">\n");
            content.append("  <summary><span class=\"change-marker\">-</span> <span class=\"dep-gav\">")
                .append(escapeHtml(removed.gav())).append("</span> (removed)</summary>\n");
            content.append("</details>\n");
        }

        if (!anyChanges) {
            content.append("<p class=\"no-changes\">No changes in this category.</p>\n");
        }
    }

    // --- Shared helpers ---

    /**
     * Builds the expandable path + decompiled code for a single sensitive API entry.
     */
    private void buildPathDetails(StringBuilder content, DependencyReport dep, SensitiveApiEntry entry) {
        // Path display
        content.append("    <details class=\"call-path\">\n");

        // Show a condensed path summary
        String pathSummary = entry.fullPath().isEmpty() ? entry.entryPoint() + " → " + entry.sensitiveApi()
            : entry.fullPath().get(0) + " → ... → " + entry.fullPath().get(entry.fullPath().size() - 1);
        content.append("      <summary>").append(escapeHtml(pathSummary)).append("</summary>\n");

        // Full path as an ordered list
        if (!entry.fullPath().isEmpty()) {
            content.append("      <ol class=\"path-list\">\n");
            for (String step : entry.fullPath()) {
                content.append("        <li>").append(escapeHtml(step)).append("</li>\n");
            }
            content.append("      </ol>\n");
        }

        // Decompiled code for the entry point method
        String entryPointMethod = entry.entryPoint();
        String decompiledCode = tryDecompile(dep, entryPointMethod);
        if (decompiledCode != null) {
            content.append("      <details class=\"decompiled\">\n");
            content.append("        <summary>View decompiled source</summary>\n");
            content.append("        <pre><code>").append(escapeHtml(decompiledCode)).append("</code></pre>\n");
            content.append("      </details>\n");
        }

        content.append("    </details>\n");
    }

    /**
     * Attempts to decompile the method referenced by an entry point string.
     * The entry point format is "com.example.ClassName.methodName".
     */
    private String tryDecompile(DependencyReport dep, String entryPointMethod) {
        if (decompiler == null) return null;

        Path jarPath = dependencyJarPaths.get(dep.gav());
        if (jarPath == null) return null;

        // Parse "com.example.ClassName.methodName" into class and method parts
        int lastDot = entryPointMethod.lastIndexOf('.');
        if (lastDot <= 0) return null;

        String className = entryPointMethod.substring(0, lastDot);
        String methodName = entryPointMethod.substring(lastDot + 1);

        try {
            return decompiler.decompileMethod(jarPath, className, methodName);
        } catch (Exception e) {
            log.debug("Could not decompile {}: {}", entryPointMethod, e.getMessage());
            return null;
        }
    }

    private Map<String, List<SensitiveApiEntry>> groupBySensitiveApi(List<SensitiveApiEntry> entries) {
        Map<String, List<SensitiveApiEntry>> grouped = new TreeMap<>();
        for (SensitiveApiEntry entry : entries) {
            grouped.computeIfAbsent(entry.sensitiveApi(), k -> new ArrayList<>()).add(entry);
        }
        return grouped;
    }

    /**
     * Writes the analysis summary as JSON for the CVE check goal to consume.
     */
    private void writeAnalysisData(AnalysisSummary summary, Path reportDir) throws IOException {
        com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
        mapper.writerWithDefaultPrettyPrinter()
            .writeValue(reportDir.resolve("analysis-data.json").toFile(), summary);
    }

    private static String escapeHtml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;");
    }
}
