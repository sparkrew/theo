package io.github.chains_project.theo.static_analysis.report;

import io.github.chains_project.theo.static_analysis.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * Generates a pom-theo-suggestions.xml file containing dependency management
 * entries that would revert changes to reachable sensitive APIs. Developers
 * can diff this against their current POM and selectively apply changes.
 */
public class PomSuggestionGenerator {

    private static final Logger log = LoggerFactory.getLogger(PomSuggestionGenerator.class);

    public void generateSuggestions(ChangeSet changeSet, AnalysisSummary current,
                                    AnalysisSummary previous, Path pomDir) throws IOException {
        List<Suggestion> suggestions = collectSuggestions(changeSet, current, previous);
        if (suggestions.isEmpty()) {
            log.info("No revert suggestions to generate.");
            return;
        }

        Path outputFile = pomDir.resolve("pom-theo-suggestions.xml");
        try (BufferedWriter w = Files.newBufferedWriter(outputFile, StandardCharsets.UTF_8)) {
            w.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
            w.write("<!--\n");
            w.write("  Theo suggested dependency changes to revert reachable sensitive API additions.\n");
            w.write("  Review and selectively apply these to your pom.xml.\n");
            w.write("-->\n");
            w.write("<project>\n");
            w.write("  <dependencyManagement>\n");
            w.write("    <dependencies>\n");

            for (Suggestion s : suggestions) {
                w.write("\n");
                w.write("      <!-- " + escapeXml(s.reason) + " -->\n");
                if (s.trail != null && !s.trail.isEmpty()) {
                    w.write("      <!-- Dependency trail: " + escapeXml(String.join(" -> ", s.trail)) + " -->\n");
                }
                w.write("      <dependency>\n");
                w.write("        <groupId>" + escapeXml(s.groupId) + "</groupId>\n");
                w.write("        <artifactId>" + escapeXml(s.artifactId) + "</artifactId>\n");
                w.write("        <version>" + escapeXml(s.suggestedVersion) + "</version>\n");
                if (s.isTransitive) {
                    w.write("        <!-- Transitive dependency (depth " + s.depth + "), pulled in by: "
                            + escapeXml(s.directParent) + " -->\n");
                }
                w.write("      </dependency>\n");
            }

            w.write("\n");
            w.write("    </dependencies>\n");
            w.write("  </dependencyManagement>\n");
            w.write("</project>\n");
        }

        log.info("POM suggestions written to {}", outputFile);
    }

    private List<Suggestion> collectSuggestions(ChangeSet changeSet, AnalysisSummary current,
                                                AnalysisSummary previous) {
        List<Suggestion> suggestions = new ArrayList<>();
        Map<String, DependencyReport> currentByGa = indexByGa(current.getDependencyReports());

        for (ChangeSet.DependencyChange mod : changeSet.getModifiedDependencies()) {
            if (mod.oldVersion().equals(mod.newVersion())) continue;

            boolean hasReachableAdded = mod.addedApis().stream()
                    .anyMatch(api -> current.isReachable(mod.gav(), api.sensitiveApi()));
            if (!hasReachableAdded) continue;

            String ga = mod.groupId() + ":" + mod.artifactId();
            DependencyReport dep = currentByGa.get(ga);

            int addedReachable = (int) mod.addedApis().stream()
                    .filter(api -> current.isReachable(mod.gav(), api.sensitiveApi())).count();

            Suggestion s = new Suggestion();
            s.groupId = mod.groupId();
            s.artifactId = mod.artifactId();
            s.suggestedVersion = mod.oldVersion();
            s.isTransitive = dep != null && dep.isTransitive();
            s.depth = dep != null ? dep.getDependencyDepth() : 0;
            s.directParent = dep != null ? dep.getDirectParentGav() : null;
            s.trail = dep != null ? dep.getDependencyTrail() : null;
            s.reason = "Revert " + mod.groupId() + ":" + mod.artifactId()
                    + " from " + mod.newVersion() + " to " + mod.oldVersion()
                    + " (" + addedReachable + " new reachable sensitive APIs)";
            suggestions.add(s);
        }

        return suggestions;
    }

    private Map<String, DependencyReport> indexByGa(List<DependencyReport> reports) {
        Map<String, DependencyReport> map = new HashMap<>();
        if (reports == null) return map;
        for (DependencyReport r : reports) {
            map.put(r.getGroupId() + ":" + r.getArtifactId(), r);
        }
        return map;
    }

    private static String escapeXml(String text) {
        if (text == null) return "";
        return text.replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace("\"", "&quot;")
                   .replace("'", "&apos;");
    }

    private static class Suggestion {
        String groupId;
        String artifactId;
        String suggestedVersion;
        boolean isTransitive;
        int depth;
        String directParent;
        List<String> trail;
        String reason;
    }
}
