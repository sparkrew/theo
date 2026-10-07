package io.github.chains_project.theo.static_analysis.report;

import io.github.chains_project.theo.static_analysis.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.stream.Collectors;
import java.util.HashSet;

/**
 * Compares two analysis runs to detect what changed -- new deps, removed deps,
 * and deps whose sensitive API surface changed. This feeds the changes.html report.
 */
public class ChangeDetector {

    private static final Logger log = LoggerFactory.getLogger(ChangeDetector.class);

    /**
     * Computes what changed between the previous and current analysis.
     *
     * @param previous the last cached analysis run (null if first run)
     * @param current  the current analysis run
     * @return a ChangeSet describing all differences
     */
    public ChangeSet detectChanges(AnalysisSummary previous, AnalysisSummary current) {
        if (previous == null) {
            // First run -- everything is "new", nothing was removed or modified
            log.info("No previous run found; treating all {} dependencies as newly added",
                    current.getDependencyReports().size());
            return new ChangeSet(
                    current.getDependencyReports(),
                    Collections.emptyList(),
                    Collections.emptyList(),
                    false
            );
        }

        // Build maps of GA -> DependencyReport for fast lookup.
        // We key by "groupId:artifactId" (without version) so we can detect
        // version changes for the same logical dependency.
        Map<String, DependencyReport> previousByGa = indexByGroupArtifact(previous.getDependencyReports());
        Map<String, DependencyReport> currentByGa = indexByGroupArtifact(current.getDependencyReports());

        List<DependencyReport> added = new ArrayList<>();
        List<DependencyReport> removed = new ArrayList<>();
        List<ChangeSet.DependencyChange> modified = new ArrayList<>();

        // Find added and modified dependencies
        for (Map.Entry<String, DependencyReport> entry : currentByGa.entrySet()) {
            String ga = entry.getKey();
            DependencyReport currentReport = entry.getValue();
            DependencyReport previousReport = previousByGa.get(ga);

            if (previousReport == null) {
                // Brand new dependency that wasn't in the previous run
                added.add(currentReport);
            } else if (!previousReport.getVersion().equals(currentReport.getVersion())) {
                // Version changed -- compare sensitive APIs to see if the surface shifted
                ChangeSet.DependencyChange change = compareApis(previousReport, currentReport);
                if (change != null) {
                    modified.add(change);
                }
            } else {
                // Same version -- still worth checking if sensitive APIs changed (e.g.
                // snapshot rebuilds or if the analyzer was updated and finds new things)
                ChangeSet.DependencyChange change = compareApis(previousReport, currentReport);
                if (change != null) {
                    modified.add(change);
                }
            }
        }

        // Find removed dependencies (present in previous but not in current)
        for (String ga : previousByGa.keySet()) {
            if (!currentByGa.containsKey(ga)) {
                removed.add(previousByGa.get(ga));
            }
        }

        log.info("Change detection complete: {} added, {} removed, {} modified",
                added.size(), removed.size(), modified.size());

        return new ChangeSet(added, removed, modified, true);
    }

    /**
     * Builds a lookup map from "groupId:artifactId" to DependencyReport.
     * If the same GA appears more than once (shouldn't happen in practice),
     * the last one wins -- but we log a warning because it likely means
     * something is off in the dependency resolution.
     */
    private Map<String, DependencyReport> indexByGroupArtifact(List<DependencyReport> reports) {
        Map<String, DependencyReport> index = new LinkedHashMap<>();
        if (reports == null) {
            return index;
        }
        for (DependencyReport report : reports) {
            String ga = report.getGroupId() + ":" + report.getArtifactId();
            if (index.containsKey(ga)) {
                log.warn("Duplicate GA key {} in analysis results -- keeping the later entry", ga);
            }
            index.put(ga, report);
        }
        return index;
    }

    /**
     * Compares two DependencyReports for the same logical dependency (possibly
     * at different versions) and returns a DependencyChange if their sensitive
     * API sets differ. Returns null when there is no actual difference, so the
     * caller can skip noise-free dependencies.
     *
     * We compare by sensitiveApi name (the fully qualified method identifier)
     * since that's the stable identity for a sensitive API across versions.
     */
    private ChangeSet.DependencyChange compareApis(DependencyReport previousReport,
                                                    DependencyReport currentReport) {
        // Collect the sensitive API names from each report into sets for diffing.
        Set<String> previousApis = extractSensitiveApiNames(previousReport);
        Set<String> currentApis = extractSensitiveApiNames(currentReport);

        // "Added" APIs: present in the current version but not in the previous one
        Set<String> addedNames = new LinkedHashSet<>(currentApis);
        addedNames.removeAll(previousApis);

        // "Removed" APIs: present in the previous version but gone from the current one
        Set<String> removedNames = new LinkedHashSet<>(previousApis);
        removedNames.removeAll(currentApis);

        // If nothing actually changed, there's nothing to report
        if (addedNames.isEmpty() && removedNames.isEmpty()) {
            return null;
        }

        // Resolve the names back to full SensitiveApiEntry objects so the
        // change report can show details like category and call path.
        List<SensitiveApiEntry> addedEntries = filterEntriesByNames(currentReport.getSensitiveApis(), addedNames);
        List<SensitiveApiEntry> removedEntries = filterEntriesByNames(previousReport.getSensitiveApis(), removedNames);

        log.debug("Dependency {}:{} changed: {} APIs added, {} removed",
                currentReport.getGroupId(), currentReport.getArtifactId(),
                addedEntries.size(), removedEntries.size());

        return new ChangeSet.DependencyChange(
                currentReport.getGroupId(),
                currentReport.getArtifactId(),
                previousReport.getVersion(),
                currentReport.getVersion(),
                addedEntries,
                removedEntries
        );
    }

    /**
     * Pulls out the set of sensitive API names from a report. Uses the
     * sensitiveApi field from each entry, which is the fully qualified
     * method identifier like "java.io.FileInputStream.<init>".
     */
    private Set<String> extractSensitiveApiNames(DependencyReport report) {
        if (report.getSensitiveApis() == null) {
            return Collections.emptySet();
        }
        return report.getSensitiveApis().stream()
                .map(SensitiveApiEntry::sensitiveApi)
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    /**
     * Filters a list of SensitiveApiEntry objects to only those whose
     * sensitiveApi name is in the given set. Preserves the original order.
     */
    private List<SensitiveApiEntry> filterEntriesByNames(List<SensitiveApiEntry> entries,
                                                         Set<String> names) {
        if (entries == null || names.isEmpty()) {
            return Collections.emptyList();
        }
        // A single API name can appear in multiple call paths. We only need
        // one entry per API for the change report — the first one is enough.
        Set<String> seen = new HashSet<>();
        return entries.stream()
                .filter(entry -> names.contains(entry.sensitiveApi()))
                .filter(entry -> seen.add(entry.sensitiveApi()))
                .collect(Collectors.toList());
    }
}
