package io.github.chains_project.theo.package_miner;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * Analyzes multiple versions of a package to track how sensitive API usage changes over time.
 *
 * For each version, parses the analyzer report to extract direct and indirect API accesses,
 * then computes diffs between consecutive versions to identify permission changes.
 */
public class VersionHistoryTracker {

    private static final Logger log = LoggerFactory.getLogger(VersionHistoryTracker.class);
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Builds the version history for a package from a list of analyzer reports,
     * one per version (ordered oldest to newest).
     */
    public VersionHistory.PackageVersionHistory buildHistory(
            String groupId, String artifactId,
            List<VersionReportEntry> versionReports) {

        List<VersionHistory.VersionSnapshot> snapshots = new ArrayList<>();

        for (VersionReportEntry entry : versionReports) {
            VersionHistory.VersionSnapshot snapshot = parseSnapshot(entry);
            if (snapshot != null) {
                snapshots.add(snapshot);
            }
        }

        List<VersionHistory.PermissionChange> changes = new ArrayList<>();
        boolean hasChanges = false;

        for (int i = 1; i < snapshots.size(); i++) {
            VersionHistory.PermissionChange change = computeChange(snapshots.get(i - 1), snapshots.get(i));
            if (change.hasChanges()) {
                hasChanges = true;
            }
            changes.add(change);
        }

        return new VersionHistory.PackageVersionHistory(groupId, artifactId, snapshots, changes, hasChanges);
    }

    private VersionHistory.VersionSnapshot parseSnapshot(VersionReportEntry entry) {
        try {
            Map<String, Object> report = mapper.readValue(
                    entry.reportFile().toFile(), new TypeReference<>() {}
            );

            Set<String> directApis = new HashSet<>();
            Set<String> indirectApis = new HashSet<>();

            Object directObj = report.get("directAccesses");
            if (directObj instanceof List<?> list) {
                for (Object item : list) {
                    if (item instanceof Map<?, ?> map) {
                        String api = (String) map.get("sensitiveAPI");
                        if (api != null) directApis.add(api);
                    }
                }
            }

            Object indirectObj = report.get("indirectAccesses");
            if (indirectObj instanceof List<?> list) {
                for (Object item : list) {
                    if (item instanceof Map<?, ?> map) {
                        String api = (String) map.get("sensitiveAPI");
                        if (api != null) indirectApis.add(api);
                    }
                }
            }

            // APIs that appear in both direct and indirect: keep in direct, remove from indirect
            indirectApis.removeAll(directApis);

            return new VersionHistory.VersionSnapshot(
                    entry.version(), entry.timestamp(), directApis, indirectApis
            );
        } catch (IOException e) {
            log.error("Failed to parse report for version {}", entry.version(), e);
            return null;
        }
    }

    private VersionHistory.PermissionChange computeChange(
            VersionHistory.VersionSnapshot from, VersionHistory.VersionSnapshot to) {

        Set<String> addedDirect = new HashSet<>(to.directApis());
        addedDirect.removeAll(from.directApis());

        Set<String> removedDirect = new HashSet<>(from.directApis());
        removedDirect.removeAll(to.directApis());

        Set<String> addedIndirect = new HashSet<>(to.indirectApis());
        addedIndirect.removeAll(from.indirectApis());

        Set<String> removedIndirect = new HashSet<>(from.indirectApis());
        removedIndirect.removeAll(to.indirectApis());

        return new VersionHistory.PermissionChange(
                from.version(), to.version(),
                addedDirect, removedDirect, addedIndirect, removedIndirect
        );
    }

    /**
     * Saves the version history JSON for a package.
     */
    public void saveHistory(VersionHistory.PackageVersionHistory history, Path outputDir) throws IOException {
        Path historyDir = outputDir.resolve("version-history");
        Files.createDirectories(historyDir);
        Path file = historyDir.resolve(history.groupId() + "_" + history.artifactId() + "-history.json");
        mapper.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), history);
    }

    /**
     * Associates a version string with its analyzer report file path and release timestamp.
     */
    public record VersionReportEntry(String version, long timestamp, Path reportFile) {}
}
