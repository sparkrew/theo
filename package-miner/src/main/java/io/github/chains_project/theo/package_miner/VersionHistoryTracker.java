package io.github.chains_project.theo.package_miner;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.chains_project.theo.package_miner.model.VersionHistory;
import io.github.chains_project.theo.package_miner.util.MavenVersionParser;
import io.github.chains_project.theo.package_miner.util.ReleaseLineGrouper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class VersionHistoryTracker {

    private static final Logger log = LoggerFactory.getLogger(VersionHistoryTracker.class);
    private final ObjectMapper mapper = new ObjectMapper();

    public VersionHistory.PackageVersionHistory buildHistory(
            String groupId, String artifactId,
            List<VersionReportEntry> versionReports) {

        Map<String, VersionHistory.VersionSnapshot> snapshotByVersion = new LinkedHashMap<>();

        for (VersionReportEntry entry : versionReports) {
            VersionHistory.VersionSnapshot snapshot = parseSnapshot(entry);
            if (snapshot != null) {
                snapshotByVersion.put(snapshot.version(), snapshot);
            }
        }

        if (snapshotByVersion.size() < 2) {
            return new VersionHistory.PackageVersionHistory(groupId, artifactId,
                    new ArrayList<>(snapshotByVersion.values()), List.of(), false);
        }

        List<MavenVersionParser.ParsedVersion> parsedVersions = snapshotByVersion.keySet().stream()
                .map(MavenVersionParser::parse)
                .toList();

        List<ReleaseLineGrouper.ReleaseLine> lines = ReleaseLineGrouper.group(new ArrayList<>(parsedVersions));
        List<ReleaseLineGrouper.ComparisonPair> pairs = ReleaseLineGrouper.buildComparisonPairs(lines);

        List<VersionHistory.VersionSnapshot> orderedSnapshots = new ArrayList<>();
        for (MavenVersionParser.ParsedVersion pv : ReleaseLineGrouper.orderedVersions(lines)) {
            VersionHistory.VersionSnapshot snap = snapshotByVersion.get(pv.raw());
            if (snap != null) {
                orderedSnapshots.add(snap);
            }
        }

        List<VersionHistory.PermissionChange> changes = new ArrayList<>();
        boolean hasChanges = false;

        for (ReleaseLineGrouper.ComparisonPair pair : pairs) {
            VersionHistory.VersionSnapshot from = snapshotByVersion.get(pair.fromVersion());
            VersionHistory.VersionSnapshot to = snapshotByVersion.get(pair.toVersion());
            if (from == null || to == null) continue;

            VersionHistory.PermissionChange change = computeChange(from, to, pair.type().name());
            if (change.hasChanges()) {
                hasChanges = true;
            }
            changes.add(change);
        }

        return new VersionHistory.PackageVersionHistory(groupId, artifactId, orderedSnapshots, changes, hasChanges);
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
            VersionHistory.VersionSnapshot from, VersionHistory.VersionSnapshot to,
            String comparisonType) {

        Set<String> addedDirect = new HashSet<>(to.directApis());
        addedDirect.removeAll(from.directApis());

        Set<String> removedDirect = new HashSet<>(from.directApis());
        removedDirect.removeAll(to.directApis());

        Set<String> addedIndirect = new HashSet<>(to.indirectApis());
        addedIndirect.removeAll(from.indirectApis());

        Set<String> removedIndirect = new HashSet<>(from.indirectApis());
        removedIndirect.removeAll(to.indirectApis());

        return new VersionHistory.PermissionChange(
                from.version(), to.version(), comparisonType,
                addedDirect, removedDirect, addedIndirect, removedIndirect
        );
    }

    public void saveHistory(VersionHistory.PackageVersionHistory history, Path outputDir) throws IOException {
        Path historyDir = outputDir.resolve("version-history");
        Files.createDirectories(historyDir);
        Path file = historyDir.resolve(history.groupId() + "_" + history.artifactId() + "-history.json");
        mapper.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), history);
    }

    public record VersionReportEntry(String version, long timestamp, Path reportFile) {}
}
