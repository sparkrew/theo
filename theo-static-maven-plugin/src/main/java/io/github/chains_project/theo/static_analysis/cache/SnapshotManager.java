package io.github.chains_project.theo.static_analysis.cache;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.chains_project.theo.static_analysis.model.*;
import io.github.chains_project.theo.static_analysis.model.ReachableSnapshot.ReachableApiRecord;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Manages the snapshot history folder. Each snapshot is a small JSON file
 * containing only the reachable sensitive APIs at a point in time.
 *
 * History folder layout:
 *   ~/.theo/history/{groupId}__{artifactId}/
 *     2026-10-07T14-30-00__v1.0-SNAPSHOT-1.json
 *     2026-10-08T09-15-00__v1.0-SNAPSHOT-2.json
 */
public class SnapshotManager {

    private static final Logger log = LoggerFactory.getLogger(SnapshotManager.class);
    private static final ObjectMapper mapper = new ObjectMapper();
    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH-mm-ss").withZone(ZoneId.systemDefault());

    private final Path historyDir;

    public SnapshotManager(Path historyBaseDir, String projectGroupId, String projectArtifactId) {
        this.historyDir = historyBaseDir.resolve(projectGroupId + "__" + projectArtifactId);
    }

    /**
     * Saves a snapshot from the current analysis summary. Extracts only the
     * reachable APIs to keep the snapshot lightweight.
     *
     * @param summary the current analysis result
     * @param label   user-provided label, or null to auto-generate from project version
     * @return the label assigned to this snapshot
     */
    public String saveSnapshot(AnalysisSummary summary, String label) throws IOException {
        Files.createDirectories(historyDir);

        if (label == null || label.isBlank()) {
            label = summary.getProjectVersion() + "-" + nextSequence(summary.getProjectVersion());
        }

        List<ReachableApiRecord> records = extractReachableRecords(summary);

        ReachableSnapshot snapshot = new ReachableSnapshot(
                summary.getProjectGroupId(),
                summary.getProjectArtifactId(),
                summary.getProjectVersion(),
                label,
                System.currentTimeMillis(),
                records
        );

        String timestamp = TIMESTAMP_FORMAT.format(Instant.now());
        // Sanitize label for use in filename
        String safeLabel = label.replaceAll("[^a-zA-Z0-9._-]", "_");
        String filename = timestamp + "__" + safeLabel + ".json";

        Path file = historyDir.resolve(filename);
        mapper.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), snapshot);
        log.info("Saved snapshot '{}' to {}", label, file);

        return label;
    }

    /**
     * Loads all snapshots for this project, sorted newest first.
     */
    public List<ReachableSnapshot> loadAllSnapshots() {
        List<ReachableSnapshot> snapshots = new ArrayList<>();
        if (!Files.isDirectory(historyDir)) return snapshots;

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(historyDir, "*.json")) {
            for (Path file : stream) {
                try {
                    snapshots.add(mapper.readValue(file.toFile(), ReachableSnapshot.class));
                } catch (IOException e) {
                    log.warn("Could not read snapshot {}: {}", file.getFileName(), e.getMessage());
                }
            }
        } catch (IOException e) {
            log.warn("Could not list snapshots in {}: {}", historyDir, e.getMessage());
        }

        snapshots.sort(Comparator.comparingLong(ReachableSnapshot::getTimestamp).reversed());
        return snapshots;
    }

    /**
     * Loads the Nth most recent snapshot (1 = newest).
     * Returns null if there aren't enough snapshots.
     */
    public ReachableSnapshot loadSnapshot(int n) {
        List<ReachableSnapshot> all = loadAllSnapshots();
        if (n < 1 || n > all.size()) return null;
        return all.get(n - 1);
    }

    /**
     * Returns the next sequence number for a given project version.
     * Counts how many snapshots already exist with that version prefix.
     */
    private int nextSequence(String projectVersion) {
        List<ReachableSnapshot> all = loadAllSnapshots();
        int count = 0;
        for (ReachableSnapshot s : all) {
            if (projectVersion.equals(s.getProjectVersion())) {
                count++;
            }
        }
        return count + 1;
    }

    /**
     * Converts a snapshot back into an AnalysisSummary so it can be used
     * with ChangeDetector for comparison. The summary only contains the
     * reachable APIs — enough for change detection.
     */
    public static AnalysisSummary toAnalysisSummary(ReachableSnapshot snapshot) {
        // Group records by depGa+version to build DependencyReports
        Map<String, List<ReachableApiRecord>> byDep = new LinkedHashMap<>();
        for (ReachableApiRecord rec : snapshot.getReachableApis()) {
            String key = rec.depGroupId() + ":" + rec.depArtifactId() + ":" + rec.depVersion();
            byDep.computeIfAbsent(key, k -> new ArrayList<>()).add(rec);
        }

        List<DependencyReport> reports = new ArrayList<>();
        Set<String> reachableKeys = new HashSet<>();

        for (Map.Entry<String, List<ReachableApiRecord>> entry : byDep.entrySet()) {
            List<ReachableApiRecord> recs = entry.getValue();
            ReachableApiRecord first = recs.get(0);

            List<SensitiveApiEntry> apis = new ArrayList<>();
            for (ReachableApiRecord rec : recs) {
                apis.add(new SensitiveApiEntry(
                        rec.sensitiveApi(), "", rec.accessType(),
                        List.of(), List.of(), rec.category(), rec.subcategory()));
                reachableKeys.add(first.depGroupId() + ":" + first.depArtifactId() + ":" + first.depVersion()
                        + "::" + rec.sensitiveApi());
            }

            reports.add(new DependencyReport(
                    first.depGroupId(), first.depArtifactId(), first.depVersion(), "jar",
                    apis, 0, snapshot.getTimestamp()));
        }

        return new AnalysisSummary(
                snapshot.getProjectGroupId(), snapshot.getProjectArtifactId(),
                snapshot.getProjectVersion(), reports, reachableKeys, snapshot.getTimestamp());
    }

    /**
     * Extracts the reachable API records from an analysis summary.
     * Only includes APIs that are marked as reachable from the client.
     */
    private List<ReachableApiRecord> extractReachableRecords(AnalysisSummary summary) {
        List<ReachableApiRecord> records = new ArrayList<>();

        for (DependencyReport dep : summary.getDependencyReports()) {
            for (SensitiveApiEntry entry : dep.getSensitiveApis()) {
                if (!summary.isReachable(dep.gav(), entry.sensitiveApi())) continue;

                records.add(new ReachableApiRecord(
                        dep.getGroupId(),
                        dep.getArtifactId(),
                        dep.getVersion(),
                        entry.sensitiveApi(),
                        entry.accessType(),
                        entry.category(),
                        entry.subcategory()
                ));
            }
        }

        return records;
    }
}
