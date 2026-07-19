package io.github.chains_project.theo.package_miner;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.chains_project.theo.package_miner.model.VersionHistory;
import io.github.chains_project.theo.package_miner.util.MavenVersionParser;
import io.github.chains_project.theo.package_miner.util.ReleaseLineGrouper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import picocli.CommandLine;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Stream;

@CommandLine.Command(name = "reprocess-history", mixinStandardHelpOptions = true,
        description = "Reprocess existing version history files with release-line-aware comparison.")
public class ReprocessHistoryCommand implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(ReprocessHistoryCommand.class);

    @CommandLine.Option(names = {"-o", "--output-dir"}, paramLabel = "OUTPUT-DIR",
            description = "Directory containing the version-history folder.", required = true)
    Path outputDir;

    @Override
    public void run() {
        Path historyDir = outputDir.resolve("version-history");
        if (!Files.isDirectory(historyDir)) {
            log.error("No version-history directory found in {}.", outputDir);
            return;
        }

        ObjectMapper mapper = new ObjectMapper();
        int processed = 0;
        int updated = 0;

        try (Stream<Path> files = Files.list(historyDir)) {
            for (Path file : files.filter(f -> f.toString().endsWith("-history.json")).toList()) {
                try {
                    VersionHistory.PackageVersionHistory history = mapper.readValue(
                            file.toFile(), new TypeReference<>() {});

                    VersionHistory.PackageVersionHistory reprocessed = reprocess(history);
                    mapper.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), reprocessed);
                    processed++;

                    if (reprocessed.hasPermissionChanges() != history.hasPermissionChanges()
                            || reprocessed.changes().size() != history.changes().size()) {
                        updated++;
                    }
                } catch (IOException e) {
                    log.warn("Failed to reprocess {}: {}", file.getFileName(), e.getMessage());
                }
            }
        } catch (IOException e) {
            log.error("Failed to list history files.", e);
            return;
        }

        log.info("Reprocessed {} history files ({} had changes in comparison structure).", processed, updated);

        try {
            new VersionHistoryVisualizer().generateReport(outputDir);
        } catch (IOException e) {
            log.error("Failed to regenerate report.", e);
        }
    }

    private VersionHistory.PackageVersionHistory reprocess(VersionHistory.PackageVersionHistory history) {
        List<VersionHistory.VersionSnapshot> snapshots = history.snapshots();
        if (snapshots.size() < 2) {
            return history;
        }

        Map<String, VersionHistory.VersionSnapshot> snapshotByVersion = new LinkedHashMap<>();
        for (VersionHistory.VersionSnapshot snap : snapshots) {
            snapshotByVersion.put(snap.version(), snap);
        }

        List<MavenVersionParser.ParsedVersion> parsedVersions = snapshots.stream()
                .map(s -> MavenVersionParser.parse(s.version()))
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

        return new VersionHistory.PackageVersionHistory(
                history.groupId(), history.artifactId(), orderedSnapshots, changes, hasChanges);
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
}
