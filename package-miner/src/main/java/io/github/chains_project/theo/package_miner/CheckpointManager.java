package io.github.chains_project.theo.package_miner;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class CheckpointManager {

    private static final Logger log = LoggerFactory.getLogger(CheckpointManager.class);

    private final Path checkpointFile;
    private final Path packageListFile;
    private final Path versionHistoryCheckpointFile;
    private final ObjectMapper mapper;
    private final Set<String> completedPackages;

    public CheckpointManager(Path outputDir) {
        this.checkpointFile = outputDir.resolve("checkpoint.json");
        this.packageListFile = outputDir.resolve("selected_packages.json");
        this.versionHistoryCheckpointFile = outputDir.resolve("version_history_checkpoint.json");
        this.mapper = new ObjectMapper();
        this.completedPackages = Collections.synchronizedSet(new HashSet<>());
        load();
    }

    private void load() {
        if (Files.exists(checkpointFile)) {
            try {
                List<String> saved = mapper.readValue(checkpointFile.toFile(), new TypeReference<>() {});
                completedPackages.addAll(saved);
                log.info("Loaded checkpoint with {} completed packages.", completedPackages.size());
            } catch (IOException e) {
                log.warn("Failed to load checkpoint, starting fresh.", e);
            }
        }
    }

    public boolean isCompleted(PackageInfo pkg) {
        return completedPackages.contains(pkg.coordinate());
    }

    public void markCompleted(PackageInfo pkg) {
        completedPackages.add(pkg.coordinate());
        save();
    }

    public void save() {
        try {
            mapper.writeValue(checkpointFile.toFile(), new ArrayList<>(completedPackages));
        } catch (IOException e) {
            log.error("Failed to save checkpoint.", e);
        }
    }

    public List<PackageInfo> loadPackageList() {
        if (Files.exists(packageListFile)) {
            try {
                List<PackageInfo> saved = mapper.readValue(packageListFile.toFile(), new TypeReference<>() {});
                log.info("Loaded existing package list with {} packages.", saved.size());
                return saved;
            } catch (IOException e) {
                log.warn("Failed to load package list.", e);
            }
        }
        return null;
    }

    public void savePackageList(List<PackageInfo> packages) {
        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(packageListFile.toFile(), packages);
            log.info("Saved package list with {} packages.", packages.size());
        } catch (IOException e) {
            log.error("Failed to save package list.", e);
        }
    }

    public int getVersionHistoryBatchIndex() {
        if (Files.exists(versionHistoryCheckpointFile)) {
            try {
                Map<String, Object> data = mapper.readValue(
                        versionHistoryCheckpointFile.toFile(), new TypeReference<>() {});
                Object idx = data.get("batchIndex");
                if (idx instanceof Number n) return n.intValue();
            } catch (IOException e) {
                log.warn("Failed to load version history checkpoint.", e);
            }
        }
        return 0;
    }

    public void setVersionHistoryBatchIndex(int index) {
        try {
            mapper.writeValue(versionHistoryCheckpointFile.toFile(), Map.of("batchIndex", index));
        } catch (IOException e) {
            log.error("Failed to save version history checkpoint.", e);
        }
    }

    public int completedCount() {
        return completedPackages.size();
    }
}
