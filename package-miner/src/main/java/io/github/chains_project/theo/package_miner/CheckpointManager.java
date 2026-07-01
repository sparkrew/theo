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
 * Manages checkpointing so the mining process can be stopped and resumed.
 *
 * Persisted files:
 * 1. selected_packages.json — packages discovered in phase 1
 * 2. validated_repos.json — cloned/built repos from phase 2
 * 3. checkpoint.json — completed module coordinates from phase 3
 * 4. version_history_checkpoint.json — batch index for phase 4
 */
public class CheckpointManager {

    private static final Logger log = LoggerFactory.getLogger(CheckpointManager.class);

    private final Path checkpointFile;
    private final Path packageListFile;
    private final Path repoListFile;
    private final Path versionHistoryCheckpointFile;
    private final ObjectMapper mapper;
    private final Set<String> completedPackages;

    public CheckpointManager(Path outputDir) {
        this.checkpointFile = outputDir.resolve("checkpoint.json");
        this.packageListFile = outputDir.resolve("selected_packages.json");
        this.repoListFile = outputDir.resolve("validated_repos.json");
        this.versionHistoryCheckpointFile = outputDir.resolve("version_history_checkpoint.json");
        this.mapper = new ObjectMapper();
        this.completedPackages = Collections.synchronizedSet(new HashSet<>());
        load();
    }

    private void load() {
        if (Files.exists(checkpointFile)) {
            try {
                List<String> saved = mapper.readValue(
                        checkpointFile.toFile(), new TypeReference<>() {}
                );
                completedPackages.addAll(saved);
                log.info("Loaded checkpoint with {} completed modules.", completedPackages.size());
            } catch (IOException e) {
                log.warn("Failed to load checkpoint, starting fresh.", e);
            }
        }
    }

    public boolean isCompleted(String coordinate) {
        return completedPackages.contains(coordinate);
    }

    public boolean isCompleted(PackageInfo pkg) {
        return completedPackages.contains(pkg.coordinate());
    }

    public void markCompleted(String coordinate) {
        completedPackages.add(coordinate);
        save();
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

    // --- Package list (phase 1) ---

    public List<PackageInfo> loadPackageList() {
        if (Files.exists(packageListFile)) {
            try {
                List<PackageInfo> saved = mapper.readValue(
                        packageListFile.toFile(), new TypeReference<>() {}
                );
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

    // --- Repo list (phase 2) ---

    public List<GitHubProject.RepoInfo> loadRepoList() {
        if (Files.exists(repoListFile)) {
            try {
                List<GitHubProject.RepoInfo> saved = mapper.readValue(
                        repoListFile.toFile(), new TypeReference<>() {}
                );
                log.info("Loaded existing repo list with {} repos.", saved.size());
                return saved;
            } catch (IOException e) {
                log.warn("Failed to load repo list.", e);
            }
        }
        return null;
    }

    public void saveRepoList(List<GitHubProject.RepoInfo> repos) {
        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(repoListFile.toFile(), repos);
            log.info("Saved repo list with {} repos.", repos.size());
        } catch (IOException e) {
            log.error("Failed to save repo list.", e);
        }
    }

    // --- Version history batch tracking (phase 4) ---

    public int getVersionHistoryBatchIndex() {
        if (Files.exists(versionHistoryCheckpointFile)) {
            try {
                Map<String, Object> data = mapper.readValue(
                        versionHistoryCheckpointFile.toFile(), new TypeReference<>() {}
                );
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
