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
 * Two things are persisted:
 * 1. selected_packages.json — the full list of 2000 packages that were chosen.
 *    This is saved once after the selection phase, so if we restart we don't
 *    re-query Maven Central and end up with a different package list.
 *
 * 2. checkpoint.json — a list of Maven coordinates (groupId:artifactId:version)
 *    for packages that have already been analyzed. On resume, we skip these.
 *
 * The checkpoint is updated after each package completes (including failures),
 * so even if the process crashes mid-run, we lose at most one package's work.
 * The set is thread-safe so multiple workers can mark packages as completed concurrently.
 */
public class CheckpointManager {

    private static final Logger log = LoggerFactory.getLogger(CheckpointManager.class);

    private final Path checkpointFile;
    private final Path packageListFile;
    private final ObjectMapper mapper;
    // Thread-safe set of completed package coordinates
    private final Set<String> completedPackages;

    public CheckpointManager(Path outputDir) {
        this.checkpointFile = outputDir.resolve("checkpoint.json");
        this.packageListFile = outputDir.resolve("selected_packages.json");
        this.mapper = new ObjectMapper();
        this.completedPackages = Collections.synchronizedSet(new HashSet<>());
        load();
    }

    /**
     * Loads previously completed packages from the checkpoint file, if it exists.
     * If the file is corrupted or unreadable, we start fresh.
     */
    private void load() {
        if (Files.exists(checkpointFile)) {
            try {
                List<String> saved = mapper.readValue(
                        checkpointFile.toFile(), new TypeReference<>() {}
                );
                completedPackages.addAll(saved);
                log.info("Loaded checkpoint with {} completed packages.", completedPackages.size());
            } catch (IOException e) {
                log.warn("Failed to load checkpoint, starting fresh.", e);
            }
        }
    }

    /** Checks whether this package was already analyzed in a previous run. */
    public boolean isCompleted(PackageInfo pkg) {
        return completedPackages.contains(pkg.coordinate());
    }

    /**
     * Marks a package as completed and immediately writes the checkpoint to disk.
     * This is called after each package finishes (success or failure), so we can
     * resume without re-analyzing it.
     */
    public void markCompleted(PackageInfo pkg) {
        completedPackages.add(pkg.coordinate());
        save();
    }

    /** Writes the current set of completed packages to checkpoint.json. */
    public void save() {
        try {
            mapper.writeValue(checkpointFile.toFile(), new ArrayList<>(completedPackages));
        } catch (IOException e) {
            log.error("Failed to save checkpoint.", e);
        }
    }

    /**
     * Loads the previously selected package list from disk.
     * Returns null if no package list was saved yet (i.e., this is a fresh run).
     */
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

    /**
     * Saves the selected package list to disk. This is done once after the initial
     * selection, so on resume we use the exact same list of packages.
     */
    public void savePackageList(List<PackageInfo> packages) {
        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(packageListFile.toFile(), packages);
            log.info("Saved package list with {} packages.", packages.size());
        } catch (IOException e) {
            log.error("Failed to save package list.", e);
        }
    }

    /** Returns how many packages have been completed so far. */
    public int completedCount() {
        return completedPackages.size();
    }
}
