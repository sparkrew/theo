package io.github.chains_project.theo.package_miner;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.chains_project.theo.package_miner.model.PackageInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

public class CollectOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(CollectOrchestrator.class);

    private final Path outputDir;
    private final int totalPackages;
    private final int cutoffYear;

    public CollectOrchestrator(Path outputDir, int totalPackages, int cutoffYear) {
        this.outputDir = outputDir;
        this.totalPackages = totalPackages;
        this.cutoffYear = cutoffYear;
    }

    public void run() {
        try {
            Files.createDirectories(outputDir);
        } catch (IOException e) {
            log.error("Failed to create output directory.", e);
            return;
        }

        ObjectMapper mapper = new ObjectMapper();
        Path listFile = outputDir.resolve("selected_packages.json");
        Path checkpointFile = outputDir.resolve("collect_checkpoint.json");

        List<PackageInfo> existingPackages = loadExisting(mapper, listFile);
        int startPage = loadCheckpointPage(mapper, checkpointFile);

        log.info("=============================================================");
        log.info("  COLLECT — cutoff year {}, batch size {}",
                cutoffYear, totalPackages <= 0 ? "ALL" : totalPackages);
        if (!existingPackages.isEmpty()) {
            log.info("  Resuming: {} packages already collected, starting from page {}",
                    existingPackages.size(), startPage);
        }
        log.info("=============================================================");

        MavenCentralClient client = new MavenCentralClient();
        List<PackageInfo> newPackages;
        int lastPage;
        try {
            var result = client.fetchPopularJavaPackagesPaged(totalPackages, cutoffYear, startPage);
            newPackages = result.packages();
            lastPage = result.lastPage();
        } catch (Exception e) {
            log.error("Failed to fetch packages from ecosyste.ms.", e);
            return;
        }

        if (newPackages.isEmpty()) {
            log.info("No new packages collected.");
            return;
        }

        Set<String> existingCoords = new HashSet<>();
        for (PackageInfo p : existingPackages) {
            existingCoords.add(p.coordinate());
        }
        List<PackageInfo> allPackages = new ArrayList<>(existingPackages);
        int duplicates = 0;
        for (PackageInfo p : newPackages) {
            if (existingCoords.add(p.coordinate())) {
                allPackages.add(p);
            } else {
                duplicates++;
            }
        }
        if (duplicates > 0) {
            log.info("Skipped {} duplicate packages during merge.", duplicates);
        }

        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(listFile.toFile(), allPackages);
        } catch (IOException e) {
            log.error("Failed to save package list.", e);
            return;
        }

        saveCheckpointPage(mapper, checkpointFile, lastPage);

        log.info("Collected {} new packages ({} total). Saved to {}",
                newPackages.size(), allPackages.size(), listFile);
        log.info("Next run will resume from page {}.", lastPage);
    }

    private List<PackageInfo> loadExisting(ObjectMapper mapper, Path listFile) {
        if (Files.exists(listFile)) {
            try {
                return mapper.readValue(listFile.toFile(), new TypeReference<>() {});
            } catch (IOException e) {
                log.warn("Failed to load existing package list, starting fresh.", e);
            }
        }
        return new ArrayList<>();
    }

    private int loadCheckpointPage(ObjectMapper mapper, Path checkpointFile) {
        if (Files.exists(checkpointFile)) {
            try {
                Map<String, Object> data = mapper.readValue(checkpointFile.toFile(), new TypeReference<>() {});
                Object page = data.get("nextPage");
                if (page instanceof Number n) return n.intValue();
            } catch (IOException e) {
                log.warn("Failed to load collect checkpoint, starting from page 1.", e);
            }
        }
        return 1;
    }

    private void saveCheckpointPage(ObjectMapper mapper, Path checkpointFile, int nextPage) {
        try {
            mapper.writeValue(checkpointFile.toFile(), Map.of("nextPage", nextPage));
        } catch (IOException e) {
            log.error("Failed to save collect checkpoint.", e);
        }
    }
}
