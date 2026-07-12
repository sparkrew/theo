package io.github.chains_project.theo.package_miner;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.chains_project.theo.package_miner.model.PackageInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

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

        MavenCentralClient client = new MavenCentralClient();

        log.info("=============================================================");
        log.info("  COLLECT — cutoff year {}, limit {}",
                cutoffYear, totalPackages <= 0 ? "ALL" : totalPackages);
        log.info("=============================================================");

        List<PackageInfo> packages;
        try {
            packages = client.fetchPopularJavaPackages(totalPackages, cutoffYear);
        } catch (Exception e) {
            log.error("Failed to fetch packages from ecosyste.ms.", e);
            return;
        }

        if (packages == null || packages.isEmpty()) {
            log.error("No packages collected.");
            return;
        }

        Path listFile = outputDir.resolve("selected_packages.json");
        try {
            new ObjectMapper().writerWithDefaultPrettyPrinter()
                    .writeValue(listFile.toFile(), packages);
        } catch (IOException e) {
            log.error("Failed to save package list.", e);
            return;
        }

        log.info("Collected {} packages. Saved to {}", packages.size(), listFile);
    }
}
