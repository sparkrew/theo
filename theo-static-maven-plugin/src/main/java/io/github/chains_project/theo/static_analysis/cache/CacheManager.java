package io.github.chains_project.theo.static_analysis.cache;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.core.type.TypeReference;
import io.github.chains_project.theo.static_analysis.model.AnalysisSummary;
import io.github.chains_project.theo.static_analysis.model.BoundaryInteraction;
import io.github.chains_project.theo.static_analysis.model.CacheKey;
import io.github.chains_project.theo.static_analysis.model.DependencyReport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Manages a persistent on-disk cache so that dependency analysis results
 * survive across runs. If a dependency hasn't changed (same GAV coordinates),
 * we skip the expensive re-analysis and just load the previous report.
 *
 * Cache layout:
 *   {cacheDir}/dependencies/{groupId}/{artifactId}/{version}/report.json
 *   {cacheDir}/projects/{groupId}__{artifactId}__{version}/last-run.json
 */
public class CacheManager {

    private static final Logger logger = LoggerFactory.getLogger(CacheManager.class);

    private static final String REPORT_FILE = "report.json";
    private static final String LAST_RUN_FILE = "last-run.json";
    private static final String BOUNDARY_FILE = "boundary-interactions.json";
    private static final String PACKAGE_MAP_FILE = "package-map.json";

    private final Path cacheDir;
    private final ObjectMapper mapper;

    public CacheManager(Path cacheDir) {
        this.cacheDir = cacheDir;
        this.mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

        // Make sure the cache root exists on first use so callers
        // don't have to worry about it themselves.
        try {
            Files.createDirectories(cacheDir);
        } catch (IOException e) {
            logger.warn("Could not create cache directory at {}: {}", cacheDir, e.getMessage());
        }
    }

    // ---- dependency reports ------------------------------------------------

    /**
     * Quick existence check — avoids the cost of deserialising the report
     * when all we need to know is whether we've seen this dependency before.
     */
    public boolean isCached(CacheKey key) {
        return Files.exists(dependencyReportPath(key));
    }

    /**
     * Loads a previously stored report for the given dependency.
     * Returns null when no cached data exists or when the file is corrupt,
     * so the caller can simply fall back to a fresh analysis.
     */
    public DependencyReport loadDependencyReport(CacheKey key) {
        Path path = dependencyReportPath(key);
        if (!Files.exists(path)) {
            return null;
        }
        try {
            return mapper.readValue(path.toFile(), DependencyReport.class);
        } catch (IOException e) {
            logger.warn("Failed to read cached report at {} — will re-analyse: {}",
                    path, e.getMessage());
            return null;
        }
    }

    /**
     * Persists the analysis report for a dependency so future runs can reuse it.
     */
    public void storeDependencyReport(CacheKey key, DependencyReport report) {
        Path path = dependencyReportPath(key);
        try {
            Files.createDirectories(path.getParent());
            mapper.writeValue(path.toFile(), report);
            logger.debug("Cached dependency report at {}", path);
        } catch (IOException e) {
            // Not fatal — we just lose the caching benefit for this dependency.
            logger.warn("Could not write cached report to {}: {}", path, e.getMessage());
        }
    }

    // ---- project-level last-run metadata -----------------------------------

    /**
     * Loads the metadata snapshot from the last time we analysed this project.
     * Useful for detecting which dependencies changed since the previous run.
     */
    public AnalysisSummary loadLastRun(String projectGroupId,
                                       String projectArtifactId) {
        Path path = projectLastRunPath(projectGroupId, projectArtifactId);
        if (!Files.exists(path)) {
            return null;
        }
        try {
            return mapper.readValue(path.toFile(), AnalysisSummary.class);
        } catch (IOException e) {
            logger.warn("Failed to read last-run metadata at {}: {}", path, e.getMessage());
            return null;
        }
    }

    /**
     * Saves a snapshot of this analysis run so we can diff against it next time.
     */
    public void storeLastRun(AnalysisSummary summary) {
        Path path = projectLastRunPath(
                summary.getProjectGroupId(),
                summary.getProjectArtifactId());
        try {
            Files.createDirectories(path.getParent());
            mapper.writeValue(path.toFile(), summary);
            logger.debug("Stored last-run metadata at {}", path);
        } catch (IOException e) {
            logger.warn("Could not write last-run metadata to {}: {}", path, e.getMessage());
        }
    }

    // ---- boundary interactions and package map ------------------------------

    public void storeBoundaryInteractions(String groupId, String artifactId,
                                          List<BoundaryInteraction> boundaries) {
        Path path = projectDir(groupId, artifactId).resolve(BOUNDARY_FILE);
        try {
            Files.createDirectories(path.getParent());
            mapper.writeValue(path.toFile(), boundaries);
            logger.debug("Stored {} boundary interactions at {}", boundaries.size(), path);
        } catch (IOException e) {
            logger.warn("Could not write boundary interactions to {}: {}", path, e.getMessage());
        }
    }

    public List<BoundaryInteraction> loadBoundaryInteractions(String groupId, String artifactId) {
        Path path = projectDir(groupId, artifactId).resolve(BOUNDARY_FILE);
        if (!Files.exists(path)) {
            return Collections.emptyList();
        }
        try {
            return mapper.readValue(path.toFile(), new TypeReference<List<BoundaryInteraction>>() {});
        } catch (IOException e) {
            logger.warn("Failed to read boundary interactions at {}: {}", path, e.getMessage());
            return Collections.emptyList();
        }
    }

    public void storePackageMap(String groupId, String artifactId,
                                Map<String, Set<String>> packageMap) {
        Path path = projectDir(groupId, artifactId).resolve(PACKAGE_MAP_FILE);
        try {
            Files.createDirectories(path.getParent());
            mapper.writeValue(path.toFile(), packageMap);
            logger.debug("Stored package map at {}", path);
        } catch (IOException e) {
            logger.warn("Could not write package map to {}: {}", path, e.getMessage());
        }
    }

    public Map<String, Set<String>> loadPackageMap(String groupId, String artifactId) {
        Path path = projectDir(groupId, artifactId).resolve(PACKAGE_MAP_FILE);
        if (!Files.exists(path)) {
            return null;
        }
        try {
            return mapper.readValue(path.toFile(),
                    new TypeReference<Map<String, Set<String>>>() {});
        } catch (IOException e) {
            logger.warn("Failed to read package map at {}: {}", path, e.getMessage());
            return null;
        }
    }

    // ---- path helpers ------------------------------------------------------

    private Path dependencyReportPath(CacheKey key) {
        return cacheDir.resolve("dependencies")
                .resolve(key.groupId())
                .resolve(key.artifactId())
                .resolve(key.version())
                .resolve(REPORT_FILE);
    }

    private Path projectDir(String groupId, String artifactId) {
        String dirName = groupId + "__" + artifactId;
        return cacheDir.resolve("projects").resolve(dirName);
    }

    private Path projectLastRunPath(String groupId, String artifactId) {
        return projectDir(groupId, artifactId).resolve(LAST_RUN_FILE);
    }
}
