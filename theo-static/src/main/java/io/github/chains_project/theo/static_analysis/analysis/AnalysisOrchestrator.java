package io.github.chains_project.theo.static_analysis.analysis;

import io.github.chains_project.theo.static_analysis.cache.CacheManager;
import io.github.chains_project.theo.static_analysis.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.*;

/**
 * Coordinates the full static analysis: analyzes each dependency for sensitive
 * API usage, checks which of those APIs are reachable from the client project,
 * and merges everything into a single summary.
 */
public class AnalysisOrchestrator {

    private static final Logger log = LoggerFactory.getLogger(AnalysisOrchestrator.class);

    private final DependencyAnalyzer dependencyAnalyzer;
    private final ClientReachabilityAnalyzer reachabilityAnalyzer;
    private final CacheManager cacheManager;

    /**
     * Wires the three collaborators together. Each handles a distinct phase:
     * the dependency analyzer runs the CLI tool per-JAR, the reachability
     * analyzer walks the client call graph, and the cache manager persists
     * results between builds.
     */
    public AnalysisOrchestrator(DependencyAnalyzer dependencyAnalyzer,
                                ClientReachabilityAnalyzer reachabilityAnalyzer,
                                CacheManager cacheManager) {
        this.dependencyAnalyzer = dependencyAnalyzer;
        this.reachabilityAnalyzer = Objects.requireNonNull(reachabilityAnalyzer, "reachabilityAnalyzer must not be null");
        this.cacheManager = Objects.requireNonNull(cacheManager, "cacheManager must not be null");
    }

    /**
     * Runs the full analysis.
     *
     * @param projectGroupId    the client project's groupId
     * @param projectArtifactId the client project's artifactId
     * @param projectVersion    the client project's version
     * @param projectJarPath    path to the client project's compiled JAR
     * @param packageNames      the client project's own package names (comma-separated or as list)
     * @param packageMapPath    path to the package-to-dependency map JSON
     * @param dependencies      map of CacheKey -> (jarPath, packageNames) for each dependency
     * @return the complete AnalysisSummary
     */
    public AnalysisSummary analyze(String projectGroupId, String projectArtifactId,
                                   String projectVersion, String projectJarPath,
                                   List<String> packageNames, Path packageMapPath,
                                   List<DependencyInfo> dependencies, Path depsDir) {

        log.info("Starting analysis for {}:{}:{} with {} dependencies",
                projectGroupId, projectArtifactId, projectVersion, dependencies.size());

        // Step 1: Analyze each dependency (check cache first)
        // For each dependency, we either pull the result from disk or run the
        // expensive CLI analysis. Snapshot versions are always re-analyzed
        // because their contents can change between builds.
        List<DependencyReport> reports = new ArrayList<>();
        int cachedCount = 0;

        for (DependencyInfo dep : dependencies) {
            CacheKey key = CacheKey.fromArtifactGav(dep.groupId(), dep.artifactId(), dep.version());

            // Snapshots are always re-analyzed because they can change between builds
            if (!dep.version().endsWith("-SNAPSHOT") && cacheManager.isCached(key)) {
                DependencyReport cached = cacheManager.loadDependencyReport(key);
                if (cached != null) {
                    log.info("Using cached result for {}", key);
                    reports.add(cached);
                    cachedCount++;
                    continue;
                }
                // Cache file was corrupt or unreadable, fall through to re-analyze
                log.debug("Cache hit but load failed for {} -- will re-analyze", key);
            }

            log.debug("Analyzing dependency {}", key);
            DependencyReport report = dependencyAnalyzer.analyze(
                    dep.groupId(), dep.artifactId(), dep.version(), dep.type(),
                    dep.jarPath(), dep.packageNames()
            );
            report.setScope(dep.scope());
            report.setDependencyDepth(dep.dependencyDepth());
            cacheManager.storeDependencyReport(key, report);
            reports.add(report);
        }

        log.info("Dependency analysis complete: {} cached, {} freshly analyzed",
                cachedCount, dependencies.size() - cachedCount);

        // Step 2: Run client reachability analysis
        // Uses findReachableEntries to get both the reachable keys and the full
        // client-rooted entries (with paths starting from client methods).
        log.info("Running client reachability analysis on {}", projectJarPath);
        Map<String, List<SensitiveApiEntry>> rawEntries = reachabilityAnalyzer.findReachableEntries(
                projectJarPath, packageNames, packageMapPath, depsDir
        );

        // Normalize the keys from PackageMatcher format (groupId.artifactId:version)
        // to DependencyReport.gav() format (groupId:artifactId:version).
        Map<String, String> depKeyMapping = new HashMap<>();
        for (DependencyReport dep : reports) {
            String matcherFormat = dep.getGroupId() + "." + dep.getArtifactId() + ":" + dep.getVersion();
            depKeyMapping.put(matcherFormat, dep.gav());
        }

        Set<String> reachable = new HashSet<>();
        Map<String, List<SensitiveApiEntry>> normalizedEntries = new HashMap<>();
        for (Map.Entry<String, List<SensitiveApiEntry>> entry : rawEntries.entrySet()) {
            String normalizedGav = depKeyMapping.get(entry.getKey());
            if (normalizedGav != null) {
                normalizedEntries.put(normalizedGav, entry.getValue());
                for (SensitiveApiEntry api : entry.getValue()) {
                    reachable.add(normalizedGav + "::" + api.sensitiveApi());
                }
            }
        }
        log.info("Found {} reachable sensitive APIs from client code", reachable.size());

        // Step 3: Merge into AnalysisSummary
        AnalysisSummary summary = new AnalysisSummary(
                projectGroupId, projectArtifactId, projectVersion,
                reports, reachable, System.currentTimeMillis()
        );
        summary.setReachableEntries(normalizedEntries);

        // Step 4: Cache this run for future change detection
        cacheManager.storeLastRun(summary);
        log.info("Analysis complete for {}:{}:{}", projectGroupId, projectArtifactId, projectVersion);

        return summary;
    }

    /**
     * Lightweight analysis that skips per-dependency subprocess calls. Only runs
     * the client reachability analysis, which is fast because it uses the project's
     * own JAR and call graph. The resulting summary has DependencyReports built from
     * the reachability data — enough for the reachable report but not the full
     * all-dependencies report.
     */
    public AnalysisSummary analyzeReachableOnly(String projectGroupId, String projectArtifactId,
                                                 String projectVersion, String projectJarPath,
                                                 List<String> packageNames, Path packageMapPath,
                                                 List<DependencyInfo> dependencies, Path depsDir) {

        log.info("Running reachable-only analysis for {}:{}:{}", projectGroupId, projectArtifactId, projectVersion);

        Map<String, List<SensitiveApiEntry>> entriesByDep =
                reachabilityAnalyzer.findReachableEntries(projectJarPath, packageNames, packageMapPath, depsDir);

        log.info("Found reachable sensitive APIs across {} dependencies", entriesByDep.size());

        // Build DependencyReports from the reachability data. These won't have
        // the full per-dependency analysis but contain enough for the reachable report.
        Map<String, DependencyInfo> depInfoMap = new HashMap<>();
        for (DependencyInfo dep : dependencies) {
            depInfoMap.put(dep.groupId() + ":" + dep.artifactId() + ":" + dep.type()
                    + (dep.version() != null ? ":" + dep.version() : ""), dep);
        }

        List<DependencyReport> reports = new ArrayList<>();
        Set<String> reachableKeys = new HashSet<>();

        for (Map.Entry<String, List<SensitiveApiEntry>> entry : entriesByDep.entrySet()) {
            String depGav = entry.getKey();
            List<SensitiveApiEntry> entries = entry.getValue();

            // PackageMatcher.getDependencyName() returns "groupId.artifactId:version".
            // We match it against the known dependency list to get proper GAV fields,
            // since parsing the dot-separated string is ambiguous (dots appear in both
            // groupId and artifactId).
            DependencyInfo matched = null;
            for (DependencyInfo dep : dependencies) {
                String matchKey = dep.groupId() + "." + dep.artifactId() + ":" + dep.version();
                if (matchKey.equals(depGav)) {
                    matched = dep;
                    break;
                }
            }

            if (matched == null) {
                log.warn("No match for depGav '{}'. Sample dependency keys:", depGav);
                dependencies.stream().limit(3).forEach(d ->
                    log.warn("  candidate: '{}'", d.groupId() + "." + d.artifactId() + ":" + d.version()));
            }

            String gId, aId, ver, type;
            if (matched != null) {
                gId = matched.groupId();
                aId = matched.artifactId();
                ver = matched.version();
                type = matched.type();
            } else {
                // Fallback: split on the last colon to separate version
                int lastColon = depGav.lastIndexOf(':');
                String namepart = lastColon > 0 ? depGav.substring(0, lastColon) : depGav;
                ver = lastColon > 0 ? depGav.substring(lastColon + 1) : "";
                gId = namepart;
                aId = "";
                type = "jar";
                log.warn("Could not match dependency '{}' to a known artifact", depGav);
            }

            DependencyReport report = new DependencyReport(gId, aId, ver, type,
                    entries, 0, System.currentTimeMillis());

            if (matched != null) {
                report.setScope(matched.scope());
                report.setDependencyDepth(matched.dependencyDepth());
            }

            reports.add(report);

            for (SensitiveApiEntry apiEntry : entries) {
                reachableKeys.add(report.gav() + "::" + apiEntry.sensitiveApi());
            }
        }

        // In reachableOnly mode, the DependencyReport entries ARE the client-rooted
        // entries, so we use them directly as reachableEntries too.
        Map<String, List<SensitiveApiEntry>> reachableEntryMap = new HashMap<>();
        for (DependencyReport report : reports) {
            if (report.hasSensitiveApis()) {
                reachableEntryMap.put(report.gav(), report.getSensitiveApis());
            }
        }

        AnalysisSummary summary = new AnalysisSummary(
                projectGroupId, projectArtifactId, projectVersion,
                reports, reachableKeys, System.currentTimeMillis()
        );
        summary.setReachableEntries(reachableEntryMap);

        cacheManager.storeLastRun(summary);
        return summary;
    }

    /**
     * Loads the previous analysis run from cache for change detection.
     * Returns null if this is the first time the project has been analyzed.
     */
    public AnalysisSummary loadPreviousRun(String projectGroupId, String projectArtifactId) {
        log.debug("Loading previous run for {}:{}", projectGroupId, projectArtifactId);
        return cacheManager.loadLastRun(projectGroupId, projectArtifactId);
    }

    /**
     * Info about a single dependency to analyze. This is a simple value holder
     * that bundles everything the orchestrator needs to process one dependency.
     */
    public record DependencyInfo(
            String groupId, String artifactId, String version, String type,
            Path jarPath, Set<String> packageNames,
            String scope, int dependencyDepth
    ) {}
}
