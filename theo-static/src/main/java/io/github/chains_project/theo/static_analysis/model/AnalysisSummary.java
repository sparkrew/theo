package io.github.chains_project.theo.static_analysis.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Top-level container for an entire project analysis run.
 * Holds every dependency report plus the set of sensitive APIs
 * that are actually reachable from the project's own code.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class AnalysisSummary {

    private String projectGroupId;
    private String projectArtifactId;
    private String projectVersion;
    private List<DependencyReport> dependencyReports;

    /**
     * Sensitive APIs that the project's client code can actually reach.
     * Stored as "depGav::sensitiveApi" so we can tell which dependency
     * exposes which API without needing a composite key object.
     */
    private Set<String> reachableSensitiveApis;
    private long analyzedAt;

    /** Required by Jackson for deserialization. */
    public AnalysisSummary() {
    }

    public AnalysisSummary(String projectGroupId, String projectArtifactId, String projectVersion,
                           List<DependencyReport> dependencyReports, Set<String> reachableSensitiveApis,
                           long analyzedAt) {
        this.projectGroupId = projectGroupId;
        this.projectArtifactId = projectArtifactId;
        this.projectVersion = projectVersion;
        this.dependencyReports = dependencyReports;
        this.reachableSensitiveApis = reachableSensitiveApis != null ? reachableSensitiveApis : new HashSet<>();
        this.analyzedAt = analyzedAt;
    }

    /**
     * Checks whether a specific sensitive API in a specific dependency
     * is reachable from the project's own source code.
     */
    public boolean isReachable(String depGav, String sensitiveApi) {
        return reachableSensitiveApis != null
                && reachableSensitiveApis.contains(depGav + "::" + sensitiveApi);
    }

    /** Returns only those dependency reports that found at least one sensitive API. */
    public List<DependencyReport> getReportsWithSensitiveApis() {
        if (dependencyReports == null) {
            return List.of();
        }
        return dependencyReports.stream()
                .filter(DependencyReport::hasSensitiveApis)
                .collect(Collectors.toList());
    }

    // --- getters and setters for Jackson ---

    public String getProjectGroupId() {
        return projectGroupId;
    }

    public void setProjectGroupId(String projectGroupId) {
        this.projectGroupId = projectGroupId;
    }

    public String getProjectArtifactId() {
        return projectArtifactId;
    }

    public void setProjectArtifactId(String projectArtifactId) {
        this.projectArtifactId = projectArtifactId;
    }

    public String getProjectVersion() {
        return projectVersion;
    }

    public void setProjectVersion(String projectVersion) {
        this.projectVersion = projectVersion;
    }

    public List<DependencyReport> getDependencyReports() {
        return dependencyReports;
    }

    public void setDependencyReports(List<DependencyReport> dependencyReports) {
        this.dependencyReports = dependencyReports;
    }

    public Set<String> getReachableSensitiveApis() {
        return reachableSensitiveApis;
    }

    public void setReachableSensitiveApis(Set<String> reachableSensitiveApis) {
        this.reachableSensitiveApis = reachableSensitiveApis;
    }

    public long getAnalyzedAt() {
        return analyzedAt;
    }

    public void setAnalyzedAt(long analyzedAt) {
        this.analyzedAt = analyzedAt;
    }
}
