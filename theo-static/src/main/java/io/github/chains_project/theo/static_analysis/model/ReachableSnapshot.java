package io.github.chains_project.theo.static_analysis.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * A lightweight snapshot of the reachable sensitive APIs at a point in time.
 * Saved to the history folder so users can compare across multiple runs.
 * Intentionally small — only the data needed for the history table.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class ReachableSnapshot {

    private String projectGroupId;
    private String projectArtifactId;
    private String projectVersion;
    private String label;
    private long timestamp;
    private List<ReachableApiRecord> reachableApis;

    public ReachableSnapshot() {
    }

    public ReachableSnapshot(String projectGroupId, String projectArtifactId, String projectVersion,
                             String label, long timestamp, List<ReachableApiRecord> reachableApis) {
        this.projectGroupId = projectGroupId;
        this.projectArtifactId = projectArtifactId;
        this.projectVersion = projectVersion;
        this.label = label;
        this.timestamp = timestamp;
        this.reachableApis = reachableApis;
    }

    public String getProjectGroupId() { return projectGroupId; }
    public void setProjectGroupId(String projectGroupId) { this.projectGroupId = projectGroupId; }

    public String getProjectArtifactId() { return projectArtifactId; }
    public void setProjectArtifactId(String projectArtifactId) { this.projectArtifactId = projectArtifactId; }

    public String getProjectVersion() { return projectVersion; }
    public void setProjectVersion(String projectVersion) { this.projectVersion = projectVersion; }

    public String getLabel() { return label; }
    public void setLabel(String label) { this.label = label; }

    public long getTimestamp() { return timestamp; }
    public void setTimestamp(long timestamp) { this.timestamp = timestamp; }

    public List<ReachableApiRecord> getReachableApis() { return reachableApis; }
    public void setReachableApis(List<ReachableApiRecord> reachableApis) { this.reachableApis = reachableApis; }

    /**
     * One reachable sensitive API entry — just enough for the history table.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record ReachableApiRecord(
            String depGroupId,
            String depArtifactId,
            String depVersion,
            String sensitiveApi,
            String accessType,
            String category,
            String subcategory
    ) {
        public String depGa() {
            return depGroupId + ":" + depArtifactId;
        }
    }
}
