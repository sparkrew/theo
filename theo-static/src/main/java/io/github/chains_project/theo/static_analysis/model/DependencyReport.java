package io.github.chains_project.theo.static_analysis.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * The analysis result for a single dependency. This is the unit that gets
 * serialized to the on-disk cache, so it needs to tolerate fields added
 * in future versions (hence ignoreUnknown).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class DependencyReport {

    private String groupId;
    private String artifactId;
    private String version;
    private String type;
    private List<SensitiveApiEntry> sensitiveApis;
    private int entryPointCount;
    private long analyzedAt;
    private String scope;
    private int dependencyDepth;

    /** Required by Jackson for deserialization. */
    public DependencyReport() {
    }

    public DependencyReport(String groupId, String artifactId, String version, String type,
                            List<SensitiveApiEntry> sensitiveApis, int entryPointCount, long analyzedAt) {
        this.groupId = groupId;
        this.artifactId = artifactId;
        this.version = version;
        this.type = type;
        this.sensitiveApis = sensitiveApis;
        this.entryPointCount = entryPointCount;
        this.analyzedAt = analyzedAt;
    }

    /** Standard Maven GAV coordinate string. */
    public String gav() {
        return groupId + ":" + artifactId + ":" + version;
    }

    public boolean hasSensitiveApis() {
        return sensitiveApis != null && !sensitiveApis.isEmpty();
    }

    public int sensitiveApiCount() {
        return sensitiveApis == null ? 0 : sensitiveApis.size();
    }

    // --- getters and setters for Jackson ---

    public String getGroupId() {
        return groupId;
    }

    public void setGroupId(String groupId) {
        this.groupId = groupId;
    }

    public String getArtifactId() {
        return artifactId;
    }

    public void setArtifactId(String artifactId) {
        this.artifactId = artifactId;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public List<SensitiveApiEntry> getSensitiveApis() {
        return sensitiveApis;
    }

    public void setSensitiveApis(List<SensitiveApiEntry> sensitiveApis) {
        this.sensitiveApis = sensitiveApis;
    }

    public int getEntryPointCount() {
        return entryPointCount;
    }

    public void setEntryPointCount(int entryPointCount) {
        this.entryPointCount = entryPointCount;
    }

    public long getAnalyzedAt() {
        return analyzedAt;
    }

    public void setAnalyzedAt(long analyzedAt) {
        this.analyzedAt = analyzedAt;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public int getDependencyDepth() {
        return dependencyDepth;
    }

    public void setDependencyDepth(int dependencyDepth) {
        this.dependencyDepth = dependencyDepth;
    }
}
