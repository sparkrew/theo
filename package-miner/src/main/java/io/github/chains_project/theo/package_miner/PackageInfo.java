package io.github.chains_project.theo.package_miner;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Represents a single Maven package with its coordinates, download count, and optional SCM URL.
 * This is what we get back from Maven Central's search API (plus SCM extracted from the POM),
 * and what we persist in the selected_packages.json checkpoint file.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record PackageInfo(
        @JsonProperty("groupId") String groupId,
        @JsonProperty("artifactId") String artifactId,
        @JsonProperty("latestVersion") String latestVersion,
        @JsonProperty("downloadCount") long downloadCount,
        @JsonProperty("scmUrl") String scmUrl
) {

    /**
     * Constructor without scmUrl for backward compatibility.
     */
    public PackageInfo(String groupId, String artifactId, String latestVersion, long downloadCount) {
        this(groupId, artifactId, latestVersion, downloadCount, null);
    }

    /**
     * Returns the standard Maven coordinate string, e.g. "com.google.guava:guava:32.1.3-jre".
     * We use this as the unique key for checkpointing.
     */
    public String coordinate() {
        return groupId + ":" + artifactId + ":" + latestVersion;
    }
}
