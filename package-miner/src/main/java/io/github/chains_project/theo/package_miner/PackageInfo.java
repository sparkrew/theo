package io.github.chains_project.theo.package_miner;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Represents a single Maven package with its coordinates and download count.
 * This is what we get back from Maven Central's search API, and what we persist
 * in the selected_packages.json checkpoint file.
 */
public record PackageInfo(
        @JsonProperty("groupId") String groupId,
        @JsonProperty("artifactId") String artifactId,
        @JsonProperty("latestVersion") String latestVersion,
        @JsonProperty("downloadCount") long downloadCount
) {

    /**
     * Returns the standard Maven coordinate string, e.g. "com.google.guava:guava:32.1.3-jre".
     * We use this as the unique key for checkpointing.
     */
    public String coordinate() {
        return groupId + ":" + artifactId + ":" + latestVersion;
    }
}
