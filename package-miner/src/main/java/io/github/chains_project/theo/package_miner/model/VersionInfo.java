package io.github.chains_project.theo.package_miner.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public record VersionInfo(
        @JsonProperty("groupId") String groupId,
        @JsonProperty("artifactId") String artifactId,
        @JsonProperty("version") String version,
        @JsonProperty("timestamp") long timestamp
) {
    public String coordinate() {
        return groupId + ":" + artifactId + ":" + version;
    }

    public PackageInfo toPackageInfo() {
        return new PackageInfo(groupId, artifactId, version, 0);
    }
}
