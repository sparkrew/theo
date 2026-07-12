package io.github.chains_project.theo.package_miner.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record PackageInfo(
        @JsonProperty("groupId") String groupId,
        @JsonProperty("artifactId") String artifactId,
        @JsonProperty("latestVersion") String latestVersion,
        @JsonProperty("dependentReposCount") long dependentReposCount
) {
    public String coordinate() {
        return groupId + ":" + artifactId + ":" + latestVersion;
    }
}
