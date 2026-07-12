package io.github.chains_project.theo.package_miner.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public record PackageInfo(
        @JsonProperty("groupId") String groupId,
        @JsonProperty("artifactId") String artifactId,
        @JsonProperty("latestVersion") String latestVersion,
        @JsonProperty("downloadCount") long downloadCount,
        @JsonProperty("scmUrl") String scmUrl
) {

    public PackageInfo(String groupId, String artifactId, String latestVersion, long downloadCount) {
        this(groupId, artifactId, latestVersion, downloadCount, null);
    }

    public String coordinate() {
        return groupId + ":" + artifactId + ":" + latestVersion;
    }
}
