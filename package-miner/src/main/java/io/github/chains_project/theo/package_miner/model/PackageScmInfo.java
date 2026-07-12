package io.github.chains_project.theo.package_miner.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public record PackageScmInfo(
        @JsonProperty("groupId") String groupId,
        @JsonProperty("artifactId") String artifactId,
        @JsonProperty("latestVersion") String latestVersion,
        @JsonProperty("dependentReposCount") long dependentReposCount,
        @JsonProperty("scmUrl") String scmUrl
) {
    public static PackageScmInfo from(PackageInfo pkg, String scmUrl) {
        return new PackageScmInfo(pkg.groupId(), pkg.artifactId(), pkg.latestVersion(),
                pkg.dependentReposCount(), scmUrl);
    }
}
