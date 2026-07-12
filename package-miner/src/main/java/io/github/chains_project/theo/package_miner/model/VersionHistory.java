package io.github.chains_project.theo.package_miner.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Set;

public class VersionHistory {

    public record VersionSnapshot(
            @JsonProperty("version") String version,
            @JsonProperty("timestamp") long timestamp,
            @JsonProperty("directApis") Set<String> directApis,
            @JsonProperty("indirectApis") Set<String> indirectApis
    ) {
        public Set<String> allApis() {
            var all = new java.util.HashSet<>(directApis);
            all.addAll(indirectApis);
            return all;
        }
    }

    public record PermissionChange(
            @JsonProperty("fromVersion") String fromVersion,
            @JsonProperty("toVersion") String toVersion,
            @JsonProperty("addedDirect") Set<String> addedDirect,
            @JsonProperty("removedDirect") Set<String> removedDirect,
            @JsonProperty("addedIndirect") Set<String> addedIndirect,
            @JsonProperty("removedIndirect") Set<String> removedIndirect
    ) {
        public boolean hasChanges() {
            return !addedDirect.isEmpty() || !removedDirect.isEmpty()
                    || !addedIndirect.isEmpty() || !removedIndirect.isEmpty();
        }
    }

    public record PackageVersionHistory(
            @JsonProperty("groupId") String groupId,
            @JsonProperty("artifactId") String artifactId,
            @JsonProperty("snapshots") List<VersionSnapshot> snapshots,
            @JsonProperty("changes") List<PermissionChange> changes,
            @JsonProperty("hasPermissionChanges") boolean hasPermissionChanges
    ) {}
}
