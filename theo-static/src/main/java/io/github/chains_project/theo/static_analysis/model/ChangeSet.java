package io.github.chains_project.theo.static_analysis.model;

import java.util.List;

/**
 * The diff between two analysis runs. Used only in memory to drive
 * reporting, so there is no need for Jackson annotations or caching support.
 */
public class ChangeSet {

    private final List<DependencyReport> addedDependencies;
    private final List<DependencyReport> removedDependencies;
    private final List<DependencyChange> modifiedDependencies;
    private final boolean hasPreviousRun;

    public ChangeSet(List<DependencyReport> addedDependencies,
                     List<DependencyReport> removedDependencies,
                     List<DependencyChange> modifiedDependencies,
                     boolean hasPreviousRun) {
        this.addedDependencies = addedDependencies;
        this.removedDependencies = removedDependencies;
        this.modifiedDependencies = modifiedDependencies;
        this.hasPreviousRun = hasPreviousRun;
    }

    /** True when anything actually changed between the two runs. */
    public boolean hasChanges() {
        return !addedDependencies.isEmpty()
                || !removedDependencies.isEmpty()
                || !modifiedDependencies.isEmpty();
    }

    /** Quick count of all individual changes for summary lines. */
    public int totalChanges() {
        return addedDependencies.size()
                + removedDependencies.size()
                + modifiedDependencies.size();
    }

    public List<DependencyReport> getAddedDependencies() {
        return addedDependencies;
    }

    public List<DependencyReport> getRemovedDependencies() {
        return removedDependencies;
    }

    public List<DependencyChange> getModifiedDependencies() {
        return modifiedDependencies;
    }

    public boolean hasPreviousRun() {
        return hasPreviousRun;
    }

    /**
     * Tracks how a specific dependency's sensitive API surface changed
     * between versions, without duplicating the full report data.
     */
    public record DependencyChange(
            String groupId,
            String artifactId,
            String oldVersion,
            String newVersion,
            List<SensitiveApiEntry> addedApis,
            List<SensitiveApiEntry> removedApis
    ) {
        /** Returns the GAV for the current (new) version of this dependency. */
        public String gav() {
            return groupId + ":" + artifactId + ":" + newVersion;
        }
    }
}
