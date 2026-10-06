package io.github.chains_project.theo.static_analysis.model;

/**
 * Immutable key used to locate cached dependency analysis results on disk.
 * The path layout mirrors Maven's coordinate system so cache entries are
 * easy to find and prune manually.
 */
public record CacheKey(String groupId, String artifactId, String version) {

    /**
     * Returns the on-disk path where a dependency-level cache file lives.
     * Follows a Maven-like directory convention so the cache is human-browsable.
     */
    public String toCachePath() {
        return "dependencies/" + groupId + "/" + artifactId + "/" + version;
    }

    /**
     * Returns the cache path for a whole-project analysis result.
     * Colons are replaced with double underscores because colons are
     * illegal in file names on Windows and awkward on most filesystems.
     */
    public String toProjectCachePath(String projectGav) {
        return "projects/" + projectGav.replace(":", "__");
    }

    /** Convenience factory that reads like the GAV it represents. */
    public static CacheKey fromArtifactGav(String groupId, String artifactId, String version) {
        return new CacheKey(groupId, artifactId, version);
    }

    @Override
    public String toString() {
        return groupId + ":" + artifactId + ":" + version;
    }
}
