package io.github.chains_project.theo.package_miner;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.nio.file.Path;
import java.util.List;

/**
 * Represents a cloned GitHub repository and its build results.
 */
public class GitHubProject {

    /**
     * Top-level record for a cloned GitHub repo.
     *
     * @param githubUrl  normalized URL (https://github.com/owner/repo)
     * @param owner      GitHub owner/org
     * @param repo       repository name
     * @param cloneDir   local path where the repo was cloned
     * @param modules    list of Maven modules found in this repo
     * @param popularity highest ec_count among Maven packages pointing to this repo
     */
    public record RepoInfo(
            @JsonProperty("githubUrl") String githubUrl,
            @JsonProperty("owner") String owner,
            @JsonProperty("repo") String repo,
            @JsonProperty("cloneDir") String cloneDir,
            @JsonProperty("modules") List<ModuleInfo> modules,
            @JsonProperty("popularity") long popularity
    ) {}

    /**
     * A single Maven module within a GitHub repo.
     *
     * @param groupId                group ID from the module's pom.xml
     * @param artifactId             artifact ID from the module's pom.xml
     * @param version                version from the module's pom.xml
     * @param modulePath             relative path within the repo (e.g. "core" or ".")
     * @param jarPath                path to the built JAR (null if build failed)
     * @param packageMapPath         path to the generated package-map.json (null if preprocessor failed)
     * @param buildSucceeded         true if mvn install succeeded
     * @param preprocessorSucceeded  true if preprocessor generated a package map
     */
    public record ModuleInfo(
            @JsonProperty("groupId") String groupId,
            @JsonProperty("artifactId") String artifactId,
            @JsonProperty("version") String version,
            @JsonProperty("modulePath") String modulePath,
            @JsonProperty("jarPath") String jarPath,
            @JsonProperty("packageMapPath") String packageMapPath,
            @JsonProperty("buildSucceeded") boolean buildSucceeded,
            @JsonProperty("preprocessorSucceeded") boolean preprocessorSucceeded
    ) {
        public String coordinate() {
            return groupId + ":" + artifactId + ":" + version;
        }
    }
}
