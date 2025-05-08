package io.github.chains_project.theo.monitor.utils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;

/**
 * This class includes the util functions to process dependencies saved in the lockfile.
 */
public class DependencyParser {
    private static Map<String, Object> lockfileData;

    private DependencyParser() {
    }

    public static void initialize(Path lockfilePath) {
        try {
            lockfileData = parseLockfile(lockfilePath);

        } catch (IOException e) {
            throw new RuntimeException("Lockfile could not be found. Check the README.md for more details", e);
        }
    }

    private static Map<String, Object> parseLockfile(Path lockfilePath) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        File lockfile = new File(lockfilePath.toUri());
        return objectMapper.readValue(lockfile, new TypeReference<>() {
        });
    }

    /**
     * Maps a given jar file to the maven standard name of the dependency.
     *
     * @param jarPath the path to the jarFile
     */
    public static String findDepDetails(String jarPath) {
        if (jarPath != null) {
            String[] parts = extractDepDetails(jarPath);
            if (parts != null) {
                return findDepDetailsRecursively(lockfileData.get("dependencies"), parts[0], parts[1], parts[2]);
            }
        }
        return null;
    }

    private static String[] extractDepDetails(String jarPath) {
        String[] parts = jarPath.split("/");
        if (parts.length >= 7) {
            String version = parts[parts.length - 2];
            String artifactId = parts[parts.length - 3];
            // ToDo: improve this approximation.
            String groupId = parts[parts.length - 4];
            return new String[]{groupId, artifactId, version};
        }
        return null;
    }

    private static String findDepDetailsRecursively(Object node, String groupId, String artifactId, String version) {
        if (node instanceof Iterable) {
            for (Object child : (Iterable<?>) node) {
                String result = findDepDetailsRecursively(child, groupId, artifactId, version);
                if (result != null) {
                    return result;
                }
            }
        } else if (node instanceof Map<?, ?> map) {
            if (map.containsKey("groupId") && map.containsKey("artifactId") && map.containsKey("version")) {
                Object groupIdObj = map.get("groupId");
                Object artifactIdObj = map.get("artifactId");
                Object versionObj = map.get("version");
                if (groupIdObj instanceof String depGroupId && artifactIdObj instanceof String depArtifactId &&
                        versionObj instanceof String depVersion) {
                    if (depGroupId.contains(groupId) && depArtifactId.equals(artifactId) && depVersion.equals(version)) {
                        return depGroupId + ":" + depArtifactId + ":" + depVersion;
                    }
                }
            }
        }
        return null;
    }
}
