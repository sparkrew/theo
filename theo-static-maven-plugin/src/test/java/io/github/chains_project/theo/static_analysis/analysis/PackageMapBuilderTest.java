package io.github.chains_project.theo.static_analysis.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class PackageMapBuilderTest {

    private final PackageMapBuilder builder = new PackageMapBuilder();

    @Test
    void buildPackageMapWithEmptyListReturnsEmptyMap() {
        Map<String, Set<String>> result = builder.buildPackageMap(Collections.emptyList());

        assertTrue(result.isEmpty());
    }

    @Test
    void buildAndWriteCreatesValidJsonFile(@TempDir Path tempDir) throws IOException {
        Path outputFile = tempDir.resolve("package-map.json");

        // Use an empty artifact list so the test does not depend on external JARs
        builder.buildAndWrite(Collections.emptyList(), outputFile);

        assertTrue(Files.exists(outputFile), "Output file should exist");
        String json = Files.readString(outputFile);
        // Should be valid JSON (an empty object in this case)
        assertDoesNotThrow(() -> new ObjectMapper().readTree(json));
    }

    @Test
    void buildPackageMapExtractsPackagesFromJar() {
        // Use the JUnit Jupiter API jar which is on the test classpath
        Path junitJarPath = getJarPathForClass(org.junit.jupiter.api.Test.class);
        if (junitJarPath == null || !Files.isRegularFile(junitJarPath)) {
            // Skip gracefully if we cannot locate the jar (e.g., running from an IDE with exploded classes)
            return;
        }

        PackageMapBuilder.ArtifactInfo artifact = new PackageMapBuilder.ArtifactInfo(
            junitJarPath,
            "org.junit.jupiter",
            "junit-jupiter-api",
            "jar",
            null,
            "5.10.2"
        );

        Map<String, Set<String>> packageMap = builder.buildPackageMap(List.of(artifact));

        assertFalse(packageMap.isEmpty(), "Package map should contain entries from the JUnit jar");
        // The JUnit Jupiter API jar should contain the org.junit.jupiter.api package
        assertTrue(packageMap.containsKey("org.junit.jupiter.api"),
            "Package map should contain org.junit.jupiter.api");
    }

    @Test
    void buildAndWriteWithRealJarProducesNonEmptyJson(@TempDir Path tempDir) throws IOException {
        Path junitJarPath = getJarPathForClass(org.junit.jupiter.api.Test.class);
        if (junitJarPath == null || !Files.isRegularFile(junitJarPath)) {
            return;
        }

        PackageMapBuilder.ArtifactInfo artifact = new PackageMapBuilder.ArtifactInfo(
            junitJarPath,
            "org.junit.jupiter",
            "junit-jupiter-api",
            "jar",
            null,
            "5.10.2"
        );

        Path outputFile = tempDir.resolve("package-map.json");
        Map<String, Set<String>> result = builder.buildAndWrite(List.of(artifact), outputFile);

        assertFalse(result.isEmpty());
        assertTrue(Files.exists(outputFile));

        // Verify the JSON file has actual content
        String json = Files.readString(outputFile);
        assertTrue(json.contains("org.junit.jupiter.api"),
            "JSON output should reference the org.junit.jupiter.api package");
    }

    @Test
    void buildPackageMapSkipsArtifactWithMissingJar() {
        Path nonExistentJar = Path.of("/does/not/exist/fake.jar");

        PackageMapBuilder.ArtifactInfo artifact = new PackageMapBuilder.ArtifactInfo(
            nonExistentJar, "com.example", "fake", "jar", null, "1.0"
        );

        Map<String, Set<String>> result = builder.buildPackageMap(List.of(artifact));

        assertTrue(result.isEmpty(), "Should return empty map when jar does not exist");
    }

    /**
     * Resolves the jar file path for a given class from its protection domain.
     * Returns null if the class is not loaded from a jar (e.g., exploded classes in an IDE).
     */
    private static Path getJarPathForClass(Class<?> clazz) {
        try {
            String path = clazz.getProtectionDomain().getCodeSource().getLocation().toURI().getPath();
            if (path != null && path.endsWith(".jar")) {
                return Path.of(path);
            }
        } catch (Exception e) {
            // Protection domain or code source not available
        }
        return null;
    }
}
