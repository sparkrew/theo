package io.github.chains_project.theo.static_analysis.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Builds a mapping from Java package names to the dependency artifacts that contain
 * classes in those packages. This is the preprocessing step that later analysis phases
 * use to attribute call-graph edges back to specific dependencies.
 */
public class PackageMapBuilder {

    private static final Logger logger = LoggerFactory.getLogger(PackageMapBuilder.class);

    private final ObjectMapper objectMapper;

    public PackageMapBuilder() {
        this.objectMapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
    }

    /**
     * Describes a resolved dependency artifact with enough information to locate
     * its JAR on disk and produce a standard GAV coordinate string.
     */
    public record ArtifactInfo(
            Path jarPath,
            String groupId,
            String artifactId,
            String type,
            String classifier,
            String version
    ) {
        /**
         * Returns the Maven GAV coordinate string. The classifier is included only
         * when it is present, matching the standard Maven coordinate format.
         */
        public String gavString() {
            if (classifier != null && !classifier.isEmpty()) {
                return groupId + ":" + artifactId + ":" + type + ":" + classifier + ":" + version;
            }
            return groupId + ":" + artifactId + ":" + type + ":" + version;
        }
    }

    /**
     * Scans each artifact's JAR file and collects the Java packages found inside.
     * A single package can appear in multiple artifacts (split packages), so the
     * map values are sets of GAV strings rather than single values.
     *
     * @param artifacts the resolved dependency artifacts to scan
     * @return a map from package name to the set of GAV coordinates containing that package
     */
    public Map<String, Set<String>> buildPackageMap(List<ArtifactInfo> artifacts) {
        Map<String, Set<String>> packageMap = new TreeMap<>();

        for (ArtifactInfo artifact : artifacts) {
            Path jarPath = artifact.jarPath();

            if (jarPath == null || !Files.isRegularFile(jarPath)) {
                logger.warn("skipping artifact {} — jar file not found at {}", artifact.gavString(), jarPath);
                continue;
            }

            String gav = artifact.gavString();
            Set<String> packages = extractPackages(jarPath);

            if (packages.isEmpty()) {
                logger.debug("no .class files found in {}", gav);
                continue;
            }

            // each package maps to potentially multiple artifacts (split packages are real)
            for (String pkg : packages) {
                packageMap.computeIfAbsent(pkg, k -> new TreeSet<>()).add(gav);
            }

            logger.debug("found {} packages in {}", packages.size(), gav);
        }

        logger.info("built package map: {} packages across {} artifacts", packageMap.size(), artifacts.size());
        return packageMap;
    }

    /**
     * Writes the package map to disk as pretty-printed JSON so other tools and
     * mojos can consume it without re-scanning all the JARs.
     *
     * @param packageMap the map to serialize
     * @param outputFile the target file path (parent directories are created if needed)
     * @throws IOException if the file cannot be written
     */
    public void writePackageMap(Map<String, Set<String>> packageMap, Path outputFile) throws IOException {
        // make sure the parent directory exists — the build directory might not yet
        Files.createDirectories(outputFile.getParent());
        objectMapper.writeValue(outputFile.toFile(), packageMap);
        logger.info("wrote package map to {}", outputFile);
    }

    /**
     * Convenience method that builds the package map and writes it in one step.
     *
     * @param artifacts  the resolved dependency artifacts to scan
     * @param outputFile the target file path for the JSON output
     * @return the constructed package map
     * @throws IOException if the output file cannot be written
     */
    public Map<String, Set<String>> buildAndWrite(List<ArtifactInfo> artifacts, Path outputFile) throws IOException {
        Map<String, Set<String>> packageMap = buildPackageMap(artifacts);
        writePackageMap(packageMap, outputFile);
        return packageMap;
    }

    /**
     * Opens a JAR and collects the distinct Java package names from its .class entries.
     * Non-class entries (resources, manifests, module-info) are ignored.
     */
    private Set<String> extractPackages(Path jarPath) {
        Set<String> packages = new TreeSet<>();

        try (JarFile jarFile = new JarFile(jarPath.toFile())) {
            Enumeration<JarEntry> entries = jarFile.entries();

            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();

                if (!name.endsWith(".class") || name.equals("module-info.class")) {
                    continue;
                }

                // convert "com/example/Foo.class" to "com.example"
                int lastSlash = name.lastIndexOf('/');
                if (lastSlash > 0) {
                    String pkg = name.substring(0, lastSlash).replace('/', '.');
                    packages.add(pkg);
                } else {
                    // classes in the default (unnamed) package
                    packages.add("");
                }
            }
        } catch (IOException e) {
            logger.warn("could not read jar {}: {}", jarPath, e.getMessage());
        }

        return packages;
    }
}
