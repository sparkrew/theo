package io.github.chains_project.theo.preprocessor;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.*;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectBuilder;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * This Mojo processes the dependencies of a Maven project to create a map of packages to their dependencies.
 * It scans each jar file in the project's dependencies, extracts package names from class files,
 * and writes the resulting map to a JSON file.
 * Thanks to the creators of classport(<a href="https://github.com/yogyagamage/classport/tree/main/maven-plugin">...</a>)
 * for the inspiration.
 */
@Mojo(name = "preprocess", defaultPhase = LifecyclePhase.GENERATE_RESOURCES, requiresDependencyResolution = ResolutionScope.TEST)
@Execute(phase = LifecyclePhase.COMPILE)
public class PreprocessingMojo extends AbstractMojo {

    private final Map<String, Set<String>> packageToDependencies = new HashMap<>();
    @Parameter(defaultValue = "${project}", required = true, readonly = true)
    MavenProject project;
    @Parameter(property = "outputFile", required = true)
    private File outputFile;

    @Component
    private MavenSession session;
    @Component
    private ProjectBuilder projectBuilder;

    public void execute() {
        Set<Artifact> dependencyArtifacts = project.getArtifacts();
        getLog().info("Processing dependencies to build package-to-dependency map");

        for (Artifact artifact : dependencyArtifacts) {
            String dependencyId = getArtifactLongId(artifact);
            File jarFile = artifact.getFile();
            if (jarFile != null && jarFile.isFile()) {
                processJar(jarFile, dependencyId);
            } else {
                getLog().warn("Skipping non-jar dependency: " + dependencyId);
            }
        }
        writeMapToJson();
    }

    private void processJar(File jarFile, String dependencyId) {
        try (JarFile jar = new JarFile(jarFile)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                if (name.endsWith(".class") && !entry.isDirectory()) {
                    String className = name.replace('/', '.').replace(".class", "");
                    int lastDot = className.lastIndexOf('.');
                    if (lastDot > 0) {
                        String packageName = className.substring(0, lastDot);
                        if (packageName.contains("-"))
                            continue; // Skip names with hyphens such as meta-inf, as they are not valid Java package names
                        packageToDependencies.computeIfAbsent(packageName, k -> new HashSet<>()).add(dependencyId);
                    }
                }
            }
        } catch (IOException e) {
            getLog().error("Failed to read jar file: " + jarFile, e);
        }
    }

    private void writeMapToJson() {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.writerWithDefaultPrettyPrinter().writeValue(outputFile, packageToDependencies);
            getLog().info("Wrote package-dependency map to " + outputFile.getAbsolutePath());
        } catch (IOException e) {
            getLog().error("Failed to write JSON output", e);
        }
    }

    private String getArtifactLongId(Artifact a) {
        return a.getGroupId()
                + ":" + a.getArtifactId()
                + ":" + a.getType()
                + (a.getClassifier() != null ? ":" + a.getClassifier() : "")
                + ":" + a.getVersion();
    }
}
