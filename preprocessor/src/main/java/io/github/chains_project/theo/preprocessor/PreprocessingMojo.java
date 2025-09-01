package io.github.chains_project.theo.preprocessor;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.model.Build;
import org.apache.maven.model.Model;
import org.apache.maven.model.Plugin;
import org.apache.maven.model.PluginExecution;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.*;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.ProjectBuilder;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.apache.maven.model.io.xpp3.MavenXpp3Writer;
import org.codehaus.plexus.util.xml.Xpp3Dom;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
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
    @Parameter(property = "updatePom", defaultValue = "true")
    private boolean updatePom;
    @Parameter(property = "excludePackages", defaultValue = "META-INF,BOOT-INF,WEB-INF")
    private String excludePackages;

    @Component
    private MavenSession session;
    @Component
    private ProjectBuilder projectBuilder;

    public void execute() {
        Set<Artifact> dependencyArtifacts = project.getArtifacts();
        getLog().info("Processing dependencies to build package-to-dependency map");

        // Build a reverse map: longId -> GA (groupId:artifactId), for later includes
        Map<String, String> longIdToGA = new HashMap<>();
        Map<String, String> longIdToPrefix = new HashMap<>();

        for (Artifact artifact : dependencyArtifacts) {
            String dependencyId = getArtifactLongId(artifact);
            String ga = artifact.getGroupId() + ":" + artifact.getArtifactId();
            longIdToGA.put(dependencyId, ga);

            // Build relocation prefix as <groupId>.<artifactId> (replace "-" with ".")
            String prefix = artifact.getGroupId().replace("-", ".")
                    + "." + artifact.getArtifactId().replace("-", ".");
            longIdToPrefix.put(dependencyId, prefix);

            File jarFile = artifact.getFile();
            if (jarFile != null && jarFile.isFile()) {
                processJar(jarFile, dependencyId);
            } else {
                getLog().warn("Skipping non-jar dependency: " + dependencyId);
            }
        }

        // Identify conflicting packages and build relocations per dependency
        Map<String, String> relocationMap = buildDependencySpecificRelocations(longIdToGA, longIdToPrefix);
        Map<String, Set<String>> shadedPackageMap = applyRelocations(packageToDependencies, relocationMap);
        writeMapToJson(shadedPackageMap);

        if (updatePom) {
            try {
                mergeShadeConfigIntoPom(longIdToGA, longIdToPrefix);
            } catch (Exception e) {
                getLog().error("Failed to update pom.xml with shade configuration", e);
            }
        }
    }

    /**
     * Builds dependency-specific relocations for conflicting packages.
     * Returns a map where keys are "dependencyId:packageName" and values are relocated package names.
     */
    private Map<String, String> buildDependencySpecificRelocations(Map<String, String> longIdToGA,
                                                                   Map<String, String> longIdToPrefix) {
        Map<String, String> relocationMap = new HashMap<>();

        // First pass: identify conflicting packages
        for (Map.Entry<String, Set<String>> entry : packageToDependencies.entrySet()) {
            String packageName = entry.getKey();
            Set<String> dependencies = entry.getValue();

            if (dependencies.size() > 1) {
                // This package appears in multiple dependencies - create relocations for each
                for (String depId : dependencies) {
                    String prefix = longIdToPrefix.get(depId);
                    if (prefix != null) {
                        String relocated = prefix + "." + packageName;
                        String key = depId + ":" + packageName;
                        relocationMap.put(key, relocated);

                        getLog().debug("Will relocate " + packageName + " from " + depId + " to " + relocated);
                    }
                }
            }
        }

        getLog().info("Created " + relocationMap.size() + " dependency-specific relocations");
        return relocationMap;
    }

    private Map<String, Set<String>> applyRelocations(
            Map<String, Set<String>> packageMap,
            Map<String, String> relocations
    ) {
        Map<String, Set<String>> relocatedMap = new HashMap<>();

        for (Map.Entry<String, Set<String>> entry : packageMap.entrySet()) {
            String pkg = entry.getKey();
            Set<String> dependencies = entry.getValue();

            // For each dependency that contains this package
            for (String depId : dependencies) {
                String relocKey = depId + ":" + pkg;
                String relocated = relocations.get(relocKey);

                if (relocated != null) {
                    // Package is relocated for this dependency
                    relocatedMap.computeIfAbsent(relocated, k -> new HashSet<>()).add(depId);
                } else {
                    // Package is not relocated (no conflict)
                    relocatedMap.computeIfAbsent(pkg, k -> new HashSet<>()).add(depId);
                }
            }
        }
        return relocatedMap;
    }

    private void processJar(File jarFile, String dependencyId) {
        // Parse the exclude list
        Set<String> excludeSet = new HashSet<>();
        if (excludePackages != null && !excludePackages.trim().isEmpty()) {
            String[] excludeArray = excludePackages.split(",");
            for (String exclude : excludeArray) {
                excludeSet.add(exclude.trim().toLowerCase());
            }
        }

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

                        // Skip packages with hyphens (invalid Java package names)
                        if (packageName.contains("-")) {
                            continue;
                        }

                        // Skip packages that match any exclude pattern
                        boolean shouldExclude = false;
                        String packageLower = packageName.toLowerCase();
                        for (String exclude : excludeSet) {
                            if (packageLower.contains(exclude)) {
                                shouldExclude = true;
                                break;
                            }
                        }

                        if (!shouldExclude) {
                            packageToDependencies.computeIfAbsent(packageName, k -> new HashSet<>()).add(dependencyId);
                        }
                    }
                }
            }
        } catch (IOException e) {
            getLog().error("Failed to read jar file: " + jarFile, e);
        }
    }

    private void writeMapToJson(Map<String, Set<String>> packageMap) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.writerWithDefaultPrettyPrinter().writeValue(outputFile, packageMap);
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

    private void mergeShadeConfigIntoPom(Map<String, String> longIdToGA,
                                         Map<String, String> longIdToPrefix) throws Exception {

        // 1) Identify dependencies that have conflicting packages
        Map<String, Set<String>> dependencyToConflictingPackages = new HashMap<>();

        for (Map.Entry<String, Set<String>> entry : packageToDependencies.entrySet()) {
            String packageName = entry.getKey();
            Set<String> dependencies = entry.getValue();

            if (dependencies.size() > 1) { // conflicting package
                for (String depId : dependencies) {
                    dependencyToConflictingPackages.computeIfAbsent(depId, k -> new HashSet<>())
                            .add(packageName);
                }
            }
        }

        if (dependencyToConflictingPackages.isEmpty()) {
            getLog().info("No conflicting dependencies found. Skipping POM update for shade.");
            return;
        }

        File pomFile = project.getFile();
        if (pomFile == null || !pomFile.isFile()) {
            getLog().warn("Project POM file not found; cannot update shade configuration.");
            return;
        }

        // 2) Load model from pom.xml
        Model model;
        MavenXpp3Reader reader = new MavenXpp3Reader();
        try (FileReader fr = new FileReader(pomFile)) {
            model = reader.read(fr);
            model.setPomFile(pomFile);
        }

        // Ensure Build exists
        Build build = model.getBuild();
        if (build == null) {
            build = new Build();
            model.setBuild(build);
        }

        // 3) Find or create the maven-shade-plugin
        Plugin shade = findPlugin(build, "org.apache.maven.plugins", "maven-shade-plugin");
        if (shade == null) {
            shade = new Plugin();
            shade.setGroupId("org.apache.maven.plugins");
            shade.setArtifactId("maven-shade-plugin");
            shade.setVersion("3.5.2");
            build.addPlugin(shade);
            getLog().info("Added maven-shade-plugin to POM.");
        }

        // 4) Create separate executions for each dependency with conflicts
        int executionCount = 0;
        for (Map.Entry<String, Set<String>> entry : dependencyToConflictingPackages.entrySet()) {
            String dependencyId = entry.getKey();
            Set<String> conflictingPackages = entry.getValue();
            String ga = longIdToGA.get(dependencyId);
            String prefix = longIdToPrefix.get(dependencyId);

            if (ga != null && prefix != null) {
                String execId = "theo-shade-" + ga.replace(":", "-").replace(".", "-");

                // Check if execution already exists
                boolean execExists = shade.getExecutions().stream()
                        .anyMatch(exec -> execId.equals(exec.getId()));

                if (!execExists) {
                    PluginExecution exec = new PluginExecution();
                    exec.setId(execId);
                    exec.addGoal("shade");
                    exec.setPhase("package");

                    // Create configuration for this specific dependency
                    Xpp3Dom cfg = new Xpp3Dom("configuration");

                    // Include only this specific dependency
                    Xpp3Dom artifactSet = new Xpp3Dom("artifactSet");
                    Xpp3Dom includes = new Xpp3Dom("includes");
                    Xpp3Dom include = new Xpp3Dom("include");
                    include.setValue(ga);
                    includes.addChild(include);
                    artifactSet.addChild(includes);
                    cfg.addChild(artifactSet);

                    // Add relocations for this dependency's conflicting packages
                    Xpp3Dom relocations = new Xpp3Dom("relocations");
                    for (String pkg : conflictingPackages) {
                        Xpp3Dom relocation = new Xpp3Dom("relocation");
                        Xpp3Dom pattern = new Xpp3Dom("pattern");
                        pattern.setValue(pkg);
                        Xpp3Dom shadedPattern = new Xpp3Dom("shadedPattern");
                        shadedPattern.setValue(prefix + "." + pkg);

                        relocation.addChild(pattern);
                        relocation.addChild(shadedPattern);
                        relocations.addChild(relocation);
                    }
                    cfg.addChild(relocations);

                    exec.setConfiguration(cfg);
                    shade.addExecution(exec);
                    executionCount++;

                    getLog().info("Created shade execution '" + execId + "' for " + ga +
                            " with " + conflictingPackages.size() + " relocations");
                }
            }
        }

        if (executionCount > 0) {
            // Write model back to pom.xml
            MavenXpp3Writer writer = new MavenXpp3Writer();
            try (FileWriter fw = new FileWriter(pomFile)) {
                writer.write(fw, model);
            }
            getLog().info("pom.xml updated with " + executionCount + " shade executions.");
        }
    }

    // ----------------------- Helper methods -----------------------

    private static Plugin findPlugin(Build build, String groupId, String artifactId) {
        for (Plugin p : build.getPlugins()) {
            if (groupId.equals(p.getGroupId()) && artifactId.equals(p.getArtifactId())) {
                return p;
            }
        }
        return null;
    }
}