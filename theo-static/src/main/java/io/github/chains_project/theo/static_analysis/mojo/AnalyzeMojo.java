package io.github.chains_project.theo.static_analysis.mojo;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.chains_project.theo.static_analysis.analysis.AnalysisOrchestrator;
import io.github.chains_project.theo.static_analysis.report.ChangeDetector;
import io.github.chains_project.theo.static_analysis.analysis.ClientReachabilityAnalyzer;
import io.github.chains_project.theo.static_analysis.analysis.DependencyAnalyzer;
import io.github.chains_project.theo.static_analysis.analysis.PackageMapBuilder;
import io.github.chains_project.theo.static_analysis.cache.CacheManager;
import io.github.chains_project.theo.static_analysis.decompile.MethodDecompiler;
import io.github.chains_project.theo.static_analysis.model.AnalysisSummary;
import io.github.chains_project.theo.static_analysis.model.ChangeSet;
import io.github.chains_project.theo.static_analysis.report.CliReporter;
import io.github.chains_project.theo.static_analysis.report.HtmlReportGenerator;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Analyzes all dependencies of the current project for sensitive API usage,
 * determines which of those APIs are reachable from the client project's code,
 * and generates HTML reports. Results are cached so unchanged dependencies
 * are not re-analyzed on subsequent runs.
 */
@Mojo(
        name = "analyze",
        defaultPhase = LifecyclePhase.VERIFY,
        requiresDependencyResolution = ResolutionScope.TEST
)
public class AnalyzeMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project}", required = true, readonly = true)
    private MavenProject project;

    /** Comma-separated package names of the client project (e.g. "com.example.app"). */
    @Parameter(property = "theo.packageNames", required = true)
    private String packageNames;

    /** Directory for the HTML reports. */
    @Parameter(property = "theo.reportDir", defaultValue = "${project.build.directory}/theo-report")
    private File reportDir;

    /** Persistent cache directory. */
    @Parameter(property = "theo.cacheDir", defaultValue = "${user.home}/.theo/cache")
    private File cacheDir;

    /** Controls CLI output verbosity. When true, shows all changes; when false, only reachable changes. */
    @Parameter(property = "theo.verbose", defaultValue = "true")
    private boolean verbose;

    /** Path to the package-static-analyzer jar-with-dependencies. If not set, resolved from local repo. */
    @Parameter(property = "theo.analyzerJarPath")
    private File analyzerJarPath;

    /** Path to the package map JSON. If not set, looks in target/theo-package-map.json. */
    @Parameter(property = "theo.packageMapPath", defaultValue = "${project.build.directory}/theo-package-map.json")
    private File packageMapPath;

    /** When true, dependencies sharing the client project's groupId are skipped during analysis. */
    @Parameter(property = "theo.skipSameGroupId", defaultValue = "true")
    private boolean skipSameGroupId;

    /** Local Maven repository path, used to resolve the analyzer jar when no explicit path is given. */
    @Parameter(defaultValue = "${settings.localRepository}", readonly = true)
    private String localRepository;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        try {
            // Step 1: Ensure package map exists. If not, build it inline.
            Path mapPath = ensurePackageMap();

            // Step 2: Prepare the deps directory with all resolved JAR files.
            // SootUp needs all dependency JARs on the classpath for accurate call graphs.
            Path depsDir = prepareDepsDirectory();

            // Step 3: Resolve the package-static-analyzer JAR
            Path analyzerJar = resolveAnalyzerJar();

            // Step 4: Build the list of dependencies to analyze
            Map<String, Set<String>> packageMap = loadPackageMap(mapPath);
            List<AnalysisOrchestrator.DependencyInfo> depInfos = buildDependencyInfos(packageMap);

            // Step 5: Set up collaborators
            CacheManager cache = new CacheManager(cacheDir.toPath());
            DependencyAnalyzer depAnalyzer = new DependencyAnalyzer(analyzerJar, mapPath, depsDir);
            ClientReachabilityAnalyzer reachAnalyzer = new ClientReachabilityAnalyzer();
            AnalysisOrchestrator orchestrator = new AnalysisOrchestrator(depAnalyzer, reachAnalyzer, cache);

            // Step 6: Find the client project JAR
            String projectJarPath = findProjectJar();
            List<String> pkgNames = parsePackageNames(packageNames);

            // Step 7: Run the analysis
            AnalysisSummary previousRun = orchestrator.loadPreviousRun(
                    project.getGroupId(), project.getArtifactId());

            AnalysisSummary summary = orchestrator.analyze(
                    project.getGroupId(), project.getArtifactId(), project.getVersion(),
                    projectJarPath, pkgNames, mapPath, depInfos);

            // Step 8: Detect changes between the previous run and this one
            ChangeDetector changeDetector = new ChangeDetector();
            ChangeSet changeSet = changeDetector.detectChanges(previousRun, summary);

            // Step 9: Generate HTML reports with decompiled source snippets
            Map<String, Path> jarPaths = depInfos.stream()
                    .collect(Collectors.toMap(
                            d -> d.groupId() + ":" + d.artifactId() + ":" + d.version(),
                            AnalysisOrchestrator.DependencyInfo::jarPath,
                            (a, b) -> a));

            MethodDecompiler decompiler = new MethodDecompiler();
            HtmlReportGenerator reportGen = new HtmlReportGenerator(decompiler, jarPaths);
            reportGen.generateReports(summary, changeSet, reportDir.toPath());

            // Step 10: Print CLI summary
            CliReporter cli = new CliReporter(getLog());
            cli.printSummary(summary, changeSet, reportDir.toPath(), verbose);

        } catch (IOException e) {
            throw new MojoExecutionException("Analysis failed: " + e.getMessage(), e);
        }
    }

    /**
     * Makes sure the package map JSON exists. If the preprocess goal hasn't
     * run yet, builds the map inline using the same logic.
     */
    private Path ensurePackageMap() throws IOException {
        Path mapPath = packageMapPath.toPath();
        if (Files.exists(mapPath)) {
            getLog().info("Using existing package map: " + mapPath);
            return mapPath;
        }

        // Build it inline since the preprocess goal hasn't run
        getLog().info("Package map not found, building it now...");
        PackageMapBuilder builder = new PackageMapBuilder();
        String projectGid = project.getGroupId();
        List<PackageMapBuilder.ArtifactInfo> artifacts = project.getArtifacts().stream()
                .filter(a -> a.getFile() != null && a.getFile().isFile())
                .filter(a -> !skipSameGroupId || !a.getGroupId().equals(projectGid))
                .filter(a -> !a.getGroupId().startsWith("org.apache.maven"))
                .map(a -> new PackageMapBuilder.ArtifactInfo(
                        a.getFile().toPath(), a.getGroupId(), a.getArtifactId(),
                        a.getType(), a.getClassifier(), a.getVersion()))
                .toList();
        builder.buildAndWrite(artifacts, mapPath);
        return mapPath;
    }

    /**
     * Creates a directory with symbolic links to all resolved dependency JARs.
     * SootUp needs all JARs on the classpath for accurate call graph construction.
     */
    private Path prepareDepsDirectory() throws IOException {
        Path depsDir = Path.of(project.getBuild().getDirectory(), "theo-deps");
        if (Files.exists(depsDir)) {
            // Clean and recreate to ensure freshness
            try (Stream<Path> files = Files.list(depsDir)) {
                files.forEach(f -> {
                    try {
                        Files.deleteIfExists(f);
                    } catch (IOException ignored) {
                        // best-effort cleanup; stale links are harmless
                    }
                });
            }
        }
        Files.createDirectories(depsDir);

        for (Artifact artifact : project.getArtifacts()) {
            File jarFile = artifact.getFile();
            if (jarFile != null && jarFile.isFile() && jarFile.getName().endsWith(".jar")) {
                // Use a unique name to avoid collisions between different artifacts
                String linkName = artifact.getGroupId() + "_" + artifact.getArtifactId()
                        + "_" + artifact.getVersion() + ".jar";
                Path link = depsDir.resolve(linkName);
                if (!Files.exists(link)) {
                    Files.createSymbolicLink(link, jarFile.toPath().toAbsolutePath());
                }
            }
        }

        return depsDir;
    }

    /**
     * Resolves the path to the package-static-analyzer uber-JAR.
     * Tries the explicit parameter first, then falls back to the local Maven repository.
     */
    private Path resolveAnalyzerJar() throws MojoExecutionException {
        if (analyzerJarPath != null && analyzerJarPath.isFile()) {
            return analyzerJarPath.toPath();
        }

        // Fall back to the local Maven repository
        try {
            return DependencyAnalyzer.resolveAnalyzerJar(Path.of(localRepository));
        } catch (Exception e) {
            throw new MojoExecutionException(
                    "Could not find package-static-analyzer JAR. Either build it first "
                    + "(mvn install -pl package-static-analyzer) or set theo.analyzerJarPath.", e);
        }
    }

    /**
     * Builds the list of DependencyInfo objects from resolved Maven artifacts
     * and the package map.
     */
    private List<AnalysisOrchestrator.DependencyInfo> buildDependencyInfos(Map<String, Set<String>> packageMap) {
        // Reverse the package map: for each dependency GAV, collect its packages
        Map<String, Set<String>> gavToPackages = new HashMap<>();
        for (Map.Entry<String, Set<String>> entry : packageMap.entrySet()) {
            String pkg = entry.getKey();
            for (String gav : entry.getValue()) {
                gavToPackages.computeIfAbsent(gav, k -> new HashSet<>()).add(pkg);
            }
        }

        List<AnalysisOrchestrator.DependencyInfo> infos = new ArrayList<>();
        String projectGroupId = project.getGroupId();

        for (Artifact artifact : project.getArtifacts()) {
            if (artifact.getFile() == null || !artifact.getFile().isFile()) {
                continue;
            }

            // Sub-modules of the same project rarely need privilege analysis, and
            // analyzing them slows down the build without adding much value.
            if (skipSameGroupId && artifact.getGroupId().equals(projectGroupId)) {
                getLog().debug("Skipping same-groupId dependency: " + artifact.getId());
                continue;
            }

            // Maven's own libraries are build infrastructure, not application dependencies.
            if (artifact.getGroupId().startsWith("org.apache.maven")) {
                getLog().debug("Skipping Maven infrastructure dependency: " + artifact.getId());
                continue;
            }

            String gavWithType = artifact.getGroupId() + ":" + artifact.getArtifactId()
                    + ":" + artifact.getType()
                    + (artifact.getClassifier() != null ? ":" + artifact.getClassifier() : "")
                    + ":" + artifact.getVersion();

            Set<String> packages = gavToPackages.getOrDefault(gavWithType, Set.of());
            if (packages.isEmpty()) {
                // Try without type/classifier as a simpler lookup
                String simpleGav = artifact.getGroupId() + ":" + artifact.getArtifactId()
                        + ":" + artifact.getVersion();
                packages = gavToPackages.getOrDefault(simpleGav, Set.of());
            }

            infos.add(new AnalysisOrchestrator.DependencyInfo(
                    artifact.getGroupId(), artifact.getArtifactId(), artifact.getVersion(),
                    artifact.getType(), artifact.getFile().toPath(), packages
            ));
        }

        return infos;
    }

    /**
     * Finds the compiled JAR of the client project.
     * Tries the Maven artifact first, then the target directory, and finally the classes directory.
     */
    private String findProjectJar() throws MojoExecutionException {
        File artifact = project.getArtifact().getFile();
        if (artifact != null && artifact.isFile()) {
            return artifact.getAbsolutePath();
        }

        // Fallback: look in target directory
        String expectedName = project.getArtifactId() + "-" + project.getVersion() + ".jar";
        File targetJar = new File(project.getBuild().getDirectory(), expectedName);
        if (targetJar.isFile()) {
            return targetJar.getAbsolutePath();
        }

        // Last resort: use the target/classes directory for an unpackaged build
        String classesDir = project.getBuild().getOutputDirectory();
        if (classesDir != null && new File(classesDir).isDirectory()) {
            return classesDir;
        }

        throw new MojoExecutionException("Could not find project artifact. Run 'mvn package' first.");
    }

    /**
     * Loads the package map JSON into a map of package name to set of GAV coordinates.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Set<String>> loadPackageMap(Path mapPath) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        TypeReference<Map<String, Set<String>>> typeRef = new TypeReference<>() {};
        return mapper.readValue(mapPath.toFile(), typeRef);
    }

    /**
     * Splits a comma-separated string of package names into a clean list.
     */
    private List<String> parsePackageNames(String names) {
        if (names == null || names.isBlank()) {
            return List.of();
        }
        return Arrays.stream(names.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }
}
