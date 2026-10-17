package io.github.chains_project.theo.static_analysis.mojo;

import io.github.chains_project.theo.static_analysis.analysis.PackageMapBuilder;
import io.github.chains_project.theo.static_analysis.analysis.PackageMapBuilder.ArtifactInfo;
import org.apache.maven.artifact.Artifact;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;

import java.io.File;
import java.io.IOException;
import java.util.List;

/**
 * Preprocesses the project's resolved dependencies to build a package-to-dependency map.
 * This map tells downstream analysis which dependency each Java package originates from,
 * so call-graph edges can be attributed to specific GAV coordinates.
 *
 * <p>The heavy lifting is in {@link PackageMapBuilder} — this mojo just bridges
 * Maven's dependency model into a format that class can consume.</p>
 */
@Mojo(
        name = "preprocess",
        defaultPhase = LifecyclePhase.GENERATE_RESOURCES,
        requiresDependencyResolution = ResolutionScope.TEST
)
public class PreprocessMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project}", required = true, readonly = true)
    private MavenProject project;

    @Parameter(property = "theo.outputFile", defaultValue = "${project.build.directory}/theo-package-map.json")
    private File outputFile;

    @Override
    public void execute() throws MojoExecutionException {
        List<ArtifactInfo> artifacts = project.getArtifacts().stream()
                .map(PreprocessMojo::toArtifactInfo)
                .toList();

        getLog().info("scanning " + artifacts.size() + " resolved dependencies for package mapping");

        PackageMapBuilder builder = new PackageMapBuilder();

        try {
            builder.buildAndWrite(artifacts, outputFile.toPath());
        } catch (IOException e) {
            throw new MojoExecutionException("failed to write package map to " + outputFile, e);
        }

        // store the output path so downstream mojos (like analyze) can pick it up
        // without the user having to re-specify it
        project.getProperties().setProperty("theo.packageMap", outputFile.getAbsolutePath());

        getLog().info("package map written to " + outputFile.getAbsolutePath());
    }

    /**
     * Converts a Maven {@link Artifact} into the plain {@link ArtifactInfo} record
     * that {@link PackageMapBuilder} expects. This keeps Maven types out of the
     * builder so it stays testable without a Maven runtime.
     */
    private static ArtifactInfo toArtifactInfo(Artifact artifact) {
        return new ArtifactInfo(
                artifact.getFile() != null ? artifact.getFile().toPath() : null,
                artifact.getGroupId(),
                artifact.getArtifactId(),
                artifact.getType(),
                artifact.getClassifier(),
                artifact.getVersion()
        );
    }
}
