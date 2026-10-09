package io.github.chains_project.theo.static_analysis.mojo;

import io.github.chains_project.theo.static_analysis.cache.CacheManager;
import io.github.chains_project.theo.static_analysis.cache.SnapshotManager;
import io.github.chains_project.theo.static_analysis.model.AnalysisSummary;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

import java.io.File;
import java.io.IOException;

/**
 * Saves the most recent analysis run as a named snapshot in the history folder.
 * Run this after an analyze or cve-check goal to persist the current state
 * for future comparison via the history table.
 *
 * Usage:
 *   mvn theo-static:snapshot
 *   mvn theo-static:snapshot -Dtheo.snapshotLabel=before-upgrade
 */
@Mojo(name = "snapshot")
public class SnapshotMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project}", required = true, readonly = true)
    private MavenProject project;

    /** Persistent cache directory where last-run.json lives. */
    @Parameter(property = "theo.cacheDir", defaultValue = "${user.home}/.theo/cache")
    private File cacheDir;

    /** History folder for snapshots. */
    @Parameter(property = "theo.historyDir", defaultValue = "${user.home}/.theo/history")
    private File historyDir;

    /** Optional label for this snapshot. Defaults to projectVersion-N. */
    @Parameter(property = "theo.snapshotLabel")
    private String snapshotLabel;

    @Override
    public void execute() throws MojoExecutionException {
        if ("pom".equals(project.getPackaging())) {
            getLog().info("Skipping POM module " + project.getArtifactId());
            return;
        }

        // Load the most recent analysis from cache
        CacheManager cache = new CacheManager(cacheDir.toPath());
        AnalysisSummary summary = cache.loadLastRun(
                project.getGroupId(), project.getArtifactId());

        if (summary == null) {
            getLog().warn("No analysis found. Run 'analyze' or 'cve-check' first.");
            return;
        }

        try {
            SnapshotManager snapshots = new SnapshotManager(
                    historyDir.toPath(), project.getGroupId(), project.getArtifactId());
            String label = snapshots.saveSnapshot(summary, snapshotLabel);
            getLog().info("Snapshot saved as '" + label + "'");
        } catch (IOException e) {
            throw new MojoExecutionException("Failed to save snapshot: " + e.getMessage(), e);
        }
    }
}
