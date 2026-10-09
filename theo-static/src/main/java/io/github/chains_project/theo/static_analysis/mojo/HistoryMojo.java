package io.github.chains_project.theo.static_analysis.mojo;

import io.github.chains_project.theo.static_analysis.cache.SnapshotManager;
import io.github.chains_project.theo.static_analysis.model.ReachableSnapshot;
import io.github.chains_project.theo.static_analysis.report.HistoryReportGenerator;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

import java.io.File;
import java.io.IOException;
import java.util.List;

/**
 * Generates a history.html table from saved snapshots, showing the presence
 * of reachable sensitive APIs across all snapshots for this project.
 *
 * Usage:
 *   mvn theo-static:history
 */
@Mojo(name = "history")
public class HistoryMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project}", required = true, readonly = true)
    private MavenProject project;

    /** History folder for snapshots. */
    @Parameter(property = "theo.historyDir", defaultValue = "${user.home}/.theo/history")
    private File historyDir;

    /** Directory for the HTML report output. */
    @Parameter(property = "theo.reportDir", defaultValue = "${project.build.directory}/theo-report")
    private File reportDir;

    @Override
    public void execute() throws MojoExecutionException {
        if ("pom".equals(project.getPackaging())) {
            getLog().info("Skipping POM module " + project.getArtifactId());
            return;
        }

        SnapshotManager snapshots = new SnapshotManager(
                historyDir.toPath(), project.getGroupId(), project.getArtifactId());

        List<ReachableSnapshot> all = snapshots.loadAllSnapshots();
        if (all.isEmpty()) {
            getLog().warn("No snapshots found. Run 'snapshot' first to save analysis runs.");
            return;
        }

        getLog().info("Found " + all.size() + " snapshots for " + project.getGroupId() + ":" + project.getArtifactId());

        try {
            HistoryReportGenerator generator = new HistoryReportGenerator();
            generator.generateReport(all, reportDir.toPath());
            getLog().info("History report: " + reportDir.toPath().resolve("history.html"));
        } catch (IOException e) {
            throw new MojoExecutionException("Failed to generate history report: " + e.getMessage(), e);
        }
    }
}
