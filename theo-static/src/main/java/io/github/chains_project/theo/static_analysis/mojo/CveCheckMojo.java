package io.github.chains_project.theo.static_analysis.mojo;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.chains_project.theo.static_analysis.cve.CveEnricher;
import io.github.chains_project.theo.static_analysis.cve.CveResult;
import io.github.chains_project.theo.static_analysis.model.AnalysisSummary;
import io.github.chains_project.theo.static_analysis.report.CliReporter;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/**
 * Checks dependencies for known CVEs using the OSV.dev database and
 * augments the existing HTML reports with vulnerability badges. This
 * goal reads the analysis output from the analyze goal, so it should
 * run after it.
 */
@Mojo(name = "cve-check", defaultPhase = LifecyclePhase.VERIFY)
public class CveCheckMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project}", required = true, readonly = true)
    private MavenProject project;

    /** Directory containing the HTML reports from the analyze goal. */
    @Parameter(property = "theo.reportDir", defaultValue = "${project.build.directory}/theo-report")
    private File reportDir;

    @Override
    public void execute() throws MojoExecutionException {
        Path reportPath = reportDir.toPath();
        Path analysisDataPath = reportPath.resolve("analysis-data.json");

        if (!Files.exists(analysisDataPath)) {
            getLog().warn("No analysis data found at " + analysisDataPath);
            getLog().warn("Run the 'analyze' goal first: mvn theo-static:analyze");
            return;
        }

        try {
            // Load the analysis summary from the analyze goal's output
            ObjectMapper mapper = new ObjectMapper();
            AnalysisSummary summary = mapper.readValue(analysisDataPath.toFile(), AnalysisSummary.class);

            // Run CVE enrichment against the OSV.dev database
            CveEnricher enricher = new CveEnricher();
            Map<String, List<CveResult>> cveResults = enricher.enrichReports(
                    summary.getDependencyReports(), reportPath);

            // Print CLI summary of any vulnerabilities found
            CliReporter cli = new CliReporter(getLog());
            cli.printCveSummary(cveResults);

        } catch (IOException e) {
            throw new MojoExecutionException("CVE check failed: " + e.getMessage(), e);
        }
    }
}
