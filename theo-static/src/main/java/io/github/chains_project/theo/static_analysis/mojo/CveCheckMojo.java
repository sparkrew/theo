package io.github.chains_project.theo.static_analysis.mojo;

import io.github.chains_project.theo.static_analysis.cve.CveEnricher;
import io.github.chains_project.theo.static_analysis.cve.CveResult;
import io.github.chains_project.theo.static_analysis.model.AnalysisSummary;
import io.github.chains_project.theo.static_analysis.report.CliReporter;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.ResolutionScope;

import java.util.List;
import java.util.Map;

/**
 * Runs the full analysis (same as the analyze goal) and then checks all
 * dependencies for known CVEs via the OSV.dev database. The HTML reports
 * are augmented with CVE badges and unaudited capability indicators.
 */
@Mojo(
        name = "cve-check",
        defaultPhase = LifecyclePhase.VERIFY,
        requiresDependencyResolution = ResolutionScope.TEST
)
public class CveCheckMojo extends AnalyzeMojo {

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        // Run the full analysis first (preprocess, analyze deps, generate reports)
        AnalysisSummary summary = runAnalysis();

        // POM modules are skipped by runAnalysis
        if (summary == null) return;

        // Then enrich the reports with CVE data from OSV.dev
        CveEnricher enricher = new CveEnricher();
        Map<String, List<CveResult>> cveResults = enricher.enrichReports(
                summary.getDependencyReports(), reportDir.toPath());

        CliReporter cli = new CliReporter(getLog());
        cli.printCveSummary(cveResults, summary);
    }
}
