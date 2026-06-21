package io.github.chains_project.theo.package_miner;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Tracks how many packages made it through each stage of the mining pipeline.
 *
 * This gives us a clear picture of where packages drop off:
 * - How many were selected from Maven Central
 * - How many JARs we successfully downloaded
 * - How many had their dependencies resolved by the preprocessor
 * - How many were successfully analyzed by theo-static
 * - How many turned out to have at least one sensitive API
 *
 * All counters are thread-safe so they can be incremented from parallel worker threads.
 * At the end, a summary is logged and also written to a JSON file for later reference.
 */
public class MiningStats {

    private static final Logger log = LoggerFactory.getLogger(MiningStats.class);

    private final AtomicInteger totalSelected = new AtomicInteger(0);
    private final AtomicInteger downloadSuccess = new AtomicInteger(0);
    private final AtomicInteger downloadFailed = new AtomicInteger(0);
    private final AtomicInteger preprocessorSuccess = new AtomicInteger(0);
    private final AtomicInteger preprocessorFailed = new AtomicInteger(0);
    private final AtomicInteger analyzerSuccess = new AtomicInteger(0);
    private final AtomicInteger analyzerFailed = new AtomicInteger(0);
    private final AtomicInteger withSensitiveApis = new AtomicInteger(0);
    private final AtomicInteger withoutSensitiveApis = new AtomicInteger(0);
    // Packages where the analyzer found at least one public entry point method
    private final AtomicInteger withEntryPoints = new AtomicInteger(0);
    // Packages with zero entry points — nothing to analyze
    private final AtomicInteger withoutEntryPoints = new AtomicInteger(0);

    public void setTotalSelected(int count) {
        totalSelected.set(count);
    }

    public void recordDownloadSuccess() {
        downloadSuccess.incrementAndGet();
    }

    public void recordDownloadFailure() {
        downloadFailed.incrementAndGet();
    }

    public void recordPreprocessorSuccess() {
        preprocessorSuccess.incrementAndGet();
    }

    public void recordPreprocessorFailure() {
        preprocessorFailed.incrementAndGet();
    }

    public void recordAnalyzerSuccess() {
        analyzerSuccess.incrementAndGet();
    }

    public void recordAnalyzerFailure() {
        analyzerFailed.incrementAndGet();
    }

    public void recordWithSensitiveApis() {
        withSensitiveApis.incrementAndGet();
    }

    public void recordWithoutSensitiveApis() {
        withoutSensitiveApis.incrementAndGet();
    }

    public void recordEntryPoints(int count) {
        if (count > 0) {
            withEntryPoints.incrementAndGet();
        } else {
            withoutEntryPoints.incrementAndGet();
        }
    }

    /**
     * Logs a human-readable summary of the pipeline statistics and writes them
     * to a JSON file so they can be referenced later.
     */
    public void printSummary(Path outputDir) {
        log.info("=============================================================");
        log.info("                    MINING PIPELINE SUMMARY                   ");
        log.info("=============================================================");
        log.info("  Packages selected from Maven Central:  {}", totalSelected.get());
        log.info("-------------------------------------------------------------");
        log.info("  JAR download succeeded:                {}", downloadSuccess.get());
        log.info("  JAR download failed:                   {}", downloadFailed.get());
        log.info("-------------------------------------------------------------");
        log.info("  Preprocessor succeeded:                {}", preprocessorSuccess.get());
        log.info("  Preprocessor failed:                   {}", preprocessorFailed.get());
        log.info("-------------------------------------------------------------");
        log.info("  Static analyzer succeeded:             {}", analyzerSuccess.get());
        log.info("  Static analyzer failed:                {}", analyzerFailed.get());
        log.info("-------------------------------------------------------------");
        log.info("  Packages WITH entry points:            {}", withEntryPoints.get());
        log.info("  Packages WITHOUT entry points:         {}", withoutEntryPoints.get());
        log.info("-------------------------------------------------------------");
        log.info("  Packages WITH sensitive APIs:          {}", withSensitiveApis.get());
        log.info("  Packages WITHOUT sensitive APIs:       {}", withoutSensitiveApis.get());
        log.info("=============================================================");

        // Also save the stats to a JSON file for programmatic access
        saveSummaryJson(outputDir);
    }

    private void saveSummaryJson(Path outputDir) {
        try {
            SummaryRecord summary = new SummaryRecord(
                    totalSelected.get(),
                    downloadSuccess.get(),
                    downloadFailed.get(),
                    preprocessorSuccess.get(),
                    preprocessorFailed.get(),
                    analyzerSuccess.get(),
                    analyzerFailed.get(),
                    withEntryPoints.get(),
                    withoutEntryPoints.get(),
                    withSensitiveApis.get(),
                    withoutSensitiveApis.get()
            );
            ObjectMapper mapper = new ObjectMapper();
            mapper.writerWithDefaultPrettyPrinter()
                    .writeValue(outputDir.resolve("mining_summary.json").toFile(), summary);
        } catch (IOException e) {
            log.error("Failed to write summary JSON.", e);
        }
    }

    /**
     * The summary as a record, serialized to mining_summary.json at the end of the run.
     */
    public record SummaryRecord(
            int totalSelected,
            int downloadSuccess,
            int downloadFailed,
            int preprocessorSuccess,
            int preprocessorFailed,
            int analyzerSuccess,
            int analyzerFailed,
            int withEntryPoints,
            int withoutEntryPoints,
            int withSensitiveApis,
            int withoutSensitiveApis
    ) {}
}
