package io.github.chains_project.theo.package_miner.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

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
    private final AtomicInteger withEntryPoints = new AtomicInteger(0);
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
