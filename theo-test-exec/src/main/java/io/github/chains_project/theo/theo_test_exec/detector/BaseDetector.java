package io.github.chains_project.theo.theo_test_exec.detector;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.chains_project.theo.theo_commons.APILoader;
import io.github.chains_project.theo.theo_commons.SensitiveAPIDescriptor;
import io.github.chains_project.theo.theo_test_exec.detectorCategories.DetectorCategoryFactory;
import io.github.chains_project.theo.theo_test_exec.utils.AccessRecord;
import io.github.chains_project.theo.theo_test_exec.utils.JsonUtils;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * This class includes the methods to receive the events recorded by the JFR, process them and generate reports.
 */
public class BaseDetector {
    private static final String JDK_EVENT_PREFIX = "jdk.";
    private static final String THEO_EVENT_PREFIX = "theo.";
    private static final List<DetectorCategoryFactory.DetectionCategory> detectors =
            new ArrayList<>(EnumSet.allOf(DetectorCategoryFactory.DetectionCategory.class));
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    /**
     * Reads JFR events from a JFR recording file and sends them for further processing.
     *
     * @param recordingFile JFR recording file
     * @param reportFile    the report file path
     * @param removeNoise   if set to true, the detector will remove noise from the report. This includes classloads and reflections.
     * @param packageName   the package name of the project under consideration to filter the events
     */
    public void trackJFREvents(Path recordingFile, Path reportFile, String removeNoise, String packageName,
                               String packageMapPath) {
        List<SensitiveAPIDescriptor> sensitiveAPIList = APILoader.loadFromClasspath(
                "sensitive_apis.json", new TypeReference<>() {
                }
        );
        Map<String, List<SensitiveAPIDescriptor>> sensitiveApiMap = sensitiveAPIList.stream()
                .collect(Collectors.groupingBy(SensitiveAPIDescriptor::className));
        Map<String, String> props = Map.of(
                "removeNoise", removeNoise,
                "packageName", packageName,
                "packageMapPath", packageMapPath
        );
        Processor processor = new Processor(sensitiveApiMap, props);
        processEvents(() -> {
            try {
                return new RecordingFile(recordingFile);
            } catch (IOException e) {
                log.error("Error reading the JFR recordings: ", e);
                return null;
            }
        }, reportFile, processor);
    }

    private void processEvents(Supplier<AutoCloseable> eventSupplier, Path reportPath, Processor processor) {
        List<AccessRecord> allAccessRecords = new ArrayList<>();
        try (AutoCloseable eventStream = eventSupplier.get()) {
            if (eventStream instanceof RecordingFile rf) {
                while (rf.hasMoreEvents()) {
                    processEvent(rf.readEvent(), processor, allAccessRecords);
                }
            }
        } catch (Exception e) {
            log.error("Error reading the JFR recordings: ", e);
        }
        log.info("Processing completed...");
        JsonUtils.writeToFile(reportPath, convertAccessRecordsToReport(allAccessRecords));
        processor.writeNewSensitiveApisToFile("new-sensitive-apis.json");
        log.info("Access records are written to " + reportPath);
    }

    private void processEvent(RecordedEvent event, Processor processor, List<AccessRecord> allAccessRecords) {
        String eventName = event.getEventType().getName();
        // We consider all Theo events defined within the Theo Agent. Currently, there is only one event, so we can map
        // the full name if we want.
        if (eventName.startsWith(THEO_EVENT_PREFIX)) {
            Optional.ofNullable(processor.readRecordings(event))
                    .ifPresent(allAccessRecords::addAll);
        }
        // We consider all events defined within the detector categories factory.
        for (DetectorCategoryFactory.DetectionCategory category : detectors) {
            if (eventName.equals(JDK_EVENT_PREFIX + category.toString())) {
                Optional.ofNullable(processor.readRecordings(category.toString(), event))
                        .ifPresent(allAccessRecords::addAll);
                break;
            }
        }
    }

    private Map<String, Map<String, Map<String, String>>> convertAccessRecordsToReport(List<AccessRecord> accessRecords) {
        Map<String, Map<String, Map<String, String>>> report = new TreeMap<>();
        for (AccessRecord ar : accessRecords) {
            report
                    .computeIfAbsent(ar.dependency(), d -> new TreeMap<>())
                    .computeIfAbsent(ar.sensitiveAPI(), s -> new TreeMap<>())
                    .put(ar.method(), ar.position());
        }
        return report;
    }
}
