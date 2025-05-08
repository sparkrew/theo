package io.github.chains_project.theo.monitor.detector;

import io.github.chains_project.theo.monitor.detectorCategories.DetectorCategoryFactory;
import io.github.chains_project.theo.monitor.utils.AccessRecord;
import io.github.chains_project.theo.monitor.utils.DependencyParser;
import io.github.chains_project.theo.monitor.utils.JsonUtils;
import jdk.jfr.consumer.EventStream;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordingFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Supplier;

/**
 * This class includes the methods to receive the events recorded by the JFR, process them and generate reports.
 */
public class BaseDetector {
    private static final List<DetectorCategoryFactory.DetectionCategory> detectors =
            new ArrayList<>(EnumSet.allOf(DetectorCategoryFactory.DetectionCategory.class));
    private static final String JDK_EVENT_PREFIX = "jdk.";
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    /**
     * Receives realtime JFR events and sends them for further processing.
     *
     * @param repositoryPath JFR repository path
     * @param reportFile     the report file path
     * @param lockfile       the lockfile path
     */
    public void trackJFREventsOnline(Path repositoryPath, Path reportFile, Path lockfile, Processor processor) {
        DependencyParser.initialize(lockfile);
        processEvents(() -> {
            EventStream eventStream;
            try {
                eventStream = EventStream.openRepository(repositoryPath);
                return eventStream;
            } catch (IOException e) {
                log.error("Error opening event stream: ", e);
                return null;
            }
        }, reportFile, processor);
    }

    /**
     * Reads JFR events from a JFR recording file and sends them for further processing.
     *
     * @param recordingFile JFR recording file
     * @param reportFile    the report file path
     * @param lockfile      the lockfile path
     */
    public void trackJFREventsOffline(Path recordingFile, Path reportFile, Path lockfile, Processor processor) {
        DependencyParser.initialize(lockfile);
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
            if (eventStream instanceof EventStream es) {
                es.onEvent(event -> processEvent(event, processor, allAccessRecords));
                es.start();
            } else if (eventStream instanceof RecordingFile rf) {
                while (rf.hasMoreEvents()) {
                    processEvent(rf.readEvent(), processor, allAccessRecords);
                }
            }
        } catch (Exception e) {
            log.error("Error reading the JFR recordings: ", e);
        }
        log.info("Processing completed...");
        JsonUtils.writeToFile(reportPath, convertAccessRecordsToReport(allAccessRecords));
        log.info("Access records are written to " + reportPath);
    }

    private void processEvent(RecordedEvent event, Processor processor, List<AccessRecord> allAccessRecords) {
        String eventName = event.getEventType().getName();
        for (DetectorCategoryFactory.DetectionCategory category : detectors) {
            if (eventName.equals(JDK_EVENT_PREFIX + category.toString())) {
                Optional.ofNullable(processor.readRecordings(category.toString(), event))
                        .ifPresent(allAccessRecords::add);
                break;
            }
        }
    }

    private Map<String, List<AccessRecord.DetectorEvent>> convertAccessRecordsToReport(List<AccessRecord> accessRecords) {
        Map<String, List<AccessRecord.DetectorEvent>> report = new HashMap<>();
        for (AccessRecord accessRecord : accessRecords) {
            String dependency = accessRecord.dependency();
            List<AccessRecord.DetectorEvent> records = accessRecord.records();
            if (report.containsKey(dependency)) {
                report.get(dependency).addAll(records);
            } else {
                report.put(dependency, new ArrayList<>(records));
            }
        }
        return report;
    }

    private List<AccessRecord> loadAccessPrivilegesFromFile(String fileName) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        File file = new File(fileName);
        List<AccessRecord> allAccessRecords = new ArrayList<>();
        Map<String, List<AccessRecord.DetectorEvent>> existingAccessRecords =
                objectMapper.readValue(file, new TypeReference<>() {
                });
        for (Map.Entry<String, List<AccessRecord.DetectorEvent>> entry : existingAccessRecords.entrySet()) {
            allAccessRecords.add(new AccessRecord(entry.getKey(), entry.getValue()));
        }
        return allAccessRecords;
    }
}
