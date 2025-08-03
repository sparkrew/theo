package io.github.chains_project.theo.theo_test_exec.detector;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import io.github.chains_project.theo.theo_commons.PackageMatcher;
import io.github.chains_project.theo.theo_commons.SensitiveAPIDescriptor;
import io.github.chains_project.theo.theo_test_exec.detectorCategories.AbstractCategory;
import io.github.chains_project.theo.theo_test_exec.detectorCategories.DetectorCategoryFactory;
import io.github.chains_project.theo.theo_test_exec.utils.AccessRecord;
import jdk.jfr.consumer.RecordedEvent;
import jdk.jfr.consumer.RecordedFrame;
import jdk.jfr.consumer.RecordedMethod;
import jdk.jfr.consumer.RecordedStackTrace;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * This class includes the methods to further process the recordings from the JFR.
 */
public class Processor {

    private final Predicate<String> noiseRemovalPredicate = className ->
            className.equals("java.lang.ClassLoader") ||
                    className.equals("java.lang.Class") ||
                    className.equals("java.lang.reflect.Method") ||
                    className.equals("java.lang.reflect.Constructor") ||
                    className.equals("java.lang.reflect.Field");
    //ToDo: This predicate must be updated to make it more applicable.
    private final Predicate<String> methodRemovablePredicate = className -> (className == null ||
            className.contains("surefire") || className.contains("junit") || className.contains(".theo.") || className.contains("org.apache.pdfbox."));
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    private final Map<String, List<SensitiveAPIDescriptor>> sensitiveApiMap;
    private final List<SensitiveAPIDescriptor> newlyDiscoveredApis = new ArrayList<>();
    private final Map<String, String> props;

    public Processor(Map<String, List<SensitiveAPIDescriptor>> sensitiveApiMap, Map<String, String> props) {
        this.sensitiveApiMap = sensitiveApiMap;
        this.props = props;
    }

    static String filterName(String name) {
        // Replace $ followed by digit (e.g., $Array1234) with nothing
        name = name.replaceAll("\\$\\d+", "");
        // Replace $ followed by letter (e.g. Java.ArrayInitializer) with a dot
        name = name.replaceAll("\\$(?=[A-Za-z])", ".");
        return name;
    }

    /**
     * Reads the JFR recordings and extracts dependency privileges.
     *
     * @param detectorCategory the category of the detector
     * @param event            the event observed by the JFR
     */
    public List<AccessRecord> readRecordings(String detectorCategory, RecordedEvent event) {
        List<AccessRecord> accessRecords = new ArrayList<>();
        try {
            if (event.getStackTrace() == null) return null;

            List<RecordedFrame> frames = event.getStackTrace().getFrames().stream()
                    .filter(RecordedFrame::isJavaFrame)
                    .toList();

            AbstractCategory category = DetectorCategoryFactory.createCategory(event, detectorCategory, props.get("packageName"));
            if (category != null) {
                List<SensitiveAPIDescriptor> sensitiveApiEvents = findSensitiveApis(event.getStackTrace(), detectorCategory);
                if (sensitiveApiEvents.size() == 0) {
                    // Jfr can identify following events. However, they do not carry the exact method in the stacktrace
                    // most of the time. AspectJ cannot track them either. That is because these classes are loaded by
                    // the JVM at the startup. AFAIK, these jfr events have native implementations within the JVM.
                    // Therefore, we make approximations when such events are detected, and add the sensitive APIs
                    // manually.
                    if (detectorCategory.equals("ProcessStart") || detectorCategory.equals("SystemProcess")) {
                        sensitiveApiEvents.add(new SensitiveAPIDescriptor(
                                "java.lang.ProcessBuilder|java.lang.Runtime",
                                "unknown",
                                "PROCESS",
                                "OPERATING SYSTEM"
                        ));
                    }
                    if (detectorCategory.equals("NativeLibrary")) {
                        sensitiveApiEvents.add(new SensitiveAPIDescriptor(
                                "native",
                                "unknown",
                                "PROCESS",
                                "OPERATING SYSTEM"
                        ));
                    }
                    // ClassLoads are noisy.
                    if (!detectorCategory.equals("ClassLoad")) {
                        // log.info("No sensitive API calls found in event: {}!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
                        //         event.getEventType().getName());
                        // log.info("Stack trace: {}", frames);
                    }
                }
                FrameIndices indices = findAccessFrameIndices(frames);
                for (SensitiveAPIDescriptor sensitiveEvent : sensitiveApiEvents) {
                    String sensitiveClassMethod = concatClassMethodName(sensitiveEvent.className(), sensitiveEvent.method());
                    accessRecords.addAll(buildAccessRecords(frames, indices, category, sensitiveClassMethod));
                }
            }
        } catch (Exception e) {
            log.error("Error reading event: {}", event.getEventType().getName(), e);
        }
        return accessRecords;
    }

    /**
     * Reads the JFR recordings and extracts dependency privileges.
     *
     * @param event the event observed by the JFR
     */
    public List<AccessRecord> readRecordings(RecordedEvent event) {
        List<AccessRecord> accessRecords = new ArrayList<>();
        try {
            if (event.getStackTrace() == null) return null;
            List<RecordedFrame> frames = event.getStackTrace().getFrames().stream()
                    .filter(RecordedFrame::isJavaFrame)
                    .toList();
            AbstractCategory category = DetectorCategoryFactory.createCategory(event, "Theo", props.get("packageName"));
            String sensitiveClassMethod = concatClassMethodName(
                    event.getString("className"),
                    event.getString("methodName")
            );
            FrameIndices indices = findAccessFrameIndices(frames);
            accessRecords.addAll(buildAccessRecords(frames, indices, category, sensitiveClassMethod));
        } catch (Exception e) {
            log.error("Error reading event: {}", event.getEventType().getName(), e);
        }
        return accessRecords;
    }

    // ToDo: check this, if the order is right this should be right
    // Here, we take an approximation that the sensitive APIs are the final APIs called in the stack trace.
    // For each sensitive API, we iterate over the stacktrace. The third party API closest to the sensitive
    // API is considered as the last, the first one is the one that is closest to the entry point.
    private FrameIndices findAccessFrameIndices(List<RecordedFrame> frames) {
        int firstIndex = -1;
        int lastIndex = -1;
        List<Integer> internalIndices = new ArrayList<>();

        for (int i = 0; i < frames.size(); i++) {
            RecordedFrame frame = frames.get(i);
            String className = frame.getMethod().getType().getName();
            String packageName = className.contains(".") ? className.substring(0, className.lastIndexOf('.')) : className;
            String depName = PackageMatcher.getDependencyName(packageName, Path.of(props.get("packageMapPath")));
            if (depName != null && !depName.isEmpty() && !methodRemovablePredicate.test(className)) {
                if (firstIndex == -1) {
                    firstIndex = i;
                } else {
                    internalIndices.add(i);
                }
                lastIndex = i;
            }
        }
        return new FrameIndices(firstIndex, lastIndex, internalIndices);
    }

    private List<AccessRecord> buildAccessRecords(
            List<RecordedFrame> frames,
            FrameIndices indices,
            AbstractCategory category,
            String sensitiveClassMethod
    ) {
        List<AccessRecord> records = new ArrayList<>();
        int firstIndex = indices.firstIndex;
        int lastIndex = indices.lastIndex;
        List<Integer> internalIndices = indices.internalIndices;
        if (firstIndex != -1) {
            if (firstIndex == lastIndex) {
                records.add(toAccessRecord(frames.get(firstIndex), "First, Last", category, sensitiveClassMethod));
            } else {
                records.add(toAccessRecord(frames.get(firstIndex), "Last", category, sensitiveClassMethod));
                // To remove the last item, which should be considered as Last
                for (int i = 0; i < internalIndices.size() - 1; i++) {
                    int idx = internalIndices.get(i);
                    records.add(toAccessRecord(frames.get(idx), "Internal", category, sensitiveClassMethod));
                }
                records.add(toAccessRecord(frames.get(lastIndex), "First", category, sensitiveClassMethod));
            }
        }
        return records;
    }

    // Once we are sure we do not need this method we can remove it.
    private int findFrameIndex(List<RecordedFrame> frames, String classMethod) {
        for (int i = 0; i < frames.size(); i++) {
            RecordedMethod method = frames.get(i).getMethod();
            String full = concatClassMethodName(method.getType().getName(), method.getName());
            if (full.equals(classMethod)) return i;
        }
        return -1;
    }

    private AccessRecord toAccessRecord(RecordedFrame frame, String position, AbstractCategory category, String sensitiveMethod) {
        RecordedMethod method = frame.getMethod();
        String className = method.getType().getName();
        String methodName = method.getName();
        String classMethod = concatClassMethodName(className, methodName);
        String packageName = className.contains(".") ? className.substring(0, className.lastIndexOf('.')) : className;
        String depName = PackageMatcher.getDependencyName(packageName, Path.of(props.get("packageMapPath")));
        return new AccessRecord(depName, classMethod, position, category, sensitiveMethod);
    }

    private boolean isDirectTestMethodCall(RecordedStackTrace stackTrace) {
        // Assumes stack trace is ordered.
        for (RecordedFrame frame : stackTrace.getFrames()) {
            if (!frame.isJavaFrame()) {
                continue;
            }
            String className = frame.getMethod().getType().getName();
            // If we find a class from the application first then even if another test method is seen in the stack
            // trace later, then we consider this as a method that represents the actual application execution.
            if (className.startsWith(props.get("packageName"))) {
                return false;
            }
            if (className.endsWith("Test") || className.endsWith("Tests") || className.endsWith("TestCase")) {
                // If we come with a test method first, before a method from the actual program, that means that method
                // call is a test preparatory step that does not belong to the actual application.
                return true;
            }
        }
        log.error("Stack trace contains no recognizable test or application code.");
        return false; // This is a case that should not have happened.
    }

    /**
     * Analyzes a stack trace and finds all sensitive API calls
     *
     * @param stackTrace The recorded stack trace from JFR
     * @return List of detected sensitive API calls with their details
     */
    private List<SensitiveAPIDescriptor> findSensitiveApis(RecordedStackTrace stackTrace, String detectorCategory) {
        List<SensitiveAPIDescriptor> result = new ArrayList<>();
        for (RecordedFrame frame : stackTrace.getFrames()) {
            if (!frame.isJavaFrame()) {
                continue;
            }
            String className = frame.getMethod().getType().getName();
            if (props.get("removeNoise").equals("true") && noiseRemovalPredicate.test(className)) {
                // If configs are set to remove noise we remove the sensitive APIs that are present in almost all cases.
                // It is not straightforward to detect which classloads are harmful and which ones are not, even if we
                // filter third party methods.
                continue;

            }
            // We do not want any initial methods that were called by other functionalities in the project. For example,
            // we don't care about the methods invoked by JUnit. JUnit uses reflection to identify and execute test
            // cases. That interferes with our sensitive method identification.
            // In the stack trace methods invoked by JUnit appear before the client project methods. Therefore, we only
            // process until we find the methods called directly by the client project (we identify it through the
            // package name) under study.
            if (className.startsWith(props.get("packageName"))) {
                break;
            }
            if (methodRemovablePredicate.test(className)) {
                continue;
            }
            String methodName = frame.getMethod().getName();
            SensitiveAPIDescriptor match = findMatchingSensitiveApi(
                    filterName(className),
                    filterName(methodName),
                    detectorCategory
            );
            if (match != null) {
                result.add(match);
            }
        }
        return result;
    }


    /**
     * Finds a matching sensitive API for the given class and method
     *
     * @param className  The full class name
     * @param methodName The method name
     * @return SensitiveApi if found, null otherwise
     */
    private SensitiveAPIDescriptor findMatchingSensitiveApi(String className, String methodName, String detectorCategory) {
        List<SensitiveAPIDescriptor> classApis = sensitiveApiMap.get(className);
        if (classApis != null) {
            for (SensitiveAPIDescriptor api : classApis) {
                if (api.method().equals(methodName) || api.method().equals("*")) {
                    return api;
                }
            }
        }
        //return findOrDiscoverSensitiveApi(className, methodName, detectorCategory, classApis);
        return null;
    }

    // This method is to find new sensitive API that are not in the original list based on the class and method names.
    // But, we do not want this functionality for now.
    private SensitiveAPIDescriptor findOrDiscoverSensitiveApi(String className, String methodName, String detectorCategory, List<SensitiveAPIDescriptor> classApis) {
        // We observed many sensitive APIs which are not in the API list. Therefore, we carry out this iterative
        // process to dynamically collect new sensitive APIs
        if (detectorCategory.equals("ClassLoad")) { // But we don't collect new APIs for ClassLoad events.
            return null;
        }
        for (Map.Entry<String, List<SensitiveAPIDescriptor>> entry : sensitiveApiMap.entrySet()) {
            String existingClass = entry.getKey();
            // Check if the new className starts with an existing sensitive class prefix. Here we match the prefix of
            // all classes (e.g., java.io.) and consider all classes that have that prefix as sensitive APIs.
            // This should be manually checked and updated.
            if (methodName.matches(".*\\d.*") || methodName.contains("$")) {
                // If the method name contains a digit or a $, we skip it as it is likely a synthetic method,
                // a method generated by the compiler (e.g., lambda expressions).
                continue;
            }
            if (className.startsWith("java.lang.") || className.startsWith("java.util.")) {
                continue;
                // If the class is from java.lang or java.util, we skip it as it is not always sensitive.Should we
                // keep them if the class is the same as an existing sensitive class? If so, uncomment the following line.
                // if (!className.equals(existingClass))
            }
            if (className.startsWith(existingClass.substring(0, existingClass.lastIndexOf('.')))) {
                // Clone category/subcategory from the first matching descriptor. This is an approximation of the
                // category. Should also be updated later manually.
                List<SensitiveAPIDescriptor> existingApis = entry.getValue();
                if (existingApis != null && !existingApis.isEmpty()) {
                    SensitiveAPIDescriptor referenceApi = existingApis.get(0);
                    if (classApis == null) {
                        classApis = new ArrayList<>();
                        //sensitiveApiMap.put(className, classApis);
                    }
                    boolean alreadyExists = classApis.stream()
                            .anyMatch(api -> api.method().equals(methodName));
                    if (!alreadyExists) {
                        SensitiveAPIDescriptor newApi = new SensitiveAPIDescriptor(
                                className,
                                methodName,
                                referenceApi.category(),
                                referenceApi.subcategory()
                        );
                        //classApis.add(newApi);
                        newlyDiscoveredApis.add(newApi);
                        return newApi;
                    }
                }
            }
        }
        return null;
    }

    /**
     * Writes the newly discovered sensitive APIs to a file in JSON format.
     *
     * @param filePath The path to the file where the new sensitive APIs should be written.
     */
    public void writeNewSensitiveApisToFile(String filePath) {
        if (newlyDiscoveredApis.isEmpty()) {
            log.info("No new sensitive APIs found.");
            return;
        }
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);

        try {
            mapper.writeValue(new File(filePath), newlyDiscoveredApis);
            log.info("New sensitive APIs written to " + filePath);
        } catch (IOException e) {
            log.error("Failed to write new sensitive APIs: " + e.getMessage());
        }
    }

    private String concatClassMethodName(String className, String methodName) {
        return (filterName(className).concat("." + filterName(methodName)));
    }

    private static class FrameIndices {
        int firstIndex;
        int lastIndex;
        List<Integer> internalIndices;

        FrameIndices(int firstIndex, int lastIndex, List<Integer> internalIndices) {
            this.firstIndex = firstIndex;
            this.lastIndex = lastIndex;
            this.internalIndices = internalIndices;
        }
    }
}
