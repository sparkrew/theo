package io.github.chains_project.theo.monitor.detector;

import io.github.chains_project.theo.monitor.detectorCategories.AbstractCategory;
import io.github.chains_project.theo.monitor.detectorCategories.DetectorCategoryFactory;
import io.github.chains_project.theo.monitor.utils.AccessRecord;
import io.github.chains_project.theo.monitor.utils.DependencyParser;
import io.github.chains_project.theo.monitor.utils.FrameInfo;
import jdk.jfr.consumer.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Predicate;

/**
 * This class includes the methods to further process the recordings from the JFR.
 */
public class Processor {

    private final Predicate<RecordedClassLoader> bootstrapMethodPredicate = classLoader ->
            classLoader == null || classLoader.getName() == null || classLoader.getName().equals("bootstrap");
    private final Predicate<String> methodRemovablePredicate = className -> (className == null ||
            className.contains("surefire") || className.contains("junit") || className.contains("theo"));
    private final Logger log = LoggerFactory.getLogger(this.getClass());

    /**
     * Reads the JFR recordings and extracts dependency privileges.
     *
     * @param detectorCategory the name of the event observed by the JFR
     * @param event            the event observed by the JFR
     */
    public final AccessRecord readRecordings(String detectorCategory, RecordedEvent event) {
        if (event.getStackTrace() == null) {
            System.out.println("No stack trace found for the event: " + event.getEventType().getName());
            return null;
        }
        RecordedStackTrace stackTrace = event.getStackTrace();
        List<FrameInfo> frameInfo = constructStackTrace(stackTrace);
        if (frameInfo == null || frameInfo.isEmpty()) {
            System.out.println("No valid frmaeinfo: " + event.getEventType().getName());
            return null;
        }
        // ToDo: this is not working. Improve the construct stack trace method
        FrameInfo frame = frameInfo.get(frameInfo.size() - 1); // Assuming getLast() is correct
        String method = frame.methodName();
        String className = frame.className();
        String depName = frame.dependency();
        if (depName == null) {
            return null;
        }
        // ToDo: remove the base dependency from the calledBy list
        List<AbstractCategory.SubMethod> calledBy = getCalledByTrace(frameInfo);
        try {
            AbstractCategory category = DetectorCategoryFactory.createCategory(method, className, calledBy,
                    event, detectorCategory);
            if (category != null) {
                AccessRecord.DetectorEvent detectorEvent = new AccessRecord.DetectorEvent(detectorCategory,
                        List.of(category));
                return new AccessRecord(depName, List.of(detectorEvent));
            }
        } catch (NullPointerException | IllegalArgumentException e) {
            log.error("Error reading the event: {}", event.getEventType().getName(), e);
        }
        return null;
    }

    private List<FrameInfo> constructStackTrace(RecordedStackTrace stackTrace) {
        return stackTrace.getFrames().stream()
                .filter(RecordedFrame::isJavaFrame)
                .filter(frame -> {
                    RecordedMethod method = frame.getMethod();
                    RecordedClass type = method.getType();
                    return isMethodValid(type);
                })
                .map(this::createFrameInfo)
                .toList();
    }

    private boolean isMethodValid(RecordedClass type) {
        return !bootstrapMethodPredicate.test(type.getClassLoader())
                && !methodRemovablePredicate.test(type.getName())
                && DependencyParser.findDepDetails(getJarPath(type)) != null;
    }

    private FrameInfo createFrameInfo(RecordedFrame frame) {
        RecordedMethod method = frame.getMethod();
        RecordedClass type = method.getType();
        String depName = DependencyParser.findDepDetails(getJarPath(type));
        return new FrameInfo(
                getModule(type),
                type.getName(),
                method.getName(),
                getClass(type),
                depName
        );
    }

    private String getClass(RecordedClass type) {
        try {
            Class<?> clazz = Class.forName(type.getName());
            Class<?> current = clazz;
            while ((current = current.getDeclaringClass()) != null) {
                clazz = current;
            }
            return clazz.getSimpleName() + ".java";
        } catch (ClassNotFoundException ignored) {
            return null;
        }
    }

    private String getModule(RecordedClass type) {
        try {
            return Class.forName(type.getName()).getModule().getName();
        } catch (ClassNotFoundException ignored) {
            return null;
        }
    }

    private String getJarPath(RecordedClass type) {
        try {
            Class<?> clazz = Class.forName(type.getName());
            String jarLocation = clazz.getProtectionDomain().getCodeSource().getLocation().toString();
            if (jarLocation.contains("target")) {
                return null;
            }
            // return jarLocation.substring(jarLocation.lastIndexOf("/.m2") +1);
            return jarLocation;
        } catch (ClassNotFoundException | NullPointerException e) {
            return null;
        }
    }

    private List<AbstractCategory.SubMethod> getCalledByTrace(List<FrameInfo> frameInfo) {
        List<AbstractCategory.SubMethod> calledBy = new ArrayList<>();
        for (FrameInfo info : frameInfo) {
            String depName = info.dependency();
            boolean foundDependency = false;
            for (AbstractCategory.SubMethod subMethod : calledBy) {
                if (subMethod.getDependency().equals(depName)) {
                    int index = calledBy.indexOf(subMethod);
                    List<String> methods = new ArrayList<>(subMethod.getMethods());
                    methods.add(concatClassMethodName(info.className(), info.methodName()));
                    subMethod.setMethods(methods);
                    calledBy.set(index, subMethod);
                    foundDependency = true;
                    break;
                }
            }
            if (!foundDependency && depName != null) {
                AbstractCategory.SubMethod subMethod = new AbstractCategory.SubMethod(
                        depName,
                        Collections.singletonList(concatClassMethodName(info.className(), info.methodName()))
                );
                calledBy.add(subMethod);
            }
        }
        return calledBy;
    }

    private String concatClassMethodName(String className, String methodName) {
        return (className.replace(".java", "").concat(methodName));
    }
}
