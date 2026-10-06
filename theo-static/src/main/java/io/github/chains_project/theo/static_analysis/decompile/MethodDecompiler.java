package io.github.chains_project.theo.static_analysis.decompile;

import org.benf.cfr.reader.api.CfrDriver;
import org.benf.cfr.reader.api.OutputSinkFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Wraps the CFR decompiler to extract decompiled source code for individual methods
 * from JAR files. Used by the HTML report generator to show readable source for
 * dependency methods that touch sensitive APIs.
 */
public class MethodDecompiler {

    private static final Logger log = LoggerFactory.getLogger(MethodDecompiler.class);

    private static final String DECOMPILATION_UNAVAILABLE = "// decompilation unavailable for this method";

    public MethodDecompiler() {
        // no state needed — CFR drivers are created per invocation
    }

    /**
     * Decompiles a specific method from a class inside a JAR.
     *
     * @param jarPath                 path to the JAR containing the class
     * @param fullyQualifiedClassName e.g. "org.apache.commons.io.FileUtils"
     * @param methodName              e.g. "readFileToString"
     * @return the decompiled source of the method, the full class if extraction fails,
     *         or a fallback message if decompilation fails entirely
     */
    public String decompileMethod(Path jarPath, String fullyQualifiedClassName, String methodName) {
        String classSource = decompileClass(jarPath, fullyQualifiedClassName);
        if (classSource.equals(DECOMPILATION_UNAVAILABLE)) {
            return DECOMPILATION_UNAVAILABLE;
        }
        return extractMethod(classSource, methodName);
    }

    /**
     * Decompiles an entire class from a JAR file.
     *
     * @param jarPath                 path to the JAR containing the class
     * @param fullyQualifiedClassName e.g. "org.apache.commons.io.FileUtils"
     * @return the full decompiled source, or a fallback message on failure
     */
    public String decompileClass(Path jarPath, String fullyQualifiedClassName) {
        try {
            // CFR targets a specific class inside a JAR with the "jar!path" syntax.
            // Without this, it tries to decompile every class in the JAR and the
            // jarfilter option (which filters JAR names, not class names) won't help.
            String classFilePath = fullyQualifiedClassName.replace('.', '/') + ".class";
            String target = jarPath.toAbsolutePath() + "!" + classFilePath;

            Map<String, String> options = new HashMap<>();
            options.put("silent", "true");

            StringBuilder output = new StringBuilder();
            OutputSinkFactory sinkFactory = new OutputSinkFactory() {
                @Override
                public List<SinkClass> getSupportedSinks(SinkType sinkType, Collection<SinkClass> available) {
                    return List.of(SinkClass.STRING);
                }

                @Override
                public <T> Sink<T> getSink(SinkType sinkType, SinkClass sinkClass) {
                    return obj -> {
                        if (sinkType == SinkType.JAVA) {
                            output.append(obj);
                        }
                    };
                }
            };

            CfrDriver driver = new CfrDriver.Builder()
                    .withOptions(options)
                    .withOutputSink(sinkFactory)
                    .build();

            driver.analyse(List.of(target));

            String result = output.toString().trim();
            if (result.isEmpty()) {
                log.debug("CFR produced empty output for class {} in {}", fullyQualifiedClassName, jarPath);
                return DECOMPILATION_UNAVAILABLE;
            }
            return result;

        } catch (Exception e) {
            log.debug("Failed to decompile class {} from {}: {}", fullyQualifiedClassName, jarPath, e.getMessage());
            return DECOMPILATION_UNAVAILABLE;
        }
    }

    /**
     * Extracts a single method from decompiled class source by finding its signature
     * and using brace counting to locate the closing brace.
     * Falls back to the full class source if the method can't be isolated.
     */
    private String extractMethod(String classSource, String methodName) {
        String[] lines = classSource.split("\n");
        int methodStart = -1;

        // Find the line containing the method signature — look for the method name
        // followed by a parenthesis, which distinguishes method declarations from
        // field references or comments that happen to mention the name.
        for (int i = 0; i < lines.length; i++) {
            String trimmed = lines[i].trim();
            if (trimmed.contains(methodName + "(") && !trimmed.startsWith("//") && !trimmed.startsWith("*")) {
                methodStart = i;
                break;
            }
        }

        if (methodStart == -1) {
            log.debug("Could not locate method '{}' in decompiled source, returning full class", methodName);
            return classSource;
        }

        // Walk forward from the signature, counting braces to find where the method ends.
        int braceDepth = 0;
        boolean seenOpenBrace = false;
        StringBuilder methodSource = new StringBuilder();

        for (int i = methodStart; i < lines.length; i++) {
            methodSource.append(lines[i]).append("\n");

            for (char c : lines[i].toCharArray()) {
                if (c == '{') {
                    braceDepth++;
                    seenOpenBrace = true;
                } else if (c == '}') {
                    braceDepth--;
                }
            }

            // The method body is complete when we've seen at least one open brace
            // and the depth returns to zero.
            if (seenOpenBrace && braceDepth == 0) {
                return methodSource.toString().trim();
            }
        }

        // Brace counting didn't converge — the source might be unusual.
        log.debug("Brace counting did not converge for method '{}', returning full class", methodName);
        return classSource;
    }
}
