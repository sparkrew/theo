package io.github.chains_project.theo.theo_static;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.chains_project.theo.theo_static.utils.SensitivePathAnalysisResult;
import io.github.chains_project.theo.theo_static.utils.SensitivePathResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.*;

public class OutputFormatter {

    private static final Logger log = LoggerFactory.getLogger(OutputFormatter.class);

    /**
     * Processes the sensitive path analysis result and generates a JSON report.
     *
     * @param analysisResult The result of the sensitive path analysis.
     * @param outputFilePath The path where the output JSON file will be written.
     */
    public static void process(SensitivePathAnalysisResult analysisResult, String outputFilePath) {
        // Using TreeMap so there won't be diffs for the same input
        Map<String, Map<String, Map<String, String>>> result = new TreeMap<>();
        for (SensitivePathResult pathResult : analysisResult.sensitivePaths) {
            String sensitiveAPI = pathResult.securitySensitiveAPI;
            Map<String, Map<String, String>> depPosMap = pathResult.dependencyPositionMap;
            for (Map.Entry<String, Map<String, String>> depEntry : depPosMap.entrySet()) {
                String dep = depEntry.getKey();
                Map<String, String> methodPositionMap = depEntry.getValue();
                for (Map.Entry<String, String> methodEntry : methodPositionMap.entrySet()) {
                    String method = methodEntry.getKey();
                    String position = methodEntry.getValue();
                    result
                            .computeIfAbsent(dep, k -> new TreeMap<>())
                            .computeIfAbsent(sensitiveAPI, k -> new TreeMap<>())
                            .put(method, position);
                }
            }
        }
        ObjectMapper mapper = new ObjectMapper();
        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(new File(outputFilePath), result);
        } catch (IOException e) {
            throw new RuntimeException("Failed to write the final output into the report: " + outputFilePath, e);
        }
    }
}
