package io.github.chains_project.theo.package_static_analyzer;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.util.*;

/**
 * Writes the analysis report as a JSON file.
 *
 * The report structure:
 * {
 *   "metadata": { jarPath, entryPoints, totalPaths, directCount, indirectCount, timestamp },
 *   "directAccesses": [
 *     { entryPoint, sensitiveAPI, fullPath }
 *   ],
 *   "indirectAccesses": [
 *     { entryPoint, sensitiveAPI, dependencies: [...], fullPath }
 *   ],
 *   "sensitiveAPISummary": {
 *     "java.io.FileInputStream.<init>": { "accessType": "DIRECT", "count": 3 },
 *     "java.net.Socket.<init>":         { "accessType": "INDIRECT", "dependencies": [...], "count": 1 }
 *   }
 * }
 */
public class ReportWriter {

    private static final Logger log = LoggerFactory.getLogger(ReportWriter.class);

    public static void write(List<PackageStaticAnalyzer.SensitiveApiPath> paths,
                             String jarPath, int entryPointCount, String outputPath) {
        // Split results into direct and indirect accesses
        List<Map<String, Object>> directAccesses = new ArrayList<>();
        List<Map<String, Object>> indirectAccesses = new ArrayList<>();

        // Summary: for each sensitive API, how it's accessed and how many times
        Map<String, Map<String, Object>> summary = new TreeMap<>();

        for (PackageStaticAnalyzer.SensitiveApiPath path : paths) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("entryPoint", path.entryPoint());
            entry.put("sensitiveAPI", path.sensitiveAPI());
            entry.put("fullPath", path.fullPath());

            if ("DIRECT".equals(path.accessType())) {
                directAccesses.add(entry);
            } else {
                entry.put("dependencies", path.dependencies());
                indirectAccesses.add(entry);
            }

            // Build per-API summary
            summary.compute(path.sensitiveAPI(), (api, existing) -> {
                if (existing == null) {
                    Map<String, Object> info = new LinkedHashMap<>();
                    info.put("accessType", path.accessType());
                    if (!path.dependencies().isEmpty()) {
                        info.put("dependencies", new TreeSet<>(path.dependencies()));
                    }
                    info.put("count", 1);
                    return info;
                } else {
                    // If we've seen this API before with a different access type, mark as BOTH
                    String prevType = (String) existing.get("accessType");
                    if (!prevType.equals(path.accessType()) && !"BOTH".equals(prevType)) {
                        existing.put("accessType", "BOTH");
                    }
                    // Merge dependencies
                    if (!path.dependencies().isEmpty()) {
                        @SuppressWarnings("unchecked")
                        Set<String> deps = (Set<String>) existing.computeIfAbsent(
                                "dependencies", k -> new TreeSet<>());
                        deps.addAll(path.dependencies());
                    }
                    existing.put("count", (int) existing.get("count") + 1);
                    return existing;
                }
            });
        }

        // Build the final report
        Map<String, Object> report = new LinkedHashMap<>();

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("jarPath", jarPath);
        metadata.put("entryPoints", entryPointCount);
        metadata.put("totalPaths", paths.size());
        metadata.put("directCount", directAccesses.size());
        metadata.put("indirectCount", indirectAccesses.size());
        metadata.put("uniqueSensitiveAPIs", summary.size());
        metadata.put("timestamp", System.currentTimeMillis());
        report.put("metadata", metadata);

        report.put("directAccesses", directAccesses);
        report.put("indirectAccesses", indirectAccesses);
        report.put("sensitiveAPISummary", summary);

        ObjectMapper mapper = new ObjectMapper();
        try {
            mapper.writerWithDefaultPrettyPrinter().writeValue(new File(outputPath), report);
        } catch (IOException e) {
            log.error("Failed to write report to {}", outputPath, e);
        }
    }
}
