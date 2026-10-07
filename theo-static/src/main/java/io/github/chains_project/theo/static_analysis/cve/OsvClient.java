package io.github.chains_project.theo.static_analysis.cve;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;

/**
 * Queries the OSV.dev vulnerability database for known CVEs affecting
 * Maven dependencies. OSV aggregates advisories from NVD, GitHub, and
 * other sources, so one query covers multiple databases.
 *
 * No API key is required — OSV's public API is free and rate-limited
 * generously enough for per-build usage.
 */
public class OsvClient {

    private static final Logger log = LoggerFactory.getLogger(OsvClient.class);
    private static final ObjectMapper mapper = new ObjectMapper();
    private static final String OSV_QUERY_URL = "https://api.osv.dev/v1/query";
    private static final String OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";

    // OSV recommends keeping batch sizes reasonable to avoid timeouts
    private static final int BATCH_CHUNK_SIZE = 100;

    private final HttpClient httpClient;

    public OsvClient() {
        this.httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    }

    /**
     * Queries OSV for vulnerabilities affecting a single Maven package version.
     *
     * @param groupId    Maven groupId
     * @param artifactId Maven artifactId
     * @param version    Maven version
     * @return list of CVE results, empty if none found or on error
     */
    public List<CveResult> query(String groupId, String artifactId, String version) {
        String mavenName = groupId + ":" + artifactId;
        String body = String.format(
            "{\"package\":{\"ecosystem\":\"Maven\",\"name\":\"%s\"},\"version\":\"%s\"}",
            escapeJson(mavenName), escapeJson(version)
        );

        String response = sendRequest(OSV_QUERY_URL, body);
        if (response == null) {
            return Collections.emptyList();
        }

        try {
            JsonNode root = mapper.readTree(response);
            JsonNode vulns = root.path("vulns");
            if (vulns.isMissingNode() || !vulns.isArray()) {
                return Collections.emptyList();
            }
            return parseVulns(vulns);
        } catch (Exception e) {
            log.warn("Failed to parse OSV response for {}: {}", mavenName, e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Batch query for multiple dependencies at once. More efficient than
     * individual queries when checking many dependencies.
     *
     * @param dependencies list of [groupId, artifactId, version] triples
     * @return map of "groupId:artifactId:version" -> list of CveResults
     */
    public Map<String, List<CveResult>> queryBatch(List<String[]> dependencies) {
        Map<String, List<CveResult>> allResults = new LinkedHashMap<>();

        if (dependencies == null || dependencies.isEmpty()) {
            return allResults;
        }

        // Split into chunks if the batch is large
        for (int offset = 0; offset < dependencies.size(); offset += BATCH_CHUNK_SIZE) {
            int end = Math.min(offset + BATCH_CHUNK_SIZE, dependencies.size());
            List<String[]> chunk = dependencies.subList(offset, end);
            Map<String, List<CveResult>> chunkResults = queryBatchChunk(chunk);
            allResults.putAll(chunkResults);
        }

        return allResults;
    }

    /**
     * Sends a single batch request for a chunk of dependencies (up to BATCH_CHUNK_SIZE).
     */
    private Map<String, List<CveResult>> queryBatchChunk(List<String[]> chunk) {
        Map<String, List<CveResult>> results = new LinkedHashMap<>();

        // Build the queries array
        StringBuilder queriesJson = new StringBuilder("[");
        List<String> gavKeys = new ArrayList<>();

        for (int i = 0; i < chunk.size(); i++) {
            String[] dep = chunk.get(i);
            String groupId = dep[0];
            String artifactId = dep[1];
            String version = dep[2];
            String mavenName = groupId + ":" + artifactId;
            String gavKey = groupId + ":" + artifactId + ":" + version;
            gavKeys.add(gavKey);

            if (i > 0) {
                queriesJson.append(",");
            }
            queriesJson.append(String.format(
                "{\"package\":{\"ecosystem\":\"Maven\",\"name\":\"%s\"},\"version\":\"%s\"}",
                escapeJson(mavenName), escapeJson(version)
            ));
        }
        queriesJson.append("]");

        String body = "{\"queries\":" + queriesJson + "}";
        String response = sendRequest(OSV_BATCH_URL, body);

        if (response == null) {
            // On failure, return empty lists for every dependency
            for (String gavKey : gavKeys) {
                results.put(gavKey, Collections.emptyList());
            }
            return results;
        }

        try {
            JsonNode root = mapper.readTree(response);
            JsonNode resultsArray = root.path("results");

            for (int i = 0; i < gavKeys.size(); i++) {
                String gavKey = gavKeys.get(i);
                if (i < resultsArray.size()) {
                    JsonNode entry = resultsArray.get(i);
                    JsonNode vulns = entry.path("vulns");
                    if (vulns.isArray() && !vulns.isEmpty()) {
                        results.put(gavKey, parseVulns(vulns));
                    }
                    // Only include entries that actually have vulnerabilities
                }
            }
        } catch (Exception e) {
            log.warn("Failed to parse OSV batch response: {}", e.getMessage());
        }

        return results;
    }

    /**
     * Extracts a list of CveResult objects from the "vulns" array returned by OSV.
     */
    private List<CveResult> parseVulns(JsonNode vulnsArray) {
        List<CveResult> results = new ArrayList<>();
        for (JsonNode vuln : vulnsArray) {
            String id = vuln.path("id").asText("");
            String summary = vuln.path("summary").asText("No description available");
            String severity = extractSeverity(vuln);
            String link = "https://osv.dev/vulnerability/" + id;
            List<String> cweIds = extractCweIds(vuln);
            Set<String> categories = CweCategoryMapper.categorizeByCwes(
                CweCategoryMapper.parseCweIds(cweIds));
            results.add(new CveResult(id, summary, severity, link, cweIds, categories));
        }
        return results;
    }

    /**
     * Extracts CWE IDs from the advisory. GitHub advisories store them
     * in database_specific.cwe_ids as an array of strings like "CWE-22".
     */
    private List<String> extractCweIds(JsonNode vulnNode) {
        List<String> cweIds = new ArrayList<>();
        JsonNode cweArray = vulnNode.path("database_specific").path("cwe_ids");
        if (cweArray.isArray()) {
            for (JsonNode cwe : cweArray) {
                cweIds.add(cwe.asText());
            }
        }
        return cweIds;
    }

    /**
     * Tries to extract a severity label from a vulnerability node. OSV doesn't
     * always use the same structure, so we check a few places:
     *
     * 1. database_specific.severity — some advisories (notably GitHub) put it here directly
     * 2. severity array with CVSS_V3 scoring — we map the numeric score to a label
     * 3. Skip if neither is available
     */
    private String extractSeverity(JsonNode vulnNode) {
        // Try the database-specific severity field first (common in GitHub advisories)
        JsonNode dbSeverity = vulnNode.path("database_specific").path("severity");
        if (!dbSeverity.isMissingNode() && dbSeverity.isTextual()) {
            return dbSeverity.asText().toUpperCase();
        }

        // Try the CVSS v3 score from the severity array
        JsonNode severityArray = vulnNode.path("severity");
        if (severityArray.isArray()) {
            for (JsonNode entry : severityArray) {
                String type = entry.path("type").asText();
                if ("CVSS_V3".equals(type)) {
                    String vector = entry.path("score").asText("");
                    // The "score" field in OSV is actually the CVSS vector string,
                    // so we need to parse out the base score. The vector looks like
                    // "CVSS:3.1/AV:N/AC:L/..." — we try to get the numeric score
                    // from the database_specific block instead, or parse the vector.
                    double score = parseCvssScore(vector, vulnNode);
                    return mapScoreToLabel(score);
                }
            }
        }

        return "";
    }

    /**
     * Attempts to extract a numeric CVSS score. First checks database_specific.cvss
     * for a pre-computed score, then tries to parse from the vector string if
     * the score field contains one.
     */
    private double parseCvssScore(String vectorOrScore, JsonNode vulnNode) {
        // Some advisories have a numeric CVSS score in database_specific
        JsonNode cvssNode = vulnNode.path("database_specific").path("cvss");
        if (!cvssNode.isMissingNode()) {
            JsonNode scoreNode = cvssNode.path("score");
            if (scoreNode.isNumber()) {
                return scoreNode.asDouble();
            }
        }

        // Try parsing the value as a plain number (some responses put the score directly)
        try {
            return Double.parseDouble(vectorOrScore);
        } catch (NumberFormatException ignored) {
            // Not a plain number — could be a CVSS vector string, which we can't
            // easily score without a full parser. Fall back to -1.
        }

        return -1.0;
    }

    /**
     * Maps a numeric CVSS score to the standard severity label.
     */
    private String mapScoreToLabel(double score) {
        if (score >= 9.0) return "CRITICAL";
        if (score >= 7.0) return "HIGH";
        if (score >= 4.0) return "MEDIUM";
        if (score >= 0.1) return "LOW";
        return "";
    }

    /**
     * Sends an HTTP POST request with a JSON body and returns the response as a string.
     * Returns null on any failure so callers can return empty results gracefully.
     */
    private String sendRequest(String url, String jsonBody) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(30))
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                log.warn("OSV API returned status {} for request to {}", response.statusCode(), url);
                return null;
            }

            return response.body();

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("OSV request interrupted: {}", e.getMessage());
            return null;
        } catch (Exception e) {
            log.warn("OSV request to {} failed: {}", url, e.getMessage());
            return null;
        }
    }

    /**
     * Minimal JSON string escaping for values we embed in hand-built JSON.
     * Covers the characters that would break the JSON structure.
     */
    private static String escapeJson(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\")
                     .replace("\"", "\\\"")
                     .replace("\n", "\\n")
                     .replace("\r", "\\r")
                     .replace("\t", "\\t");
    }
}
