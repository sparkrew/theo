package io.github.chains_project.theo.package_static_analyzer;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test that runs the package-static-analyzer on well-known Maven Central
 * packages and verifies that expected sensitive APIs are detected.
 *
 * Each test case downloads a real JAR from Maven Central, runs the full analysis
 * pipeline (SootUp call graph + sensitive API detection), and checks that the report
 * contains the expected categories of sensitive API usage.
 *
 * These packages were chosen because they are widely used and have well-known
 * interactions with sensitive Java APIs:
 * - jackson-databind: heavy use of reflection (Class.forName, Method.invoke, etc.)
 * - log4j-core: filesystem I/O (writing log files), reflection
 * - netty-transport: network socket operations (ServerSocket, SocketChannel)
 * - commons-io: filesystem I/O (FileInputStream, FileOutputStream, Files.*)
 */
class PackageStaticAnalyzerTest {

    private static final String MAVEN_REPO = "https://repo1.maven.org/maven2";
    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(30))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    @TempDir
    static Path sharedTempDir;
    private static Path jarsDir;
    private static Path reportsDir;

    @BeforeAll
    static void setup() throws IOException {
        jarsDir = sharedTempDir.resolve("jars");
        reportsDir = sharedTempDir.resolve("reports");
        Files.createDirectories(jarsDir);
        Files.createDirectories(reportsDir);
    }

    /**
     * Each test case: groupId, artifactId, version, package name(s), expected sensitive API substrings.
     *
     * We check that the report's sensitiveAPISummary keys contain at least one API
     * matching each expected substring. This is intentionally loose — we care that
     * the analyzer detects the right *categories* of sensitive behavior, not the
     * exact count or specific API variant.
     */
    static Stream<Arguments> knownPackages() {
        return Stream.of(
                Arguments.of(
                        "com.fasterxml.jackson.core", "jackson-databind", "2.17.2",
                        "com.fasterxml.jackson",
                        // Jackson uses reflection heavily: Class.forName, getDeclaredMethod, Field.set, etc.
                        List.of("java.lang.Class", "java.lang.reflect")
                ),
                Arguments.of(
                        "org.apache.logging.log4j", "log4j-core", "2.23.1",
                        "org.apache.logging.log4j",
                        // Log4j writes to files and uses reflection for plugin loading
                        List.of("java.io.File", "java.lang.Class")
                ),
                Arguments.of(
                        "io.netty", "netty-transport", "4.1.111.Final",
                        "io.netty.channel,io.netty.bootstrap",
                        // Netty creates sockets and channels for network I/O
                        List.of("java.net", "java.nio.channels")
                ),
                Arguments.of(
                        "commons-io", "commons-io", "2.16.1",
                        "org.apache.commons.io",
                        // Commons IO is all about file operations
                        List.of("java.io.File")
                )
        );
    }

    @ParameterizedTest(name = "{1} ({2})")
    @MethodSource("knownPackages")
    void analyzerDetectsSensitiveAPIs(
            String groupId, String artifactId, String version,
            String packageNames, List<String> expectedApiPrefixes
    ) throws Exception {

        // Step 1: Download the JAR from Maven Central
        Path jarPath = downloadJar(groupId, artifactId, version);
        assertNotNull(jarPath, "Failed to download JAR for " + artifactId);
        assertTrue(Files.exists(jarPath), "Downloaded JAR does not exist: " + jarPath);

        // Step 2: Create an empty package map.
        // The analyzer still works without dependency info — it just won't resolve
        // dependency names for indirect accesses. Good enough for this test.
        Path packageMapPath = sharedTempDir.resolve(artifactId + "-map.json");
        new ObjectMapper().writeValue(packageMapPath.toFile(), Map.of());

        // Step 3: Run the analyzer
        String reportFile = reportsDir.resolve(artifactId + "-report.json").toString();
        PackageStaticAnalyzer.process(
                jarPath.toString(),
                reportFile,
                packageNames,
                packageMapPath,
                null
        );

        // Step 4: Verify the report was created and is non-empty
        Path reportPath = Path.of(reportFile);
        assertTrue(Files.exists(reportPath), "Report was not created for " + artifactId);
        assertTrue(Files.size(reportPath) > 0, "Report is empty for " + artifactId);

        // Step 5: Parse the report and check for expected sensitive APIs
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> report = mapper.readValue(reportPath.toFile(), new TypeReference<>() {});

        // Check metadata
        @SuppressWarnings("unchecked")
        Map<String, Object> metadata = (Map<String, Object>) report.get("metadata");
        assertNotNull(metadata, "Report missing metadata for " + artifactId);
        int totalPaths = (int) metadata.get("totalPaths");
        assertTrue(totalPaths > 0,
                artifactId + " should have at least one path to a sensitive API, found " + totalPaths);

        // Check that we found at least some accesses (direct or indirect)
        @SuppressWarnings("unchecked")
        List<?> directAccesses = (List<?>) report.get("directAccesses");
        @SuppressWarnings("unchecked")
        List<?> indirectAccesses = (List<?>) report.get("indirectAccesses");
        int totalAccesses = (directAccesses != null ? directAccesses.size() : 0)
                + (indirectAccesses != null ? indirectAccesses.size() : 0);
        assertTrue(totalAccesses > 0,
                artifactId + " should have some accesses recorded");

        // Check the sensitiveAPISummary for expected API prefixes
        @SuppressWarnings("unchecked")
        Map<String, Object> summary = (Map<String, Object>) report.get("sensitiveAPISummary");
        assertNotNull(summary, "Report missing sensitiveAPISummary for " + artifactId);
        assertFalse(summary.isEmpty(), artifactId + " should have at least one sensitive API in summary");

        Set<String> detectedApis = summary.keySet();
        for (String expectedPrefix : expectedApiPrefixes) {
            boolean found = detectedApis.stream().anyMatch(api -> api.startsWith(expectedPrefix));
            assertTrue(found,
                    artifactId + " should detect a sensitive API starting with '" + expectedPrefix
                            + "' but only found: " + detectedApis);
        }

        // Log a summary for visibility
        System.out.println("=== " + artifactId + " " + version + " ===");
        System.out.println("  Entry points: " + metadata.get("entryPoints"));
        System.out.println("  Total paths:  " + totalPaths);
        System.out.println("  Direct:       " + metadata.get("directCount"));
        System.out.println("  Indirect:     " + metadata.get("indirectCount"));
        System.out.println("  Unique APIs:  " + metadata.get("uniqueSensitiveAPIs"));
        System.out.println("  Detected:     " + detectedApis.stream().sorted().limit(10).toList()
                + (detectedApis.size() > 10 ? " ... (" + detectedApis.size() + " total)" : ""));
    }

    /**
     * Downloads a JAR from Maven Central. Caches it in the temp dir so repeated
     * runs within the same test execution don't re-download.
     */
    private Path downloadJar(String groupId, String artifactId, String version)
            throws IOException, InterruptedException {
        String fileName = artifactId + "-" + version + ".jar";
        Path targetPath = jarsDir.resolve(fileName);

        if (Files.exists(targetPath)) {
            return targetPath;
        }

        String groupPath = groupId.replace('.', '/');
        String url = MAVEN_REPO + "/" + groupPath + "/" + artifactId + "/" + version + "/" + fileName;

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(60))
                .GET()
                .build();

        HttpResponse<InputStream> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofInputStream());
        if (response.statusCode() == 200) {
            try (InputStream body = response.body()) {
                Files.copy(body, targetPath, StandardCopyOption.REPLACE_EXISTING);
            }
            return targetPath;
        }

        System.err.println("Failed to download " + url + " (HTTP " + response.statusCode() + ")");
        return null;
    }
}
