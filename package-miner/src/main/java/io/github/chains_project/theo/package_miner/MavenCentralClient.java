package io.github.chains_project.theo.package_miner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/**
 * Talks to Maven Central to discover packages and download their JARs.
 *
 * We use two different Maven Central endpoints:
 * - The Solr search API (search.maven.org) to find and list packages
 * - The repository (repo1.maven.org) to download actual JAR files
 *
 * All requests are rate-limited to 1 per second to be a good citizen.
 */
public class MavenCentralClient {

    private static final Logger log = LoggerFactory.getLogger(MavenCentralClient.class);
    private static final String SEARCH_BASE = "https://search.maven.org/solrsearch/select";
    private static final String REPO_BASE = "https://repo1.maven.org/maven2";
    private static final int PAGE_SIZE = 200;
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(60);
    // Be polite to Maven Central — wait at least 1 second between search requests
    private static final long RATE_LIMIT_MS = 1000;

    private final HttpClient httpClient;
    private final ObjectMapper mapper;

    public MavenCentralClient() {
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        this.mapper = new ObjectMapper();
    }

    /**
     * Fetches the most popular packages from Maven Central, sorted by download count.
     * We page through results since the API returns at most 200 per request.
     *
     * @param count how many popular packages we want (e.g. 1000)
     * @return list of packages sorted by popularity (most downloaded first)
     */
    public List<PackageInfo> fetchPopularPackages(int count) throws IOException, InterruptedException {
        log.info("Fetching top {} popular packages from Maven Central...", count);
        List<PackageInfo> results = new ArrayList<>();
        int fetched = 0;

        while (fetched < count) {
            int rows = Math.min(PAGE_SIZE, count - fetched);
            // Sort by ec_count (estimated count) descending to get the most downloaded packages first
            String url = SEARCH_BASE + "?q=*:*&rows=" + rows + "&start=" + fetched
                    + "&wt=json&sort=ec_count+desc";
            JsonNode response = doSearch(url);
            JsonNode docs = response.path("response").path("docs");
            if (docs.isEmpty()) break;

            for (JsonNode doc : docs) {
                PackageInfo info = parseDoc(doc);
                if (info != null) {
                    results.add(info);
                }
            }
            fetched += docs.size();
            log.info("Fetched {}/{} popular packages.", results.size(), count);
            Thread.sleep(RATE_LIMIT_MS);
        }
        return results;
    }

    /**
     * Fetches random packages from Maven Central. We do this by picking random offsets
     * into the full package listing and grabbing a page of results from each offset.
     *
     * We use a fixed seed (42) for the random number generator so that the same set
     * of "random" packages is selected every time — this makes the experiment reproducible.
     *
     * @param count   how many random packages we want (e.g. 1000)
     * @param exclude packages we've already selected (the popular ones) — we skip these
     * @return list of randomly selected packages
     */
    public List<PackageInfo> fetchRandomPackages(int count, List<PackageInfo> exclude)
            throws IOException, InterruptedException {
        log.info("Fetching {} random packages from Maven Central...", count);
        List<PackageInfo> results = new ArrayList<>();

        // Build a set of already-selected packages so we don't pick duplicates
        var excludeSet = new java.util.HashSet<String>();
        for (PackageInfo p : exclude) {
            excludeSet.add(p.groupId() + ":" + p.artifactId());
        }

        // First, find out how many packages exist in total on Maven Central
        int totalAvailable = getTotalCount();
        Random random = new Random(42); // fixed seed for reproducibility
        int attempts = 0;
        int maxAttempts = count * 5; // give up if we can't find enough unique packages

        while (results.size() < count && attempts < maxAttempts) {
            // Jump to a random position in the full package listing
            int start = random.nextInt(Math.max(1, totalAvailable - PAGE_SIZE));
            String url = SEARCH_BASE + "?q=*:*&rows=" + PAGE_SIZE + "&start=" + start + "&wt=json";
            JsonNode response = doSearch(url);
            JsonNode docs = response.path("response").path("docs");

            // Filter out packages we've already selected
            List<PackageInfo> candidates = new ArrayList<>();
            for (JsonNode doc : docs) {
                PackageInfo info = parseDoc(doc);
                if (info != null) {
                    String key = info.groupId() + ":" + info.artifactId();
                    if (!excludeSet.contains(key)) {
                        candidates.add(info);
                        excludeSet.add(key);
                    }
                }
            }

            // Shuffle the candidates so we don't always pick from the beginning of each page
            Collections.shuffle(candidates, random);
            for (PackageInfo c : candidates) {
                if (results.size() >= count) break;
                results.add(c);
            }
            attempts++;
            log.info("Fetched {}/{} random packages (attempt {}).", results.size(), count, attempts);
            Thread.sleep(RATE_LIMIT_MS);
        }
        return results;
    }

    /**
     * Downloads the source JAR (-sources.jar) for a given package.
     * Not all packages publish source JARs, so this may return null.
     * The source JAR is used for package name extraction (contains .java files
     * that reflect the project's own package structure without bundled dependencies).
     *
     * @param pkg         the package to download
     * @param downloadDir where to save the JAR
     * @return path to the downloaded source JAR, or null if unavailable
     */
    public Path downloadSourceJar(PackageInfo pkg, Path downloadDir)
            throws IOException, InterruptedException {
        Files.createDirectories(downloadDir);
        String groupPath = pkg.groupId().replace('.', '/');
        String jarName = pkg.artifactId() + "-" + pkg.latestVersion() + "-sources.jar";
        String url = REPO_BASE + "/" + groupPath + "/" + pkg.artifactId()
                + "/" + pkg.latestVersion() + "/" + jarName;

        Path targetFile = downloadDir.resolve(
                pkg.groupId() + "_" + pkg.artifactId() + "_" + pkg.latestVersion() + "-sources.jar"
        );
        if (Files.exists(targetFile)) {
            log.debug("Source JAR already exists: {}", targetFile);
            return targetFile;
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();

        HttpResponse<InputStream> response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
        if (response.statusCode() == 200) {
            try (InputStream body = response.body()) {
                Files.copy(body, targetFile, StandardCopyOption.REPLACE_EXISTING);
            }
            return targetFile;
        }
        log.warn("Source JAR not available for {}:{} (HTTP {}).",
                pkg.groupId(), pkg.artifactId(), response.statusCode());
        return null;
    }

    /**
     * Downloads the bytecode JAR (the regular packaged artifact) for a given package.
     * This is the compiled JAR that SootUp/theo-static needs for bytecode analysis.
     *
     * @param pkg         the package to download
     * @param downloadDir where to save the JAR
     * @return path to the downloaded bytecode JAR, or null if the download failed
     */
    public Path downloadBytecodeJar(PackageInfo pkg, Path downloadDir)
            throws IOException, InterruptedException {
        return downloadRegularJar(pkg, downloadDir);
    }

    /**
     * Downloads the POM file for a given package from Maven Central.
     * We need the POM to set up a temporary Maven project so the preprocessor plugin
     * can resolve all transitive dependencies and build the package map.
     *
     * @param pkg         the package whose POM we want
     * @param downloadDir where to save the POM
     * @return path to the downloaded POM, or null if the download failed
     */
    public Path downloadPom(PackageInfo pkg, Path downloadDir)
            throws IOException, InterruptedException {
        Files.createDirectories(downloadDir);
        String groupPath = pkg.groupId().replace('.', '/');
        String pomName = pkg.artifactId() + "-" + pkg.latestVersion() + ".pom";
        String url = REPO_BASE + "/" + groupPath + "/" + pkg.artifactId()
                + "/" + pkg.latestVersion() + "/" + pomName;

        Path targetFile = downloadDir.resolve(
                pkg.groupId() + "_" + pkg.artifactId() + "_" + pkg.latestVersion() + ".pom"
        );
        if (Files.exists(targetFile)) {
            log.debug("POM already exists: {}", targetFile);
            return targetFile;
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();

        HttpResponse<InputStream> response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
        if (response.statusCode() == 200) {
            try (InputStream body = response.body()) {
                Files.copy(body, targetFile, StandardCopyOption.REPLACE_EXISTING);
            }
            return targetFile;
        }
        log.error("Failed to download POM for {}:{} (HTTP {}).",
                pkg.groupId(), pkg.artifactId(), response.statusCode());
        return null;
    }

    /**
     * Downloads the regular (compiled bytecode) JAR from Maven Central.
     */
    private Path downloadRegularJar(PackageInfo pkg, Path downloadDir)
            throws IOException, InterruptedException {
        String groupPath = pkg.groupId().replace('.', '/');
        String jarName = pkg.artifactId() + "-" + pkg.latestVersion() + ".jar";
        String url = REPO_BASE + "/" + groupPath + "/" + pkg.artifactId()
                + "/" + pkg.latestVersion() + "/" + jarName;

        Path targetFile = downloadDir.resolve(
                pkg.groupId() + "_" + pkg.artifactId() + "_" + pkg.latestVersion() + ".jar"
        );
        if (Files.exists(targetFile)) {
            return targetFile;
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();

        HttpResponse<InputStream> response = httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
        if (response.statusCode() == 200) {
            try (InputStream body = response.body()) {
                Files.copy(body, targetFile, StandardCopyOption.REPLACE_EXISTING);
            }
            return targetFile;
        }
        log.error("Failed to download any JAR for {}:{} (HTTP {}).",
                pkg.groupId(), pkg.artifactId(), response.statusCode());
        return null;
    }

    /**
     * Fetches all versions of a package released within the last {@code years} years.
     * Uses the Maven Central Solr API with core=gav to list all GAV combinations,
     * then filters by timestamp.
     *
     * @param groupId    the groupId of the package
     * @param artifactId the artifactId of the package
     * @param years      how many years back to look (e.g. 2)
     * @return list of VersionInfo, sorted oldest to newest by timestamp
     */
    public List<VersionInfo> fetchVersions(String groupId, String artifactId, int years)
            throws IOException, InterruptedException {
        long cutoffMs = Instant.now().minus(years * 365L, ChronoUnit.DAYS).toEpochMilli();
        List<VersionInfo> versions = new ArrayList<>();
        int start = 0;

        while (true) {
            String url = SEARCH_BASE + "?q=g:" + groupId + "+AND+a:" + artifactId
                    + "&core=gav&rows=" + PAGE_SIZE + "&start=" + start + "&wt=json";
            JsonNode response = doSearch(url);
            JsonNode docs = response.path("response").path("docs");
            if (docs.isEmpty()) break;

            for (JsonNode doc : docs) {
                String version = doc.path("v").asText(null);
                long timestamp = doc.path("timestamp").asLong(0);
                if (version != null && timestamp >= cutoffMs) {
                    versions.add(new VersionInfo(groupId, artifactId, version, timestamp));
                }
            }
            start += docs.size();
            int numFound = response.path("response").path("numFound").asInt(0);
            if (start >= numFound) break;
            Thread.sleep(RATE_LIMIT_MS);
        }

        versions.sort((a, b) -> Long.compare(a.timestamp(), b.timestamp()));
        return versions;
    }

    /**
     * Downloads the bytecode JAR for a specific version of a package.
     */
    public Path downloadBytecodeJarForVersion(VersionInfo version, Path downloadDir)
            throws IOException, InterruptedException {
        PackageInfo pkg = new PackageInfo(version.groupId(), version.artifactId(), version.version(), 0);
        return downloadBytecodeJar(pkg, downloadDir);
    }

    /**
     * Downloads the source JAR for a specific version of a package.
     */
    public Path downloadSourceJarForVersion(VersionInfo version, Path downloadDir)
            throws IOException, InterruptedException {
        PackageInfo pkg = new PackageInfo(version.groupId(), version.artifactId(), version.version(), 0);
        return downloadSourceJar(pkg, downloadDir);
    }

    /**
     * Downloads the POM for a specific version of a package.
     */
    public Path downloadPomForVersion(VersionInfo version, Path downloadDir)
            throws IOException, InterruptedException {
        PackageInfo pkg = new PackageInfo(version.groupId(), version.artifactId(), version.version(), 0);
        return downloadPom(pkg, downloadDir);
    }

    /**
     * Asks Maven Central how many packages exist in total. We need this to pick
     * meaningful random offsets when selecting random packages.
     */
    private int getTotalCount() throws IOException, InterruptedException {
        String url = SEARCH_BASE + "?q=*:*&rows=0&wt=json";
        JsonNode response = doSearch(url);
        return response.path("response").path("numFound").asInt(1000000);
    }

    /**
     * Sends a GET request to the Maven Central Solr search API and parses the JSON response.
     * Throws if the response is not HTTP 200.
     */
    private JsonNode doSearch(String url) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .header("Accept", "application/json")
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("Maven Central search returned HTTP " + response.statusCode()
                    + " for URL: " + url);
        }
        return mapper.readTree(response.body());
    }

    /**
     * Extracts package info from a single Solr search result document.
     * The fields we care about are:
     * - g: groupId
     * - a: artifactId
     * - latestVersion (or v): the latest version string
     * - ec_count: estimated download count (for sorting by popularity)
     */
    private PackageInfo parseDoc(JsonNode doc) {
        String groupId = doc.path("g").asText(null);
        String artifactId = doc.path("a").asText(null);
        String latestVersion = doc.path("latestVersion").asText(null);
        if (latestVersion == null) {
            latestVersion = doc.path("v").asText(null);
        }
        if (groupId == null || artifactId == null || latestVersion == null) {
            return null;
        }
        long downloadCount = doc.path("ec_count").asLong(0);
        return new PackageInfo(groupId, artifactId, latestVersion, downloadCount);
    }
}
