package io.github.chains_project.theo.package_miner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.chains_project.theo.package_miner.model.PackageInfo;
import io.github.chains_project.theo.package_miner.model.VersionInfo;
import io.github.chains_project.theo.package_miner.util.LanguageFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Duration;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class MavenCentralClient {

    private static final Logger log = LoggerFactory.getLogger(MavenCentralClient.class);
    private static final String ECOSYSTEMS_BASE = "https://packages.ecosyste.ms/api/v1/registries/repo1.maven.org/packages";
    private static final String SEARCH_BASE = "https://search.maven.org/solrsearch/select";
    private static final String REPO_BASE = "https://repo1.maven.org/maven2";
    private static final int PAGE_SIZE = 200;
    private static final int ECOSYSTEMS_PAGE_SIZE = 10;
    private static final Duration VERSION_FETCH_TIMEOUT = Duration.ofMinutes(5);
    private static final long RATE_LIMIT_MS = 1000;

    private final HttpClient httpClient;
    private final ObjectMapper mapper;

    public MavenCentralClient() {
        this.httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        this.mapper = new ObjectMapper();
    }

    public record CollectResult(List<PackageInfo> packages, int lastPage) {}

    public CollectResult fetchPopularJavaPackagesPaged(int count, int cutoffYear, int startPage)
            throws IOException, InterruptedException {
        boolean collectAll = (count <= 0);
        List<PackageInfo> results = new ArrayList<>();
        int page = startPage;
        int skippedLanguage = 0, skippedOld = 0, skippedParsing = 0;

        if (collectAll) {
            log.info("Fetching ALL popular Java packages from ecosyste.ms (starting page {})...", startPage);
        } else {
            log.info("Fetching {} popular Java packages from ecosyste.ms (starting page {})...", count, startPage);
        }

        while (collectAll || results.size() < count) {
            String url = ECOSYSTEMS_BASE + "?sort=dependent_repos_count&order=desc"
                    + "&per_page=" + ECOSYSTEMS_PAGE_SIZE + "&page=" + page
                    + "&mailto=tulipgamage@gmail.com";

            JsonNode data = fetchEcosystemsPage(url);
            if (data == null || !data.isArray() || data.isEmpty()) {
                log.warn("No more packages available from ecosyste.ms after page {}.", page);
                break;
            }

            for (JsonNode pkg : data) {
                String name = pkg.path("name").asText(null);
                if (name == null || !name.contains(":")) {
                    skippedParsing++;
                    continue;
                }

                String[] parts = name.split(":", 2);
                String groupId = parts[0];
                String artifactId = parts[1];
                String latestVersion = pkg.path("latest_release_number").asText(null);
                String lastRelease = pkg.path("latest_release_published_at").asText(null);
                long dependentReposCount = pkg.path("dependent_repos_count").asLong(0);

                if (latestVersion == null) {
                    skippedParsing++;
                    continue;
                }

                if (lastRelease != null && !lastRelease.isEmpty()) {
                    try {
                        int releaseYear = Integer.parseInt(lastRelease.substring(0, 4));
                        if (releaseYear < cutoffYear) {
                            skippedOld++;
                            continue;
                        }
                    } catch (NumberFormatException | StringIndexOutOfBoundsException e) {
                        // can't parse date, keep the package
                    }
                }

                if (LanguageFilter.isLikelyKotlinOrScala(groupId, artifactId)) {
                    skippedLanguage++;
                    continue;
                }

                results.add(new PackageInfo(groupId, artifactId, latestVersion, dependentReposCount));

                if (!collectAll && results.size() >= count) break;
            }

            page++;

            if (data.size() < ECOSYSTEMS_PAGE_SIZE) {
                break;
            }

            log.info("Fetched {}{} packages ({} old, {} non-Java, {} unparseable skipped). Page {}.",
                    results.size(), collectAll ? "" : "/" + count,
                    skippedOld, skippedLanguage, skippedParsing, page - 1);
            Thread.sleep(RATE_LIMIT_MS);
        }

        log.info("Selected {} packages (pages {}-{}).", results.size(), startPage, page - 1);
        return new CollectResult(results, page);
    }

    private JsonNode fetchEcosystemsPage(String url) throws InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Accept", "application/json")
                .GET()
                .build();

        long waitMs = 5000;
        while (true) {
            try {
                HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() == 200) {
                    return mapper.readTree(response.body());
                }
                log.warn("ecosyste.ms API returned HTTP {}, retrying in {} seconds...",
                        response.statusCode(), waitMs / 1000);
            } catch (IOException e) {
                log.warn("ecosyste.ms request failed ({}), retrying in {} seconds...",
                        e.getMessage(), waitMs / 1000);
            }
            Thread.sleep(waitMs);
            waitMs = Math.min(waitMs * 2, 60000);
        }
    }

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

    public Path downloadBytecodeJar(PackageInfo pkg, Path downloadDir)
            throws IOException, InterruptedException {
        return downloadRegularJar(pkg, downloadDir);
    }

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

        versions.sort(Comparator.comparingLong(VersionInfo::timestamp));
        return versions;
    }

    public Path downloadBytecodeJarForVersion(VersionInfo version, Path downloadDir)
            throws IOException, InterruptedException {
        PackageInfo pkg = new PackageInfo(version.groupId(), version.artifactId(), version.version(), 0);
        return downloadBytecodeJar(pkg, downloadDir);
    }

    public Path downloadSourceJarForVersion(VersionInfo version, Path downloadDir)
            throws IOException, InterruptedException {
        PackageInfo pkg = new PackageInfo(version.groupId(), version.artifactId(), version.version(), 0);
        return downloadSourceJar(pkg, downloadDir);
    }

    private JsonNode doSearch(String url) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(VERSION_FETCH_TIMEOUT)
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
}
