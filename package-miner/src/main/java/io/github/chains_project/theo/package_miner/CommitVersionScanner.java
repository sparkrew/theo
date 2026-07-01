package io.github.chains_project.theo.package_miner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Scans git commit history to find commits that change the project version in pom.xml.
 * Used for tracking how sensitive API permissions evolve across releases.
 */
public class CommitVersionScanner {

    private static final Logger log = LoggerFactory.getLogger(CommitVersionScanner.class);
    private static final Pattern VERSION_TAG_PATTERN = Pattern.compile(
            "<version>\\s*([^<$]+?)\\s*</version>"
    );
    // Match semver-like versions (e.g. 1.2.3, 1.0.0-SNAPSHOT, 2.1.0-beta1)
    private static final Pattern SEMVER_PATTERN = Pattern.compile(
            "\\d+\\.\\d+(?:\\.\\d+)?(?:[.\\-].*)?$"
    );

    /**
     * A commit that changed the project version.
     */
    public record VersionCommit(String hash, String version, String isoDate) {}

    /**
     * Converts a shallow clone to a full clone by fetching the complete history.
     */
    public boolean deepenClone(Path repoDir) {
        try {
            ProcessBuilder pb = new ProcessBuilder("git", "fetch", "--unshallow", "--quiet");
            pb.directory(repoDir.toFile());
            pb.redirectErrorStream(true);
            Process process = pb.start();
            drainOutput(process);
            boolean finished = process.waitFor(10, TimeUnit.MINUTES);
            if (!finished) {
                process.destroyForcibly();
                return false;
            }
            // Exit code 128 often means the repo is already unshallowed — that's OK
            return process.exitValue() == 0 || process.exitValue() == 128;
        } catch (Exception e) {
            log.warn("Failed to deepen clone in {}: {}", repoDir, e.getMessage());
            return false;
        }
    }

    /**
     * Finds commits in the last N years that changed the version in the given pom.xml.
     * Returns a chronologically ordered list (oldest first).
     *
     * @param repoDir          the cloned repository directory
     * @param pomRelativePath  relative path to pom.xml within the repo (e.g. "pom.xml" or "core/pom.xml")
     * @param yearsBack        how many years of history to scan
     */
    public List<VersionCommit> findVersionChangingCommits(Path repoDir, String pomRelativePath, int yearsBack) {
        String since = LocalDate.now().minusYears(yearsBack).format(DateTimeFormatter.ISO_DATE);

        // Get all commits that touched the pom.xml, newest first
        List<String[]> commits = listCommitsTouchingFile(repoDir, pomRelativePath, since);
        if (commits.isEmpty()) return List.of();

        List<VersionCommit> result = new ArrayList<>();
        String previousVersion = null;

        // Process oldest to newest (reverse the list)
        for (int i = commits.size() - 1; i >= 0; i--) {
            String hash = commits.get(i)[0];
            String date = commits.get(i)[1];

            String version = extractVersionFromCommit(repoDir, hash, pomRelativePath);
            if (version == null) continue;

            // Skip non-semver versions (e.g. property references like ${project.version})
            if (!SEMVER_PATTERN.matcher(version).matches()) continue;

            if (previousVersion == null) {
                result.add(new VersionCommit(hash, version, date));
                previousVersion = version;
            } else if (!version.equals(previousVersion) && isMajorOrMinorChange(previousVersion, version)) {
                result.add(new VersionCommit(hash, version, date));
                previousVersion = version;
            }
        }

        return result;
    }

    /**
     * Checks out a specific commit in the repository.
     */
    public boolean checkoutCommit(Path repoDir, String hash) {
        return runGit(repoDir, "git", "checkout", "--quiet", "--force", hash);
    }

    /**
     * Returns to the default branch (main/master).
     */
    public boolean restoreHead(Path repoDir) {
        // Try common default branch names
        if (runGit(repoDir, "git", "checkout", "--quiet", "main")) return true;
        if (runGit(repoDir, "git", "checkout", "--quiet", "master")) return true;
        // Fallback: checkout the branch that HEAD was on before
        return runGit(repoDir, "git", "checkout", "--quiet", "-");
    }

    /**
     * Extracts the <version> tag from pom.xml at a specific commit.
     * Uses git show to read the file content without checking out.
     */
    String extractVersionFromCommit(Path repoDir, String hash, String pomRelativePath) {
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "git", "show", hash + ":" + pomRelativePath
            );
            pb.directory(repoDir.toFile());
            pb.redirectErrorStream(true);
            Process process = pb.start();

            String content;
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                content = reader.lines().collect(java.util.stream.Collectors.joining("\n"));
            }

            process.waitFor(30, TimeUnit.SECONDS);
            if (process.exitValue() != 0) return null;

            // Find the first <version> tag that is a direct child of <project>
            // (not inside <parent>, <dependency>, etc.)
            // Simple heuristic: find version after </parent> or before <parent>,
            // or the first version if no parent
            return extractProjectVersion(content);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Extracts the project's own version from POM content.
     * Handles the common case where <version> appears both in <parent> and at project level.
     */
    static String extractProjectVersion(String pomContent) {
        // Strategy: find <version> tags and skip the one inside <parent>
        int parentStart = pomContent.indexOf("<parent>");
        int parentEnd = pomContent.indexOf("</parent>");

        Matcher matcher = VERSION_TAG_PATTERN.matcher(pomContent);
        String firstVersion = null;

        while (matcher.find()) {
            String version = matcher.group(1);
            int pos = matcher.start();

            // Skip versions inside <parent> block
            if (parentStart >= 0 && parentEnd >= 0 && pos > parentStart && pos < parentEnd) {
                continue;
            }
            // Skip versions inside <dependency> or <plugin> blocks (rough heuristic)
            String before = pomContent.substring(Math.max(0, pos - 200), pos);
            if (before.contains("<dependency>") || before.contains("<plugin>")) {
                // Check if there's a closing tag between the dependency/plugin and here
                if (!before.contains("</dependency>") && !before.contains("</plugin>")) {
                    continue;
                }
            }

            return version;
        }

        // Fallback: if we only found versions inside parent, return the parent version
        // (some modules inherit version from parent)
        matcher.reset();
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    /**
     * Returns true if the version change is a major or minor bump (not just a patch).
     * Compares the first two components of semver-like versions.
     * E.g. 1.2.3 → 1.3.0 = true (minor), 1.2.3 → 2.0.0 = true (major),
     *      1.2.3 → 1.2.4 = false (patch only).
     */
    static boolean isMajorOrMinorChange(String from, String to) {
        int[] fromParts = parseMajorMinor(from);
        int[] toParts = parseMajorMinor(to);
        if (fromParts == null || toParts == null) return true; // can't parse — include it
        return fromParts[0] != toParts[0] || fromParts[1] != toParts[1];
    }

    private static int[] parseMajorMinor(String version) {
        // Strip qualifiers like -SNAPSHOT, -beta1, -RC1
        String base = version.split("[\\-+]")[0];
        String[] parts = base.split("\\.");
        if (parts.length < 2) return null;
        try {
            return new int[]{ Integer.parseInt(parts[0]), Integer.parseInt(parts[1]) };
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private List<String[]> listCommitsTouchingFile(Path repoDir, String filePath, String since) {
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "git", "log", "--since=" + since, "--format=%H|%aI", "--", filePath
            );
            pb.directory(repoDir.toFile());
            pb.redirectErrorStream(true);
            Process process = pb.start();

            List<String[]> result = new ArrayList<>();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    String[] parts = line.split("\\|", 2);
                    if (parts.length == 2) {
                        result.add(parts);
                    }
                }
            }
            process.waitFor(30, TimeUnit.SECONDS);
            return result;
        } catch (Exception e) {
            log.debug("Failed to list commits for {} in {}: {}", filePath, repoDir, e.getMessage());
            return List.of();
        }
    }

    private boolean runGit(Path repoDir, String... command) {
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.directory(repoDir.toFile());
            pb.redirectErrorStream(true);
            Process process = pb.start();
            drainOutput(process);
            boolean finished = process.waitFor(60, TimeUnit.SECONDS);
            return finished && process.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    private void drainOutput(Process process) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            while (reader.readLine() != null) { }
        }
    }
}
