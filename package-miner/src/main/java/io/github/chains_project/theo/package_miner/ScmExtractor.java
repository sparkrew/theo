package io.github.chains_project.theo.package_miner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts GitHub repository URLs from Maven POM files by parsing the {@code <scm>} tag,
 * and detects Kotlin/Scala projects by checking for language-specific plugins and dependencies.
 */
public class ScmExtractor {

    private static final Logger log = LoggerFactory.getLogger(ScmExtractor.class);

    // Matches GitHub owner/repo from various SCM URL formats
    private static final Pattern GITHUB_PATTERN = Pattern.compile(
            "github\\.com[/:]([A-Za-z0-9_.\\-]+)/([A-Za-z0-9_.\\-]+?)(?:\\.git)?(?:/.*)?$"
    );

    private static final String[] KOTLIN_SCALA_GROUPIDS = {
            "org.jetbrains.kotlin", "org.scala-lang", "org.scala-sbt",
            "io.github.kotlin", "org.jetbrains.kotlinx"
    };

    private static final String[] KOTLIN_SCALA_ARTIFACTIDS = {
            "kotlin-maven-plugin", "scala-maven-plugin", "kotlin-stdlib",
            "kotlin-stdlib-jdk8", "kotlin-stdlib-jdk7", "scala-library",
            "scala-compiler", "scala-reflect", "kotlin-gradle-plugin"
    };

    public enum ScmStatus {
        NO_SCM_TAG,
        NON_GITHUB_SCM,
        GITHUB
    }

    /**
     * Result of SCM extraction: status + GitHub URL (if found) + raw SCM URL (if non-GitHub).
     */
    public record ScmResult(ScmStatus status, String githubUrl, String rawScmUrl) {
        public static ScmResult noScm() {
            return new ScmResult(ScmStatus.NO_SCM_TAG, null, null);
        }
        public static ScmResult nonGitHub(String rawUrl) {
            return new ScmResult(ScmStatus.NON_GITHUB_SCM, null, rawUrl);
        }
        public static ScmResult github(String normalizedUrl) {
            return new ScmResult(ScmStatus.GITHUB, normalizedUrl, null);
        }
    }

    /**
     * Parses a POM file and extracts SCM information, distinguishing between
     * no SCM tag, non-GitHub SCM, and GitHub SCM.
     */
    public static ScmResult extractScmInfo(Path pomFile) {
        try {
            Document doc = parsePomDoc(pomFile);

            NodeList scmNodes = doc.getElementsByTagName("scm");
            if (scmNodes.getLength() == 0) return ScmResult.noScm();

            Element scm = (Element) scmNodes.item(0);

            // Collect all raw SCM URLs for fallback reporting
            String url = getChildText(scm, "url");
            String connection = getChildText(scm, "connection");
            String devConnection = getChildText(scm, "developerConnection");

            // Try each for a GitHub URL
            String result = extractFromUrl(url);
            if (result != null) return ScmResult.github(result);

            result = extractFromUrl(connection);
            if (result != null) return ScmResult.github(result);

            result = extractFromUrl(devConnection);
            if (result != null) return ScmResult.github(result);

            // SCM tag exists but no GitHub URL — record the raw URL
            String rawUrl = url != null ? url : (connection != null ? connection : devConnection);
            return ScmResult.nonGitHub(rawUrl);
        } catch (Exception e) {
            log.debug("Failed to parse POM for SCM: {}", pomFile, e);
            return ScmResult.noScm();
        }
    }

    /**
     * Convenience method that returns just the GitHub URL or null.
     */
    public static String extractGitHubUrl(Path pomFile) {
        ScmResult result = extractScmInfo(pomFile);
        return result.githubUrl();
    }

    /**
     * Checks whether a POM file indicates a Kotlin or Scala project.
     * Looks for language-specific plugins, dependencies, and groupId patterns.
     */
    public static boolean isKotlinOrScala(Path pomFile) {
        try {
            Document doc = parsePomDoc(pomFile);

            NodeList groupIds = doc.getElementsByTagName("groupId");
            for (int i = 0; i < groupIds.getLength(); i++) {
                String gid = groupIds.item(i).getTextContent().trim().toLowerCase();
                for (String indicator : KOTLIN_SCALA_GROUPIDS) {
                    if (gid.contains(indicator)) return true;
                }
            }

            NodeList artifactIds = doc.getElementsByTagName("artifactId");
            for (int i = 0; i < artifactIds.getLength(); i++) {
                String aid = artifactIds.item(i).getTextContent().trim().toLowerCase();
                for (String indicator : KOTLIN_SCALA_ARTIFACTIDS) {
                    if (aid.equals(indicator)) return true;
                }
            }

            return false;
        } catch (Exception e) {
            log.debug("Failed to parse POM for language check: {}", pomFile, e);
            return false;
        }
    }

    /**
     * Quick check on groupId/artifactId strings before downloading the POM.
     */
    public static boolean isLikelyKotlinOrScala(String groupId, String artifactId) {
        String gLower = groupId.toLowerCase();
        String aLower = artifactId.toLowerCase();
        return gLower.contains("kotlin") || gLower.contains("scala")
                || gLower.contains("kotlinx") || gLower.contains("groovy")
                || gLower.contains("clojure")
                || aLower.contains("kotlin") || aLower.contains("scala")
                || aLower.contains("groovy") || aLower.contains("clojure");
    }

    private static String extractFromUrl(String raw) {
        if (raw == null || raw.isBlank()) return null;
        Matcher matcher = GITHUB_PATTERN.matcher(raw);
        if (matcher.find()) {
            String owner = matcher.group(1);
            String repo = matcher.group(2);
            return "https://github.com/" + owner + "/" + repo;
        }
        return null;
    }

    private static String getChildText(Element parent, String tagName) {
        NodeList children = parent.getElementsByTagName(tagName);
        if (children.getLength() > 0) {
            return children.item(0).getTextContent().trim();
        }
        return null;
    }

    private static Document parsePomDoc(Path pomFile) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(pomFile.toFile());
    }
}
