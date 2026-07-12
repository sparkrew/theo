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

public class ScmExtractor {

    private static final Logger log = LoggerFactory.getLogger(ScmExtractor.class);

    private static final Pattern GITHUB_PATTERN = Pattern.compile(
            "github\\.com[/:]([A-Za-z0-9_.\\-]+)/([A-Za-z0-9_.\\-]+?)(?:\\.git)?(?:/.*)?$"
    );

    public enum ScmStatus {
        NO_SCM_TAG,
        NON_GITHUB_SCM,
        GITHUB
    }

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

    public static ScmResult extractScmInfo(Path pomFile) {
        try {
            Document doc = parsePomDoc(pomFile);

            NodeList scmNodes = doc.getElementsByTagName("scm");
            if (scmNodes.getLength() == 0) return ScmResult.noScm();

            Element scm = (Element) scmNodes.item(0);

            String url = getChildText(scm, "url");
            String connection = getChildText(scm, "connection");
            String devConnection = getChildText(scm, "developerConnection");

            String result = extractFromUrl(url);
            if (result != null) return ScmResult.github(result);

            result = extractFromUrl(connection);
            if (result != null) return ScmResult.github(result);

            result = extractFromUrl(devConnection);
            if (result != null) return ScmResult.github(result);

            String rawUrl = url != null ? url : (connection != null ? connection : devConnection);
            return ScmResult.nonGitHub(rawUrl);
        } catch (Exception e) {
            log.debug("Failed to parse POM for SCM: {}", pomFile, e);
            return ScmResult.noScm();
        }
    }

    public static String extractGitHubUrl(Path pomFile) {
        ScmResult result = extractScmInfo(pomFile);
        return result.githubUrl();
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
