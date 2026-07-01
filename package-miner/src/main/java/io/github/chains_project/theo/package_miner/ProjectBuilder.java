package io.github.chains_project.theo.package_miner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Handles cloning GitHub repositories, detecting project structure,
 * building with Maven, and running the preprocessor.
 */
public class ProjectBuilder {

    private static final Logger log = LoggerFactory.getLogger(ProjectBuilder.class);
    private static final long BUILD_TIMEOUT_MINUTES = 30;
    private static final long PREPROCESSOR_TIMEOUT_MINUTES = 10;
    private static final long CLONE_TIMEOUT_MINUTES = 10;

    /**
     * Clones a GitHub repository (shallow, depth 1) into the repos directory.
     * Returns the clone directory, or null on failure.
     */
    public Path cloneRepo(String githubUrl, Path reposDir, GitHubTokenManager tokenMgr) {
        String owner = extractOwner(githubUrl);
        String repo = extractRepo(githubUrl);
        Path cloneDir = reposDir.resolve(owner + "_" + repo);

        if (Files.isDirectory(cloneDir) && Files.exists(cloneDir.resolve(".git"))) {
            log.debug("Repo already cloned: {}", cloneDir);
            return cloneDir;
        }

        try {
            Files.createDirectories(reposDir);
            String cloneUrl = tokenMgr.formatCloneUrl(githubUrl);

            ProcessBuilder pb = new ProcessBuilder(
                    "git", "clone", "--depth", "1", "--quiet", cloneUrl, cloneDir.toString()
            );
            pb.redirectErrorStream(true);
            Process process = pb.start();
            drainOutput(process);

            boolean finished = process.waitFor(CLONE_TIMEOUT_MINUTES, TimeUnit.MINUTES);
            if (!finished) {
                process.destroyForcibly();
                log.warn("Clone timed out for {}", githubUrl);
                return null;
            }
            if (process.exitValue() != 0) {
                log.warn("Clone failed for {} (exit code {})", githubUrl, process.exitValue());
                return null;
            }
            return cloneDir;
        } catch (Exception e) {
            log.warn("Error cloning {}: {}", githubUrl, e.getMessage());
            return null;
        }
    }

    /**
     * Returns true if the directory is a Gradle project (has build.gradle but no pom.xml).
     */
    public boolean isGradleProject(Path dir) {
        boolean hasPom = Files.exists(dir.resolve("pom.xml"));
        boolean hasGradle = Files.exists(dir.resolve("build.gradle"))
                || Files.exists(dir.resolve("build.gradle.kts"));
        return hasGradle && !hasPom;
    }

    /**
     * Detects Maven modules from the root pom.xml.
     * Returns a list of module relative paths. For single-module projects, returns ["."].
     */
    public List<String> detectModules(Path projectDir) {
        Path pomFile = projectDir.resolve("pom.xml");
        if (!Files.exists(pomFile)) return List.of();

        try {
            Document doc = parsePom(pomFile);
            NodeList modulesNodes = doc.getElementsByTagName("modules");
            if (modulesNodes.getLength() == 0) return List.of(".");

            Element modulesEl = (Element) modulesNodes.item(0);
            NodeList moduleNodes = modulesEl.getElementsByTagName("module");
            if (moduleNodes.getLength() == 0) return List.of(".");

            List<String> modules = new ArrayList<>();
            for (int i = 0; i < moduleNodes.getLength(); i++) {
                String moduleName = moduleNodes.item(i).getTextContent().trim();
                if (!moduleName.isEmpty() && Files.isDirectory(projectDir.resolve(moduleName))) {
                    modules.add(moduleName);
                }
            }
            return modules.isEmpty() ? List.of(".") : modules;
        } catch (Exception e) {
            log.debug("Failed to detect modules in {}: {}", projectDir, e.getMessage());
            return List.of(".");
        }
    }

    /**
     * Reads groupId, artifactId, and version from a module's pom.xml.
     * Falls back to parent groupId/version if not declared directly.
     */
    public GitHubProject.ModuleInfo readModuleInfo(Path moduleDir, String modulePath) {
        Path pomFile = moduleDir.resolve("pom.xml");
        if (!Files.exists(pomFile)) return null;

        try {
            Document doc = parsePom(pomFile);
            Element root = doc.getDocumentElement();

            String artifactId = getDirectChildText(root, "artifactId");
            String groupId = getDirectChildText(root, "groupId");
            String version = getDirectChildText(root, "version");

            // Fall back to parent element for groupId and version
            NodeList parentNodes = root.getElementsByTagName("parent");
            if (parentNodes.getLength() > 0) {
                Element parent = (Element) parentNodes.item(0);
                if (groupId == null) groupId = getDirectChildText(parent, "groupId");
                if (version == null) version = getDirectChildText(parent, "version");
            }

            if (artifactId == null) return null;
            if (groupId == null) groupId = "";
            if (version == null) version = "";

            return new GitHubProject.ModuleInfo(
                    groupId, artifactId, version, modulePath,
                    null, null, false, false
            );
        } catch (Exception e) {
            log.debug("Failed to read module info from {}: {}", pomFile, e.getMessage());
            return null;
        }
    }

    /**
     * Builds the project from the root directory using Maven.
     * Runs: mvn install -DskipTests
     */
    public boolean buildProject(Path projectDir) {
        return runMaven(projectDir, List.of(
                "mvn", "install", "-DskipTests",
                "-Dcheckstyle.skip=true",
                "-Dspotless.skip=true",
                "-Denforcer.skip=true",
                "-Dmaven.javadoc.skip=true",
                "-Dpmd.skip=true",
                "-Dspotbugs.skip=true",
                "-Djacoco.skip=true",
                "-Dgpg.skip=true",
                "-Danimal.sniffer.skip=true",
                "-Drat.skip=true",
                "-Dlicense.skip=true",
                "-B", "-q"),
                BUILD_TIMEOUT_MINUTES, "build");
    }

    /**
     * Runs the preprocessor on a specific module directory.
     * Generates the package-map.json at the specified output path.
     */
    public boolean runPreprocessor(Path moduleDir, Path outputFile) {
        try {
            Files.createDirectories(outputFile.getParent());
        } catch (IOException e) {
            return false;
        }
        return runMaven(moduleDir,
                List.of("mvn",
                        "io.github.chains-project:theo-preprocessor-maven-plugin:1.0-SNAPSHOT:preprocess",
                        "-DoutputFile=" + outputFile.toAbsolutePath(),
                        "-B", "-q"),
                PREPROCESSOR_TIMEOUT_MINUTES, "preprocessor");
    }

    /**
     * Finds the main JAR in a module's target/ directory.
     * Skips sources, javadoc, tests, and original JARs.
     */
    public Path findModuleJar(Path moduleDir) {
        Path targetDir = moduleDir.resolve("target");
        if (!Files.isDirectory(targetDir)) return null;

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(targetDir, "*.jar")) {
            Path best = null;
            for (Path jar : stream) {
                String name = jar.getFileName().toString();
                if (name.endsWith("-sources.jar") || name.endsWith("-javadoc.jar")
                        || name.endsWith("-tests.jar") || name.startsWith("original-")
                        || name.contains("-test-")) {
                    continue;
                }
                // Prefer the non-uber JAR (shorter name usually)
                if (best == null || name.length() < best.getFileName().toString().length()) {
                    best = jar;
                }
            }
            return best;
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Finds the module whose pom.xml matches the given groupId:artifactId.
     * Returns the module path, or null if no match.
     */
    public String matchModuleToArtifact(Path projectDir, List<String> modulePaths,
                                        String groupId, String artifactId) {
        for (String modulePath : modulePaths) {
            Path moduleDir = modulePath.equals(".") ? projectDir : projectDir.resolve(modulePath);
            GitHubProject.ModuleInfo info = readModuleInfo(moduleDir, modulePath);
            if (info != null && info.artifactId().equals(artifactId)) {
                if (groupId == null || groupId.isEmpty() || info.groupId().equals(groupId)) {
                    return modulePath;
                }
            }
        }
        return null;
    }

    private boolean runMaven(Path workDir, List<String> command, long timeoutMinutes, String label) {
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.directory(workDir.toFile());
            pb.redirectErrorStream(true);
            Process process = pb.start();
            drainOutput(process);

            boolean finished = process.waitFor(timeoutMinutes, TimeUnit.MINUTES);
            if (!finished) {
                process.destroyForcibly();
                log.warn("Maven {} timed out in {}", label, workDir);
                return false;
            }
            if (process.exitValue() != 0) {
                log.debug("Maven {} failed in {} (exit code {})", label, workDir, process.exitValue());
                return false;
            }
            return true;
        } catch (Exception e) {
            log.debug("Error running Maven {} in {}: {}", label, workDir, e.getMessage());
            return false;
        }
    }

    private void drainOutput(Process process) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            while (reader.readLine() != null) {
                // Consume output to prevent blocking
            }
        }
    }

    private Document parsePom(Path pomFile) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(pomFile.toFile());
    }

    /**
     * Gets the text content of a direct child element (not nested descendants).
     */
    private String getDirectChildText(Element parent, String tagName) {
        var children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            if (children.item(i) instanceof Element el && el.getTagName().equals(tagName)) {
                return el.getTextContent().trim();
            }
        }
        return null;
    }

    static String extractOwner(String githubUrl) {
        // https://github.com/owner/repo
        String[] parts = githubUrl.replace("https://github.com/", "").split("/");
        return parts.length > 0 ? parts[0] : "";
    }

    static String extractRepo(String githubUrl) {
        String[] parts = githubUrl.replace("https://github.com/", "").split("/");
        return parts.length > 1 ? parts[1].replace(".git", "") : "";
    }
}
