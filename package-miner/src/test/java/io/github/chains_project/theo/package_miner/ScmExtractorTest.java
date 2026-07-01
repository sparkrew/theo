package io.github.chains_project.theo.package_miner;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class ScmExtractorTest {

    @Test
    void extractsGitHubUrlFromScmUrlTag(@TempDir Path tempDir) throws IOException {
        Path pom = writePom(tempDir, """
                <project>
                  <scm>
                    <url>https://github.com/google/guava</url>
                  </scm>
                </project>
                """);
        assertEquals("https://github.com/google/guava", ScmExtractor.extractGitHubUrl(pom));
    }

    @Test
    void extractsGitHubUrlFromConnection(@TempDir Path tempDir) throws IOException {
        Path pom = writePom(tempDir, """
                <project>
                  <scm>
                    <connection>scm:git:https://github.com/apache/commons-io.git</connection>
                  </scm>
                </project>
                """);
        assertEquals("https://github.com/apache/commons-io", ScmExtractor.extractGitHubUrl(pom));
    }

    @Test
    void extractsGitHubUrlFromSshConnection(@TempDir Path tempDir) throws IOException {
        Path pom = writePom(tempDir, """
                <project>
                  <scm>
                    <developerConnection>scm:git:ssh://github.com:spring-projects/spring-framework.git</developerConnection>
                  </scm>
                </project>
                """);
        assertEquals("https://github.com/spring-projects/spring-framework", ScmExtractor.extractGitHubUrl(pom));
    }

    @Test
    void extractsGitHubUrlFromGitAtFormat(@TempDir Path tempDir) throws IOException {
        Path pom = writePom(tempDir, """
                <project>
                  <scm>
                    <connection>scm:git:git@github.com:owner/repo.git</connection>
                  </scm>
                </project>
                """);
        assertEquals("https://github.com/owner/repo", ScmExtractor.extractGitHubUrl(pom));
    }

    @Test
    void extractsGitHubUrlFromGitProtocol(@TempDir Path tempDir) throws IOException {
        Path pom = writePom(tempDir, """
                <project>
                  <scm>
                    <connection>scm:git:git://github.com/owner/repo.git</connection>
                  </scm>
                </project>
                """);
        assertEquals("https://github.com/owner/repo", ScmExtractor.extractGitHubUrl(pom));
    }

    @Test
    void returnsNullWhenNoScmTag(@TempDir Path tempDir) throws IOException {
        Path pom = writePom(tempDir, """
                <project>
                  <groupId>com.example</groupId>
                </project>
                """);
        assertNull(ScmExtractor.extractGitHubUrl(pom));
    }

    @Test
    void returnsNullForNonGitHubScm(@TempDir Path tempDir) throws IOException {
        Path pom = writePom(tempDir, """
                <project>
                  <scm>
                    <url>https://gitlab.com/owner/repo</url>
                  </scm>
                </project>
                """);
        assertNull(ScmExtractor.extractGitHubUrl(pom));
    }

    @Test
    void prefersUrlOverConnection(@TempDir Path tempDir) throws IOException {
        Path pom = writePom(tempDir, """
                <project>
                  <scm>
                    <url>https://github.com/correct/repo</url>
                    <connection>scm:git:https://github.com/wrong/repo.git</connection>
                  </scm>
                </project>
                """);
        assertEquals("https://github.com/correct/repo", ScmExtractor.extractGitHubUrl(pom));
    }

    @Test
    void detectsKotlinProject(@TempDir Path tempDir) throws IOException {
        Path pom = writePom(tempDir, """
                <project>
                  <dependencies>
                    <dependency>
                      <groupId>org.jetbrains.kotlin</groupId>
                      <artifactId>kotlin-stdlib</artifactId>
                    </dependency>
                  </dependencies>
                </project>
                """);
        assertTrue(ScmExtractor.isKotlinOrScala(pom));
    }

    @Test
    void detectsScalaProject(@TempDir Path tempDir) throws IOException {
        Path pom = writePom(tempDir, """
                <project>
                  <dependencies>
                    <dependency>
                      <groupId>org.scala-lang</groupId>
                      <artifactId>scala-library</artifactId>
                    </dependency>
                  </dependencies>
                </project>
                """);
        assertTrue(ScmExtractor.isKotlinOrScala(pom));
    }

    @Test
    void pureJavaProjectNotDetectedAsKotlinScala(@TempDir Path tempDir) throws IOException {
        Path pom = writePom(tempDir, """
                <project>
                  <dependencies>
                    <dependency>
                      <groupId>com.google.guava</groupId>
                      <artifactId>guava</artifactId>
                    </dependency>
                  </dependencies>
                </project>
                """);
        assertFalse(ScmExtractor.isKotlinOrScala(pom));
    }

    @Test
    void quickLanguageCheckDetectsKotlin() {
        assertTrue(ScmExtractor.isLikelyKotlinOrScala("org.jetbrains.kotlinx", "coroutines-core"));
        assertTrue(ScmExtractor.isLikelyKotlinOrScala("com.example", "my-kotlin-lib"));
        assertFalse(ScmExtractor.isLikelyKotlinOrScala("com.google.guava", "guava"));
    }

    private Path writePom(Path dir, String content) throws IOException {
        Path pom = dir.resolve("test-pom.xml");
        Files.writeString(pom, content);
        return pom;
    }
}
