package io.github.chains_project.theo.package_miner;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CommitVersionScannerTest {

    @Test
    void extractsProjectVersionSimple() {
        String pom = """
                <project>
                  <groupId>com.example</groupId>
                  <artifactId>mylib</artifactId>
                  <version>1.2.3</version>
                </project>
                """;
        assertEquals("1.2.3", CommitVersionScanner.extractProjectVersion(pom));
    }

    @Test
    void extractsProjectVersionSkippingParent() {
        String pom = """
                <project>
                  <parent>
                    <groupId>com.example</groupId>
                    <artifactId>parent</artifactId>
                    <version>2.0.0</version>
                  </parent>
                  <artifactId>child</artifactId>
                  <version>1.5.0</version>
                </project>
                """;
        assertEquals("1.5.0", CommitVersionScanner.extractProjectVersion(pom));
    }

    @Test
    void fallsBackToParentVersionWhenNoProjectVersion() {
        String pom = """
                <project>
                  <parent>
                    <groupId>com.example</groupId>
                    <artifactId>parent</artifactId>
                    <version>3.0.0</version>
                  </parent>
                  <artifactId>child</artifactId>
                </project>
                """;
        assertEquals("3.0.0", CommitVersionScanner.extractProjectVersion(pom));
    }

    @Test
    void returnsNullWhenNoVersion() {
        String pom = """
                <project>
                  <groupId>com.example</groupId>
                  <artifactId>mylib</artifactId>
                </project>
                """;
        assertNull(CommitVersionScanner.extractProjectVersion(pom));
    }

    @Test
    void skipsVersionInsideDependency() {
        String pom = """
                <project>
                  <version>1.0.0</version>
                  <dependencies>
                    <dependency>
                      <groupId>org.example</groupId>
                      <artifactId>dep</artifactId>
                      <version>9.9.9</version>
                    </dependency>
                  </dependencies>
                </project>
                """;
        assertEquals("1.0.0", CommitVersionScanner.extractProjectVersion(pom));
    }

    @Test
    void handlesSnapshotVersion() {
        String pom = """
                <project>
                  <version>2.0.0-SNAPSHOT</version>
                </project>
                """;
        assertEquals("2.0.0-SNAPSHOT", CommitVersionScanner.extractProjectVersion(pom));
    }

    @Test
    void majorChangeDetected() {
        assertTrue(CommitVersionScanner.isMajorOrMinorChange("1.2.3", "2.0.0"));
    }

    @Test
    void minorChangeDetected() {
        assertTrue(CommitVersionScanner.isMajorOrMinorChange("1.2.3", "1.3.0"));
    }

    @Test
    void patchOnlyChangeIgnored() {
        assertFalse(CommitVersionScanner.isMajorOrMinorChange("1.2.3", "1.2.4"));
    }

    @Test
    void snapshotQualifierStrippedForComparison() {
        assertFalse(CommitVersionScanner.isMajorOrMinorChange("1.2.3", "1.2.4-SNAPSHOT"));
        assertTrue(CommitVersionScanner.isMajorOrMinorChange("1.2.3", "1.3.0-SNAPSHOT"));
    }

    @Test
    void twoPartVersionsCompared() {
        assertTrue(CommitVersionScanner.isMajorOrMinorChange("1.2", "1.3"));
        assertFalse(CommitVersionScanner.isMajorOrMinorChange("1.2", "1.2"));
    }

    @Test
    void unparsableVersionIncludedByDefault() {
        assertTrue(CommitVersionScanner.isMajorOrMinorChange("1.2.3", "beta"));
    }
}
