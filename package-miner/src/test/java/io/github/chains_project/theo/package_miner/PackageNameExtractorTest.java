package io.github.chains_project.theo.package_miner;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.*;

class PackageNameExtractorTest {

    // --- findBasePackageNames tests ---

    @Test
    void singleCommonBaseWith3Parts() {
        Set<String> packages = Set.of(
                "io.github.myname.core",
                "io.github.myname.util",
                "io.github.myname.api"
        );
        List<String> result = PackageNameExtractor.findBasePackageNames(packages);

        assertEquals(1, result.size());
        assertEquals("io.github.myname", result.get(0));
    }

    @Test
    void commonBaseWithMoreThan3Parts() {
        Set<String> packages = Set.of(
                "com.example.project.module.sub1",
                "com.example.project.module.sub2"
        );
        List<String> result = PackageNameExtractor.findBasePackageNames(packages);

        assertEquals(1, result.size());
        assertEquals("com.example.project.module", result.get(0));
    }

    @Test
    void commonBaseTooShortFallsBackToMultiplePrefixes() {
        // org.apache is only 2 parts — too common to be a useful base
        Set<String> packages = Set.of(
                "org.apache.pdfbox.pdmodel",
                "org.apache.pdfbox.cos",
                "org.apache.xmpbox.type",
                "org.apache.xmpbox.schema"
        );
        List<String> result = PackageNameExtractor.findBasePackageNames(packages);

        assertEquals(2, result.size());
        assertTrue(result.contains("org.apache.pdfbox"));
        assertTrue(result.contains("org.apache.xmpbox"));
    }

    @Test
    void noCommonPrefixAtAll() {
        Set<String> packages = Set.of(
                "com.google.guava.collect",
                "io.netty.channel.socket",
                "org.apache.commons.io"
        );
        List<String> result = PackageNameExtractor.findBasePackageNames(packages);

        assertEquals(3, result.size());
        assertTrue(result.contains("com.google.guava"));
        assertTrue(result.contains("io.netty.channel"));
        assertTrue(result.contains("org.apache.commons"));
    }

    @Test
    void singlePackageReturnsItself() {
        Set<String> packages = Set.of("com.example.mylib");
        List<String> result = PackageNameExtractor.findBasePackageNames(packages);

        assertEquals(1, result.size());
        assertEquals("com.example.mylib", result.get(0));
    }

    @Test
    void packageWithFewerThan3PartsReturnedAsIs() {
        Set<String> packages = Set.of("ab", "cd");
        List<String> result = PackageNameExtractor.findBasePackageNames(packages);

        // Can't extract 3-part prefixes, so falls back to all packages
        assertTrue(result.contains("ab"));
        assertTrue(result.contains("cd"));
    }

    @Test
    void deeplyNestedPackagesCollapse() {
        Set<String> packages = Set.of(
                "io.github.user.project.a.b.c",
                "io.github.user.project.d.e",
                "io.github.user.project.f"
        );
        List<String> result = PackageNameExtractor.findBasePackageNames(packages);

        assertEquals(1, result.size());
        assertEquals("io.github.user.project", result.get(0));
    }

    // --- extractFromJar tests with synthetic JARs ---

    @Test
    void extractsPackagesFromBytecodeJar(@TempDir Path tempDir) throws IOException {
        Path jar = createJarWithEntries(tempDir, "test.jar",
                "com/example/mylib/Main.class",
                "com/example/mylib/util/Helper.class",
                "com/example/mylib/api/Service.class"
        );

        List<String> result = PackageNameExtractor.extractFromJar(jar, Set.of());

        assertEquals(1, result.size());
        assertEquals("com.example.mylib", result.get(0));
    }

    @Test
    void extractsPackagesFromSourceJar(@TempDir Path tempDir) throws IOException {
        Path jar = createJarWithEntries(tempDir, "test-sources.jar",
                "com/example/mylib/Main.java",
                "com/example/mylib/util/Helper.java"
        );

        List<String> result = PackageNameExtractor.extractFromJar(jar, Set.of());

        assertEquals(1, result.size());
        assertEquals("com.example.mylib", result.get(0));
    }

    @Test
    void filtersDependencyPackagesFromUberJar(@TempDir Path tempDir) throws IOException {
        // Simulate an uber JAR with both project classes and bundled dependency classes
        Path jar = createJarWithEntries(tempDir, "uber.jar",
                "com/example/mylib/Main.class",
                "com/example/mylib/util/Helper.class",
                "com/google/common/collect/ImmutableList.class",
                "org/slf4j/Logger.class"
        );

        // The package map says these are dependencies
        Set<String> depPackages = Set.of("com.google.common.collect", "org.slf4j");

        List<String> result = PackageNameExtractor.extractFromJar(jar, depPackages);

        assertEquals(1, result.size());
        assertEquals("com.example.mylib", result.get(0));
    }

    @Test
    void skipsMETAINFEntries(@TempDir Path tempDir) throws IOException {
        Path jar = createJarWithEntries(tempDir, "test.jar",
                "com/example/mylib/Main.class",
                "META-INF/MANIFEST.MF",
                "META-INF/versions/9/module-info.class"
        );

        List<String> result = PackageNameExtractor.extractFromJar(jar, Set.of());

        assertEquals(1, result.size());
        assertEquals("com.example.mylib", result.get(0));
    }

    @Test
    void emptyJarReturnsEmptyList(@TempDir Path tempDir) throws IOException {
        Path jar = createJarWithEntries(tempDir, "empty.jar");

        List<String> result = PackageNameExtractor.extractFromJar(jar, Set.of());

        assertTrue(result.isEmpty());
    }

    private Path createJarWithEntries(Path dir, String name, String... entries) throws IOException {
        Path jarPath = dir.resolve(name);
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(jarPath.toFile()))) {
            for (String entry : entries) {
                jos.putNextEntry(new JarEntry(entry));
                jos.write(new byte[]{0}); // dummy content
                jos.closeEntry();
            }
        }
        return jarPath;
    }
}
