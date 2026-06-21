package io.github.chains_project.theo.theo_commons;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class PackageMatcherTest {

    @Test
    void loadIgnoredPrefixesSinglePackage() {
        Set<String> prefixes = PackageMatcher.loadIgnoredPrefixes("com.example.myapp");

        assertTrue(prefixes.contains("com.example.myapp."),
                "Should include the provided package with trailing dot");
        assertTrue(prefixes.contains("java."),
                "Should include java. as a built-in ignored prefix");
        assertTrue(prefixes.contains("javax."),
                "Should include javax. as a built-in ignored prefix");
    }

    @Test
    void loadIgnoredPrefixesMultiplePackages() {
        Set<String> prefixes = PackageMatcher.loadIgnoredPrefixes(
                List.of("org.apache.pdfbox", "org.apache.xmpbox")
        );

        assertTrue(prefixes.contains("org.apache.pdfbox."));
        assertTrue(prefixes.contains("org.apache.xmpbox."));
        assertTrue(prefixes.contains("java."));
    }

    @Test
    void loadIgnoredPrefixesHandlesTrailingDot() {
        Set<String> prefixes = PackageMatcher.loadIgnoredPrefixes("com.example.");

        assertTrue(prefixes.contains("com.example."),
                "Should not double the trailing dot");
        long count = prefixes.stream().filter(p -> p.equals("com.example.")).count();
        assertEquals(1, count, "Should have exactly one entry for com.example.");
    }

    @Test
    void loadIgnoredPrefixesHandlesNullAndEmpty() {
        Set<String> withNull = PackageMatcher.loadIgnoredPrefixes((String) null);
        Set<String> withEmpty = PackageMatcher.loadIgnoredPrefixes("");
        Set<String> withBlank = PackageMatcher.loadIgnoredPrefixes("   ");

        // All should still have the built-in prefixes
        assertTrue(withNull.contains("java."));
        assertTrue(withEmpty.contains("java."));
        assertTrue(withBlank.contains("java."));

        // None should have added a bogus entry
        assertFalse(withNull.stream().anyMatch(p -> p.equals(".")));
        assertFalse(withEmpty.stream().anyMatch(p -> p.equals(".")));
    }

    @ParameterizedTest
    @ValueSource(strings = {"java.", "javax.", "sun.", "jdk.", "jakarta.", "org.junit.",
            "org.testng.", "org.eclipse.", "org.slf4j.", "org.apache.", "org.aspectj.", "com.sun."})
    void builtInIgnoredPrefixesPresent(String prefix) {
        Set<String> prefixes = PackageMatcher.loadIgnoredPrefixes("com.test");
        assertTrue(prefixes.contains(prefix),
                "Built-in prefix '" + prefix + "' should be present");
    }

    @Test
    void loadIgnoredPrefixesEmptyList() {
        Set<String> prefixes = PackageMatcher.loadIgnoredPrefixes(List.of());

        assertTrue(prefixes.contains("java."),
                "Empty list should still include built-in prefixes");
        // Should only have the built-in ones, no extras
        assertFalse(prefixes.stream().anyMatch(p -> p.length() <= 1));
    }

    @Test
    void getDependencyNameReturnsNullForMissingPackage(@TempDir Path tempDir) throws IOException {
        Path mapFile = tempDir.resolve("map.json");
        new ObjectMapper().writeValue(mapFile.toFile(), Map.of(
                "com.example.known", List.of("com.example:known:jar:1.0")
        ));

        // Force a fresh load by using a new map file
        String result = PackageMatcher.getDependencyName("com.example.unknown", mapFile);
        assertNull(result, "Should return null for a package not in the map");
    }

    @Test
    void getDependencyNameReturnsNullForNullInput(@TempDir Path tempDir) throws IOException {
        Path mapFile = tempDir.resolve("map.json");
        new ObjectMapper().writeValue(mapFile.toFile(), Map.of());

        assertNull(PackageMatcher.getDependencyName(null, mapFile));
        assertNull(PackageMatcher.getDependencyName("", mapFile));
    }
}
