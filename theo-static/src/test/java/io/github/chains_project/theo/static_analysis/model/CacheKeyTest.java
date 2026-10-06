package io.github.chains_project.theo.static_analysis.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class CacheKeyTest {

    @Test
    void toCachePathReturnsMavenStylePath() {
        CacheKey key = new CacheKey("com.example", "my-lib", "1.0.0");
        assertEquals("dependencies/com.example/my-lib/1.0.0", key.toCachePath());
    }

    @Test
    void toProjectCachePathReplacesColonsWithDoubleUnderscores() {
        CacheKey key = new CacheKey("com.example", "my-lib", "1.0.0");
        String result = key.toProjectCachePath("org.acme:web-app:2.3.1");
        assertEquals("projects/org.acme__web-app__2.3.1", result);
    }

    @Test
    void fromArtifactGavCreatesCorrectKey() {
        CacheKey key = CacheKey.fromArtifactGav("org.slf4j", "slf4j-api", "2.0.9");
        assertEquals("org.slf4j", key.groupId());
        assertEquals("slf4j-api", key.artifactId());
        assertEquals("2.0.9", key.version());
    }

    @Test
    void toStringReturnsGavFormat() {
        CacheKey key = new CacheKey("com.example", "my-lib", "1.0.0");
        assertEquals("com.example:my-lib:1.0.0", key.toString());
    }

    @Test
    void recordEqualityWorksForSameGav() {
        CacheKey a = new CacheKey("com.example", "my-lib", "1.0.0");
        CacheKey b = new CacheKey("com.example", "my-lib", "1.0.0");
        assertEquals(a, b);
        assertEquals(a.hashCode(), b.hashCode());
    }

    @Test
    void recordEqualityFailsForDifferentGav() {
        CacheKey a = new CacheKey("com.example", "my-lib", "1.0.0");
        CacheKey b = new CacheKey("com.example", "my-lib", "2.0.0");
        assertNotEquals(a, b);
    }
}
