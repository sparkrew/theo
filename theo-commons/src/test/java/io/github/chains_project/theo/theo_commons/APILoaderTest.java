package io.github.chains_project.theo.theo_commons;

import com.fasterxml.jackson.core.type.TypeReference;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class APILoaderTest {

    @Test
    void loadsSensitiveApisFromClasspath() {
        List<SensitiveAPIDescriptor> apis = APILoader.loadFromClasspath(
                "sensitive_apis.json", new TypeReference<>() {}
        );

        assertNotNull(apis);
        assertFalse(apis.isEmpty(), "Should load at least one sensitive API");
        assertTrue(apis.size() > 100, "Expected 200+ sensitive APIs, got " + apis.size());
    }

    @Test
    void loadedApisHaveAllFields() {
        List<SensitiveAPIDescriptor> apis = APILoader.loadFromClasspath(
                "sensitive_apis.json", new TypeReference<>() {}
        );

        for (SensitiveAPIDescriptor api : apis) {
            assertNotNull(api.className(), "className should not be null");
            assertNotNull(api.method(), "method should not be null");
            assertNotNull(api.category(), "category should not be null");
            assertNotNull(api.subcategory(), "subcategory should not be null");
            assertFalse(api.className().isBlank(), "className should not be blank");
            assertFalse(api.method().isBlank(), "method should not be blank");
        }
    }

    @Test
    void containsKnownSensitiveApis() {
        List<SensitiveAPIDescriptor> apis = APILoader.loadFromClasspath(
                "sensitive_apis.json", new TypeReference<>() {}
        );

        boolean hasFileInputStream = apis.stream().anyMatch(
                a -> "java.io.FileInputStream".equals(a.className()) && "<init>".equals(a.method())
        );
        boolean hasClassForName = apis.stream().anyMatch(
                a -> "java.lang.Class".equals(a.className()) && "forName".equals(a.method())
        );
        boolean hasSocket = apis.stream().anyMatch(
                a -> "java.net.Socket".equals(a.className())
        );

        assertTrue(hasFileInputStream, "Should contain java.io.FileInputStream.<init>");
        assertTrue(hasClassForName, "Should contain java.lang.Class.forName");
        assertTrue(hasSocket, "Should contain java.net.Socket");
    }

    @Test
    void throwsOnMissingResource() {
        assertThrows(RuntimeException.class, () ->
                APILoader.loadFromClasspath("nonexistent.json", new TypeReference<List<SensitiveAPIDescriptor>>() {})
        );
    }
}
