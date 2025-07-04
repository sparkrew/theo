package io.github.chains_project.theo.theo_commons;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

public class APILoader {

    public static <T> T loadFromClasspath(String resourceName, TypeReference<T> typeReference) {
        ObjectMapper mapper = new ObjectMapper();
        try (InputStream inputStream = APILoader.class.getClassLoader().getResourceAsStream(resourceName)) {
            if (inputStream == null) {
                throw new FileNotFoundException("Could not find " + resourceName + " in classpath.");
            }
            return mapper.readValue(inputStream, typeReference);
        } catch (IOException e) {
            throw new RuntimeException("Failed to read " + resourceName, e);
        }
    }
}
