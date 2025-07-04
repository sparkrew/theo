package io.github.chains_project.theo.theo_agent.agent;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.chains_project.theo.theo_commons.APILoader;
import io.github.chains_project.theo.theo_commons.SensitiveAPIDescriptor;
import org.slf4j.Logger;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class SensitiveApiRegistry {
    private static final Map<String, SensitiveAPIDescriptor> methodLookup = new ConcurrentHashMap<>();
    private static final Logger log = org.slf4j.LoggerFactory.getLogger(SensitiveApiRegistry.class);
    private static volatile boolean initialized = false;

    public static void initialize() {
        if (initialized) return;
        synchronized (SensitiveApiRegistry.class) {
            if (initialized) return;
            try {
                List<SensitiveAPIDescriptor> apiList = APILoader.loadFromClasspath(
                        "agent_sensitive_apis.json",
                        new TypeReference<>() {
                        }
                );
                registerSensitiveApis(apiList);
                initialized = true;
            } catch (Exception e) {
                log.error("Failed to initialize SensitiveApiRegistry: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    public static void registerSensitiveApis(List<SensitiveAPIDescriptor> apis) {
        for (SensitiveAPIDescriptor api : apis) {
            String key = createLookupKey(api.className(), api.method());
            methodLookup.put(key, api);
        }
    }

    public static SensitiveAPIDescriptor findSensitiveApi(String className, String methodName) {
        if (!initialized) initialize();
        String key = createLookupKey(className, methodName);
        return methodLookup.get(key);
    }

    // We use the same method within theo-test-exec. Maybe we can move this to theo-commons.
    static String filterName(String name) {
        // Replace $ followed by digit (e.g., $Array1234) with nothing
        name = name.replaceAll("\\$\\d+", "");
        // Replace $ followed by letter (e.g. Java.ArrayInitializer) with a dot
        name = name.replaceAll("\\$(?=[A-Za-z])", ".");
        return name;
    }

    private static String createLookupKey(String className, String methodName) {
        return filterName(className) + "#" + filterName(methodName);
    }
}
