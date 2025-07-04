package io.github.chains_project.theo.theo_static.utils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SensitivePathResult {
    public final String entryPoint;
    public final String thirdPartyMethod;
    public final String securitySensitiveAPI;
    public final List<String> fullPath;
    public final Map<String, Map<String, String>> dependencyPositionMap;
    // depName -> method -> position (First, Internal, Last)

    public SensitivePathResult(String entryPoint, String thirdPartyMethod, String sensitiveAPI, List<String> fullPath,
                               Map<String, Map<String, String>> dependencyPositionMap) {
        this.entryPoint = entryPoint;
        this.thirdPartyMethod = thirdPartyMethod;
        this.securitySensitiveAPI = sensitiveAPI;
        this.fullPath = fullPath;
        this.dependencyPositionMap = dependencyPositionMap;
    }

    // Existing constructor for backward compatibility (optional)
    public SensitivePathResult(String entryPoint, String thirdPartyMethod, String sensitiveAPI, List<String> fullPath) {
        this(entryPoint, thirdPartyMethod, sensitiveAPI, fullPath, new HashMap<>());
    }

    @Override
    public String toString() {
        return "SensitivePathResult{" +
                "entryPoint='" + entryPoint + '\'' +
                ", thirdPartyMethod='" + thirdPartyMethod + '\'' +
                ", securitySensitiveAPI='" + securitySensitiveAPI + '\'' +
                ", fullPath=" + fullPath +
                ", dependencyPositionMap=" + dependencyPositionMap +
                '}';
    }
}
