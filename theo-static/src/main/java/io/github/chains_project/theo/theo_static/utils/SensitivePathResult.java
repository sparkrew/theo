package io.github.chains_project.theo.theo_static.utils;

import java.util.List;

public class SensitivePathResult {
    public final String entryPoint;
    public final String thirdPartyMethod;
    public final String securitySensitiveAPI;
    public final List<String> fullPath;
    public final String dependencyName;
    public final String dependencyDirectness;

    public SensitivePathResult(String entryPoint, String thirdPartyMethod, String sensitiveAPI, List<String> fullPath,
                               String dependencyName, String dependencyDirectness) {
        this.entryPoint = entryPoint;
        this.thirdPartyMethod = thirdPartyMethod;
        this.securitySensitiveAPI = sensitiveAPI;
        this.fullPath = fullPath;
        this.dependencyName = dependencyName;
        this.dependencyDirectness = dependencyDirectness;
    }

    @Override
    public String toString() {
        return "SensitivePathResult{" +
                "entryPoint='" + entryPoint + '\'' +
                ", thirdPartyMethod='" + thirdPartyMethod + '\'' +
                ", securitySensitiveAPI='" + securitySensitiveAPI + '\'' +
                ", fullPath=" + fullPath +
                ", dependencyName='" + dependencyName + '\'' +
                ", dependencyDirectness='" + dependencyDirectness + '\'' +
                '}';
    }
}
