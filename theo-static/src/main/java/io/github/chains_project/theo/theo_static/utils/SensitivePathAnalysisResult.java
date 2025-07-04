package io.github.chains_project.theo.theo_static.utils;

import java.util.List;

/**
 * Root container for the complete sensitive path analysis results.
 * This is the top-level object that gets serialized to JSON.
 */
public class SensitivePathAnalysisResult {
    public AnalysisMetadata metadata;
    public List<SensitivePathResult> sensitivePaths;

    public SensitivePathAnalysisResult() {
        // Default constructor for JSON deserialization
    }

    public SensitivePathAnalysisResult(AnalysisMetadata metadata, List<SensitivePathResult> sensitivePaths) {
        this.metadata = metadata;
        this.sensitivePaths = sensitivePaths;
    }

    /**
     * Get the total number of sensitive paths found.
     */
    public int getTotalPaths() {
        return sensitivePaths != null ? sensitivePaths.size() : 0;
    }

    /**
     * Check if any sensitive paths were found.
     */
    public boolean hasSensitivePaths() {
        return sensitivePaths != null && !sensitivePaths.isEmpty();
    }

    @Override
    public String toString() {
        return "SensitivePathAnalysisResult{" +
                "metadata=" + metadata +
                ", sensitivePaths=" + sensitivePaths +
                '}';
    }
}
