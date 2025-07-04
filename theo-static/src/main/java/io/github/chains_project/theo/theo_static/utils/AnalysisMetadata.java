package io.github.chains_project.theo.theo_static.utils;

/**
 * Metadata information about the sensitive path analysis run.
 */
public class AnalysisMetadata {
    public String jarPath;
    public int totalEntryPoints;
    public int totalSensitivePaths;
    public int totalThirdPartyCalls;
    public long timestamp;

    public AnalysisMetadata() {
        // Default constructor for JSON deserialization
    }

    public AnalysisMetadata(String jarPath, int totalEntryPoints, int totalSensitivePaths,
                            int totalThirdPartyCalls, long analysisTimestamp) {
        this.jarPath = jarPath;
        this.totalEntryPoints = totalEntryPoints;
        this.totalSensitivePaths = totalSensitivePaths;
        this.totalThirdPartyCalls = totalThirdPartyCalls;
        this.timestamp = analysisTimestamp;
    }
}