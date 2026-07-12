package io.github.chains_project.theo.package_miner.util;

public class LanguageFilter {

    public static boolean isLikelyKotlinOrScala(String groupId, String artifactId) {
        String gLower = groupId.toLowerCase();
        String aLower = artifactId.toLowerCase();
        return gLower.contains("kotlin") || gLower.contains("scala")
                || gLower.contains("kotlinx") || gLower.contains("groovy")
                || gLower.contains("clojure")
                || aLower.contains("kotlin") || aLower.contains("scala")
                || aLower.contains("groovy") || aLower.contains("clojure");
    }
}
