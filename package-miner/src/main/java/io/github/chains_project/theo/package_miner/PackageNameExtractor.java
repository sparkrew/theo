package io.github.chains_project.theo.package_miner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Extracts the project's own package name(s) from the classes inside a JAR file,
 * filtering out packages that belong to bundled dependencies (uber JAR case).
 *
 * The heuristic:
 * 1. Scan all .class files in the JAR and collect their package names
 * 2. Remove any package that appears in the dependency package map (produced by the preprocessor)
 * 3. Find the longest common prefix among the remaining packages
 * 4. If that prefix has at least 3 parts (e.g. "io.github.myname"), use it as the base
 * 5. If the prefix is too short (e.g. "org.apache"), collect all distinct 3-part prefixes
 *
 * This handles uber/fat JARs correctly: bundled dependency classes (like com.google.common,
 * org.slf4j, etc.) get filtered out by step 2 since they appear in the package map.
 */
public class PackageNameExtractor {

    private static final Logger log = LoggerFactory.getLogger(PackageNameExtractor.class);
    private static final int MIN_BASE_PARTS = 3;

    /**
     * Extracts the project package name(s) from a JAR, filtering out dependency packages.
     *
     * @param jarPath            path to the JAR file to scan
     * @param dependencyPackages package names that belong to dependencies (from the preprocessor's
     *                           package map). These are subtracted so uber JAR bundled classes
     *                           don't pollute the result. Can be empty if no package map is available.
     * @return list of package name(s) representing the project's own code
     */
    public static List<String> extractFromJar(Path jarPath, Set<String> dependencyPackages) {
        Set<String> allPackages = scanJarPackages(jarPath);
        if (allPackages.isEmpty()) {
            return List.of();
        }

        // Remove packages that belong to known dependencies.
        // This is the key step that handles uber JARs — bundled dependency classes
        // show up in the package map, so we can filter them out.
        Set<String> projectPackages = new LinkedHashSet<>();
        for (String pkg : allPackages) {
            if (!dependencyPackages.contains(pkg)) {
                projectPackages.add(pkg);
            }
        }

        if (projectPackages.isEmpty()) {
            // Every package in the JAR matched a dependency — unusual, but possible
            // if the project itself has no unique packages. Fall back to the full set.
            log.warn("All packages in JAR matched dependencies, using full set for: {}", jarPath);
            projectPackages = allPackages;
        }

        log.debug("JAR {} has {} total packages, {} after filtering dependencies.",
                jarPath.getFileName(), allPackages.size(), projectPackages.size());

        return findBasePackageNames(projectPackages);
    }

    /**
     * Scans a JAR and returns all distinct package names.
     * Handles both source JARs (.java files) and bytecode JARs (.class files).
     * Source JARs are preferred because they only contain the project's own code,
     * not bundled dependencies like uber JARs might.
     */
    private static Set<String> scanJarPackages(Path jarPath) {
        Set<String> packages = new LinkedHashSet<>();
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                if (entry.isDirectory() || name.startsWith("META-INF/")) continue;

                // Handle both .java (source JAR) and .class (bytecode JAR) files
                String suffix = null;
                if (name.endsWith(".java")) suffix = ".java";
                else if (name.endsWith(".class")) suffix = ".class";
                if (suffix == null) continue;

                String qualifiedName = name.replace('/', '.').replace(suffix, "");
                int lastDot = qualifiedName.lastIndexOf('.');
                if (lastDot > 0) {
                    packages.add(qualifiedName.substring(0, lastDot));
                }
            }
        } catch (IOException e) {
            log.error("Failed to read JAR file: {}", jarPath, e);
        }
        return packages;
    }

    /**
     * Given a set of the project's own package names, finds the base package name(s).
     *
     * First tries to find a common prefix with at least 3 parts. If the common prefix
     * is too short (like "org.apache"), falls back to collecting all distinct 3-part
     * prefixes from the packages.
     */
    static List<String> findBasePackageNames(Set<String> allPackages) {
        String commonPrefix = findLongestCommonPrefix(allPackages);

        if (commonPrefix != null && countParts(commonPrefix) >= MIN_BASE_PARTS) {
            log.info("Found common base package: {}", commonPrefix);
            return List.of(commonPrefix);
        }

        // Common prefix too short — collect all distinct 3-part prefixes
        Set<String> prefixes = new TreeSet<>();
        for (String pkg : allPackages) {
            String prefix = getFirstNParts(pkg, MIN_BASE_PARTS);
            if (prefix != null) {
                prefixes.add(prefix);
            }
        }

        if (prefixes.isEmpty()) {
            log.warn("Could not extract {}-part prefixes, using all package names.", MIN_BASE_PARTS);
            return new ArrayList<>(allPackages);
        }

        log.info("Found {} base package name(s): {}", prefixes.size(), prefixes);
        return new ArrayList<>(prefixes);
    }

    private static String findLongestCommonPrefix(Set<String> packages) {
        if (packages.isEmpty()) return null;

        Iterator<String> it = packages.iterator();
        String[] referenceParts = it.next().split("\\.");
        int commonLength = referenceParts.length;

        while (it.hasNext()) {
            String[] parts = it.next().split("\\.");
            commonLength = Math.min(commonLength, parts.length);
            for (int i = 0; i < commonLength; i++) {
                if (!referenceParts[i].equals(parts[i])) {
                    commonLength = i;
                    break;
                }
            }
            if (commonLength == 0) return null;
        }

        return String.join(".", Arrays.copyOf(referenceParts, commonLength));
    }

    private static int countParts(String packageName) {
        if (packageName == null || packageName.isEmpty()) return 0;
        return packageName.split("\\.").length;
    }

    private static String getFirstNParts(String packageName, int n) {
        String[] parts = packageName.split("\\.");
        if (parts.length < n) return null;
        return String.join(".", Arrays.copyOf(parts, n));
    }
}
