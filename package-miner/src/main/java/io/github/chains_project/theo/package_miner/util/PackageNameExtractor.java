package io.github.chains_project.theo.package_miner.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class PackageNameExtractor {

    private static final Logger log = LoggerFactory.getLogger(PackageNameExtractor.class);
    private static final int MIN_BASE_PARTS = 3;

    public static List<String> extractFromJar(Path jarPath, Set<String> dependencyPackages) {
        Set<String> allPackages = scanJarPackages(jarPath);
        if (allPackages.isEmpty()) {
            return List.of();
        }

        Set<String> projectPackages = new LinkedHashSet<>();
        for (String pkg : allPackages) {
            if (!dependencyPackages.contains(pkg)) {
                projectPackages.add(pkg);
            }
        }

        if (projectPackages.isEmpty()) {
            log.warn("All packages in JAR matched dependencies, using full set for: {}", jarPath);
        }

        log.debug("JAR {} has {} total packages, {} after filtering dependencies.",
                jarPath.getFileName(), allPackages.size(), projectPackages.size());

        return findBasePackageNames(projectPackages);
    }

    private static Set<String> scanJarPackages(Path jarPath) {
        Set<String> packages = new LinkedHashSet<>();
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                if (entry.isDirectory() || name.startsWith("META-INF/")) continue;

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

    public static List<String> findBasePackageNames(Set<String> allPackages) {
        String commonPrefix = findLongestCommonPrefix(allPackages);

        if (commonPrefix != null && countParts(commonPrefix) >= MIN_BASE_PARTS) {
            log.info("Found common base package: {}", commonPrefix);
            return List.of(commonPrefix);
        }

        Set<String> prefixes = new TreeSet<>();
        for (String pkg : allPackages) {
            String prefix = getFirstNParts(pkg);
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

    private static String getFirstNParts(String packageName) {
        String[] parts = packageName.split("\\.");
        if (parts.length < PackageNameExtractor.MIN_BASE_PARTS) return null;
        return String.join(".", Arrays.copyOf(parts, PackageNameExtractor.MIN_BASE_PARTS));
    }
}
