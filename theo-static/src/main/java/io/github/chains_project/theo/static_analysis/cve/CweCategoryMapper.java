package io.github.chains_project.theo.static_analysis.cve;

import java.util.*;

/**
 * Maps CWE IDs to Theo's sensitive API categories based on the categorization
 * from Table II of "What's in a Package?" (arXiv:2408.02846). This allows us
 * to place CVEs under the same categories used for sensitive API grouping,
 * since each CWE targets a specific kind of system resource.
 */
public class CweCategoryMapper {

    // The mapping is static — it comes from the paper's table and doesn't change at runtime.
    // Key: CWE ID (integer), Value: set of categories this CWE relates to.
    // A CWE can appear in multiple subcategories, so it may map to more than one top-level category.
    private static final Map<Integer, Set<String>> CWE_TO_CATEGORIES = new HashMap<>();

    static {
        // -- Filesystem category --
        // Input: opening or reading files
        addMapping(Set.of(73, 91, 319, 552, 576, 611), "FILESYSTEM");
        // Output: creating or writing files
        addMapping(Set.of(116, 117), "FILESYSTEM");
        // Miscellaneous: paths, permissions, traversal, etc.
        addMapping(Set.of(22, 367, 732), "FILESYSTEM");
        // Reading environment variables (includes network-related env vars)
        addMapping(Set.of(214, 526, 291, 706, 755, 1327), "FILESYSTEM");

        // -- Network category --
        // Connection: URL/web connections, dispatching requests
        addMapping(Set.of(89, 404, 444, 523, 600, 601, 772, 830, 918, 943, 1072), "NETWORK");
        // Http: requests, responses, cookies, client operations
        addMapping(Set.of(20, 79, 213, 295, 352, 384, 602, 614, 754), "NETWORK");
        // Socket: socket endpoints and transport-level issues
        addMapping(Set.of(246, 577, 923, 941, 1385), "NETWORK");
        // Naming/directory: JNDI and similar lookups
        addMapping(Set.of(502), "NETWORK");

        // -- Process category --
        // Codec/crypto: encoding, decoding, encryption
        addMapping(Set.of(84, 177, 261, 327), "PROCESS");
        // Dependency: loading packages or libraries
        addMapping(Set.of(111, 114), "PROCESS");
        // Reflection: dynamic class loading and invocation
        addMapping(Set.of(470, 578, 749, 917), "PROCESS");
        // Operating system: executing OS programs or commands
        addMapping(Set.of(78), "PROCESS");
        // Scripting: building or executing scripts (CWE-79 is shared with Network/Http)
        addMapping(Set.of(79), "PROCESS");

        // Cross-category CWEs (some CWEs span more than one top-level category)
        // CWE-1385 is both a socket issue (Network) and a codec concern (Process)
        addMapping(Set.of(1385), "PROCESS");
        // CWE-116 relates to both file output (Filesystem) and HTTP output (Network)
        addMapping(Set.of(116), "NETWORK");
        // CWE-319 is about cleartext transmission — relevant to both file input and network
        addMapping(Set.of(319), "NETWORK");
    }

    private static void addMapping(Set<Integer> cwes, String category) {
        for (int cwe : cwes) {
            CWE_TO_CATEGORIES.computeIfAbsent(cwe, k -> new LinkedHashSet<>()).add(category);
        }
    }

    /**
     * Returns the set of Theo categories that a list of CWE IDs maps to.
     * If none of the CWEs are in our mapping, returns a set containing "OTHER".
     *
     * @param cweIds list of CWE IDs (as integers, e.g. [22, 78])
     * @return set of category names (e.g. {"FILESYSTEM", "PROCESS"})
     */
    public static Set<String> categorizeByCwes(List<Integer> cweIds) {
        if (cweIds == null || cweIds.isEmpty()) {
            return Set.of("OTHER");
        }

        Set<String> categories = new LinkedHashSet<>();
        for (int cwe : cweIds) {
            Set<String> mapped = CWE_TO_CATEGORIES.get(cwe);
            if (mapped != null) {
                categories.addAll(mapped);
            }
        }

        return categories.isEmpty() ? Set.of("OTHER") : categories;
    }

    /**
     * Parses CWE ID strings like "CWE-22" into integers.
     * Silently skips malformed entries.
     */
    public static List<Integer> parseCweIds(List<String> cweStrings) {
        if (cweStrings == null) {
            return List.of();
        }
        List<Integer> ids = new ArrayList<>();
        for (String s : cweStrings) {
            try {
                String num = s.startsWith("CWE-") ? s.substring(4) : s;
                ids.add(Integer.parseInt(num.trim()));
            } catch (NumberFormatException ignored) {
                // skip malformed CWE strings
            }
        }
        return ids;
    }

    /**
     * Returns all known categories in display order.
     */
    public static List<String> allCategories() {
        return List.of("FILESYSTEM", "NETWORK", "PROCESS", "OTHER");
    }
}
