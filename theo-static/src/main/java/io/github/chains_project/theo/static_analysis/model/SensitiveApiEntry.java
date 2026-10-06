package io.github.chains_project.theo.static_analysis.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * A single finding: one sensitive API that a dependency can reach,
 * along with the call chain that connects the dependency's entry point
 * to the sensitive method.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SensitiveApiEntry(
        /** The fully qualified sensitive API, e.g. "java.io.FileInputStream.<init>". */
        String sensitiveApi,

        /** The dependency method that starts the call path toward the sensitive API. */
        String entryPoint,

        /** Whether the dependency calls the sensitive API directly or through intermediaries. */
        String accessType,

        /** Intermediary dependencies involved when accessType is INDIRECT. May be empty for DIRECT. */
        List<String> dependencies,

        /** The complete call chain from entryPoint down to sensitiveApi. */
        List<String> fullPath,

        /** High-level category from the sensitive API descriptor, if available. */
        String category,

        /** More specific classification within the category, if available. */
        String subcategory
) {
}
