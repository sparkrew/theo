package io.github.chains_project.theo.static_analysis.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * A client-to-dependency method call boundary crossing discovered during
 * call graph analysis. Recorded for all reachable client→dep edges,
 * not only those that lead to a sensitive API.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record BoundaryInteraction(
        /** The client project method that calls into the dependency. */
        String clientMethod,

        /** The first dependency method called by the client method. */
        String depMethod,

        /** The dependency's artifact as "groupId:artifactId". */
        String depArtifactGa
) {
}
