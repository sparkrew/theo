package io.github.chains_project.theo.static_analysis.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * A method in a call path together with the Maven artifact it belongs to.
 * Used in {@link SensitiveApiEntry#fullPath()} so that attribution can
 * determine who owns each step without re-querying the package map.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record PathMethod(
        /** Fully qualified method, e.g. "com.example.MyClass.doStuff". */
        String method,

        /** Owning artifact as "groupId:artifactId", or null for JDK / unresolved. */
        String artifactGa
) {
}
