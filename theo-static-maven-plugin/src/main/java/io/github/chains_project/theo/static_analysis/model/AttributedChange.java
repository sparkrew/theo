package io.github.chains_project.theo.static_analysis.model;

/**
 * A sensitive API change paired with its root-cause attribution.
 * Wraps a {@link SensitiveApiEntry} with the reason the change occurred.
 */
public record AttributedChange(
        /** The sensitive API entry that was added or removed. */
        SensitiveApiEntry entry,

        /** "ADDED" or "REMOVED". */
        String changeDirection,

        /** Who caused this change. Null for removals (reported without scoring). */
        RootCause rootCause,

        /** The dependency GA this entry belongs to, e.g. "org.lib:parser". */
        String depGa,

        /** Human-readable explanation of the attribution decision. */
        String explanation
) {
}
