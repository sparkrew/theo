package io.github.chains_project.theo.static_analysis.model;

/**
 * Why a sensitive API change happened, ranked by how silently
 * the change was introduced from the client developer's perspective.
 */
public enum RootCause {

    /** The client changed the boundary call to the dep. Direct access. */
    CLIENT_INITIATED(1, "Client Initiated"),

    /** The client changed the boundary call. Indirect access through another dep. */
    CLIENT_INITIATED_INDIRECT(2, "Client Initiated (Indirect)"),

    /** Boundary stable, direct dep version changed, direct access. */
    DEP_INITIATED(3, "Dep Initiated"),

    /** Boundary stable, direct dep version changed, indirect access. */
    DEP_INITIATED_INDIRECT(3, "Dep Initiated (Indirect)"),

    /** Boundary stable, direct dep version unchanged — a transitive dep changed. */
    INDIRECT_DEP_INITIATED(4, "Indirect Dep Initiated");

    private final int criticality;
    private final String label;

    RootCause(int criticality, String label) {
        this.criticality = criticality;
        this.label = label;
    }

    public int criticality() {
        return criticality;
    }

    public String label() {
        return label;
    }
}
