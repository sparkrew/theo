package io.github.chains_project.theo.theo_test_exec.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class ReservedStackActivation extends AbstractCategory {

    public final String activatedMethod;

    /**
     * Creates a new ReservedStackActivation object that stores information about activation of Reserved Stack
     * Area caused by stack overflow with ReservedStackAccess annotated method in call stack.
     *
     * @param activatedMethod the name of the method that caused the activation
     */
    @JsonCreator
    ReservedStackActivation(@JsonProperty("activatedMethod") String activatedMethod) {
        super();
        this.activatedMethod = activatedMethod;
    }
}
