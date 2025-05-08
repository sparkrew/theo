package io.github.chains_project.theo.monitor.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class ReservedStackActivation extends AbstractCategory {

    public final String activatedMethod;

    /**
     * Creates a new ReservedStackActivation object that stores information about activation of Reserved Stack
     * Area caused by stack overflow with ReservedStackAccess annotated method in call stack.
     *
     * @param method          the method which accessed a reserved stack
     * @param className       the class of the method
     * @param calledBy        the methods which called the respective method as found in the stacktrace
     * @param activatedMethod the method which activated a reserved stack as recorded by jfr
     */
    @JsonCreator
    ReservedStackActivation(@JsonProperty("method") String method,
                            @JsonProperty("className") String className,
                            @JsonProperty("calledBy") List<SubMethod> calledBy,
                            @JsonProperty("method") String activatedMethod) {
        super(method, className, calledBy);
        this.activatedMethod = activatedMethod;
    }
}
