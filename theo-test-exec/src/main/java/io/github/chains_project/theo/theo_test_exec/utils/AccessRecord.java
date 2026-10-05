package io.github.chains_project.theo.theo_test_exec.utils;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.github.chains_project.theo.theo_test_exec.detectorCategories.AbstractCategory;

public record AccessRecord(String dependency, String method, String position, AbstractCategory category,
                           String sensitiveAPI) {
    /**
     * Creates a new AccessRecord object that is a record of all resource accesses for a specific dependency.
     *
     * @param dependency   the dependency
     * @param method       the method of the dependency in the stacktrace
     * @param position     the position in which called the respective method is found in the stacktrace.
     *                     the value could be one of [first, internal, last].
     * @param category     the category of the jfr event, which is used to determine the type of access
     * @param sensitiveAPI the sensitive API that was accessed
     */
    @JsonCreator
    public AccessRecord(@JsonProperty("dependency") String dependency,
                        @JsonProperty("method") String method,
                        @JsonProperty("position") String position,
                        @JsonProperty("category") AbstractCategory category,
                        @JsonProperty("sensitiveAPI") String sensitiveAPI) {
        this.dependency = dependency;
        this.method = method;
        this.position = position;
        this.category = category;
        this.sensitiveAPI = sensitiveAPI;
    }

    /**
     * Gets the name of the dependency that the AccessRecord belongs to.
     */
    @Override
    public String dependency() {
        return dependency;
    }

    @Override
    public String toString() {
        return "AccessRecord{" +
                "dependency='" + dependency + '\'' +
                ", method='" + method + '\'' +
                ", position='" + position + '\'' +
                ", category='" + category.toString() + '\'' +
                ", sensitiveMethod='" + sensitiveAPI + '\'' +
                '}';
    }
}
