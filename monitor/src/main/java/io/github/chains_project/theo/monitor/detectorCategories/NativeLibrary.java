package io.github.chains_project.theo.monitor.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class NativeLibrary extends AbstractCategory {

    public final String name;

    /**
     * Creates a new NativeLibrary object that stores information about native libraries.
     *
     * @param method    the method which accessed a native library
     * @param className the class of the method
     * @param calledBy  the methods which called the respective method as found in the stacktrace
     * @param name      the library name
     */
    @JsonCreator
    NativeLibrary(@JsonProperty("method") String method,
                  @JsonProperty("className") String className,
                  @JsonProperty("calledBy") List<SubMethod> calledBy,
                  @JsonProperty("name") String name) {
        super(method, className, calledBy);
        this.name = name;
    }
}
