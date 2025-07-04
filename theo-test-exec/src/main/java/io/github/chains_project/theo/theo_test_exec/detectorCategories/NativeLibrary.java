package io.github.chains_project.theo.theo_test_exec.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class NativeLibrary extends AbstractCategory {

    public final String name;

    /**
     * Creates a new NativeLibrary object that stores information about native libraries.
     *
     * @param name         the library name
     */
    @JsonCreator
    NativeLibrary(@JsonProperty("name") String name) {
        super();
        this.name = name;
    }
}
