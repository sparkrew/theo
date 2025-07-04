package io.github.chains_project.theo.theo_test_exec.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class Deserialization extends AbstractCategory {

    public final String deserializedClassName;

    /**
     * Creates a new Deserialization object that stores information about a
     * deserializing event.
     *
     * @param deserializedClassName the name of the class that was deserialized
     */
    @JsonCreator
    Deserialization(@JsonProperty("deserializedClassName") String deserializedClassName) {
        super();
        this.deserializedClassName = deserializedClassName;
    }
}
