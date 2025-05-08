package io.github.chains_project.theo.monitor.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class Deserialization extends AbstractCategory {

    public final String deserializedClassName;
    public final String bytesRead;
    public final String arrayLength;
    public final String filterConfigured;

    /**
     * Creates a new Deserialization object that stores information about a
     * deserializing event.
     *
     * @param method                the method which executed the deserialization
     * @param className             the class of the method
     * @param calledBy              the methods which called the respective method as found in the stacktrace
     * @param deserializedClassName the class name of the deserialized class
     * @param bytesRead             bytes read
     * @param arrayLength           array length
     * @param filterConfigured      a boolean value indicating whether a filter is configured or not
     */
    @JsonCreator
    Deserialization(@JsonProperty("method") String method,
                    @JsonProperty("className") String className,
                    @JsonProperty("calledBy") List<SubMethod> calledBy,
                    @JsonProperty("deserializedClassName") String deserializedClassName,
                    @JsonProperty("bytesRead") String bytesRead,
                    @JsonProperty("arrayLength") String arrayLength,
                    @JsonProperty("filterConfigured") String filterConfigured) {
        super(method, className, calledBy);
        this.deserializedClassName = deserializedClassName;
        this.bytesRead = bytesRead;
        this.arrayLength = arrayLength;
        this.filterConfigured = filterConfigured;
    }
}
