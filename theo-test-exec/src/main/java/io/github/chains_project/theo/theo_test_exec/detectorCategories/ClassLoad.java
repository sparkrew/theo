package io.github.chains_project.theo.theo_test_exec.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class ClassLoad extends AbstractCategory {

    public final String loadedClass;

    /**
     * Creates a new ClassLoad object that stores information about a
     * classloading event.
     *
     * @param loadedClass  the loaded class captured by the jfr
     */
    @JsonCreator
    ClassLoad(@JsonProperty("loadedClass") String loadedClass) {
        super();
        this.loadedClass = loadedClass;
    }
}
