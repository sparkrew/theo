package io.github.chains_project.theo.monitor.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class FileWrite extends AbstractCategory {

    public final String filePath;

    /**
     * Creates a new FileWrite object that stores information about writing to a file.
     *
     * @param method    the method which executed the fileWrite event
     * @param className the class of the method
     * @param calledBy  the methods which called the respective method as found in the stacktrace
     * @param filePath  the full path of the file
     */
    @JsonCreator
    public FileWrite(@JsonProperty("method") String method,
                     @JsonProperty("className") String className,
                     @JsonProperty("calledBy") List<SubMethod> calledBy,
                     @JsonProperty("filePath") String filePath) {
        super(method, className, calledBy);
        this.filePath = filePath;
    }
}
