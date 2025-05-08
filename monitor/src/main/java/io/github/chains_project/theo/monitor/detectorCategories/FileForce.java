package io.github.chains_project.theo.monitor.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class FileForce extends AbstractCategory {

    public final String filePath;
    public final String metaDataUpdated;

    /**
     * Creates a new FileForce object that stores information about writing
     * force updates to a file.
     *
     * @param method          the method which executed the fileForce
     * @param className       the class of the method
     * @param calledBy        the methods which called the respective method as found in the stacktrace
     * @param filePath        the full path of the file
     * @param metaDataUpdated a boolean value indicating Whether the file metadata is updated
     */
    @JsonCreator
    FileForce(@JsonProperty("method") String method,
              @JsonProperty("className") String className,
              @JsonProperty("calledBy") List<SubMethod> calledBy,
              @JsonProperty("filePath") String filePath,
              @JsonProperty("metaDataUpdated") String metaDataUpdated) {
        super(method, className, calledBy);
        this.filePath = filePath;
        this.metaDataUpdated = metaDataUpdated;
    }
}
