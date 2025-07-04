package io.github.chains_project.theo.theo_test_exec.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class FileForce extends AbstractCategory {

    public final String filePath;
    public final String metaDataUpdated;

    /**
     * Creates a new FileForce object that stores information about writing
     * force updates to a file.
     *
     * @param filePath        the full path of the file
     * @param metaDataUpdated a boolean value indicating Whether the file metadata is updated
     */
    @JsonCreator
    FileForce(@JsonProperty("filePath") String filePath,
              @JsonProperty("metaDataUpdated") String metaDataUpdated) {
        super();
        this.filePath = filePath;
        this.metaDataUpdated = metaDataUpdated;
    }
}
