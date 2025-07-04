package io.github.chains_project.theo.theo_test_exec.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class FileWrite extends AbstractCategory {

    public final String filePath;

    /**
     * Creates a new FileWrite object that stores information about writing to a file.
     *
     * @param filePath     the full path of the file
     */
    @JsonCreator
    public FileWrite(@JsonProperty("filePath") String filePath) {
        super();
        this.filePath = filePath;
    }
}
