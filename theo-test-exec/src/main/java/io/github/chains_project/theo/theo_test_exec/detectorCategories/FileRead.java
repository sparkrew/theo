package io.github.chains_project.theo.theo_test_exec.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class FileRead extends AbstractCategory {

    public final String filePath;
    public final String bytesRead;

    /**
     * Creates a new FileRead object that stores information about reading a file.
     *
     * @param filePath     the full path of the file
     * @param bytesRead    number of bytes read from the file
     */
    @JsonCreator
    FileRead(@JsonProperty("filePath") String filePath,
             @JsonProperty("bytesRead") String bytesRead) {
        super();
        this.filePath = filePath;
        this.bytesRead = bytesRead;
    }
}
