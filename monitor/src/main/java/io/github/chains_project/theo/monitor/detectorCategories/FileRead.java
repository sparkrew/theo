package io.github.chains_project.theo.monitor.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class FileRead extends AbstractCategory {

    public final String filePath;
    public final String bytesRead;
    public final String endOfFile;

    /**
     * Creates a new FileRead object that stores information about reading a file.
     *
     * @param method    the method which executed the fileRead
     * @param className the class of the method
     * @param calledBy  the methods which called the respective method as found in the stacktrace
     * @param filePath  the full path of the file
     * @param bytesRead number of bytes read from the file
     * @param endOfFile a boolean value indicating Whether the end of file was reached
     */
    @JsonCreator
    FileRead(@JsonProperty("method") String method,
             @JsonProperty("className") String className,
             @JsonProperty("calledBy") List<SubMethod> calledBy,
             @JsonProperty("filePath") String filePath,
             @JsonProperty("bytesRead") String bytesRead,
             @JsonProperty("endOfFile") String endOfFile) {
        super(method, className, calledBy);
        this.filePath = filePath;
        this.bytesRead = bytesRead;
        this.endOfFile = endOfFile;
    }
}
