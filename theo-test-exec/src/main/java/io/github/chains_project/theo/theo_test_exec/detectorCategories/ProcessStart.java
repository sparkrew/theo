package io.github.chains_project.theo.theo_test_exec.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class ProcessStart extends AbstractCategory {

    public final String directory;
    public final String command;

    /**
     * Creates a new ProcessStart object that stores information about OS processes.
     *
     * @param directory    the directory
     * @param command      the command executed
     */
    @JsonCreator
    ProcessStart(@JsonProperty("directory") String directory,
                 @JsonProperty("command") String command) {
        super();
        this.directory = directory;
        this.command = command;
    }
}
