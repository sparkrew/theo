package io.github.chains_project.theo.theo_test_exec.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class SystemProcess extends AbstractCategory {

    public final String pid;
    public final String command;

    /**
     * Creates a new SystemProcess object that stores information about system processes.
     *
     * @param pid     process ID
     * @param command the command executed
     */
    @JsonCreator
    SystemProcess(@JsonProperty("filePath") String pid, @JsonProperty("command") String command) {
        super();
        this.pid = pid;
        this.command = command;
    }
}
