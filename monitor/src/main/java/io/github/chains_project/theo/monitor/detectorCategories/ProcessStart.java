package io.github.chains_project.theo.monitor.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class ProcessStart extends AbstractCategory {

    public final String directory;
    public final String command;

    /**
     * Creates a new ProcessStart object that stores information about OS processes.
     *
     * @param method    the method which executed started a process
     * @param className the class of the method
     * @param calledBy  the methods which called the respective method as found in the stacktrace
     * @param directory the directory
     * @param command   the command executed
     */
    @JsonCreator
    ProcessStart(@JsonProperty("method") String method,
                 @JsonProperty("className") String className,
                 @JsonProperty("calledBy") List<SubMethod> calledBy,
                 @JsonProperty("directory") String directory,
                 @JsonProperty("command") String command) {
        super(method, className, calledBy);
        this.directory = directory;
        this.command = command;
    }
}
