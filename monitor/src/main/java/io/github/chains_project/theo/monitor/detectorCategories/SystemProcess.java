package io.github.chains_project.theo.monitor.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class SystemProcess extends AbstractCategory {

    public final String pid;
    public final String command;

    /**
     * Creates a new SystemProcess object that stores information about system processes.
     *
     * @param method    the method which executed a system process
     * @param className the class of the method
     * @param calledBy  the methods which called the respective method as found in the stacktrace
     * @param pid       process ID
     * @param command   the executed command
     */
    @JsonCreator
    SystemProcess(@JsonProperty("method") String method,
                  @JsonProperty("className") String className,
                  @JsonProperty("calledBy") List<SubMethod> calledBy,
                  @JsonProperty("filePath") String pid,
                  @JsonProperty("command") String command) {
        super(method, className, calledBy);
        this.pid = pid;
        this.command = command;
    }
}
