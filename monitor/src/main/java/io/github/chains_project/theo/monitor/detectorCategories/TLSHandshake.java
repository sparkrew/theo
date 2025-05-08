package io.github.chains_project.theo.monitor.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class TLSHandshake extends AbstractCategory {

    public final String peerHost;
    public final String peerPort;
    public final String certificateId;

    /**
     * Creates a new FileRead object that stores information about reading a file.
     *
     * @param method        the method which executed a classload
     * @param className     the class of the method
     * @param calledBy      the methods which called the respective method as found in the stacktrace
     * @param peerHost      the full path of the file
     * @param peerPort      number of bytes read from the file
     * @param certificateId a boolean value indicating Whether the end of file was reached
     */
    @JsonCreator
    TLSHandshake(@JsonProperty("method") String method,
                 @JsonProperty("className") String className,
                 @JsonProperty("calledBy") List<SubMethod> calledBy,
                 @JsonProperty("peerHost") String peerHost,
                 @JsonProperty("peerPort") String peerPort,
                 @JsonProperty("certificateId") String certificateId) {
        super(method, className, calledBy);
        this.peerHost = peerHost;
        this.peerPort = peerPort;
        this.certificateId = certificateId;
    }
}
