package io.github.chains_project.theo.theo_test_exec.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class TLSHandshake extends AbstractCategory {

    public final String peerHost;
    public final String peerPort;
    public final String certificateId;

    /**
     * Creates a new FileRead object that stores information about reading a file.
     *
     * @param peerHost      the full path of the file
     * @param peerPort      number of bytes read from the file
     * @param certificateId a boolean value indicating Whether the end of file was reached
     */
    @JsonCreator
    TLSHandshake(@JsonProperty("peerHost") String peerHost,
                 @JsonProperty("peerPort") String peerPort,
                 @JsonProperty("certificateId") String certificateId) {
        super();
        this.peerHost = peerHost;
        this.peerPort = peerPort;
        this.certificateId = certificateId;
    }
}
