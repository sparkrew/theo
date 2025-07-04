package io.github.chains_project.theo.theo_test_exec.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class SocketRead extends AbstractCategory {

    public final String host;
    public final String address;
    public final String port;

    /**
     * Creates a new SocketRead object that stores information about reading data from a socket.
     *
     * @param host         host
     * @param address      network address
     * @param port         port number
     */
    @JsonCreator
    SocketRead(@JsonProperty("host") String host,
               @JsonProperty("address") String address,
               @JsonProperty("port") String port) {
        super();
        this.host = host;
        this.address = address;
        this.port = port;
    }
}
