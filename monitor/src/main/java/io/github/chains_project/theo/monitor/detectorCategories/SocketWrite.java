package io.github.chains_project.theo.monitor.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class SocketWrite extends AbstractCategory {

    public final String host;
    public final String address;
    public final String port;
    public final String bytesWritten;

    /**
     * Creates a new SocketRead object that stores information about writing data to a socket.
     *
     * @param method       the method which executed a socket write
     * @param className    the class of the method
     * @param calledBy     the methods which called the respective method as found in the stacktrace
     * @param host         host
     * @param address      network address
     * @param port         port number
     * @param bytesWritten number of bytes written to the socket
     */
    @JsonCreator
    SocketWrite(@JsonProperty("method") String method,
                @JsonProperty("className") String className,
                @JsonProperty("calledBy") List<SubMethod> calledBy,
                @JsonProperty("host") String host,
                @JsonProperty("address") String address,
                @JsonProperty("port") String port,
                @JsonProperty("bytesWritten") String bytesWritten) {
        super(method, className, calledBy);
        this.host = host;
        this.address = address;
        this.port = port;
        this.bytesWritten = bytesWritten;
    }
}
