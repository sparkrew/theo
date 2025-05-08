package io.github.chains_project.theo.monitor.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class SocketRead extends AbstractCategory {

    public final String host;
    public final String address;
    public final String port;
    public final String bytesRead;
    public final String endOfStream;

    /**
     * Creates a new SocketRead object that stores information about reading data from a socket.
     *
     * @param method      the method which executed a socket read
     * @param className   the class of the method
     * @param calledBy    the methods which called the respective method as found in the stacktrace
     * @param host        host
     * @param address     network address
     * @param port        port number
     * @param bytesRead   number of bytes read from the socket
     * @param endOfStream whether the  endOfStream is reached
     */
    @JsonCreator
    SocketRead(@JsonProperty("method") String method,
               @JsonProperty("className") String className,
               @JsonProperty("calledBy") List<SubMethod> calledBy,
               @JsonProperty("host") String host,
               @JsonProperty("address") String address,
               @JsonProperty("port") String port,
               @JsonProperty("bytesRead") String bytesRead,
               @JsonProperty("endOfStream") String endOfStream) {
        super(method, className, calledBy);
        this.host = host;
        this.address = address;
        this.port = port;
        this.bytesRead = bytesRead;
        this.endOfStream = endOfStream;
    }
}
