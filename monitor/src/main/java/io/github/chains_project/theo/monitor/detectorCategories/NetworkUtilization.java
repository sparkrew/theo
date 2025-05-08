package io.github.chains_project.theo.monitor.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class NetworkUtilization extends AbstractCategory {

    public final String readRate;
    public final String writeRate;
    public final String networkInterface;

    /**
     * Creates a new NetworkUtilization object that stores information about network utilization.
     *
     * @param method           the method which caused network utilization
     * @param className        the class of the method
     * @param calledBy         the methods which called the respective method as found in the stacktrace
     * @param readRate         number of incoming bits per second
     * @param writeRate        number of outgoing bits per second
     * @param networkInterface network interface name
     */
    @JsonCreator
    NetworkUtilization(@JsonProperty("method") String method,
                       @JsonProperty("className") String className,
                       @JsonProperty("calledBy") List<SubMethod> calledBy,
                       @JsonProperty("readRate") String readRate,
                       @JsonProperty("writeRate") String writeRate,
                       @JsonProperty("networkInterface") String networkInterface) {
        super(method, className, calledBy);
        this.readRate = readRate;
        this.writeRate = writeRate;
        this.networkInterface = networkInterface;
    }
}
