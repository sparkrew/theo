package io.github.chains_project.theo.theo_test_exec.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class NetworkUtilization extends AbstractCategory {

    public final String readRate;
    public final String writeRate;
    public final String networkInterface;

    /**
     * Creates a new NetworkUtilization object that stores information about network utilization.
     *
     * @param readRate         number of incoming bits per second
     * @param writeRate        number of outgoing bits per second
     * @param networkInterface network interface name
     */
    @JsonCreator
    NetworkUtilization(@JsonProperty("readRate") String readRate,
                       @JsonProperty("writeRate") String writeRate,
                       @JsonProperty("networkInterface") String networkInterface) {
        super();
        this.readRate = readRate;
        this.writeRate = writeRate;
        this.networkInterface = networkInterface;
    }
}
