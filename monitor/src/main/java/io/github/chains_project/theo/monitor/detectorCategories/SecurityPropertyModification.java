package io.github.chains_project.theo.monitor.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class SecurityPropertyModification extends AbstractCategory {

    public final String key;
    public final String value;

    /**
     * Creates a new SecurityPropertyModification object indicating the modification of Security property.
     *
     * @param method    the method which executed modified a security property
     * @param className the class of the method
     * @param calledBy  the methods which called the respective method as found in the stacktrace
     * @param key       the key of the security property modified
     * @param value     the value of the security property modified
     */
    @JsonCreator
    SecurityPropertyModification(@JsonProperty("method") String method,
                                 @JsonProperty("className") String className,
                                 @JsonProperty("calledBy") List<SubMethod> calledBy,
                                 @JsonProperty("key") String key,
                                 @JsonProperty("value") String value) {
        super(method, className, calledBy);
        this.key = key;
        this.value = value;
    }
}
