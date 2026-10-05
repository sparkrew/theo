package io.github.chains_project.theo.theo_test_exec.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class SecurityPropertyModification extends AbstractCategory {

    public final String key;
    public final String value;

    /**
     * Creates a new SecurityPropertyModification object indicating the modification of Security property.
     *
     * @param key          the key of the security property modified
     * @param value        the value of the security property modified
     */
    @JsonCreator
    SecurityPropertyModification(@JsonProperty("key") String key,
                                 @JsonProperty("value") String value) {
        super();
        this.key = key;
        this.value = value;
    }
}
