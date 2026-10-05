package io.github.chains_project.theo.theo_test_exec.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * This class represents a custom API access category for the Theo detector.
 * It includes the API category, subcategory, and any additional parameters.
 */
public class CustomAPIAccess extends AbstractCategory {
    public final String apiCategory;
    public final String apiSubcategory;
    public final String parameters;

    @JsonCreator
    public CustomAPIAccess(@JsonProperty("apiCategory") String apiCategory,
                           @JsonProperty("apiSubcategory") String apiSubcategory,
                           @JsonProperty("parameters") String parameters) {
        super();
        this.apiCategory = apiCategory;
        this.apiSubcategory = apiSubcategory;
        this.parameters = parameters;
    }
}
