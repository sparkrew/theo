package io.github.chains_project.theo.theo_commons;

/**
 * Represents a third-party API descriptor.
 * This is used to define third-party APIs in the JSON resource.
 */
public record ThirdPartyAPIDescriptor(String className, String method) {
    /**
     * Creates a new ThirdPartyAPIDescriptor object.
     *
     * @param className the name of the class containing the method
     * @param method    the name of the method
     */
    public ThirdPartyAPIDescriptor {
        // Constructor body can be empty as all fields are final and initialized in the record header.
    }
}
