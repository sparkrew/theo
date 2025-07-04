package io.github.chains_project.theo.theo_commons;

/**
 * Represents a method descriptor containing class name, method name, category and subcategory.
 * This is used to define sensitive APIs in the JSON resource.
 */
public record SensitiveAPIDescriptor(String className, String method, String category, String subcategory) {

    /**
     * Creates a new SensitiveAPIDescriptor object.
     *
     * @param className   the name of the class containing the method
     * @param method      the name of the method
     * @param category    the category of the sensitive API
     * @param subcategory the subcategory of the sensitive API
     */
    public SensitiveAPIDescriptor {
        // Constructor body can be empty as all fields are final and initialized in the record header.
    }
}
