package io.github.chains_project.theo.monitor.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

import java.util.List;

@JsonTypeInfo(
        use = JsonTypeInfo.Id.NAME,
        property = "type"
)
@JsonSubTypes({
        @JsonSubTypes.Type(value = ClassLoad.class, name = "classLoad"),
        @JsonSubTypes.Type(value = Deserialization.class, name = "deserialization"),
        @JsonSubTypes.Type(value = FileForce.class, name = "fileForce"),
        @JsonSubTypes.Type(value = FileRead.class, name = "fileRead"),
        @JsonSubTypes.Type(value = FileWrite.class, name = "fileWrite"),
        @JsonSubTypes.Type(value = NativeLibrary.class, name = "nativeLibrary"),
        @JsonSubTypes.Type(value = NetworkUtilization.class, name = "networkUtilization"),
        @JsonSubTypes.Type(value = ProcessStart.class, name = "processStart"),
        @JsonSubTypes.Type(value = ReservedStackActivation.class, name = "reservedStackActivation"),
        @JsonSubTypes.Type(value = SecurityPropertyModification.class, name = "securityPropertyModification"),
        @JsonSubTypes.Type(value = SocketRead.class, name = "SocketRead"),
        @JsonSubTypes.Type(value = SocketWrite.class, name = "socketWrite"),
        @JsonSubTypes.Type(value = SystemProcess.class, name = "systemProcess"),
        @JsonSubTypes.Type(value = ThreadStart.class, name = "threadStart"),
        @JsonSubTypes.Type(value = TLSHandshake.class, name = "TLSHandshake"),
})
public abstract class AbstractCategory {
    private final String method;
    private final String className;
    private final List<SubMethod> calledBy;

    /**
     * Creates a new AbstractCategory object that stores information about jfr events.
     *
     * @param method    the method which called the event
     * @param className the classname of the method
     * @param calledBy  the stacktrace of the event
     */
    @JsonCreator
    AbstractCategory(@JsonProperty("method") String method,
                     @JsonProperty("className") String className,
                     @JsonProperty("calledBy") List<SubMethod> calledBy) {
        this.method = method;
        this.className = className;
        this.calledBy = calledBy;
    }

    public String getMethod() {
        return method;
    }

    public String getClassName() {
        return className;
    }

    public List<SubMethod> getCalledBy() {
        return calledBy;
    }


    @Override
    public String toString() {
        return ("Category{method = %s, className = %s, calledBy = %s}")
                .formatted(method, className, calledBy.toString());
    }

    public static class SubMethod {
        private final String dependency;
        private List<String> methods;

        /**
         * Creates a new SubMethod object that is a record of methods in the stacktrace.
         *
         * @param dependency the package name of the observed method
         * @param methods    methods recorded with the pattern classname.methodname for each dependency
         */
        @JsonCreator
        public SubMethod(@JsonProperty("dependency") String dependency,
                         @JsonProperty("methods") List<String> methods) {
            this.dependency = dependency;
            this.methods = methods;
        }

        /**
         * Gets the name of the package
         *
         * @return the dependency id
         */
        public Object getDependency() {
            return dependency;
        }

        public List<String> getMethods() {
            return methods;
        }

        public void setMethods(List<String> methods) {
            this.methods = methods;
        }

        @Override
        public String toString() {
            return ("SubMethod{dependency = %s, methods = %s}")
                    .formatted(dependency, methods);
        }
    }
}
