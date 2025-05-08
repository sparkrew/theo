package io.github.chains_project.theo.monitor.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class ClassLoad extends AbstractCategory {

    public final String loadedClass;
    public final String definingClassLoader;
    public final String initiatingClassLoader;

    /**
     * Creates a new ClassLoad object that stores information about a
     * classloading event.
     *
     * @param method                the method which executed a classload
     * @param className             the class of the method
     * @param calledBy              the methods which called the respective method as found in the stacktrace
     * @param loadedClass           the loaded class captured by the jfr
     * @param definingClassLoader   the class loader which defined the loaded class
     * @param initiatingClassLoader the class loader which initiated the loaded class
     */
    @JsonCreator
    ClassLoad(@JsonProperty("method") String method,
              @JsonProperty("className") String className,
              @JsonProperty("calledBy") List<SubMethod> calledBy,
              @JsonProperty("loadedClass") String loadedClass,
              @JsonProperty("definingClassLoader") String definingClassLoader,
              @JsonProperty("initiatingClassLoader") String initiatingClassLoader) {
        super(method, className, calledBy);
        this.loadedClass = loadedClass;
        this.definingClassLoader = definingClassLoader;
        this.initiatingClassLoader = initiatingClassLoader;
    }
}
