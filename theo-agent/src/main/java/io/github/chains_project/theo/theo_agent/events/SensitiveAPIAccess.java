package io.github.chains_project.theo.theo_agent.events;

import jdk.jfr.Event;
import jdk.jfr.Label;
import jdk.jfr.Name;
import jdk.jfr.StackTrace;

@Name("theo.SensitiveAPIAccess")
@Label("Sensitive API Access")
@StackTrace(true)
public class SensitiveAPIAccess extends Event {
    @Label("API Category")
    public String apiCategory;

    @Label("API Subcategory")
    public String apiSubcategory;

    @Label("Method Name")
    public String methodName;

    @Label("Class Name")
    public String className;

    @Label("Parameters")
    public String parameters;
}
