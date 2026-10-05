package io.github.chains_project.theo.theo_test_exec.detectorCategories;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;

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

    /**
     * Creates a new AbstractCategory object that stores information about jfr events.
     */
    @JsonCreator
    AbstractCategory() {

    }
}
