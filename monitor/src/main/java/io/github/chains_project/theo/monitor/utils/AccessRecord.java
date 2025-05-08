package io.github.chains_project.theo.monitor.utils;

import io.github.chains_project.theo.monitor.detectorCategories.AbstractCategory;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record AccessRecord(String dependency, List<DetectorEvent> records) {
    /**
     * Creates a new AccessRecord object that is a record of all resource accesses for a specific dependency.
     *
     * @param dependency the dependency
     * @param records    a list of runtime accesses
     */
    @JsonCreator
    public AccessRecord(@JsonProperty("dependency") String dependency,
                        @JsonProperty("records") List<DetectorEvent> records) {
        this.dependency = dependency;
        this.records = records;
    }

    /**
     * Gets the list of the runtime access records from the AccessRecord.
     */
    @Override
    public List<DetectorEvent> records() {
        return records;
    }

    /**
     * Gets the name of the dependency that the AccessRecord belongs to.
     */
    @Override
    public String dependency() {
        return dependency;
    }

    @Override
    public String toString() {
        return ("AccessRecord{dependency = %s, records = %s}")
                .formatted(dependency, records.toString());
    }

    public record DetectorEvent(String detectorCategory, List<AbstractCategory> events) {
        /**
         * Creates a new DetectorEvent object that is a record of specific resource access.
         *
         * @param detectorCategory event category name
         * @param events           a list of detector category objects for the specific event
         *                         and for the specific method with information on runtime accesses
         */
        @JsonCreator
        public DetectorEvent(@JsonProperty("detectorCategory") String detectorCategory,
                             @JsonProperty("accesses") List<AbstractCategory> events) {
            this.detectorCategory = detectorCategory;
            this.events = events;
        }

        @Override
        public String toString() {
            return ("DetectorEvent{detectorCategory = %s, events = %s}")
                    .formatted(detectorCategory, events.toString());
        }
    }
}
