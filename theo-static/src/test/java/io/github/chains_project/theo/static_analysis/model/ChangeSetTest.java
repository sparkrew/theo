package io.github.chains_project.theo.static_analysis.model;

import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ChangeSetTest {

    @Test
    void hasChangesReturnsFalseWhenAllListsEmpty() {
        ChangeSet cs = new ChangeSet(
                Collections.emptyList(),
                Collections.emptyList(),
                Collections.emptyList(),
                true);
        assertFalse(cs.hasChanges());
    }

    @Test
    void hasChangesReturnsTrueWhenAddedIsNonEmpty() {
        DependencyReport added = new DependencyReport(
                "g", "a", "1.0", "jar", null, 0, 0L);
        ChangeSet cs = new ChangeSet(
                List.of(added),
                Collections.emptyList(),
                Collections.emptyList(),
                true);
        assertTrue(cs.hasChanges());
    }

    @Test
    void hasChangesReturnsTrueWhenRemovedIsNonEmpty() {
        DependencyReport removed = new DependencyReport(
                "g", "a", "1.0", "jar", null, 0, 0L);
        ChangeSet cs = new ChangeSet(
                Collections.emptyList(),
                List.of(removed),
                Collections.emptyList(),
                true);
        assertTrue(cs.hasChanges());
    }

    @Test
    void hasChangesReturnsTrueWhenModifiedIsNonEmpty() {
        ChangeSet.DependencyChange change = new ChangeSet.DependencyChange(
                "g", "a", "1.0", "2.0",
                Collections.emptyList(), Collections.emptyList());
        ChangeSet cs = new ChangeSet(
                Collections.emptyList(),
                Collections.emptyList(),
                List.of(change),
                true);
        assertTrue(cs.hasChanges());
    }

    @Test
    void totalChangesSumsAllLists() {
        DependencyReport dep1 = new DependencyReport(
                "g1", "a1", "1.0", "jar", null, 0, 0L);
        DependencyReport dep2 = new DependencyReport(
                "g2", "a2", "1.0", "jar", null, 0, 0L);
        ChangeSet.DependencyChange change = new ChangeSet.DependencyChange(
                "g3", "a3", "1.0", "2.0",
                Collections.emptyList(), Collections.emptyList());

        ChangeSet cs = new ChangeSet(
                List.of(dep1),
                List.of(dep2),
                List.of(change),
                true);
        assertEquals(3, cs.totalChanges());
    }

    @Test
    void hasPreviousRunReturnsConstructorValue() {
        ChangeSet withPrevious = new ChangeSet(
                Collections.emptyList(), Collections.emptyList(),
                Collections.emptyList(), true);
        assertTrue(withPrevious.hasPreviousRun());

        ChangeSet withoutPrevious = new ChangeSet(
                Collections.emptyList(), Collections.emptyList(),
                Collections.emptyList(), false);
        assertFalse(withoutPrevious.hasPreviousRun());
    }

    @Test
    void dependencyChangeGavReturnsCorrectFormat() {
        ChangeSet.DependencyChange change = new ChangeSet.DependencyChange(
                "com.example", "my-lib", "1.0.0", "2.0.0",
                Collections.emptyList(), Collections.emptyList());
        assertEquals("com.example:my-lib:2.0.0", change.gav());
    }
}
