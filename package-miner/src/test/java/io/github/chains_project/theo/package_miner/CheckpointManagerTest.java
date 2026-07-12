package io.github.chains_project.theo.package_miner;

import io.github.chains_project.theo.package_miner.model.PackageInfo;
import io.github.chains_project.theo.package_miner.util.CheckpointManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CheckpointManagerTest {

    @Test
    void freshStartHasNoCompletedPackages(@TempDir Path tempDir) {
        CheckpointManager cm = new CheckpointManager(tempDir);

        assertEquals(0, cm.completedCount());
        assertFalse(cm.isCompleted(pkg("com.example", "lib", "1.0")));
    }

    @Test
    void markCompletedAndCheck(@TempDir Path tempDir) {
        CheckpointManager cm = new CheckpointManager(tempDir);
        PackageInfo pkg = pkg("com.example", "lib", "1.0");

        cm.markCompleted(pkg);

        assertTrue(cm.isCompleted(pkg));
        assertEquals(1, cm.completedCount());
    }

    @Test
    void persistsAcrossInstances(@TempDir Path tempDir) {
        PackageInfo pkg1 = pkg("com.example", "lib-a", "1.0");
        PackageInfo pkg2 = pkg("com.example", "lib-b", "2.0");

        CheckpointManager cm1 = new CheckpointManager(tempDir);
        cm1.markCompleted(pkg1);
        cm1.markCompleted(pkg2);

        CheckpointManager cm2 = new CheckpointManager(tempDir);

        assertTrue(cm2.isCompleted(pkg1));
        assertTrue(cm2.isCompleted(pkg2));
        assertEquals(2, cm2.completedCount());
    }

    @Test
    void saveAndLoadPackageList(@TempDir Path tempDir) {
        CheckpointManager cm = new CheckpointManager(tempDir);

        assertNull(cm.loadPackageList(), "No list saved yet, should return null");

        List<PackageInfo> packages = List.of(
                pkg("com.google.guava", "guava", "32.1.3-jre"),
                pkg("org.slf4j", "slf4j-api", "2.0.16")
        );
        cm.savePackageList(packages);

        List<PackageInfo> loaded = cm.loadPackageList();
        assertNotNull(loaded);
        assertEquals(2, loaded.size());
        assertEquals("com.google.guava", loaded.get(0).groupId());
        assertEquals("guava", loaded.get(0).artifactId());
        assertEquals("32.1.3-jre", loaded.get(0).latestVersion());
    }

    @Test
    void packageListPersistsAcrossInstances(@TempDir Path tempDir) {
        CheckpointManager cm1 = new CheckpointManager(tempDir);
        cm1.savePackageList(List.of(pkg("a", "b", "1.0")));

        CheckpointManager cm2 = new CheckpointManager(tempDir);
        List<PackageInfo> loaded = cm2.loadPackageList();

        assertNotNull(loaded);
        assertEquals(1, loaded.size());
        assertEquals("a:b:1.0", loaded.get(0).coordinate());
    }

    @Test
    void duplicateMarkCompletedDoesNotIncreaseCount(@TempDir Path tempDir) {
        CheckpointManager cm = new CheckpointManager(tempDir);
        PackageInfo pkg = pkg("com.example", "lib", "1.0");

        cm.markCompleted(pkg);
        cm.markCompleted(pkg);
        cm.markCompleted(pkg);

        assertEquals(1, cm.completedCount());
    }

    private PackageInfo pkg(String groupId, String artifactId, String version) {
        return new PackageInfo(groupId, artifactId, version, 0);
    }
}
