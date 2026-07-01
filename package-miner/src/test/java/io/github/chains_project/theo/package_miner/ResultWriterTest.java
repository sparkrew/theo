package io.github.chains_project.theo.package_miner;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class ResultWriterTest {

    private static final List<String> API_KEYS = List.of(
            "java.io.FileInputStream.<init>",
            "java.lang.Class.forName",
            "java.net.Socket.<init>"
    );

    @Test
    void headerContainsAllApiColumns(@TempDir Path tempDir) throws IOException {
        ResultWriter writer = new ResultWriter(tempDir, API_KEYS);
        writer.writeHeader();

        String csv = Files.readString(tempDir.resolve("sensitive_api_usage.csv"));
        String[] headerCols = csv.split("\n")[0].split(",");

        assertEquals("groupId", headerCols[0]);
        assertEquals("artifactId", headerCols[1]);
        assertEquals("version", headerCols[2]);
        assertEquals("scmUrl", headerCols[3]);
        assertEquals("java.io.FileInputStream.<init>", headerCols[4]);
        assertEquals("java.lang.Class.forName", headerCols[5]);
        assertEquals("java.net.Socket.<init>", headerCols[6]);
    }

    @Test
    void appendResultWritesTrueFalseCorrectly(@TempDir Path tempDir) throws IOException {
        ResultWriter writer = new ResultWriter(tempDir, API_KEYS);
        writer.writeHeader();

        PackageInfo pkg = new PackageInfo("com.example", "mylib", "1.0", 500);
        writer.appendResult(pkg, Set.of("java.lang.Class.forName"));

        List<String> lines = Files.readAllLines(tempDir.resolve("sensitive_api_usage.csv"));
        assertEquals(2, lines.size());

        String[] cols = lines.get(1).split(",");
        assertEquals("com.example", cols[0]);
        assertEquals("mylib", cols[1]);
        assertEquals("1.0", cols[2]);
        // cols[3] = scmUrl (empty)
        assertEquals("False", cols[4]);
        assertEquals("True", cols[5]);
        assertEquals("False", cols[6]);
    }

    @Test
    void appendMultipleRows(@TempDir Path tempDir) throws IOException {
        ResultWriter writer = new ResultWriter(tempDir, API_KEYS);
        writer.writeHeader();

        writer.appendResult(new PackageInfo("a", "b", "1.0", 0),
                Set.of("java.io.FileInputStream.<init>", "java.net.Socket.<init>"));
        writer.appendResult(new PackageInfo("c", "d", "2.0", 0),
                Set.of());

        List<String> lines = Files.readAllLines(tempDir.resolve("sensitive_api_usage.csv"));
        assertEquals(3, lines.size());

        String[] row1 = lines.get(1).split(",");
        assertEquals("True", row1[4]);
        assertEquals("False", row1[5]);
        assertEquals("True", row1[6]);

        String[] row2 = lines.get(2).split(",");
        assertEquals("False", row2[4]);
        assertEquals("False", row2[5]);
        assertEquals("False", row2[6]);
    }

    @Test
    void escapesCommasInValues(@TempDir Path tempDir) throws IOException {
        ResultWriter writer = new ResultWriter(tempDir, API_KEYS);
        writer.writeHeader();

        writer.appendResult(new PackageInfo("com.example", "my,lib", "1.0", 0), Set.of());

        String csv = Files.readString(tempDir.resolve("sensitive_api_usage.csv"));
        String dataLine = csv.split("\n")[1];
        assertTrue(dataLine.contains("\"my,lib\""));
    }
}
