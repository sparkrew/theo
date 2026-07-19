package io.github.chains_project.theo.package_miner;

import io.github.chains_project.theo.package_miner.util.MavenVersionParser;
import io.github.chains_project.theo.package_miner.util.MavenVersionParser.ParsedVersion;
import io.github.chains_project.theo.package_miner.util.ReleaseLineGrouper;
import io.github.chains_project.theo.package_miner.util.ReleaseLineGrouper.*;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ReleaseLineGrouperTest {

    @Test
    void groupsByMajorVersion() {
        List<ParsedVersion> versions = parseAll("1.0.0", "1.1.0", "2.0.0", "2.1.0", "3.0.0");
        List<ReleaseLine> lines = ReleaseLineGrouper.group(versions);

        assertEquals(3, lines.size());
        assertEquals(1, lines.get(0).major());
        assertEquals(2, lines.get(0).versions().size());
        assertEquals(2, lines.get(1).major());
        assertEquals(2, lines.get(1).versions().size());
        assertEquals(3, lines.get(2).major());
        assertEquals(1, lines.get(2).versions().size());
    }

    @Test
    void sortsWithinLine() {
        List<ParsedVersion> versions = parseAll("2.3.0", "2.1.0", "2.2.0");
        List<ReleaseLine> lines = ReleaseLineGrouper.group(versions);

        assertEquals(1, lines.size());
        assertEquals("2.1.0", lines.get(0).versions().get(0).raw());
        assertEquals("2.2.0", lines.get(0).versions().get(1).raw());
        assertEquals("2.3.0", lines.get(0).versions().get(2).raw());
    }

    @Test
    void withinLinePairs() {
        List<ParsedVersion> versions = parseAll("1.0.0", "1.1.0", "1.2.0");
        List<ReleaseLine> lines = ReleaseLineGrouper.group(versions);
        List<ComparisonPair> pairs = ReleaseLineGrouper.buildComparisonPairs(lines);

        assertEquals(2, pairs.size());
        assertEquals("1.0.0", pairs.get(0).fromVersion());
        assertEquals("1.1.0", pairs.get(0).toVersion());
        assertEquals(ComparisonType.NON_MAJOR, pairs.get(0).type());
        assertEquals("1.1.0", pairs.get(1).fromVersion());
        assertEquals("1.2.0", pairs.get(1).toVersion());
    }

    @Test
    void crossLinePairs() {
        List<ParsedVersion> versions = parseAll("1.0.0", "1.1.0", "2.0.0", "2.1.0");
        List<ReleaseLine> lines = ReleaseLineGrouper.group(versions);
        List<ComparisonPair> pairs = ReleaseLineGrouper.buildComparisonPairs(lines);

        assertEquals(3, pairs.size());
        // within line 1
        assertEquals("1.0.0", pairs.get(0).fromVersion());
        assertEquals("1.1.0", pairs.get(0).toVersion());
        assertEquals(ComparisonType.NON_MAJOR, pairs.get(0).type());
        // cross line
        assertEquals("1.1.0", pairs.get(1).fromVersion());
        assertEquals("2.0.0", pairs.get(1).toVersion());
        assertEquals(ComparisonType.CROSS_LINE, pairs.get(1).type());
        // within line 2
        assertEquals("2.0.0", pairs.get(2).fromVersion());
        assertEquals("2.1.0", pairs.get(2).toVersion());
        assertEquals(ComparisonType.NON_MAJOR, pairs.get(2).type());
    }

    @Test
    void parallelReleaseLinesHandledCorrectly() {
        // Simulates: 2.13.3, 3.0.0, 3.0.1, 2.13.4 (backport after 3.x)
        List<ParsedVersion> versions = parseAll("2.13.3", "3.0.0", "3.0.1", "2.13.4");
        List<ReleaseLine> lines = ReleaseLineGrouper.group(versions);
        List<ComparisonPair> pairs = ReleaseLineGrouper.buildComparisonPairs(lines);

        assertEquals(2, lines.size());
        // Line 2.x sorted
        assertEquals("2.13.3", lines.get(0).versions().get(0).raw());
        assertEquals("2.13.4", lines.get(0).versions().get(1).raw());
        // Line 3.x sorted
        assertEquals("3.0.0", lines.get(1).versions().get(0).raw());
        assertEquals("3.0.1", lines.get(1).versions().get(1).raw());

        // Pairs: 2.13.3→2.13.4, 2.13.4→3.0.0 (cross), 3.0.0→3.0.1
        assertEquals(3, pairs.size());
        assertEquals("2.13.3", pairs.get(0).fromVersion());
        assertEquals("2.13.4", pairs.get(0).toVersion());
        assertEquals(ComparisonType.NON_MAJOR, pairs.get(0).type());

        assertEquals("2.13.4", pairs.get(1).fromVersion());
        assertEquals("3.0.0", pairs.get(1).toVersion());
        assertEquals(ComparisonType.CROSS_LINE, pairs.get(1).type());

        assertEquals("3.0.0", pairs.get(2).fromVersion());
        assertEquals("3.0.1", pairs.get(2).toVersion());
        assertEquals(ComparisonType.NON_MAJOR, pairs.get(2).type());
    }

    @Test
    void singleVersionInLine() {
        List<ParsedVersion> versions = parseAll("1.0.0", "2.0.0");
        List<ReleaseLine> lines = ReleaseLineGrouper.group(versions);
        List<ComparisonPair> pairs = ReleaseLineGrouper.buildComparisonPairs(lines);

        assertEquals(1, pairs.size());
        assertEquals(ComparisonType.CROSS_LINE, pairs.get(0).type());
    }

    @Test
    void orderedVersionsFlattensCorrectly() {
        List<ParsedVersion> versions = parseAll("3.0.0", "1.0.0", "2.0.0", "1.1.0");
        List<ReleaseLine> lines = ReleaseLineGrouper.group(versions);
        List<ParsedVersion> ordered = ReleaseLineGrouper.orderedVersions(lines);

        assertEquals("1.0.0", ordered.get(0).raw());
        assertEquals("1.1.0", ordered.get(1).raw());
        assertEquals("2.0.0", ordered.get(2).raw());
        assertEquals("3.0.0", ordered.get(3).raw());
    }

    private List<ParsedVersion> parseAll(String... versions) {
        List<ParsedVersion> result = new ArrayList<>();
        for (String v : versions) {
            result.add(MavenVersionParser.parse(v));
        }
        return result;
    }
}
