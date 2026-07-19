package io.github.chains_project.theo.package_miner;

import io.github.chains_project.theo.package_miner.util.MavenVersionParser;
import io.github.chains_project.theo.package_miner.util.MavenVersionParser.ParsedVersion;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MavenVersionParserTest {

    @Test
    void parsesStandardSemver() {
        ParsedVersion v = MavenVersionParser.parse("2.13.4");
        assertEquals(2, v.major());
        assertEquals(13, v.minor());
        assertEquals(4, v.patch());
        assertNull(v.qualifier());
    }

    @Test
    void parsesTwoSegments() {
        ParsedVersion v = MavenVersionParser.parse("3.5");
        assertEquals(3, v.major());
        assertEquals(5, v.minor());
        assertEquals(0, v.patch());
        assertNull(v.qualifier());
    }

    @Test
    void stripsIgnorableQualifiers() {
        assertNull(MavenVersionParser.parse("1.0.0-final").qualifier());
        assertNull(MavenVersionParser.parse("2.3.1-RELEASE").qualifier());
        assertNull(MavenVersionParser.parse("4.1.131.Final").qualifier());
        assertNull(MavenVersionParser.parse("31.1-jre").qualifier());
        assertNull(MavenVersionParser.parse("1.0.0-GA").qualifier());
    }

    @Test
    void preservesNonIgnorableQualifiers() {
        assertEquals("sp1", MavenVersionParser.parse("1.0.0-sp1").qualifier());
    }

    @Test
    void stripsLeadingV() {
        ParsedVersion v = MavenVersionParser.parse("v2.0.1");
        assertEquals(2, v.major());
        assertEquals(0, v.minor());
        assertEquals(1, v.patch());
    }

    @Test
    void comparesCorrectly() {
        ParsedVersion v1 = MavenVersionParser.parse("2.13.3");
        ParsedVersion v2 = MavenVersionParser.parse("2.13.4");
        ParsedVersion v3 = MavenVersionParser.parse("3.0.0");

        assertTrue(v1.compareTo(v2) < 0);
        assertTrue(v2.compareTo(v3) < 0);
        assertTrue(v1.compareTo(v3) < 0);
    }

    @Test
    void equalVersionsCompareToZero() {
        ParsedVersion a = MavenVersionParser.parse("1.2.3");
        ParsedVersion b = MavenVersionParser.parse("1.2.3");
        assertEquals(0, a.compareTo(b));
    }

    @Test
    void qualifierlessComesBeforeQualifier() {
        ParsedVersion a = MavenVersionParser.parse("1.0.0");
        ParsedVersion b = MavenVersionParser.parse("1.0.0-sp1");
        assertTrue(a.compareTo(b) < 0);
    }

    @Test
    void handlesLargeNumbers() {
        ParsedVersion v = MavenVersionParser.parse("4.1.131.Final");
        assertEquals(4, v.major());
        assertEquals(1, v.minor());
        assertEquals(131, v.patch());
    }

    @Test
    void preservesRawString() {
        ParsedVersion v = MavenVersionParser.parse("4.1.131.Final");
        assertEquals("4.1.131.Final", v.raw());
    }
}
