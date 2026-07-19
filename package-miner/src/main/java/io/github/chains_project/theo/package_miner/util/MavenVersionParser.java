package io.github.chains_project.theo.package_miner.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MavenVersionParser {

    private static final Pattern VERSION_PATTERN = Pattern.compile(
            "^v?(\\d+)(?:\\.(\\d+))?(?:\\.(\\d+))?(?:[.\\-](.+))?$"
    );

    private static final Pattern IGNORABLE_QUALIFIER = Pattern.compile(
            "(?i)^(final|release|ga|jre|android)$"
    );

    public record ParsedVersion(String raw, int major, int minor, int patch, String qualifier)
            implements Comparable<ParsedVersion> {

        @Override
        public int compareTo(ParsedVersion other) {
            int c = Integer.compare(this.major, other.major);
            if (c != 0) return c;
            c = Integer.compare(this.minor, other.minor);
            if (c != 0) return c;
            c = Integer.compare(this.patch, other.patch);
            if (c != 0) return c;
            if (this.qualifier == null && other.qualifier == null) return 0;
            if (this.qualifier == null) return -1;
            if (other.qualifier == null) return 1;
            return this.qualifier.compareTo(other.qualifier);
        }
    }

    public static ParsedVersion parse(String version) {
        if (version == null || version.isBlank()) {
            return new ParsedVersion(version, 0, 0, 0, null);
        }

        Matcher m = VERSION_PATTERN.matcher(version.trim());
        if (!m.matches()) {
            return new ParsedVersion(version, 0, 0, 0, version);
        }

        int major = Integer.parseInt(m.group(1));
        int minor = m.group(2) != null ? Integer.parseInt(m.group(2)) : 0;
        int patch = m.group(3) != null ? Integer.parseInt(m.group(3)) : 0;
        String qualifier = m.group(4);

        if (qualifier != null && IGNORABLE_QUALIFIER.matcher(qualifier).matches()) {
            qualifier = null;
        }

        return new ParsedVersion(version, major, minor, patch, qualifier);
    }
}
