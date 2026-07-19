package io.github.chains_project.theo.package_miner.util;

import java.util.*;
import java.util.stream.Collectors;

public class ReleaseLineGrouper {

    public record ReleaseLine(int major, List<MavenVersionParser.ParsedVersion> versions) {}

    public record ComparisonPair(String fromVersion, String toVersion, ComparisonType type) {}

    public enum ComparisonType { WITHIN_LINE, CROSS_LINE }

    public static List<ReleaseLine> group(List<MavenVersionParser.ParsedVersion> versions) {
        Map<Integer, List<MavenVersionParser.ParsedVersion>> grouped = versions.stream()
                .collect(Collectors.groupingBy(MavenVersionParser.ParsedVersion::major));

        List<ReleaseLine> lines = new ArrayList<>();
        for (var entry : grouped.entrySet()) {
            List<MavenVersionParser.ParsedVersion> sorted = new ArrayList<>(entry.getValue());
            sorted.sort(Comparator.naturalOrder());
            lines.add(new ReleaseLine(entry.getKey(), sorted));
        }

        lines.sort(Comparator.comparingInt(ReleaseLine::major));
        return lines;
    }

    public static List<ComparisonPair> buildComparisonPairs(List<ReleaseLine> lines) {
        List<ComparisonPair> pairs = new ArrayList<>();

        for (int i = 0; i < lines.size(); i++) {
            ReleaseLine line = lines.get(i);
            List<MavenVersionParser.ParsedVersion> versions = line.versions();

            for (int j = 1; j < versions.size(); j++) {
                pairs.add(new ComparisonPair(
                        versions.get(j - 1).raw(),
                        versions.get(j).raw(),
                        ComparisonType.WITHIN_LINE));
            }

            if (i + 1 < lines.size()) {
                ReleaseLine nextLine = lines.get(i + 1);
                pairs.add(new ComparisonPair(
                        versions.get(versions.size() - 1).raw(),
                        nextLine.versions().get(0).raw(),
                        ComparisonType.CROSS_LINE));
            }
        }

        return pairs;
    }

    public static List<MavenVersionParser.ParsedVersion> orderedVersions(List<ReleaseLine> lines) {
        List<MavenVersionParser.ParsedVersion> ordered = new ArrayList<>();
        for (ReleaseLine line : lines) {
            ordered.addAll(line.versions());
        }
        return ordered;
    }
}
