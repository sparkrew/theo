#!/usr/bin/env python3
"""
Retroactively reclassify root-cause attributions in existing changes.html reports.

Fixes INDIRECT_DEP_INITIATED badges that should be UNKNOWN_INITIATION:
  - DIRECT access entries should never be INDIRECT_DEP_INITIATED
  - INDIRECT access entries where no transitive dep changed version should be
    UNKNOWN_INITIATION

Uses snapshot pairs to determine which deps changed version between runs.

Usage:
    python3 reclassify_attributions.py <project_name> [--dry-run]

Example:
    python3 reclassify_attributions.py apache_avro --dry-run
    python3 reclassify_attributions.py apache_avro
"""

import argparse
import json
import re
import sys
from pathlib import Path

REPORTS_BASE = Path("/scratch/yogya/client-results/history")
THEO_HISTORY = Path("/scratch/yogya/client-results/theo-history-snapshots")

# Badge patterns in HTML
INDIRECT_DEP_BADGE = '<span class="root-cause indirect-dep-initiated">Indirect Dep Initiated</span>'
UNKNOWN_BADGE = '<span class="root-cause unknown-initiation">Unknown Initiation</span>'
UNKNOWN_CSS = '        .root-cause.unknown-initiation { background: #f3f4f6; color: #4b5563; }'

# Regex to find INDIRECT_DEP_INITIATED badges with surrounding context
# The badge appears after a sensitive API summary line, near access type info
BADGE_PATTERN = re.compile(
    r'(<span class="root-cause indirect-dep-initiated">Indirect Dep Initiated</span>)'
)

# Pattern to find the access type near a badge — look for DIRECT/INDIRECT in
# the surrounding sensitive-api summary or path-endpoints div
ACCESS_TYPE_PATTERN = re.compile(
    r'<span class="access-type[^"]*">\s*(DIRECT|INDIRECT)\s*</span>'
)


def load_snapshots_for_project(project_name):
    """Load all snapshot files for all modules in a project, grouped by module GA."""
    snapshots_by_module = {}

    if not THEO_HISTORY.exists():
        print(f"Snapshot directory not found: {THEO_HISTORY}")
        return snapshots_by_module

    for module_dir in THEO_HISTORY.iterdir():
        if not module_dir.is_dir():
            continue

        snapshots = []
        for snap_file in module_dir.glob("*.json"):
            try:
                with open(snap_file) as f:
                    snap = json.load(f)
                snapshots.append(snap)
            except (json.JSONDecodeError, OSError):
                continue

        if snapshots:
            snapshots.sort(key=lambda s: s.get("timestamp", 0))
            snapshots_by_module[module_dir.name] = snapshots

    return snapshots_by_module


def build_version_map(snapshot):
    """Build {groupId:artifactId → version} from a snapshot's reachableApis."""
    versions = {}
    for api in snapshot.get("reachableApis", []):
        ga = api.get("depGroupId", "") + ":" + api.get("depArtifactId", "")
        ver = api.get("depVersion", "")
        if ga and ver:
            versions[ga] = ver
    return versions


def has_transitive_dep_change(prev_versions, curr_versions, dep_ga):
    """Check if any dep other than dep_ga changed version."""
    for ga, ver in curr_versions.items():
        if ga == dep_ga:
            continue
        prev_ver = prev_versions.get(ga)
        if prev_ver is not None and prev_ver != ver:
            return True
        if prev_ver is None:
            return True
    for ga in prev_versions:
        if ga != dep_ga and ga not in curr_versions:
            return True
    return False


def build_transitive_change_map(snapshots_by_module):
    """For each snapshot label pair, determine if any transitive dep changed.

    Returns: {label → bool} where True means some transitive dep changed
    between the previous snapshot and this one.
    """
    any_transitive_change = {}

    for module_ga, snapshots in snapshots_by_module.items():
        for i in range(1, len(snapshots)):
            prev = snapshots[i - 1]
            curr = snapshots[i]
            label = curr.get("label", "")

            prev_versions = build_version_map(prev)
            curr_versions = build_version_map(curr)

            # Check per-dep: for each dep in the current snapshot, did any
            # OTHER dep change version?
            for ga in curr_versions:
                if has_transitive_dep_change(prev_versions, curr_versions, ga):
                    any_transitive_change.setdefault(label, {})[ga] = True
                else:
                    any_transitive_change.setdefault(label, {}).setdefault(ga, False)

    return any_transitive_change


def reclassify_changes_html(html_content, transitive_info):
    """Reclassify INDIRECT_DEP_INITIATED badges in a changes.html file.

    Args:
        html_content: the HTML string
        transitive_info: {dep_ga → bool} whether transitive deps changed for
                         each dep. If None, reclassify all DIRECT access entries.

    Returns: (updated_html, count_of_changes)
    """
    changes = 0

    # Strategy: find each INDIRECT_DEP_INITIATED badge, look at surrounding
    # context to determine access type and dep GA, then decide.
    #
    # The HTML structure around a badge is:
    #   <details class="sensitive-api ...">
    #     <summary>api.name <span class="access-type ...">DIRECT</span>
    #       <span class="root-cause indirect-dep-initiated">...</span></summary>
    #   OR the badge is on the dep-level summary line.
    #
    # We split the HTML into chunks around each badge and inspect context.

    parts = html_content.split(INDIRECT_DEP_BADGE)
    if len(parts) <= 1:
        return html_content, 0

    result = [parts[0]]
    for i in range(1, len(parts)):
        # Look at context BEFORE the badge (last ~500 chars of previous part)
        context_before = result[-1][-500:] if len(result[-1]) > 500 else result[-1]

        # Determine access type from context
        access_matches = ACCESS_TYPE_PATTERN.findall(context_before)
        access_type = access_matches[-1] if access_matches else None

        should_reclassify = False

        if access_type == "DIRECT":
            # DIRECT access should never be INDIRECT_DEP_INITIATED
            should_reclassify = True
        elif access_type == "INDIRECT" and transitive_info is not None:
            # INDIRECT access: check if any transitive dep actually changed
            # Try to extract the dep GA from context
            dep_ga = extract_dep_ga_from_context(context_before)
            if dep_ga and dep_ga in transitive_info:
                if not transitive_info[dep_ga]:
                    should_reclassify = True
            elif dep_ga is None:
                # Can't determine dep — conservative, don't reclassify
                pass
        elif access_type is None and transitive_info is not None:
            # No access type found — could be a dep-level badge
            # Check if any transitive dep changed at all
            has_any_change = any(transitive_info.values()) if transitive_info else False
            if not has_any_change:
                should_reclassify = True

        if should_reclassify:
            result.append(UNKNOWN_BADGE)
            changes += 1
        else:
            result.append(INDIRECT_DEP_BADGE)

        result.append(parts[i])

    return "".join(result), changes


def extract_dep_ga_from_context(context):
    """Try to extract the dependency GA from HTML context before a badge.

    Looks for the dep-gav span: <span class="dep-gav">groupId:artifactId:version</span>
    """
    match = re.findall(r'<span class="dep-gav">([^<]+)</span>', context)
    if match:
        gav = match[-1]
        parts = gav.split(":")
        if len(parts) >= 2:
            return parts[0] + ":" + parts[1]
    return None


def ensure_unknown_css(html_content):
    """Add the unknown-initiation CSS rule if not already present."""
    if "unknown-initiation" in html_content:
        return html_content, False

    # Insert after the indirect-dep-initiated CSS rule
    old_css_patterns = [
        '.root-cause.indirect-dep-initiated { background: #fef2f2; color: #dc2626; }',
        '.root-cause.indirect-dep-initiated { background: #f5f3ff; color: #7c3aed; }',
    ]

    for old_css in old_css_patterns:
        if old_css in html_content:
            html_content = html_content.replace(
                old_css,
                old_css + "\n" + UNKNOWN_CSS
            )
            return html_content, True

    return html_content, False


def process_project(project_name, dry_run=False):
    project_dir = REPORTS_BASE / project_name

    if not project_dir.exists():
        print(f"Project directory not found: {project_dir}")
        sys.exit(1)

    tracking_file = project_dir / "analysis_results.json"
    if not tracking_file.exists():
        print(f"Tracking file not found: {tracking_file}")
        sys.exit(1)

    with open(tracking_file) as f:
        tracking = json.load(f)

    commits = tracking.get("commits", [])
    print(f"Project: {project_name}")
    print(f"Commits: {len(commits)}")

    # Load snapshots and build transitive change info
    print("Loading snapshots...")
    snapshots_by_module = load_snapshots_for_project(project_name)
    print(f"Found snapshots for {len(snapshots_by_module)} module(s)")

    transitive_map = build_transitive_change_map(snapshots_by_module)
    print(f"Built transitive change info for {len(transitive_map)} snapshot(s)")

    if dry_run:
        print("\n[DRY RUN]\n")

    total_files = 0
    total_changes = 0
    total_css_added = 0

    for commit_entry in commits:
        sha = commit_entry.get("sha", "")
        short = sha[:8]
        commit_dir = project_dir / short

        if not commit_dir.exists():
            continue

        # Find all changes.html files under this commit
        for changes_file in commit_dir.rglob("changes.html"):
            with open(changes_file, encoding="utf-8") as f:
                content = f.read()

            if INDIRECT_DEP_BADGE not in content:
                continue

            # Get transitive info for this commit label
            transitive_info = transitive_map.get(short, None)

            updated, count = reclassify_changes_html(content, transitive_info)
            updated, css_added = ensure_unknown_css(updated)

            if count > 0 or css_added:
                total_files += 1
                total_changes += count
                if css_added:
                    total_css_added += 1

                rel = changes_file.relative_to(project_dir)
                print(f"  {rel}: {count} badge(s) reclassified"
                      + (" + CSS added" if css_added else ""))

                if not dry_run:
                    with open(changes_file, "w", encoding="utf-8") as f:
                        f.write(updated)

    print(f"\nSummary:")
    print(f"  Files updated: {total_files}")
    print(f"  Badges reclassified: {total_changes}")
    print(f"  CSS rules added: {total_css_added}")


def main():
    parser = argparse.ArgumentParser(
        description="Reclassify root-cause attributions in existing reports")
    parser.add_argument("project", help="Project directory name (e.g. apache_avro)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would change without modifying files")
    args = parser.parse_args()

    process_project(args.project, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
