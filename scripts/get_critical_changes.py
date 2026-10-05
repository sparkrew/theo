#!/usr/bin/env python3
"""
Build critical_version_changes.json from package-miner version-history output.

Reads the version-history JSON files produced by package-miner and filters
to only the dependencies referenced in a repos JSON file (e.g. top_42_repos.json).

Usage:
    python3 scripts/get_critical_changes.py \
        --version-history-dir /path/to/output/version-history \
        --repos-file scripts/top_42_repos.json \
        --output scripts/critical_version_changes.json

"""

import argparse
import json
import os
import sys
from pathlib import Path


def load_version_history(history_dir, coord):
    """Load a version-history JSON file for a given groupId:artifactId coordinate."""
    group_id, artifact_id = coord.split(":")
    filename = f"{group_id}_{artifact_id}-history.json"
    filepath = Path(history_dir) / filename
    if not filepath.exists():
        return None
    with open(filepath) as f:
        return json.load(f)


def extract_critical_changes(history):
    """Extract version transitions that added or removed sensitive APIs."""
    changes = history.get("changes", [])
    critical = []
    for change in changes:
        if not (change.get("addedDirect") or change.get("removedDirect")):
            continue

        from_ver = change["fromVersion"]
        to_ver = change["toVersion"]

        for api in change.get("addedDirect", []):
            critical.append({
                "api": api,
                "type": "addition_direct",
                "version_change": [from_ver, to_ver],
            })
        for api in change.get("removedDirect", []):
            critical.append({
                "api": api,
                "type": "removal_direct",
                "version_change": [from_ver, to_ver],
            })

    return critical


def main():
    parser = argparse.ArgumentParser(
        description="Build critical_version_changes.json from package-miner version-history output")
    parser.add_argument("--version-history-dir", required=True,
                        help="Path to the version-history directory from package-miner output")
    parser.add_argument("--repos-file", required=True,
                        help="JSON file with repos and their dependencies (e.g. top_42_repos.json)")
    parser.add_argument("--output", "-o", default="critical_version_changes.json",
                        help="Output JSON file (default: critical_version_changes.json)")
    args = parser.parse_args()

    with open(args.repos_file) as f:
        repos = json.load(f)

    all_deps = set()
    for repo in repos:
        all_deps.update(repo.get("dependencies", []))

    print(f"Found {len(all_deps)} unique dependencies across {len(repos)} repos", file=sys.stderr)

    result = []
    found = 0
    with_changes = 0

    for coord in sorted(all_deps):
        history = load_version_history(args.version_history_dir, coord)
        if history is None:
            print(f"  {coord}: no version-history file found, skipping", file=sys.stderr)
            continue

        found += 1
        critical = extract_critical_changes(history)

        if critical:
            with_changes += 1
            print(f"  {coord}: {len(critical)} critical changes", file=sys.stderr)
        else:
            print(f"  {coord}: no API changes between versions", file=sys.stderr)
            continue

        result.append({
            "dependency": coord,
            "critical_version_changes": critical,
        })

    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\nDone. {found}/{len(all_deps)} dependencies had version-history files.", file=sys.stderr)
    print(f"{with_changes} dependencies had critical API changes.", file=sys.stderr)
    print(f"Saved to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
