#!/usr/bin/env python3
"""
Extract packages with direct sensitive API changes from version-history reports.

Usage:
    python extract_sensitive_packages.py <output-dir> [--out result.json]

Where <output-dir> contains:
    - version-history/*-history.json
    - selected_packages.json (optional, for latestVersion/dependentReposCount lookup)
"""

import argparse
import json
import sys
from pathlib import Path


def has_direct_changes(history: dict) -> bool:
    for change in history.get("changes", []):
        if change.get("addedDirect") or change.get("removedDirect"):
            return True
    return False


def main():
    parser = argparse.ArgumentParser(
        description="Extract packages with direct sensitive API permission changes."
    )
    parser.add_argument(
        "output_dir",
        type=Path,
        help="Directory containing version-history/ and selected_packages.json",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output JSON file path (default: <output_dir>/sensitive_packages.json)",
    )
    args = parser.parse_args()

    output_dir: Path = args.output_dir
    history_dir = output_dir / "version-history"

    if not history_dir.is_dir():
        print(f"Error: {history_dir} does not exist.", file=sys.stderr)
        sys.exit(1)

    # Load selected_packages.json for lookup
    lookup = {}
    selected_file = output_dir / "selected_packages.json"
    if selected_file.exists():
        with open(selected_file) as f:
            for pkg in json.load(f):
                key = (pkg["groupId"], pkg["artifactId"])
                lookup[key] = pkg
        print(f"Loaded {len(lookup)} packages from selected_packages.json")
    else:
        print("Warning: selected_packages.json not found; latestVersion and dependentReposCount will be null.", file=sys.stderr)

    results = []
    history_files = sorted(history_dir.glob("*-history.json"))
    print(f"Found {len(history_files)} version-history files")

    for hf in history_files:
        with open(hf) as f:
            history = json.load(f)

        if not history.get("hasPermissionChanges", False):
            continue
        if not has_direct_changes(history):
            continue

        gid = history["groupId"]
        aid = history["artifactId"]
        pkg_info = lookup.get((gid, aid))

        results.append({
            "groupId": gid,
            "artifactId": aid,
            "latestVersion": pkg_info["latestVersion"] if pkg_info else None,
            "dependentReposCount": pkg_info["dependentReposCount"] if pkg_info else None,
        })

    results.sort(key=lambda p: (-(p["dependentReposCount"] or 0), p["groupId"], p["artifactId"]))

    out_path = args.out or (output_dir / "sensitive_packages.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Wrote {len(results)} packages with direct sensitive API changes to {out_path}")


if __name__ == "__main__":
    main()
