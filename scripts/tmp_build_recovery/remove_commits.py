#!/usr/bin/env python3
"""Remove specific commits from tracking so they get re-analyzed.

Usage:
    python3 remove_commits.py <sha1> [sha2 sha3 ...]
    python3 remove_commits.py --file commits.txt

Matches by prefix (8+ chars is enough). Removes tracking entries,
report directories, and noDepChangeCommits entries.
"""

import json
import shutil
import sys
from pathlib import Path

REPORTS_BASE = Path("/scratch/yogya/client-results/history")


def load_shas():
    shas = []
    args = sys.argv[1:]
    if not args:
        print(f"Usage: {sys.argv[0]} <sha1> [sha2 ...]\n"
              f"       {sys.argv[0]} --file commits.txt")
        sys.exit(1)
    if args[0] == "--file":
        with open(args[1]) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    shas.append(line)
    else:
        shas = args
    return shas


def sha_matches(full_sha, target):
    return full_sha.startswith(target) or target.startswith(full_sha[:8])


def main():
    targets = load_shas()
    if not REPORTS_BASE.exists():
        print(f"Reports directory not found: {REPORTS_BASE}")
        sys.exit(1)

    total_removed = 0
    for project_dir in sorted(REPORTS_BASE.iterdir()):
        tracking_file = project_dir / "analysis_results.json"
        if not tracking_file.exists():
            continue

        with open(tracking_file) as f:
            data = json.load(f)

        before = len(data["commits"])
        removed = []
        kept = []
        for c in data["commits"]:
            if any(sha_matches(c["sha"], t) for t in targets):
                removed.append(c)
            else:
                kept.append(c)

        no_dep_before = len(data.get("noDepChangeCommits", []))
        data["noDepChangeCommits"] = [
            s for s in data.get("noDepChangeCommits", [])
            if not any(sha_matches(s, t) for t in targets)
        ]
        no_dep_removed = no_dep_before - len(data["noDepChangeCommits"])

        if not removed and no_dep_removed == 0:
            continue

        for c in removed:
            sha8 = c["sha"][:8]
            report_dir = project_dir / sha8
            if report_dir.exists():
                shutil.rmtree(report_dir)
                print(f"  {project_dir.name}: removed dir {sha8}")
            else:
                print(f"  {project_dir.name}: removed entry {sha8} (no dir)")
            total_removed += 1

        if no_dep_removed > 0:
            print(f"  {project_dir.name}: removed {no_dep_removed} no-dep-change entries")
            total_removed += no_dep_removed

        data["commits"] = kept
        with open(tracking_file, "w") as f:
            json.dump(data, f, indent=2)

    if total_removed == 0:
        print("No matching commits found in any project")
    else:
        print(f"\nTotal: {total_removed} entries removed")


if __name__ == "__main__":
    main()
