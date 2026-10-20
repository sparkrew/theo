#!/usr/bin/env python3
"""Remove all tracking entries and report directories for commits
processed AFTER a given commit SHA.

Usage:
    python3 rollback_after_commit.py <commit_sha> [reports_base]

The commit itself is KEPT. Everything after it is removed.
"""

import json
import shutil
import sys
from pathlib import Path

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <commit_sha> [reports_base]")
    sys.exit(1)

CUTOFF = sys.argv[1]
REPORTS_BASE = Path(
    sys.argv[2] if len(sys.argv) > 2
    else Path.home() / "projects/def-baudry/yogya/theo-all/client-results/history"
)


def main():
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

        commits = data.get("commits", [])
        cutoff_idx = None
        for i, c in enumerate(commits):
            if c["sha"].startswith(CUTOFF):
                cutoff_idx = i
                break

        if cutoff_idx is None:
            continue

        to_remove = commits[cutoff_idx + 1:]
        if not to_remove:
            continue

        print(f"\n{project_dir.name}: removing {len(to_remove)} commits after {CUTOFF[:8]}")
        for c in to_remove:
            sha8 = c["sha"][:8]
            report_dir = project_dir / sha8
            if report_dir.exists():
                shutil.rmtree(report_dir)
                print(f"  removed dir  {sha8}")
            else:
                print(f"  removed entry {sha8} (no dir)")
            total_removed += 1

        data["commits"] = commits[:cutoff_idx + 1]

        # Also remove these from noDepChangeCommits
        removed_shas = {c["sha"] for c in to_remove}
        data["noDepChangeCommits"] = [
            s for s in data.get("noDepChangeCommits", [])
            if s not in removed_shas
        ]

        with open(tracking_file, "w") as f:
            json.dump(data, f, indent=2)

    print(f"\nTotal: {total_removed} entries removed")


if __name__ == "__main__":
    main()
