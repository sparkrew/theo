#!/usr/bin/env python3
"""Remove failed/build_failed entries from tracking so they get retried.

Cleans up:
  - The tracking entry in analysis_results.json
  - The error directory (<commit_sha8>/error.txt)

Does NOT touch cache or snapshots (Theo goals only run after successful builds).

Usage:
    python3 clear_failed_builds.py [reports_base]

Default: ~/projects/def-baudry/yogya/theo-all/client-results/history
"""

import json
import shutil
import sys
from pathlib import Path

REPORTS_BASE = Path(
    sys.argv[1] if len(sys.argv) > 1
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

        before = len(data["commits"])
        failed = [
            c for c in data["commits"]
            if c.get("analysisResult") in ("build_failed", "failed")
        ]
        if not failed:
            continue

        for c in failed:
            err_dir = project_dir / c["sha"][:8]
            if err_dir.exists():
                shutil.rmtree(err_dir)
                print(f"  removed {err_dir}")

        data["commits"] = [
            c for c in data["commits"]
            if c.get("analysisResult") not in ("build_failed", "failed")
        ]

        with open(tracking_file, "w") as f:
            json.dump(data, f, indent=2)

        removed = before - len(data["commits"])
        total_removed += removed
        print(f"{project_dir.name}: removed {removed} failed, {len(data['commits'])} remain")

    print(f"\nTotal: {total_removed} failed entries cleared")


if __name__ == "__main__":
    main()
