#!/usr/bin/env python3
"""List all failed/build_failed commits without modifying anything.

Usage:
    python3 list_failed_builds.py [reports_base]
"""

import json
import sys
from pathlib import Path

REPORTS_BASE = Path(
    sys.argv[1] if len(sys.argv) > 1
    else Path("/scratch/yogya/client-results/history")
)

def main():
    if not REPORTS_BASE.exists():
        print(f"Reports directory not found: {REPORTS_BASE}")
        sys.exit(1)

    total = 0
    for project_dir in sorted(REPORTS_BASE.iterdir()):
        tracking_file = project_dir / "analysis_results.json"
        if not tracking_file.exists():
            continue

        with open(tracking_file) as f:
            data = json.load(f)

        failed = [
            c for c in data["commits"]
            if c.get("analysisResult") in ("build_failed", "failed")
        ]
        if not failed:
            continue

        print(f"\n{project_dir.name}:")
        for c in failed:
            sha = c["sha"][:8]
            result = c.get("analysisResult", "?")
            date = c.get("commitInfo", {}).get("date", "?")
            error = c.get("error", "")[:120]
            print(f"  {sha}  {result:14s}  {date}  {error}")
            total += 1

    print(f"\nTotal: {total} failed commits")


if __name__ == "__main__":
    main()
