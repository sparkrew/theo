#!/usr/bin/env python3
"""
Delete all result files created after a given commit for a project.

Usage:
    python3 delete_results_after_commit.py <project_name> <commit_sha> [--dry-run]

Example:
    python3 delete_results_after_commit.py apache_avro 96cd2074a64cfa08390b0d8561ad76b22b31a16b --dry-run
    python3 delete_results_after_commit.py apache_avro 96cd2074a64cfa08390b0d8561ad76b22b31a16b
"""

import argparse
import json
import shutil
import sys
from pathlib import Path

REPORTS_BASE = Path("/scratch/yogya/client-results/history")
THEO_HISTORY = Path("/scratch/yogya/client-results/theo-history-snapshots")
THEO_CACHE = Path("/scratch/yogya/client-results/theo-cache")


def main():
    parser = argparse.ArgumentParser(
        description="Delete result files after a given commit")
    parser.add_argument("project", help="Project directory name (e.g. apache_avro)")
    parser.add_argument("commit", help="Delete results AFTER this commit SHA")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be deleted without deleting")
    args = parser.parse_args()

    project_dir = REPORTS_BASE / args.project
    tracking_file = project_dir / "analysis_results.json"

    if not tracking_file.exists():
        print(f"Tracking file not found: {tracking_file}")
        sys.exit(1)

    with open(tracking_file) as f:
        tracking = json.load(f)

    commits = tracking.get("commits", [])
    cutoff_sha = args.commit

    # Find the index of the cutoff commit
    cutoff_idx = None
    for i, c in enumerate(commits):
        if c["sha"].startswith(cutoff_sha) or cutoff_sha.startswith(c["sha"]):
            cutoff_idx = i
            break

    if cutoff_idx is None:
        print(f"Commit {cutoff_sha} not found in tracking.")
        print(f"Available commits ({len(commits)}):")
        for c in commits[-10:]:
            print(f"  {c['sha'][:8]}  {c.get('commitInfo', {}).get('date', '?')}")
        sys.exit(1)

    commits_to_keep = commits[:cutoff_idx + 1]
    commits_to_delete = commits[cutoff_idx + 1:]

    if not commits_to_delete:
        print(f"No commits after {cutoff_sha[:8]} to delete.")
        sys.exit(0)

    print(f"Project: {args.project}")
    print(f"Cutoff: {cutoff_sha[:8]} (index {cutoff_idx})")
    print(f"Keeping: {len(commits_to_keep)} commits")
    print(f"Deleting: {len(commits_to_delete)} commits")
    if args.dry_run:
        print("\n[DRY RUN]\n")

    # Also remove noDepChangeCommits that are after the cutoff.
    # We use git ancestry to determine order, but since the tracking
    # file is ordered chronologically, we can use a simpler approach:
    # collect all SHAs of commits to delete and filter them out.
    delete_shas = {c["sha"] for c in commits_to_delete}

    # Collect snapshot labels to delete (commit[:8])
    snapshot_labels = {c["sha"][:8] for c in commits_to_delete}

    # 1. Delete commit report directories
    deleted_dirs = 0
    for c in commits_to_delete:
        short = c["sha"][:8]
        commit_dir = project_dir / short
        if commit_dir.exists():
            print(f"  rm -rf {commit_dir}")
            if not args.dry_run:
                shutil.rmtree(commit_dir)
            deleted_dirs += 1

    # 2. Delete snapshot files that match deleted commit labels
    deleted_snapshots = 0
    if THEO_HISTORY.exists():
        for snap_dir in THEO_HISTORY.iterdir():
            if not snap_dir.is_dir():
                continue
            for snap_file in list(snap_dir.glob("*.json")):
                if any(label in snap_file.name for label in snapshot_labels):
                    print(f"  rm {snap_file}")
                    if not args.dry_run:
                        snap_file.unlink()
                    deleted_snapshots += 1

    # 3. Update tracking file
    no_dep_before = tracking.get("noDepChangeCommits", [])
    no_dep_after = [s for s in no_dep_before if s not in delete_shas]
    removed_no_dep = len(no_dep_before) - len(no_dep_after)

    if not args.dry_run:
        tracking["commits"] = commits_to_keep
        tracking["noDepChangeCommits"] = no_dep_after
        backup = tracking_file.with_suffix(".json.bak")
        shutil.copy2(tracking_file, backup)
        print(f"  Backup: {backup}")
        tmp = tracking_file.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(tracking, f, indent=2)
        tmp.rename(tracking_file)
        print(f"  Updated: {tracking_file}")
    else:
        print(f"\n  Would update {tracking_file}")
        print(f"    commits: {len(commits)} -> {len(commits_to_keep)}")
        if removed_no_dep:
            print(f"    noDepChangeCommits: {len(no_dep_before)} -> {len(no_dep_after)}")

    print(f"\nSummary:")
    print(f"  Commit dirs deleted: {deleted_dirs}")
    print(f"  Snapshots deleted: {deleted_snapshots}")
    print(f"  Tracking entries removed: {len(commits_to_delete)}")
    if removed_no_dep:
        print(f"  No-dep-change entries removed: {removed_no_dep}")


if __name__ == "__main__":
    main()
