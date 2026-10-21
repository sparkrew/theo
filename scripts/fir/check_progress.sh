#!/bin/bash
# Quick progress check — run on login node anytime
# Usage: bash scripts/check_progress.sh

BASE="/scratch/yogya/client-results/history"

echo "=== Theo History Analysis Progress ==="
echo ""

if [ ! -d "$BASE" ]; then
    echo "No results directory yet: $BASE"
    exit 0
fi

python3 -c "
import json
from pathlib import Path
base = Path('$BASE')
total_done = 0
total_skip = 0
for p in sorted(base.iterdir()):
    t = p / 'analysis_results.json'
    if t.exists():
        d = json.load(open(t))
        commits = d.get('commits', [])
        done = len(commits)
        skip = len(d.get('noDepChangeCommits', []))
        success = sum(1 for c in commits if c.get('analysisResult')=='success')
        copied = sum(1 for c in commits if c.get('analysisResult')=='copied')
        failed = sum(1 for c in commits if c.get('analysisResult') in ('failed','build_failed'))
        total_done += done
        total_skip += skip
        last = commits[-1] if commits else None
        last_sha = last['sha'][:8] if last else '-'
        print(f'  {p.name:40s}  done={done:3d} (ok={success}, copied={copied}, fail={failed})  skip={skip:3d}  last={last_sha}')
print()
print(f'  TOTAL: {total_done} commits processed, {total_skip} no-dep-change skipped')
"

echo ""
echo "=== Running jobs ==="
squeue -u "$USER" --format="%.10i %.20j %.8T %.10M %.6D %R"
