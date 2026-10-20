#!/bin/bash
#SBATCH --job-name=theo-hist-24h
#SBATCH --account=def-baudry
#SBATCH --time=24:00:00
#SBATCH --mem=48G
#SBATCH --cpus-per-task=4
#SBATCH --output=%x-%j.out
#SBATCH --error=%x-%j.err
#SBATCH --mail-type=END,FAIL
#SBATCH --mail-user=achinthaisuru97@gmail.com

# --- Modules ---
module purge
module load StdEnv/2023
module load maven/3.9.10
module load python/3.11.5

# --- SDKMAN (manages Java 17 + 21 switching) ---
export SDKMAN_DIR="$HOME/.sdkman"
if [ -f "$SDKMAN_DIR/bin/sdkman-init.sh" ]; then
    source "$SDKMAN_DIR/bin/sdkman-init.sh"
else
    echo "ERROR: sdkman not found at $SDKMAN_DIR" >&2
    exit 1
fi

# module load maven sets JAVA_HOME to its bundled java 17 — override with sdkman
sdk use java 21.0.12+1.1-tem

# --- Python venv ---
THEO_ROOT="$HOME/projects/def-baudry/yogya/theo-all/theo"
if [ -d "$THEO_ROOT/scripts/venv" ]; then
    source "$THEO_ROOT/scripts/venv/bin/activate"
elif [ -d "$THEO_ROOT/venv" ]; then
    source "$THEO_ROOT/venv/bin/activate"
fi

# --- Maven local repo on SCRATCH (fast I/O, no quota pressure) ---
export MAVEN_OPTS="-Xmx32g"

# --- Run ---
cd "$THEO_ROOT"
python3 scripts/run_history_analysis.py

echo ""
echo "=== Job finished at $(date) ==="
echo "=== Checking progress ==="
python3 -c "
import json
from pathlib import Path
base = Path('$HOME/projects/def-baudry/yogya/theo-all/client-results/history')
if not base.exists():
    print('No results directory yet')
else:
    for p in sorted(base.iterdir()):
        t = p / 'analysis_results.json'
        if t.exists():
            d = json.load(open(t))
            done = len(d.get('commits', []))
            skip = len(d.get('noDepChangeCommits', []))
            success = sum(1 for c in d.get('commits',[]) if c.get('analysisResult')=='success')
            failed = sum(1 for c in d.get('commits',[]) if c.get('analysisResult') in ('failed','build_failed'))
            print(f'  {p.name}: {done} done ({success} ok, {failed} fail), {skip} no-dep-skipped')
"
