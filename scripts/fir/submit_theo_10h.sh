#!/bin/bash
#SBATCH --job-name=theo-hist-10h
#SBATCH --account=def-baudry
#SBATCH --time=10:00:00
#SBATCH --mem=4G
#SBATCH --cpus-per-task=1
#SBATCH --output=%x-%j.out
#SBATCH --error=%x-%j.err
#SBATCH --mail-type=END,FAIL
#SBATCH --mail-user=tulipgamage@gmail.com

module purge
module load StdEnv/2023
module load maven/3.9.10
module load python/3.11.5

export SDKMAN_DIR="$HOME/.sdkman"
if [ -f "$SDKMAN_DIR/bin/sdkman-init.sh" ]; then
    source "$SDKMAN_DIR/bin/sdkman-init.sh"
else
    echo "ERROR: sdkman not found at $SDKMAN_DIR" >&2
    exit 1
fi

# module load maven sets JAVA_HOME to its bundled java 17 — override with sdkman
# sdk use java 21.0.12+1.1-tem

THEO_ROOT="$HOME/projects/def-baudry/yogya/theo-all/theo"
if [ -d "$THEO_ROOT/scripts/venv" ]; then
    source "$THEO_ROOT/scripts/venv/bin/activate"
elif [ -d "$THEO_ROOT/venv" ]; then
    source "$THEO_ROOT/venv/bin/activate"
fi

export MAVEN_OPTS="-Xmx3g"

cd "$THEO_ROOT"
python3 scripts/run_history_analysis.py

echo ""
echo "Job finished at $(date)"
echo "Checking progress"
python3 -c "
import json
from pathlib import Path
base = Path('/scratch/yogya/client-results/history')
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

