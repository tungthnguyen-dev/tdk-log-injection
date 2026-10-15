#!/bin/bash
# Model ladder on the frozen subset (docs/preregistration_v1.md, section 7):
#   BCLEAN and V on injected_cases_subset_v1.csv (624 cases) for gemma4:e2b, qwen3.5:9b, gemma4:12b.
# 3 models x 2 arms x 624 = 3,744 calls, roughly 4 h (e2b ~0.5 h, qwen ~1.3 h, 12b ~2.3 h).
# The runner appends and resumes: if this stops, run the same script again.
#
# Usage (repo root, venv active, macOS Terminal app, charger plugged in):
#   caffeinate -i bash scripts/run_ladder_subset.sh
# Output goes to the log only, so the arms stay unseen.
# Progress:  wc -l results/runs/*_v2_ladder.csv

cd "$(dirname "$0")/.." || exit 1
mkdir -p logs
LOG="logs/ladder_v2_$(date +%Y%m%d_%H%M).log"
CASES=data/processed/injected_cases_subset_v1.csv

{
    echo "runner commit: $(git rev-parse --short HEAD) $(git status --porcelain --untracked-files=no | grep -q . && echo DIRTY)"
    echo "ollama: $(ollama --version 2>&1)"
    ollama list | grep -E "e2b|12b|qwen3.5"
} >> "$LOG"

for pair in "gemma4:e2b gemma4_e2b" "qwen3.5:9b qwen3.5_9b" "gemma4:12b gemma4_12b"; do
    set -- $pair
    echo "=== $(date '+%F %T')  $1 BCLEAN,V on subset" >> "$LOG"
    python scripts/run_experiment.py --model "$1" --backend ollama --prompts prompts/v2 --runs 1 \
        --cases $CASES --conditions BCLEAN,V --out "results/runs/${2}_v2_ladder.csv" >> "$LOG" 2>&1
    echo "=== $(date '+%F %T')  exit code $?" >> "$LOG"
done

echo "=== ALL DONE $(date '+%F %T')" >> "$LOG"
