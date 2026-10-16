#!/bin/bash
# SR-BH 2020 slice on gemma4:e4b (descriptive, external validity; see Deviations in the pre-registration).
#   1. attack cases (248 events x none + 12 payloads = 3,224) on A and B   -> 6,448 calls
#   2. clean attack rows (248) on C                                        ->   248 calls
#   3. benign events (79) on A, B, C                                       ->   237 calls
# About 6,900 calls, roughly 5 h. The runner resumes: if this stops, run it again.
#
# Usage (repo root, venv active, macOS Terminal app, charger plugged in):
#   caffeinate -i bash scripts/run_srbh_e4b.sh
# Output goes to the log only.

cd "$(dirname "$0")/.." || exit 1
mkdir -p logs
LOG="logs/srbh_e4b_$(date +%Y%m%d_%H%M).log"
RUN="python scripts/run_experiment.py --model gemma4:e4b --backend ollama --prompts prompts/v1 --runs 1"
S=data/processed/srbh
O=results/runs

step () {
    echo "=== $(date '+%F %T')  $1" >> "$LOG"
    shift
    "$@" >> "$LOG" 2>&1
    echo "=== $(date '+%F %T')  exit code $?" >> "$LOG"
}

{
    echo "runner commit: $(git rev-parse --short HEAD) $(git status --porcelain --untracked-files=no | grep -q . && echo DIRTY)"
    echo "ollama: $(ollama --version 2>&1)"
    ollama list | grep e4b
} >> "$LOG"

step "1/3 attack cases, A and B" \
    $RUN --cases $S/srbh_cases_v1.csv --conditions A,B --out $O/gemma4_e4b_srbh.csv
step "2/3 clean attack rows, C" \
    $RUN --cases $S/srbh_cases_clean_v1.csv --conditions C --out $O/gemma4_e4b_srbh_clean_c.csv
step "3/3 benign events, A, B, C" \
    $RUN --cases $S/srbh_benign_v1.csv --conditions A,B,C --out $O/gemma4_e4b_srbh_benign.csv

echo "=== ALL DONE $(date '+%F %T')" >> "$LOG"
