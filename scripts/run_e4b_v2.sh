cd "$(dirname "$0")/.." || exit 1
mkdir -p logs
LOG="logs/e4b_v2_$(date +%Y%m%d_%H%M).log"

RUN="python scripts/run_experiment.py --model gemma4:e4b --backend ollama --prompts prompts/v2 --runs 1"
D=data/processed
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

step "1/5 BCLEAN, full set" \
    $RUN --cases $D/injected_cases_v1.csv --conditions BCLEAN \
         --out $O/gemma4_e4b_v2_bclean.csv

step "2/5 DWRONG, 96 controls" \
    $RUN --cases $D/controls_v1.csv --conditions DWRONG \
         --out $O/gemma4_e4b_v2_dwrong.csv

step "3/5 V, VP, VS, PLACEBO, full set" \
    $RUN --cases $D/injected_cases_v1.csv --conditions V,VP,VS,PLACEBO \
         --out $O/gemma4_e4b_v2_components.csv

step "4/5 V, VP, VS, PLACEBO, benign controls" \
    $RUN --cases $D/benign_control_v1.csv --conditions V,VP,VS,PLACEBO \
         --out $O/gemma4_e4b_v2_components_benign.csv

step "5/5 DOSE, subset x 6 levels" \
    $RUN --cases $D/injected_cases_subset_v1.csv \
         --conditions DOSE55,DOSE65,DOSE75,DOSE85,DOSE95,DOSE99 \
         --out $O/gemma4_e4b_v2_dose.csv

echo "=== ALL DONE $(date '+%F %T')" >> "$LOG"