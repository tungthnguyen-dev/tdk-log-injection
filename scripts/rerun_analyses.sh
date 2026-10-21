#!/bin/bash
# Re-run every offline analysis and figure from the committed result files (no LLM calls).
# Order matters: the mixed-model check and the figures read results/analysis/*/results.json.
#
# Usage (repo root, venv active):
#   bash scripts/rerun_analyses.sh
set -e
cd "$(dirname "$0")/.." || exit 1
PY=${PYTHON:-python}
E4B_V2="results/runs/gemma4_e4b_v2_bclean.csv results/runs/gemma4_e4b_v2_components.csv
        results/runs/gemma4_e4b_v2_components_benign.csv results/runs/gemma4_e4b_v2_dose.csv
        results/runs/gemma4_e4b_v2_dwrong.csv"

step () { echo; echo "=== $1"; }

step "checks";                  $PY scripts/test_analyse_prereg.py
step "ladder self-test";        $PY scripts/analyse_ladder.py --selftest
step "H1-H4, v1 data";          $PY scripts/analyse_prereg.py --stage v1 > /dev/null
step "H1-H4, all data";         $PY scripts/analyse_prereg.py --stage all --e4b-v2 $E4B_V2 > /dev/null
step "mixed model";             $PY scripts/glmm_sensitivity.py --stage v1 > /dev/null
                                $PY scripts/glmm_sensitivity.py --stage all --e4b-v2 results/runs/gemma4_e4b_v2_bclean.csv > /dev/null
step "same-session H2 (e4b)";   $PY scripts/analyse_same_session.py --file results/runs/gemma4_e4b_v2_bprime_bclean.csv \
                                    --compare results/runs/gemma4_e4b_v2_bclean.csv \
                                    --out results/analysis/sensitivity/e4b_bprime.json > /dev/null
step "model ladder";            $PY scripts/analyse_ladder.py > /dev/null
step "cloud extension";         $PY scripts/analyse_extension.py > /dev/null
step "SR-BH summary";           $PY scripts/analyze_srbh.py > /dev/null
step "figures";                 $PY scripts/make_figures_haiku.py > /dev/null
                                $PY scripts/make_figures_combined.py > /dev/null
echo; echo "Done. Review with: git status"
