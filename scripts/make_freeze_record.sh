#!/bin/bash
# Build docs/freeze_record_v1.md: the record behind the data-freeze-v1 tag.
# Run from the repo root on an up-to-date main, with every PR merged and a clean working tree.
#
#   RUNNER_VENV=.venv ANALYSIS_VENV=~/venvs/tdk-detector bash scripts/make_freeze_record.sh
#
# It re-runs the analyses and checks that no tracked file changes (byte-for-byte reproduction).
# Nothing is committed or tagged by this script.

set -u
cd "$(dirname "$0")/.." || exit 1
RUNNER_VENV="${RUNNER_VENV:-.venv}"
ANALYSIS_VENV="${ANALYSIS_VENV:-$HOME/venvs/tdk-detector}"
OUT=docs/freeze_record_v1.md
LOGDIR=logs/freeze_v1
mkdir -p "$LOGDIR" docs

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "Tracked files have uncommitted changes. Commit or stash them first."; exit 1
fi
COMMIT=$(git rev-parse HEAD)
BRANCH=$(git rev-parse --abbrev-ref HEAD)

# ---------- validation: re-run, then check that nothing tracked changed ----------
run () {   # name, venv, command...
    local name="$1" venv="$2"; shift 2
    ( source "$venv/bin/activate" && "$@" ) > "$LOGDIR/$name.log" 2>&1
    echo "$?"
}
echo "Re-running analyses (logs in $LOGDIR/) ..."
RC_RERUN=$(run rerun_analyses "$ANALYSIS_VENV" bash scripts/rerun_analyses.sh)
RC_RESCORE=$(run rescore_sanitised "$ANALYSIS_VENV" python scripts/rescore_sanitised.py)
RC_DEF=$(run analyze_condition_c "$ANALYSIS_VENV" python scripts/analyze_condition_c.py)
CHANGED=$(git status --porcelain --untracked-files=no)

# ---------- write the record ----------
{
echo "# Freeze record v1"
echo
echo "Record behind the git tag \`data-freeze-v1\`. Generated $(date '+%Y-%m-%d %H:%M %Z') by \`scripts/make_freeze_record.sh\`."
echo
echo "## Frozen commit"
echo
echo "- Commit: \`$COMMIT\` (branch \`$BRANCH\`)"
echo "- The tag points to the commit that adds this file, which is this commit plus the record itself."
echo
echo "## Validation"
echo
echo "| Step | Exit code |"
echo "|---|---|"
echo "| \`bash scripts/rerun_analyses.sh\` | $RC_RERUN |"
echo "| \`python scripts/rescore_sanitised.py\` | $RC_RESCORE |"
echo "| \`python scripts/analyze_condition_c.py\` | $RC_DEF |"
echo
if [ -z "$CHANGED" ]; then
    echo "After the re-runs no tracked file changed: every \`results.json\`, table and figure reproduces byte for byte."
else
    echo "**After the re-runs these tracked files changed (to be explained before tagging):**"
    echo
    echo '```'; echo "$CHANGED"; echo '```'
fi
echo
echo "## Checksums (SHA-256, tracked files only)"
echo
echo "Run outputs, inputs, payloads, prompts and analysis results. Verify with \`shasum -a 256 -c\` on the block below."
echo
echo '```'
git ls-files results/runs data/frozen data/processed payloads/payloads.csv prompts/v1 prompts/v2 'results/analysis/*/results.json' \
    | sort -u | xargs shasum -a 256
echo '```'
echo
echo "## Environment"
echo
echo "### Machine (local runs and this validation)"
echo
echo '```'
sw_vers 2>/dev/null
echo "CPU: $(sysctl -n machdep.cpu.brand_string 2>/dev/null)"
echo "RAM: $(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1073741824 )) GB"
echo '```'
echo
echo "### Ollama and local model digests"
echo
echo '```'
ollama --version 2>&1
ollama list 2>&1
echo '```'
echo
echo "### Runner environment (\`$RUNNER_VENV\`)"
echo
echo '```'
( source "$RUNNER_VENV/bin/activate" && python --version && pip freeze ) 2>&1
echo '```'
echo
echo "### Analysis environment (\`$ANALYSIS_VENV\`)"
echo
echo '```'
( source "$ANALYSIS_VENV/bin/activate" && python --version && pip freeze ) 2>&1
echo '```'
echo
echo "## Which machine ran which runs"
echo
echo "| Runs | Machine |"
echo "|---|---|"
echo "| All local Ollama runs: gemma4:e2b, e4b, 12b, qwen3.5:9b (A/B/C, v2 arms, ladder, B'+BCLEAN, SR-BH) | T. H. T. Nguyen's MacBook Pro (machine above) |"
echo "| Claude Haiku 4.5, Haiku 5.5, Gemini 2.5 Flash, Gemini 3.6 Flash (cloud APIs) | B. Abdullaev's MacBook Air (Apple M4), macOS 26.7.1; Python 3.14.8, anthropic 0.125.0, google-genai 2.31.0 |"
echo
echo "The 8 result files from 8-9 Oct (Claude Haiku 4.5 v1 and gemma4 e2b/e4b/12b A/B/C, each with its benign-control file) were written by the earlier runner and store the prompt version and hash only; their settings are documented in \`README.md\` and \`docs/threat_model.md\` (pre-registration Section 8). All later rows also store the runner commit, backend version, model digest or reported model version, and the parameters actually sent."
echo
echo "## Not in the repository"
echo
echo "- \`models/\`: detector fold models; rebuilt by \`scripts/train_detector.py\` (and \`models/srbh/\` by \`scripts/make_srbh_cases.py\`)."
echo "- \`.env\`: API keys."
echo "- \`data/external/\`: the SR-BH 2020 source file (doi:10.7910/DVN/OGOIXX); the converted slice is in \`data/processed/srbh/\`."
echo "- \`logs/\` and local notes: run logs and personal notes, not needed to reproduce the results."
echo "- Smoke and test outputs in \`results/runs/\` that are untracked (e.g. \`dummy_test.csv\`, \`resume_test.csv\`)."
} > "$OUT"

echo
echo "Wrote $OUT"
echo "rerun_analyses=$RC_RERUN rescore_sanitised=$RC_RESCORE analyze_condition_c=$RC_DEF"
if [ -z "$CHANGED" ]; then echo "Byte-for-byte: OK (no tracked file changed)"; else echo "CHANGED FILES:"; echo "$CHANGED"; fi
