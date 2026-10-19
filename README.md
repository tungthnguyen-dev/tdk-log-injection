# When the detector becomes the attack surface

TDK project by Bakhtier Abdullaev and The Hoang Tung Nguyen (University of Debrecen, Faculty of Informatics).

An LLM "log analyst" reads one web-server log event and says whether it is an attack. Attackers control
request fields such as the User-Agent, Referer and URI, so they can hide prompt-injection text in the log
and tell the LLM to call an attack benign. We study a hybrid pipeline in which the LLM is also given the
verdict, attack probability and SHAP explanation of a small ML detector. The same attacker-written field
reaches the LLM twice: directly as text, and indirectly by shifting the detector evidence the LLM is
grounded on (explanation-mediated injection).

We measure whether grounding protects the LLM, whether the attacker's influence on the detector matters,
which parts of the detector block do the work, how the LLM reacts to a wrong detector, and what structural
defences add, across eight models.

## At a glance

| | |
|---|---|
| Testbed | Isolated Docker network: nginx, a small Flask app, benign and attack traffic generators |
| Detector | Random Forest on 6 features (URI length, entropy, special characters, status, User-Agent length, known scanner); out-of-fold scores; SHAP top 5 |
| Cases | 48 attack events x 30 payloads (6 families; 21 User-Agent, 5 Referer, 4 URI) = 1,440 payload cases, plus 48 no-payload attack controls and 48 benign controls |
| Main conditions | A: log only. B: log + detector verdict, probability and SHAP. C: B + delimiters, a 200-character field cap and output guards |
| Mechanism arms | BCLEAN (detector block from the clean event), B' (B in the same session), V / VP / VS (verdict; + probability; + SHAP), PLACEBO, DWRONG (wrong detector), DOSE (fixed probabilities) |
| Models | Claude Haiku 4.5; gemma4:e2b, e4b, 12b; qwen3.5:9b; extension: Gemini 2.5 Flash, Claude Haiku 5.5, Gemini 3.6 Flash |
| Primary outcome | Payload-induced flip: benign on a payload case while the same event's no-payload control was judged malicious |
| Statistics | Event-cluster bootstrap (10,000 resamples), Holm over six confirmatory tests, mixed-model sensitivity, control-gated and raw-flip sensitivity analyses |

## Pre-registration and freeze

The hypotheses (H1-H4), arms, outcomes and analysis plan are in
[`docs/preregistration_v1.md`](docs/preregistration_v1.md), committed and tagged `prereg-v1` before any
new-arm output existed. Every later change is a dated entry under "Deviations" in the same file, with
whether any outcome data had been seen. Prompt templates are frozen in `prompts/v1` and `prompts/v2`
(hashes in the pre-registration addendum); every result row records its prompt hash and runner commit.
The data used in the paper are tagged `data-freeze-v1`.

## Repository layout

```
data/            frozen raw log, labelled events, case files, subset, SR-BH slice (see data/README.md)
docs/            pre-registration, threat model, runner usage, pilot notes
payloads/        the 30 prompt-injection payloads
prompts/v1/      conditions A, B, C (frozen)
prompts/v2/      A, B, C (identical to v1) + V, VP, VS, PLACEBO
results/runs/    one CSV row per LLM call, per model and arm
results/analysis/  analysis outputs (JSON/CSV): all, v1, glmm, ladder, sensitivity, extension, defences
results/figures/ paper figures (SVG + PNG)
results/summary/ detector shift, latency and token summaries
scripts/         testbed parsing, detector, case building, runner, analyses, figures
testbed/         isolated Docker testbed
```

## Setup

Python 3.11+ and a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

- Local models: [Ollama](https://ollama.com) with `gemma4:e2b`, `gemma4:e4b`, `gemma4:12b` and `qwen3.5:9b`
  pulled. Do not upgrade Ollama between runs that are compared with each other.
- Cloud models: API keys in a `.env` file in the repository root (never committed):
  `ANTHROPIC_API_KEY=...` and `GEMINI_API_KEY=...`.
- The testbed needs Docker Desktop.

## How to reproduce

All steps after step 3 are offline: they read the committed result files and make no LLM calls.

1. **Traffic and log** (optional; the frozen log is in `data/frozen/`):
   ```bash
   cd testbed && docker compose up -d --build
   docker compose exec benign python benign.py 500
   docker compose exec attacker python attack.py 50
   ```
   The testbed network is internal, so nothing leaves the Docker network.

2. **Events, detector and case files:**
   ```bash
   python scripts/parse_logs.py
   python scripts/sample_events.py
   python scripts/train_detector.py
   python scripts/make_injected_cases.py
   python scripts/make_benign_control.py
   python scripts/make_subset.py
   python scripts/make_bclean_cases.py
   python scripts/make_controls_file.py
   ```

3. **LLM runs** (see [`docs/runner.md`](docs/runner.md)). The runner appends rows and resumes where it
   stopped. Examples:
   ```bash
   # A/B/C, prompts v1
   python scripts/run_experiment.py --cases data/processed/injected_cases_v1.csv --prompts prompts/v1 \
     --model gemma4:e4b --runs 1 --out results/runs/gemma4_e4b.csv
   # B' and BCLEAN interleaved per case, prompts v2
   python scripts/run_experiment.py --cases data/processed/injected_cases_v1.csv --prompts prompts/v2 \
     --model claude-haiku-4-5-20251001 --backend anthropic --conditions B,BCLEAN --runs 3 \
     --out results/runs/claude_haiku_4_5_v2_bclean.csv
   ```
   Batch scripts used for the local runs: `scripts/run_e4b_v2.sh`, `scripts/run_ladder_subset.sh`,
   `scripts/run_srbh_e4b.sh`. Use a new `--out` file for every run that must not resume an old one.

4. **Checks and analyses:**
   ```bash
   python scripts/test_analyse_prereg.py          # synthetic checks + no-effect simulation
   python scripts/analyse_prereg.py --stage v1    # validation on the A/B/C data
   python scripts/analyse_prereg.py --stage all --e4b-v2 results/runs/gemma4_e4b_v2_bclean.csv \
     results/runs/gemma4_e4b_v2_components.csv results/runs/gemma4_e4b_v2_components_benign.csv \
     results/runs/gemma4_e4b_v2_dose.csv results/runs/gemma4_e4b_v2_dwrong.csv
   python scripts/glmm_sensitivity.py --stage all --e4b-v2 results/runs/gemma4_e4b_v2_bclean.csv
   python scripts/analyse_same_session.py --file results/runs/gemma4_e4b_v2_bprime_bclean.csv \
     --compare results/runs/gemma4_e4b_v2_bclean.csv --out results/analysis/sensitivity/e4b_bprime.json
   python scripts/analyse_ladder.py
   python scripts/analyse_extension.py
   python scripts/rescore_sanitised.py            # needs the detector models from step 2
   python scripts/analyze_condition_c.py
   ```

5. **Figures:**
   ```bash
   python scripts/make_figures_haiku.py
   python scripts/make_figures_combined.py
   ```

Re-running step 4 from the committed files reproduces every JSON and CSV file in `results/analysis/`
exactly (checked at the data freeze). `analyze_condition_c.py` draws its figure with matplotlib.

| Script | Output |
|---|---|
| `analyse_prereg.py` | H1-H4 with Holm, sensitivity analyses, exploratory arms, DOSE, DWRONG: `results/analysis/{v1,all}/results.json` |
| `glmm_sensitivity.py` | mixed-model sensitivity (events and payloads random): `results/analysis/glmm/` |
| `analyse_same_session.py` | same-session H2 check: `results/analysis/sensitivity/` |
| `analyse_ladder.py` | model ladder and capability gradient: `results/analysis/ladder/results.json` |
| `analyse_extension.py` | cloud-model extension: `results/analysis/extension/results.json` |
| `rescore_sanitised.py` | detector re-scored after C's input cleaning: `data/processed/detector_sanitised_v1.csv` |
| `analyze_condition_c.py` | condition-C decomposition, floor replay, verdict-guard trade-off: `results/analysis/defences/` |
| `check_v2_runs.py`, `detector_shift.py`, `latency_tokens.py` | validity checks and summaries (no outcomes read) |

## Model settings

| Model | Where | Settings | Runs |
|---|---|---|---|
| claude-haiku-4-5-20251001 | Anthropic API | temperature 0, no thinking, max 512 tokens | 3 |
| gemma4:e2b, e4b, 12b; qwen3.5:9b | Ollama | temperature 0, seed 42, thinking off, JSON format | 1 |
| gemini-2.5-flash | Gemini API | temperature 0, thinking budget 0 | 3 |
| claude-haiku-5-5 | Anthropic API | thinking disabled; temperature not sent (the model rejects non-default values) | 3 |
| gemini-3.6-flash | Gemini API | thinking level MINIMAL; temperature not sent | 3 |

Every row stores the parameters actually sent; cloud rows also store the model version the API reports.
The local models give stable verdicts across runs, but their wording can vary with Ollama's prompt cache
(see the 19 Oct entry under Deviations).

## Docs

- [`docs/preregistration_v1.md`](docs/preregistration_v1.md): hypotheses, arms, analysis plan, deviations
- [`docs/threat_model.md`](docs/threat_model.md): attacker model, conditions, defences, measures
- [`docs/runner.md`](docs/runner.md): how the experiment runner works
- [`docs/pilot_notes.md`](docs/pilot_notes.md): pilot runs before the freeze
- [`data/README.md`](data/README.md): data description and known limitations

## Ethics and data

All attack traffic and payloads were run only inside our own isolated testbed; no third-party system was
targeted and no real user data was used. The SR-BH 2020 slice is a public dataset (CC0) used for a
descriptive external-validity check only. The paper describes payloads by family; their full texts are in
`payloads/payloads.csv`.
