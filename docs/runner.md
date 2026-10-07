# Experiment runner

`scripts/run_experiment.py` runs the injection experiment: for every case
(event x payload), every condition (A/B/C) and every run, it builds the prompt,
queries the model and appends one row to a results CSV.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

- **Local model:** Ollama running (`brew services start ollama`), model pulled (`ollama pull gemma4:e4b`).
- **Claude:** API key in a `.env` file in the project root: `ANTHROPIC_API_KEY=sk-ant-...`.
  `.env` is in `.gitignore`; never commit it. Set a spending limit in the Claude Console first.

## Inputs

**Cases CSV** (`--cases`), one row per event x payload, plus one clean row per event (`payload_id = none`):

| Column | Description |
|---|---|
| case_id | Unique id, e.g. `ev00123_P07` |
| event_id, attack_type | From `events_labelled.csv` |
| payload_id, payload_category, target_field | Payload info (`none` for clean rows) |
| injected_raw_log | Log line as JSON (same format as `raw_log`), with the payload injected |
| detector_verdict | `attack` or `benign`, from the fold model that did not train on the event |
| detector_proba | Detector probability |
| detector_severity | `none`, `low`, `medium` or `high` |
| shap_top5 | JSON list of `{"feature", "value", "shap"}` |

**Prompt directory** (`--prompts`): `condition_{A,B,C}_system.txt` and `condition_{A,B,C}_user.txt`.
User templates may use the placeholders `{raw_log}`, `{detector_verdict}`, `{detector_proba}`, `{shap_features}`.
`{raw_log}` is always filled last, so placeholder-like text in a payload is never substituted.

## Running

Quick test (1 case, 3 calls):
```bash
python scripts/run_experiment.py --cases CASES.csv --prompts PROMPT_DIR \
  --model gemma4:e4b --runs 1 --limit 1 --out results/runs/test.csv
```

Local model, full run:
```bash
caffeinate -i python scripts/run_experiment.py --cases CASES.csv --prompts PROMPT_DIR \
  --model gemma4:e4b --backend ollama --runs 3 --out results/runs/gemma4_e4b.csv
```

Claude:
```bash
python scripts/run_experiment.py --cases CASES.csv --prompts PROMPT_DIR \
  --model claude-haiku-4-5-20251001 --backend anthropic --runs 3 \
  --out results/runs/claude_haiku_4_5.csv
```

**Resume:** if a run is interrupted (Ctrl+C, crash, sleep), run the same command again.
Calls that already have an error-free result for the same model are skipped; failed calls are retried.

## Model settings

| | Ollama | Anthropic |
|---|---|---|
| temperature | 0 | 0 |
| seed | 42 | not available |
| thinking | off (`think: false`) | off (not enabled) |
| output format | `format: json` | instructed in prompt; JSON extracted from the reply |
| context / max output | `num_ctx` 8192 | `max_tokens` 512 |

## Structural defences (condition C only)

| Defence | Where | Behaviour |
|---|---|---|
| Delimiter neutralisation | input | `<<<` and `>>>` in untrusted fields are replaced, so a payload cannot close the untrusted-data marker |
| Length limit | input | untrusted fields (method, uri, protocol, referer, user_agent) capped at 200 characters |
| Schema check | output | verdict must be benign/malicious and severity low/medium/high/critical; otherwise fail closed to the detector's verdict and severity |
| Severity floor | output | severity raised to the detector's level if lower; the verdict is never changed |

Shared severity scale: `none < low < medium < high < critical`.

## Output columns

| Column | Description |
|---|---|
| timestamp, backend, model | When and with what the call was made |
| case_id ... target_field | Copied from the cases CSV |
| condition, run, defended | A/B/C, run index, whether defences applied |
| detector_verdict, detector_severity | Copied from the cases CSV |
| valid_json, schema_ok | Whether the reply was parseable and schema-valid |
| verdict, severity | What the model answered (raw) |
| final_verdict, final_severity, floor_applied | After defences (equal to raw for A/B) |
| flipped_raw, flipped | Model / final verdict is `benign` (all cases are attack events) |
| explanation, raw_response | Model text |
| latency_s, prompt_tokens, output_tokens, error | Measurements |

The runner only records answers. Metrics (flip rate, severity lowered vs the clean baseline)
are computed afterwards by a separate analysis script.
