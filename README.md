# Grounding LLM log analysis against prompt injection

TDK project by Bakhtier Abdullaev and The Hoang Tung Nguyen.

We test whether giving an LLM the verdict and SHAP attributions of a small ML detector
makes it harder to fool with prompt injection hidden in web server logs. Attackers control
fields like the URL and User-Agent, and an LLM that reads those logs can be told to call
an attack benign. We compare three setups (raw log only, log + detector output, and the
same with structural defences) on a local model (gemma4:e4b via Ollama) and a cloud model
(Claude Haiku 4.5).

## Repository layout

```
data/          frozen raw log, labelled events, experiment samples (see data/README.md)
docs/          threat model, runner usage, pilot notes
payloads/      the 30 prompt injection payloads
prompts/v1/    frozen system and user prompts for conditions A, B and C
results/       benchmark, pilot and experiment results
scripts/       parsing, sampling, detector, injected cases, benchmark, experiment runner
testbed/       isolated Docker testbed: nginx + small Flask app + traffic generators
```

## Setup

You need Python 3.11+, Docker Desktop, and Ollama for the local model.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

For Claude, put your API key in `.env` (not committed): `ANTHROPIC_API_KEY=...`

## How to reproduce

1. **Generate traffic** (optional, the frozen log is already in `data/frozen/`):
```bash
   cd testbed
   docker compose up -d --build
   docker compose exec benign python benign.py 500
   docker compose exec attacker python attack.py 50
```
   The testbed network is internal, so nothing leaves the Docker network.

2. **Parse and label the log:**
```bash
   python scripts/parse_logs.py
   python scripts/sample_events.py
```

3. **Detector and injected cases:**
```bash
   python scripts/train_detector.py
   python scripts/make_injected_cases.py
   python scripts/make_benign_control.py
```

4. **Run the experiment** (see `docs/runner.md` for all options):
```bash
   python scripts/run_experiment.py --cases data/processed/injected_cases_v1.csv \
     --prompts prompts/v1 --model gemma4:e4b --runs 3 --out results/runs/gemma4_e4b.csv
```

## Settings used

- Local: gemma4:e4b, temperature 0, seed 42, thinking off
- Cloud: claude-haiku-4-5-20251001, temperature 0, thinking off
- 48 attack events x (30 payloads + 1 clean), 48 benign control events, 3 conditions, 3 runs
- Every result row stores the prompt version and a hash of the prompt files

## Docs

- `docs/threat_model.md`: attacker model, conditions, defences, measures
- `docs/runner.md`: how the experiment runner works
- `docs/pilot_notes.md`: pilot runs before the freeze
- `data/README.md`: dataset description and known limitations

## Ethics

All attack traffic and payloads were run only inside our own isolated testbed.
No third-party system was targeted and no real user data was used.
