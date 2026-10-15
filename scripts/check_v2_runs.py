"""Validity check for result CSVs, without looking at any outcome.

Prints per file: rows (against the expected count), rows per condition, error rows,
runner commits, prompt hashes and model digests. It never prints verdicts, outcomes or flips,
so blind arms stay blind.

Usage:
    python scripts/check_v2_runs.py results/runs/gemma4_e4b_v2_bclean.csv:1488 ...
    (the ":N" part is optional)
"""
import sys

import pandas as pd

ok = True
for arg in sys.argv[1:]:
    path, _, expected = arg.partition(":")
    d = pd.read_csv(path, dtype=str, keep_default_na=False)
    n = len(d)
    errors = int((d["error"].str.strip() != "").sum()) if "error" in d else "no error column"
    commits = sorted(d["runner_commit"].unique()) if "runner_commit" in d else []
    hashes = sorted(d["prompt_hash"].unique()) if "prompt_hash" in d else []
    digests = sorted(d["model_digest"].unique()) if "model_digest" in d else []
    print(f"\n{path}")
    print(f"  rows: {n}" + (f" (expected {expected})" if expected else ""))
    print(f"  rows per condition: {d['condition'].value_counts().sort_index().to_dict()}")
    print(f"  error rows: {errors}")
    print(f"  runner_commit: {commits}")
    print(f"  prompt_hash: {hashes}")
    print(f"  model_digest: {[x[:12] for x in digests]}")
    if expected and n != int(expected):
        ok = False
    if errors not in (0, "no error column"):
        ok = False
    if any("dirty" in c or c in ("", "unknown") for c in commits):
        ok = False

print("\nALL OK" if ok else "\nCHECK THE LINES ABOVE")
