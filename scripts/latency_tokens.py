"""Latency and token counts per local model and condition (no outcomes are read).

Reads the local-model result CSVs that exist and writes
results/summary/latency_tokens_local.csv with, per file and condition:
rows, median and mean latency (s), and mean prompt / output tokens where the file has them
(the v1 A/B/C files were made by the older runner and may lack token columns).

Usage:
    python scripts/latency_tokens.py
"""
import glob
import os

import pandas as pd

PATTERNS = ["results/runs/gemma4_e2b*.csv", "results/runs/gemma4_e4b*.csv",
            "results/runs/gemma4_12b*.csv", "results/runs/qwen3.5_9b*.csv"]
OUT = "results/summary/latency_tokens_local.csv"
KEEP = ["condition", "latency_s", "prompt_tokens", "output_tokens"]   # nothing else is loaded

rows = []
for path in sorted(p for pat in PATTERNS for p in glob.glob(pat)):
    cols = pd.read_csv(path, nrows=0).columns
    if "latency_s" not in cols:
        print(f"skip (no latency_s column): {path}")
        continue
    d = pd.read_csv(path, usecols=[c for c in KEEP if c in cols])
    for cond, g in d.groupby("condition"):
        rows.append({
            "file": os.path.basename(path),
            "condition": cond,
            "rows": len(g),
            "latency_median_s": round(g["latency_s"].median(), 2),
            "latency_mean_s": round(g["latency_s"].mean(), 2),
            "prompt_tokens_mean": round(g["prompt_tokens"].mean(), 1) if "prompt_tokens" in g else None,
            "output_tokens_mean": round(g["output_tokens"].mean(), 1) if "output_tokens" in g else None,
        })

out = pd.DataFrame(rows)
os.makedirs(os.path.dirname(OUT), exist_ok=True)
out.to_csv(OUT, index=False)
print(out.to_string(index=False))
print(f"\nWrote {OUT}")
