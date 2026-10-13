"""Build the B-clean cases file: every payload case keeps its injected log, but its detector
columns (verdict, probability, severity, SHAP top 5) are taken from the same event's no-payload row.

This is the same join the runner does for condition BCLEAN (detector="clean"). The file is the frozen,
inspectable record of what BCLEAN shows the LLM, and a cross-check for the runner's BCLEAN rows.
Run BCLEAN itself with `--conditions BCLEAN` on injected_cases_v1.csv, not condition B on this file.

Usage:
    python scripts/make_bclean_cases.py
"""
import sys

import pandas as pd

SRC = "data/processed/injected_cases_v1.csv"
DST = "data/processed/injected_cases_bclean_v1.csv"
DETECTOR_COLUMNS = ["detector_verdict", "detector_proba", "detector_severity", "shap_top5"]

cases = pd.read_csv(SRC, keep_default_na=False)
clean = cases[cases["payload_id"] == "none"].set_index("event_id")
if clean.index.duplicated().any() or set(cases["event_id"]) - set(clean.index):
    sys.exit("Every event needs exactly one no-payload row")

out = cases.copy()
for c in DETECTOR_COLUMNS:
    out[c] = out["event_id"].map(clean[c])

# Checks: no-payload rows unchanged; Referer rows unchanged (the detector does not read the Referer)
changed = (out[DETECTOR_COLUMNS].astype(str) != cases[DETECTOR_COLUMNS].astype(str)).any(axis=1)
if changed[cases["payload_id"] == "none"].any():
    sys.exit("A no-payload row changed")
if changed[cases["target_field"] == "referer"].any():
    sys.exit("A Referer row changed; the detector should not read the Referer")

out.to_csv(DST, index=False)
print(f"Cases: {len(out)} ({(cases['payload_id'] != 'none').sum()} with payload)")
print("Detector block changed by the clean join, by field:")
print(changed[cases["payload_id"] != "none"].groupby(cases["target_field"]).agg(["sum", "size"]).to_string())
print(f"Saved: {DST}")
