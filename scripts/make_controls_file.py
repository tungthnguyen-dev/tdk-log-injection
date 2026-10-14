"""Build the cases file for the DWRONG arm: the 48 no-payload attack controls plus the 48 benign
controls, with their real detector output. The runner reverses that output for condition DWRONG.

Usage:
    python scripts/make_controls_file.py
"""
import sys

import pandas as pd

ATTACK = "data/processed/injected_cases_v1.csv"
BENIGN = "data/processed/benign_control_v1.csv"
DST = "data/processed/controls_v1.csv"

attack = pd.read_csv(ATTACK, keep_default_na=False)
benign = pd.read_csv(BENIGN, keep_default_na=False)
if list(attack.columns) != list(benign.columns):
    sys.exit("The two files have different columns")

controls = pd.concat([attack[attack["payload_id"] == "none"], benign], ignore_index=True)
if controls["case_id"].duplicated().any():
    sys.exit("Duplicate case_id between attack and benign controls")

controls.to_csv(DST, index=False)
print(f"Controls: {len(controls)} "
      f"({(controls['detector_verdict'] == 'attack').sum()} attack, "
      f"{(controls['detector_verdict'] == 'benign').sum()} benign by the detector)")
print(f"Saved: {DST}")
