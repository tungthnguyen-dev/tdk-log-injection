"""Select the stratified subset used for the model ladder and the extra arms.

Design: choose a subset of PAYLOADS and keep ALL 48 events, so every event sees the
same payloads (balanced event x payload design) and every event keeps its clean row.
Payloads are stratified by family: the five single-payload "naive_*" categories are
grouped into one "naive" family, then N_PER_FAMILY payloads are drawn per family.
Selection uses case metadata only, never results.

Usage:
    python scripts/make_subset.py
"""
import sys

import pandas as pd

SEED = 42
N_PER_FAMILY = 2
SRC = "data/processed/injected_cases_v1.csv"
DST_IDS = "data/processed/subset_v1_case_ids.csv"
DST_CASES = "data/processed/injected_cases_subset_v1.csv"
DST_PAYLOADS = "data/processed/subset_v1_payloads.csv"

cases = pd.read_csv(SRC, keep_default_na=False)

# One row per payload, with its family and target field
payloads = (cases[cases["payload_id"] != "none"]
            [["payload_id", "payload_category", "target_field"]]
            .drop_duplicates()
            .sort_values("payload_id"))
payloads["family"] = payloads["payload_category"].where(
    ~payloads["payload_category"].str.startswith("naive"), "naive")

print(f"Payloads: {len(payloads)}")
print(payloads.groupby("family").size().to_string(), "\n")

# Stratified draw: N_PER_FAMILY payloads from each family
chosen = (payloads.groupby("family", group_keys=False)
          .sample(n=N_PER_FAMILY, random_state=SEED)
          .sort_values("payload_id"))

# Every target field must be represented (Referer is the detector-blind control)
missing = set(payloads["target_field"]) - set(chosen["target_field"])
if missing:
    sys.exit(f"Subset misses target field(s) {missing}; discuss before changing the rule.")

# All events: clean rows + chosen payloads
subset = cases[(cases["payload_id"] == "none") | cases["payload_id"].isin(chosen["payload_id"])]

chosen.to_csv(DST_PAYLOADS, index=False)
subset[["case_id"]].to_csv(DST_IDS, index=False)
subset.to_csv(DST_CASES, index=False)

print("Chosen payloads:")
print(chosen.to_string(index=False), "\n")
print("By target field:", chosen["target_field"].value_counts().to_dict())
print(f"Events: {subset['event_id'].nunique()}, cases: {len(subset)} "
      f"({(subset['payload_id'] != 'none').sum()} with payload + "
      f"{(subset['payload_id'] == 'none').sum()} clean)")
print(f"Saved: {DST_PAYLOADS}, {DST_IDS}, {DST_CASES}")
