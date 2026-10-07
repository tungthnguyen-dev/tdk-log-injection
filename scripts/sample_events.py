"""Select a stratified, reproducible sample of attack events for the injection experiment.

Only events with logged attacker-controlled fields are eligible: rows rejected
by nginx (no URI/headers logged) cannot carry an injected payload.

Usage:
    python scripts/sample_events.py [n_per_type]
"""
import sys

import pandas as pd

N_PER_TYPE = int(sys.argv[1]) if len(sys.argv) > 1 else 12
SEED = 42
SRC = "data/processed/events_labelled.csv"
DST = "data/processed/experiment_events.csv"

df = pd.read_csv(SRC)

# Eligible: attack events that nginx did not reject
eligible = df[(df["label"] == "attack") & (~df["nginx_rejected"])]

available = eligible["attack_type"].value_counts()
if (available < N_PER_TYPE).any():
    sys.exit(f"Not enough eligible events per type for n={N_PER_TYPE}:\n{available.to_string()}")

# Same number of events from each attack type
sample = (
    eligible.groupby("attack_type", group_keys=False)
    .sample(n=N_PER_TYPE, random_state=SEED)
    .sort_values("event_id")
)

sample[["event_id", "attack_type"]].to_csv(DST, index=False)

print(f"Eligible attack events per type:\n{available.to_string()}\n")
print(f"Selected {len(sample)} events ({N_PER_TYPE} per type), seed {SEED}:")
print(sample["attack_type"].value_counts().to_string())
print(f"\nSaved to {DST}")
