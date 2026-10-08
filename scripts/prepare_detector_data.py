import sys
import pandas as pd

SRC = "data/processed/events_labelled.csv"
DST = sys.argv[1] if len(sys.argv) > 1 else "data/processed/events_detector_v1.csv"

ATTACK_TYPES = ["path_scan", "sqli", "path_traversal", "scanner_ua"]
PER_TYPE = 50

# keep_default_na=False: empty referer / user_agent stay "" instead of NaN
df = pd.read_csv(SRC, keep_default_na=False)
assert len(df) == 700, f"Expected 700 events, got {len(df)}"

# Path traversal requests rejected by nginx (400) are logged with empty
# uri, user_agent and exp_id, so parse_logs.py left attack_type empty.
rejected = (df["label"] == "attack") & (df["attack_type"] == "")
assert (df.loc[rejected, "status"] == 400).all(), "Unexpected status in rejected rows"
assert (df.loc[rejected, "uri"] == "").all(), "Rejected rows should have empty uri"

df["nginx_rejected"] = rejected
df.loc[rejected, "attack_type"] = "path_traversal"

counts = df.loc[df["label"] == "attack", "attack_type"].value_counts().to_dict()
assert counts == {t: PER_TYPE for t in ATTACK_TYPES}, f"Wrong attack counts: {counts}"
assert (df.loc[df["label"] == "benign", "attack_type"] == "none").all()
assert not (df["attack_type"] == "").any()

df.to_csv(DST, index=False)

print(f"Wrote {len(df)} events to {DST}\n")
print("By label:\n", df["label"].value_counts(), "\n")
print("By attack type:\n", df["attack_type"].value_counts(), "\n")
print(f"nginx-rejected rows (no uri/UA, not usable as injection targets): {rejected.sum()}")