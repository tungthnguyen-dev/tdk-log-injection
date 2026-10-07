"""Parse the frozen nginx JSON log into a labelled events CSV.

Labels come from the source IP (benign vs attack generator); the attack class
comes from the internal X-Exp-Id header, which is removed from the output.

Usage:
    python scripts/parse_logs.py [path_to_jsonl]
"""
import json
import sys

import pandas as pd

SRC = sys.argv[1] if len(sys.argv) > 1 else "data/frozen/access_v1.jsonl"
DST = "data/processed/events_labelled.csv"

BENIGN_IP = "172.28.0.10"
ATTACK_IP = "172.28.0.20"
EXPECTED = {"benign": 500, "attack": 200}

# 1. Read the log: one JSON object per line
records = []
with open(SRC) as f:
    for line_no, line in enumerate(f, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as e:
            sys.exit(f"Line {line_no} is not valid JSON: {e}")

df = pd.DataFrame(records)

# 2. Label from source IP
df["label"] = df["remote_addr"].map({BENIGN_IP: "benign", ATTACK_IP: "attack"})
unknown = df[df["label"].isna()]
if len(unknown) > 0:
    sys.exit(f"{len(unknown)} rows from unknown IPs: {unknown['remote_addr'].unique()}")

# 3. Attack class from exp_id, e.g. "sqli:57" -> "sqli"
df["attack_type"] = df["exp_id"].str.split(":").str[0]
df.loc[df["label"] == "benign", "attack_type"] = "none"

# Requests rejected by nginx while parsing the request line (status 400)
# are logged without URI or headers, so exp_id is empty. attack.py runs the
# classes in order (path_scan, sqli, path_traversal, scanner_ua), and only
# path traversal payloads are rejected this way.
rejected = (df["label"] == "attack") & (df["exp_id"].fillna("") == "")
assert (df.loc[rejected, "status"] == 400).all(), "Attack rows without exp_id that are not 400"
last_sqli = df.loc[df["attack_type"] == "sqli", "time"].max()
first_scanner_ua = df.loc[df["attack_type"] == "scanner_ua", "time"].min()
assert df.loc[rejected, "time"].between(last_sqli, first_scanner_ua).all(), \
    "Rejected rows fall outside the path traversal phase"
df["nginx_rejected"] = rejected
df.loc[rejected, "attack_type"] = "path_traversal"
print(f"Rows rejected by nginx (no URI/headers logged): {rejected.sum()}")

# 4. Original log line for the LLM, WITHOUT exp_id so the label is not leaked
LOG_FIELDS = ["time", "remote_addr", "method", "uri", "protocol", "status",
              "bytes", "referer", "user_agent", "request_time"]
df["raw_log"] = df[LOG_FIELDS].apply(
    lambda row: json.dumps(row.to_dict(), ensure_ascii=False), axis=1)

# 5. Drop exp_id, sort by time, assign event ids
df = df.drop(columns=["exp_id"])
df = df.sort_values("time", kind="stable").reset_index(drop=True)
df.insert(0, "event_id", [f"ev{i:05d}" for i in range(len(df))])

# 6. Quality checks
counts = df["label"].value_counts().to_dict()
assert counts == EXPECTED, f"Wrong counts: {counts}, expected {EXPECTED}"
assert df["event_id"].is_unique
assert not df["raw_log"].str.contains("exp_id").any(), "raw_log still contains exp_id"
assert not df["raw_log"].str.contains(r"benign:|sqli:|path_scan:|path_traversal:|scanner_ua:").any()

# 7. Write CSV
df.to_csv(DST, index=False)

# 8. Summary
print(f"Wrote {len(df)} events to {DST}\n")
print("By label:\n", df["label"].value_counts(), "\n")
print("By attack type:\n", df["attack_type"].value_counts(), "\n")
print("Status codes by type:\n", pd.crosstab(df["attack_type"], df["status"]), "\n")
print("One example per type (excluding nginx-rejected rows):")
for t in ["none", "path_scan", "sqli", "path_traversal", "scanner_ua"]:
    row = df[(df["attack_type"] == t) & ~df["nginx_rejected"]].iloc[0]
    print(f"  [{t}] {row['method']} {row['uri'][:70]}  ->  {row['status']}  UA={row['user_agent'][:40]}")
