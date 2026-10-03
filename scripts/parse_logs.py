import json
import sys
import pandas as pd

SRC = sys.argv[1] if len(sys.argv) > 1 else "data/frozen/access_v1.jsonl"
DST = "data/processed/events_labelled.csv"

BENIGN_IP = "172.28.0.10"
ATTACK_IP = "172.28.0.20"
EXPECTED = {"benign": 500, "attack": 200}

records = []
with open(SRC) as f:
    for line_no, line in enumerate(f, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as e:
            sys.exit(f"Dòng {line_no} không phải JSON hợp lệ: {e}")

df = pd.DataFrame(records)

df["label"] = df["remote_addr"].map({BENIGN_IP: "benign", ATTACK_IP: "attack"})
unknown = df[df["label"].isna()]
if len(unknown) > 0:
    sys.exit(f"Có {len(unknown)} dòng từ IP lạ: {unknown['remote_addr'].unique()}")

df["attack_type"] = df["exp_id"].str.split(":").str[0]
df.loc[df["label"] == "benign", "attack_type"] = "none"

LOG_FIELDS = ["time", "remote_addr", "method", "uri", "protocol", "status",
              "bytes", "referer", "user_agent", "request_time"]
df["raw_log"] = df[LOG_FIELDS].apply(
    lambda row: json.dumps(row.to_dict(), ensure_ascii=False), axis=1)

df = df.drop(columns=["exp_id"])
df = df.sort_values("time", kind="stable").reset_index(drop=True)
df.insert(0, "event_id", [f"ev{i:05d}" for i in range(len(df))])

counts = df["label"].value_counts().to_dict()
assert counts == EXPECTED, f"Sai số lượng: {counts}, mong đợi {EXPECTED}"
assert df["event_id"].is_unique
assert not df["raw_log"].str.contains("exp_id").any(), "raw_log còn chứa exp_id!"
assert not df["raw_log"].str.contains(r"benign:|sqli:|path_scan:|path_traversal:|scanner_ua:").any()

df.to_csv(DST, index=False)

print(f"Đã ghi {len(df)} sự kiện vào {DST}\n")
print("Theo nhãn:\n", df["label"].value_counts(), "\n")
print("Theo loại tấn công:\n", df["attack_type"].value_counts(), "\n")
print("Status code theo loại:\n", pd.crosstab(df["attack_type"], df["status"]), "\n")
print("Ví dụ mỗi loại:")
for t in ["none", "path_scan", "sqli", "path_traversal", "scanner_ua"]:
    row = df[df["attack_type"] == t].iloc[0]
    print(f"  [{t}] {row['method']} {row['uri'][:70]}  ->  {row['status']}  UA={row['user_agent'][:40]}")
