import argparse
import json
import os
from urllib.parse import unquote

import pandas as pd

SRC = "data/external/srbh/data_capec_multilabel.csv"
OUT_DIR = "data/processed/srbh"
SEED = 42
TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"     # Apache style, e.g. 17/Jul/2020:12:23:34 +0100

CLASSES = {
    "000 - Normal": "benign",
    "66 - SQL Injection": "sqli",
    "126 - Path Traversal": "path_traversal",
    "310 - Scanning for Vulnerable Software": "path_scan",
}

# Obvious attack patterns, checked on the lower-cased raw URI and User-Agent.
SUSPECT_URI = [r"\.\./", r"\.\.%2f", r"%2e%2e", r"%2f\.\.", r"%5c\.\.", r"etc%2fpasswd", r"etc/passwd",
               r"union.{0,20}select", r"select.{0,40}from", r"sleep\(", r"%27", r"%22\+and",
               r"<script", r"%3cscript"]
SUSPECT_UA = ["sqlmap", "nikto", "nmap", "gobuster", "dirbuster", "wfuzz", "masscan", "zgrab"]


def parse_args():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--src", default=SRC)
    p.add_argument("--n-benign", type=int, default=250)
    p.add_argument("--n-attack", type=int, default=250)
    return p.parse_args()


def load(src):
    df = pd.read_csv(src, low_memory=False)
    df["srbh_row"] = df.index                       # row number in the original file
    label_cols = [c for c in df.columns if c[:3].strip().isdigit()]
    df = df[df[label_cols].sum(axis=1) == 1]        # single-label rows only
    df = df[df[list(CLASSES)].sum(axis=1) == 1]     # ...and in one of our classes
    df["attack_type"] = df[list(CLASSES)].idxmax(axis=1).map(CLASSES)
    return df


def suspect_normal(df):
    uri = df["request_http_request"].astype(str).str.lower()
    ua = df["request_user_agent"].fillna("").astype(str).str.lower()
    bad = uri.str.contains("|".join(SUSPECT_URI), regex=True)
    bad |= ua.str.contains("|".join(SUSPECT_UA), regex=True)
    return bad


def to_log(row):
    """One SR-BH row in the testbed's log format (see data/frozen/access_v1.jsonl)."""
    t = pd.to_datetime(row["timestamp"], format=TIME_FORMAT, errors="coerce", utc=True)
    return {
        "time": t.isoformat() if pd.notna(t) else str(row["timestamp"]),
        "remote_addr": str(row["src_ip"]),
        "method": str(row["request_http_method"]),
        "uri": str(row["request_http_request"]),
        "protocol": str(row["request_http_protocol"]),
        "status": int(row["response_http_status_code"]),
        "bytes": int(row["response_content_length"]) if pd.notna(row["response_content_length"]) else 0,
        "referer": "" if pd.isna(row["request_referer"]) else str(row["request_referer"]),
        "user_agent": "" if pd.isna(row["request_user_agent"]) else str(row["request_user_agent"]),
        "request_time": None,                       # not in SR-BH; not a detector feature
        "exp_id": f"srbh:{row['attack_type']}:{row['srbh_row']}",
        "srbh_row": int(row["srbh_row"]),
        "label": "benign" if row["attack_type"] == "benign" else "attack",
        "attack_type": row["attack_type"],
        "cv_group": row["cv_group"],
    }


def main():
    args = parse_args()
    df = load(args.src)
    print("Single-label rows per class:", df["attack_type"].value_counts().to_dict())

    df = df[df["response_http_status_code"].notna()]
    df = df.drop_duplicates(subset=["request_http_method", "request_http_request", "request_user_agent"])
    print("After dropping duplicate requests:", df["attack_type"].value_counts().to_dict())

    is_benign = df["attack_type"] == "benign"
    bad = suspect_normal(df) & is_benign
    print(f"Removed {int(bad.sum())} of {int(is_benign.sum())} 'Normal' rows "
          f"({bad.sum() / is_benign.sum():.1%}) with obvious attack patterns. Matches per pattern:")
    normal = df[is_benign]
    uri = normal["request_http_request"].astype(str).str.lower()
    ua = normal["request_user_agent"].fillna("").astype(str).str.lower()
    for pat in SUSPECT_URI:
        print(f"    uri {pat:20s} {int(uri.str.contains(pat, regex=True).sum()):7d}")
    for tok in SUSPECT_UA:
        print(f"    ua  {tok:20s} {int(ua.str.contains(tok, regex=False).sum()):7d}")
    df = df[~bad]

    t = pd.to_datetime(df["timestamp"], format=TIME_FORMAT, errors="coerce", utc=True)
    if t.isna().mean() > 0.01:
        raise SystemExit("Could not parse most timestamps; check the timestamp format")
    df = df.assign(cv_group=t.dt.strftime("%Y-%m-%dT%H"))

    attack_types = ["sqli", "path_traversal", "path_scan"]
    per_class = [args.n_attack // 3 + (1 if i < args.n_attack % 3 else 0) for i in range(3)]
    parts = [df[df["attack_type"] == "benign"].sample(args.n_benign, random_state=SEED)]
    for at, n in zip(attack_types, per_class):
        pool = df[df["attack_type"] == at]
        if len(pool) < n:
            raise SystemExit(f"Only {len(pool)} {at} rows available, need {n}")
        parts.append(pool.sample(n, random_state=SEED))
    sample = pd.concat(parts).sort_values("srbh_row")

    os.makedirs(OUT_DIR, exist_ok=True)
    jsonl = os.path.join(OUT_DIR, "srbh_slice_v1.jsonl")
    with open(jsonl, "w") as f:
        for _, row in sample.iterrows():
            f.write(json.dumps(to_log(row), ensure_ascii=False) + "\n")

    check = pd.DataFrame({
        "srbh_row": sample["srbh_row"],
        "srbh_label": sample["attack_type"],
        "method": sample["request_http_method"],
        "status": sample["response_http_status_code"].astype(int),
        "uri_decoded": sample["request_http_request"].astype(str).map(unquote),
        "user_agent": sample["request_user_agent"],
        "referer": sample["request_referer"],
        "check_tung": "",        # agree / disagree / unsure
        "check_bakhtier": "",
        "note": "",
    })
    check_csv = os.path.join(OUT_DIR, "srbh_label_check_v1.csv")
    check.to_csv(check_csv, index=False)

    print(f"\nWrote {len(sample)} events to {jsonl}")
    print(sample["attack_type"].value_counts().to_string())
    print(f"Distinct cv_groups: {sample['cv_group'].nunique()}")
    print(f"Label check sheet: {check_csv}")


if __name__ == "__main__":
    main()