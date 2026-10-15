"""Sanitise-before-score: re-score the detector after condition C's input cleaning.

Condition C cleans the untrusted log fields (delimiter look-alikes neutralised, fields capped at
200 characters) only for the LLM. The detector, and so C's severity floor, scores the raw log.
This script scores every case twice with the same out-of-fold model: raw and cleaned. For each
payload case it also keeps both scores of the same event's no-payload control (four scores per case),
so a floor is "restored" only when the cleaned payload case reaches the control's raw severity.
Detector only: no LLM calls, and no verdict can change (pre-registration Section 6 item 7, Deviations h).

Usage:
    python scripts/rescore_sanitised.py
"""
import json

import joblib
import numpy as np
import pandas as pd

from run_experiment import MAX_FIELD_CHARS, SEVERITY_ORDER, sanitize_log
from train_detector import MODEL_DIR, N_FOLDS, extract_features, severity

CASES = "data/processed/injected_cases_v1.csv"
BENIGN = "data/processed/benign_control_v1.csv"
DETECTOR = "data/processed/detector_output_v1.csv"
DST = "data/processed/detector_sanitised_v1.csv"
RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def score(logs, folds):
    """Attack probability for each log JSON string, using the fold model that did not train on its event."""
    X = extract_features(pd.DataFrame([json.loads(s) for s in logs]))
    proba = np.full(len(logs), np.nan)
    for k in range(N_FOLDS):
        idx = np.where(folds == k)[0]
        if len(idx):
            model = joblib.load(f"{MODEL_DIR}/rf_fold{k}.joblib")
            proba[idx] = model.predict_proba(X.iloc[idx])[:, 1]
    assert not np.isnan(proba).any(), "Some rows have no fold"
    return proba.round(4), X


def main():
    cases = pd.concat([pd.read_csv(CASES, keep_default_na=False),
                       pd.read_csv(BENIGN, keep_default_na=False)], ignore_index=True)
    folds = pd.read_csv(DETECTOR, keep_default_na=False).set_index("event_id")["fold"]
    cases["fold"] = cases["event_id"].map(folds)
    assert cases["fold"].notna().all(), "Event without a fold"
    cases["is_benign_control"] = cases["detector_verdict"].eq("benign") & cases["payload_id"].eq("none")

    raw_logs = cases["injected_raw_log"]
    clean_logs = raw_logs.map(sanitize_log)
    f = cases["fold"].astype(int).to_numpy()
    cases["raw_proba"], X_raw = score(raw_logs, f)
    cases["clean_proba"], X_clean = score(clean_logs, f)

    # The raw re-score must reproduce the committed detector output (same models, same features)
    assert np.allclose(cases["raw_proba"], cases["detector_proba"].astype(float), atol=1e-4), \
        "Raw re-score differs from the committed detector output"

    cases["raw_severity"] = cases["raw_proba"].map(severity)
    cases["clean_severity"] = cases["clean_proba"].map(severity)
    for name, X in [("raw", X_raw), ("clean", X_clean)]:
        cases[f"{name}_ua_length"] = X["ua_length"].to_numpy()
        cases[f"{name}_uri_length"] = X["uri_length"].to_numpy()
    raw = pd.DataFrame([json.loads(s) for s in raw_logs])
    cases["ua_truncated"] = raw["user_agent"].str.len().gt(MAX_FIELD_CHARS).to_numpy()
    cases["uri_truncated"] = raw["uri"].str.len().gt(MAX_FIELD_CHARS).to_numpy()

    # The same event's no-payload control, raw and cleaned
    ctrl = cases[cases["payload_id"].eq("none")].set_index("event_id")
    for col in ["raw_proba", "raw_severity", "clean_proba", "clean_severity"]:
        cases[f"control_{col}"] = cases["event_id"].map(ctrl[col])

    out_cols = ["case_id", "event_id", "attack_type", "payload_id", "payload_category", "target_field",
                "fold", "is_benign_control", "raw_proba", "raw_severity", "clean_proba", "clean_severity",
                "control_raw_proba", "control_raw_severity", "control_clean_proba", "control_clean_severity",
                "raw_ua_length", "clean_ua_length", "raw_uri_length", "clean_uri_length",
                "ua_truncated", "uri_truncated"]
    cases[out_cols].to_csv(DST, index=False)
    print(f"Saved: {DST} ({len(cases)} rows)")
    summarise(cases)


def summarise(cases):
    r = lambda col: cases[col].map(RANK)
    pay = cases[cases["payload_id"] != "none"]
    ctrl_att = cases[cases["payload_id"].eq("none") & ~cases["is_benign_control"]]
    benign = cases[cases["is_benign_control"]]

    print("\nTruncated by the 200-character cap (payload cases):")
    print(pay.groupby("target_field")[["ua_truncated", "uri_truncated"]].sum().to_string())
    print(f"No-payload attack controls truncated: UA {int(ctrl_att['ua_truncated'].sum())}, "
          f"URI {int(ctrl_att['uri_truncated'].sum())} of {len(ctrl_att)}")

    sel = pay.assign(degraded=r("raw_severity").loc[pay.index] < r("control_raw_severity").loc[pay.index],
                     restored=r("clean_severity").loc[pay.index] >= r("control_raw_severity").loc[pay.index],
                     gap_vs_clean_ctrl=r("clean_severity").loc[pay.index] < r("control_clean_severity").loc[pay.index])
    print("\nFloor anchor per payload field (severity vs the event's raw control severity):")
    rows = []
    for field, g in sel.groupby("target_field"):
        d = g[g["degraded"]]
        rows.append({"field": field, "cases": len(g), "degraded_raw": int(g["degraded"].sum()),
                     "degraded_restored_by_cleaning": int(d["restored"].sum()),
                     "below_raw_control_after_cleaning": int((~g["restored"]).sum()),
                     "below_cleaned_control": int(g["gap_vs_clean_ctrl"].sum()),
                     "mean_raw_proba": round(g["raw_proba"].mean(), 3),
                     "mean_clean_proba": round(g["clean_proba"].mean(), 3)})
    print(pd.DataFrame(rows).to_string(index=False))

    print("\nSeverity transitions raw -> cleaned, payload cases:")
    print(pd.crosstab(pay["raw_severity"], pay["clean_severity"]).to_string())
    print("\nCleaning on clean inputs (the detector never saw cleaned inputs in training):")
    print(f"  attack controls changed severity: {int((ctrl_att['raw_severity'] != ctrl_att['clean_severity']).sum())} of {len(ctrl_att)}")
    print(f"  attacks scored benign after cleaning: payload {int((pay['clean_proba'] < 0.5).sum())} of {len(pay)}, "
          f"controls {int((ctrl_att['clean_proba'] < 0.5).sum())} of {len(ctrl_att)}")
    print(f"  benign controls scored attack after cleaning: {int((benign['clean_proba'] >= 0.5).sum())} of {len(benign)} "
          f"(raw: {int((benign['raw_proba'] >= 0.5).sum())})")


if __name__ == "__main__":
    main()
