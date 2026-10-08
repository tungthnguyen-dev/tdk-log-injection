"""Build the cases file for the runner: 48 experiment events x (1 clean + 30 payloads).

Each row is scored by the detector fold model that did not train on that event,
so injected cases keep the out-of-fold property.

Usage:
    python scripts/make_injected_cases.py
"""
import json
import os
from urllib.parse import quote

import joblib
import numpy as np
import pandas as pd
import shap

from train_detector import MODEL_DIR, N_FOLDS, attack_shap, extract_features, severity, top5

EVENTS = "data/processed/events_labelled.csv"
SAMPLE = "data/processed/experiment_events.csv"
PAYLOADS = "payloads/payloads.csv"
DETECTOR = "data/processed/detector_output_v1.csv"
DST = "data/processed/injected_cases_v1.csv"
EVASION = "results/detector_evasion_v1.csv"

COLUMNS = ["case_id", "event_id", "attack_type", "payload_id", "payload_category",
           "target_field", "injected_raw_log", "detector_verdict", "detector_proba",
           "detector_severity", "shap_top5"]


def inject(raw_log, field, text):
    """Put the payload into one client-controlled field, keeping the raw_log JSON format."""
    log = json.loads(raw_log)
    if field == "user_agent":
        log["user_agent"] = f"{log['user_agent']} {text}"   # appended, original UA kept
    elif field == "referer":
        log["referer"] = text                                # empty in all 48 events
    elif field == "uri":
        sep = "&" if "?" in log["uri"] else "?"              # 19 of 48 URIs already have a query
        log["uri"] = f"{log['uri']}{sep}note={quote(text, safe='')}"
    else:
        raise ValueError(f"Unknown target_field: {field}")
    return json.dumps(log)


def build_cases(events, payloads):
    """One clean row plus one row per payload for every event."""
    rows = []
    for _, ev in events.iterrows():
        base = {"event_id": ev["event_id"], "attack_type": ev["attack_type"], "fold": ev["fold"]}
        rows.append({**base, "case_id": f"{ev['event_id']}_none", "payload_id": "none",
                     "payload_category": "none", "target_field": "none",
                     "injected_raw_log": ev["raw_log"]})
        for _, p in payloads.iterrows():
            rows.append({**base, "case_id": f"{ev['event_id']}_{p['payload_id']}",
                         "payload_id": p["payload_id"], "payload_category": p["payload_category"],
                         "target_field": p["target_field"],
                         "injected_raw_log": inject(ev["raw_log"], p["target_field"], p["text"])})
    return pd.DataFrame(rows)


def score(cases):
    """Score every case with the fold model that did not train on its event."""
    X = extract_features(pd.DataFrame([json.loads(s) for s in cases["injected_raw_log"]]))
    proba = np.zeros(len(cases))
    shap_top5 = [""] * len(cases)
    for k in range(N_FOLDS):
        idx = np.where(cases["fold"].to_numpy() == k)[0]
        if len(idx) == 0:
            continue
        model = joblib.load(f"{MODEL_DIR}/rf_fold{k}.joblib")
        Xk = X.iloc[idx]
        proba[idx] = model.predict_proba(Xk)[:, 1]
        sv = attack_shap(shap.TreeExplainer(model), Xk)
        for row, i in enumerate(idx):
            shap_top5[i] = top5(Xk.iloc[row].to_numpy(), sv[row])
    cases["detector_verdict"] = np.where(proba >= 0.5, "attack", "benign")
    cases["detector_proba"] = proba.round(4)
    cases["detector_severity"] = [severity(p) for p in proba]
    cases["shap_top5"] = shap_top5
    return cases


def check(cases, events, detector):
    assert len(cases) == 48 * 31 == 1488, f"Expected 1488 rows, got {len(cases)}"
    assert cases["case_id"].is_unique, "Duplicate case_id"
    for s in cases["injected_raw_log"]:
        json.loads(s)                                        # every row is valid JSON

    # Clean rows must reproduce the committed detector output exactly
    clean = cases[cases["payload_id"] == "none"].merge(
        detector, on="event_id", suffixes=("", "_ref"))
    for col in ["detector_verdict", "detector_severity", "shap_top5"]:
        assert (clean[col] == clean[f"{col}_ref"]).all(), f"Clean rows differ in {col}"
    assert np.allclose(clean["detector_proba"], clean["detector_proba_ref"]), "Clean rows differ in proba"

    # A user_agent payload must not change the URI
    ua = cases[cases["target_field"] == "user_agent"].merge(
        events[["event_id", "raw_log"]], on="event_id")
    assert all(json.loads(a)["uri"] == json.loads(b)["uri"]
               for a, b in zip(ua["injected_raw_log"], ua["raw_log"])), "UA injection changed a URI"


def main():
    events = pd.read_csv(EVENTS, keep_default_na=False)
    sample = pd.read_csv(SAMPLE)
    payloads = pd.read_csv(PAYLOADS, keep_default_na=False)
    detector = pd.read_csv(DETECTOR, keep_default_na=False)

    events = (sample[["event_id"]]
              .merge(events[["event_id", "attack_type", "raw_log"]], on="event_id")
              .merge(detector[["event_id", "fold"]], on="event_id"))
    assert len(events) == 48, f"Expected 48 events, got {len(events)}"
    assert len(payloads) == 30, f"Expected 30 payloads, got {len(payloads)}"

    cases = score(build_cases(events, payloads))
    check(cases, events, detector)

    cases[COLUMNS].to_csv(DST, index=False)
    print(f"Wrote {len(cases)} cases to {DST} (all checks passed)")

    # How often the payload alone makes the detector say benign
    injected = cases[cases["payload_id"] != "none"]
    evasion = (injected.assign(detector_benign=injected["detector_verdict"] == "benign")
               .groupby(["target_field", "payload_category"])["detector_benign"].mean().round(3))
    os.makedirs(os.path.dirname(EVASION), exist_ok=True)
    evasion.to_csv(EVASION)
    print(f"\nShare of injected cases the detector calls benign (saved to {EVASION}):")
    print(evasion.to_string())


if __name__ == "__main__":
    main()