"""SR-BH 2020 external-validity slice: retrain the detector and build the runner's case files.

Descriptive only (docs/preregistration_v1.md, section 8). Steps:
  1. Keep the slice events whose dataset label was hand-checked as "agree"
     (data/processed/srbh/srbh_label_check_v1_bakhtier.csv; 79 benign + 248 attack).
  2. Rewrite each event as a raw_log with exactly the keys of the testbed's raw_log, so the LLM
     sees the same format. SR-BH-only fields (label, attack_type, srbh_row, cv_group) are never
     shown; exp_id, which holds the label in the slice file, is blanked.
  3. Retrain the testbed detector unchanged (same six features, RandomForest n_estimators=200,
     seed 42, from scripts/train_detector.py) with StratifiedGroupKFold(5) grouped by hour
     (cv_group), so one tool campaign never sits in both training and test folds.
     Out-of-fold verdict, probability, severity and SHAP top 5 for every event.
  4. Inject the 12 subset payloads (two per family) into every agree attack event, as
     scripts/make_injected_cases.py does, and score each case with the fold model that did not
     train on its event.

Writes
  data/processed/srbh/srbh_events_v1.csv            events used (event_id, labels, cv_group, raw_log)
  data/processed/srbh/srbh_detector_output_v1.csv   out-of-fold detector output per event
  results/detector_metrics_srbh_v1.json             detector metrics on SR-BH
  data/processed/srbh/srbh_cases_v1.csv             attack events x (none + 12 payloads)  -> A, B
  data/processed/srbh/srbh_cases_clean_v1.csv       attack events, no payload             -> C
  data/processed/srbh/srbh_benign_v1.csv            benign events, no payload             -> A, B, C
  results/summary/srbh_detector_shift_v1.csv        detector change caused by the payloads (inputs, not outcomes)

Usage:
    python scripts/make_srbh_cases.py
"""
import json
import os

import joblib
import numpy as np
import pandas as pd
import shap
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedGroupKFold

from make_injected_cases import COLUMNS, inject
from train_detector import FEATURES, N_FOLDS, SEED, attack_shap, extract_features, severity, top5

SLICE = "data/processed/srbh/srbh_slice_v1.jsonl"
LABELS = "data/processed/srbh/srbh_label_check_v1_bakhtier.csv"
TESTBED_EVENTS = "data/processed/events_labelled.csv"
TESTBED_BENIGN = "data/processed/benign_control_v1.csv"
PAYLOADS = "payloads/payloads.csv"
SUBSET_PAYLOADS = ["P01", "P02", "P07", "P10", "P13", "P15",
                   "P16", "P17", "P21", "P23", "P27", "P29"]     # pre-registration, section 2

OUT_DIR = "data/processed/srbh"
MODEL_DIR = "models/srbh"
METRICS = "results/detector_metrics_srbh_v1.json"
SHIFT = "results/summary/srbh_detector_shift_v1.csv"
ATTACK_TYPES = ["path_scan", "sqli", "path_traversal"]
SEV_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}


def load_events():
    slice_ = pd.DataFrame([json.loads(l) for l in open(SLICE)])
    labels = pd.read_csv(LABELS, keep_default_na=False)
    agree = labels.loc[labels["check"] == "agree", ["srbh_row"]]
    ev = slice_.merge(agree, on="srbh_row")
    assert len(ev) == len(agree) == 327, f"Expected 327 agree events, got {len(ev)}"

    # Same raw_log keys as the testbed, in the same order
    ref = json.loads(pd.read_csv(TESTBED_EVENTS, keep_default_na=False)["raw_log"].iloc[0])
    keys = list(ref)
    print("Testbed raw_log keys:", keys)
    if "exp_id" in keys:
        print(f"  testbed exp_id example: {ref['exp_id']!r} -> blanked for SR-BH (it holds the label there)")

    def raw_log(r):
        log = {k: r.get(k, "") for k in keys}
        if "exp_id" in log:
            log["exp_id"] = ""
        for k in ("uri", "user_agent", "referer"):
            if k in log and log[k] is None:
                log[k] = ""
        return json.dumps(log, ensure_ascii=False)

    ev["event_id"] = "srbh_" + ev["srbh_row"].astype(str)
    ev["raw_log"] = [raw_log(r) for r in ev.to_dict("records")]
    for col in ("uri", "user_agent"):
        ev[col] = ev[col].fillna("").astype(str)
    return ev.sort_values("srbh_row").reset_index(drop=True)


def train(ev):
    X = extract_features(ev)
    y = (ev["label"] == "attack").astype(int).to_numpy()
    groups = ev["cv_group"].to_numpy()
    cv = StratifiedGroupKFold(n_splits=N_FOLDS, shuffle=True, random_state=SEED)
    proba, fold, shap_top5 = np.zeros(len(ev)), np.zeros(len(ev), dtype=int), [""] * len(ev)
    os.makedirs(MODEL_DIR, exist_ok=True)
    for k, (tr, te) in enumerate(cv.split(X, y, groups)):
        model = RandomForestClassifier(n_estimators=200, random_state=SEED, n_jobs=-1)
        model.fit(X.iloc[tr], y[tr])
        joblib.dump(model, f"{MODEL_DIR}/rf_fold{k}.joblib")
        proba[te] = model.predict_proba(X.iloc[te])[:, 1]
        fold[te] = k
        sv = attack_shap(shap.TreeExplainer(model), X.iloc[te])
        for row, i in enumerate(te):
            shap_top5[i] = top5(X.iloc[te].iloc[row].to_numpy(), sv[row])
        print(f"  fold {k}: train {len(tr)}, test {len(te)} "
              f"({int(y[te].sum())} attack), {len(set(groups[te]))} hours")
    ev = ev.assign(fold=fold, detector_proba=proba.round(4),
                   detector_verdict=np.where(proba >= 0.5, "attack", "benign"),
                   detector_severity=[severity(p) for p in proba], shap_top5=shap_top5)

    pred = (proba >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    metrics = {
        "dataset": "SR-BH 2020 slice v1, hand-checked agree rows only",
        "n_events": int(len(ev)), "n_attack": int(y.sum()), "n_benign": int((1 - y).sum()),
        "precision": round(precision_score(y, pred), 4), "recall": round(recall_score(y, pred), 4),
        "f1": round(f1_score(y, pred), 4), "false_positive_rate": round(fp / (fp + tn), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "recall_by_attack_type": {t: round(float(pred[(ev["attack_type"] == t).to_numpy()].mean()), 4)
                                  for t in ATTACK_TYPES},
        "features": FEATURES,
        "model": f"RandomForestClassifier(n_estimators=200, random_state={SEED})",
        "cv": f"StratifiedGroupKFold(n_splits={N_FOLDS}) grouped by hour (cv_group), out-of-fold",
        "distinct_hours": int(ev["cv_group"].nunique()),
    }
    return ev, metrics


def score(cases):
    X = extract_features(pd.DataFrame([json.loads(s) for s in cases["injected_raw_log"]]).fillna(""))
    proba, shap_top5 = np.zeros(len(cases)), [""] * len(cases)
    for k in range(N_FOLDS):
        idx = np.where(cases["fold"].to_numpy() == k)[0]
        if len(idx) == 0:
            continue
        model = joblib.load(f"{MODEL_DIR}/rf_fold{k}.joblib")
        proba[idx] = model.predict_proba(X.iloc[idx])[:, 1]
        sv = attack_shap(shap.TreeExplainer(model), X.iloc[idx])
        for row, i in enumerate(idx):
            shap_top5[i] = top5(X.iloc[idx].iloc[row].to_numpy(), sv[row])
    return cases.assign(detector_verdict=np.where(proba >= 0.5, "attack", "benign"),
                        detector_proba=proba.round(4),
                        detector_severity=[severity(p) for p in proba], shap_top5=shap_top5)


def build_cases(events, payloads):
    rows = []
    for _, ev in events.iterrows():
        base = {"event_id": ev["event_id"], "attack_type": ev["attack_type"], "fold": ev["fold"]}
        rows.append({**base, "case_id": f"{ev['event_id']}_none", "payload_id": "none",
                     "payload_category": "none", "target_field": "none", "injected_raw_log": ev["raw_log"]})
        for _, p in payloads.iterrows():
            rows.append({**base, "case_id": f"{ev['event_id']}_{p['payload_id']}",
                         "payload_id": p["payload_id"], "payload_category": p["payload_category"],
                         "target_field": p["target_field"],
                         "injected_raw_log": inject(ev["raw_log"], p["target_field"], p["text"])})
    return pd.DataFrame(rows)


def main():
    ev = load_events()
    print("Agree events:", ev["attack_type"].value_counts().to_dict())

    print("\nRetraining the detector on SR-BH:")
    ev, metrics = train(ev)
    os.makedirs(os.path.dirname(METRICS), exist_ok=True)
    with open(METRICS, "w") as f:
        json.dump(metrics, f, indent=2)
    print(json.dumps(metrics, indent=2))

    ev[["event_id", "srbh_row", "label", "attack_type", "cv_group", "raw_log"]].to_csv(
        f"{OUT_DIR}/srbh_events_v1.csv", index=False)
    ev[["event_id", "detector_verdict", "detector_proba", "detector_severity", "shap_top5", "fold"]].to_csv(
        f"{OUT_DIR}/srbh_detector_output_v1.csv", index=False)

    payloads = pd.read_csv(PAYLOADS, keep_default_na=False)
    payloads = payloads[payloads["payload_id"].isin(SUBSET_PAYLOADS)]
    assert len(payloads) == 12, f"Expected 12 subset payloads, got {len(payloads)}"

    attacks = ev[ev["label"] == "attack"]
    cases = score(build_cases(attacks, payloads))
    assert len(cases) == len(attacks) * 13, f"Unexpected number of cases: {len(cases)}"
    assert cases["case_id"].is_unique

    # Clean rows must reproduce the out-of-fold detector output exactly
    clean = cases[cases["payload_id"] == "none"].merge(
        ev[["event_id", "detector_verdict", "detector_severity", "shap_top5", "detector_proba"]],
        on="event_id", suffixes=("", "_ref"))
    for col in ["detector_verdict", "detector_severity", "shap_top5"]:
        assert (clean[col] == clean[f"{col}_ref"]).all(), f"Clean rows differ in {col}"
    assert np.allclose(clean["detector_proba"], clean["detector_proba_ref"]), "Clean rows differ in proba"

    cases[COLUMNS].to_csv(f"{OUT_DIR}/srbh_cases_v1.csv", index=False)
    cases.loc[cases["payload_id"] == "none", COLUMNS].to_csv(f"{OUT_DIR}/srbh_cases_clean_v1.csv", index=False)

    benign = score(build_cases(ev[ev["label"] == "benign"], payloads.iloc[0:0]))
    benign[COLUMNS].to_csv(f"{OUT_DIR}/srbh_benign_v1.csv", index=False)

    ref_cols = list(pd.read_csv(TESTBED_BENIGN, nrows=0).columns)
    if ref_cols != COLUMNS:
        print(f"\nNOTE: benign_control_v1.csv columns differ from the case columns:\n  {ref_cols}\n  {COLUMNS}")

    # Detector side only: how the payloads move the retrained detector
    inj = cases[cases["payload_id"] != "none"].merge(
        clean[["event_id", "detector_proba", "detector_severity"]].rename(
            columns={"detector_proba": "proba_clean", "detector_severity": "sev_clean"}), on="event_id")
    inj["delta"] = inj["detector_proba"] - inj["proba_clean"]
    inj["sev_lowered"] = inj["detector_severity"].map(SEV_RANK) < inj["sev_clean"].map(SEV_RANK)
    shift = inj.groupby("target_field").agg(
        cases=("delta", "size"),
        proba_changed=("delta", lambda d: int((d.abs() > 1e-9).sum())),
        mean_change=("delta", "mean"),
        severity_lowered=("sev_lowered", "sum"),
        verdict_benign=("detector_verdict", lambda v: int((v == "benign").sum())),
        lowest_proba=("detector_proba", "min")).round(3)
    os.makedirs(os.path.dirname(SHIFT), exist_ok=True)
    shift.to_csv(SHIFT)

    print(f"\nWrote {len(cases)} attack cases, {int((cases['payload_id'] == 'none').sum())} clean attack rows, "
          f"{len(benign)} benign rows to {OUT_DIR}/")
    print(f"\nDetector shift caused by the payloads (saved to {SHIFT}):\n{shift.to_string()}")
    print(f"\nExample SR-BH raw_log:\n{ev['raw_log'].iloc[0]}")


if __name__ == "__main__":
    main()
