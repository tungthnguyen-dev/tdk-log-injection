import json
import math
import os
from collections import Counter

import joblib
import numpy as np
import pandas as pd
import shap
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedGroupKFold

SRC = "data/processed/events_detector_v1.csv"
DST = "data/processed/detector_output_v1.csv"
METRICS = "results/detector_metrics_v1.json"
MODEL_DIR = "models"

SEED = 42
N_FOLDS = 5

FEATURES = ["uri_length", "uri_entropy", "uri_special_chars",
            "status", "ua_length", "ua_known_scanner"]

SPECIAL_CHARS = set("'\"<>;()%.\\|`$*,!{}[]@~")

SCANNER_TOKENS = ["sqlmap", "nikto", "nmap", "gobuster", "dirbuster", "fuzz faster u fool",
                  "ffuf", "zgrab", "masscan", "wpscan", "nuclei", "acunetix", "nessus",
                  "python-requests", "go-http-client", "curl/", "wget/"]


def entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def extract_features(df):
    """Detector features. Uses only uri, status and user_agent (not remote_addr, referer or method)."""
    ua = df["user_agent"].str.lower()
    return pd.DataFrame({
        "uri_length": df["uri"].str.len(),
        "uri_entropy": df["uri"].map(entropy),
        "uri_special_chars": df["uri"].map(lambda u: sum(ch in SPECIAL_CHARS for ch in u)),
        "status": df["status"].astype(int),
        "ua_length": df["user_agent"].str.len(),
        "ua_known_scanner": ua.map(lambda u: int(any(t in u for t in SCANNER_TOKENS))),
    }, index=df.index)[FEATURES]


def severity(proba):
    if proba >= 0.9:
        return "high"
    if proba >= 0.7:
        return "medium"
    if proba >= 0.5:
        return "low"
    return "none"


def attack_shap(explainer, X):
    """SHAP values for the 'attack' class, shape (n_events, n_features)."""
    sv = explainer.shap_values(X)
    if isinstance(sv, list):
        return sv[1]
    if sv.ndim == 3:
        return sv[:, :, 1]
    return sv


def top5(x_row, shap_row):
    order = np.argsort(-np.abs(shap_row))[:5]
    return json.dumps([{"feature": FEATURES[i],
                        "value": round(float(x_row[i]), 3),
                        "shap": round(float(shap_row[i]), 4)} for i in order])


def main():
    df = pd.read_csv(SRC, keep_default_na=False)
    X = extract_features(df)
    y = (df["label"] == "attack").astype(int).to_numpy()

    # Identical requests (same uri + user_agent + status) stay in the same fold,
    # so the model is never tested on an exact copy of a training row.
    groups = df["uri"] + "|" + df["user_agent"] + "|" + df["status"].astype(str)

    cv = StratifiedGroupKFold(n_splits=N_FOLDS, shuffle=True, random_state=SEED)
    proba = np.zeros(len(df))
    fold = np.zeros(len(df), dtype=int)
    shap_top5 = [""] * len(df)

    os.makedirs(MODEL_DIR, exist_ok=True)
    for k, (train_idx, test_idx) in enumerate(cv.split(X, y, groups)):
        model = RandomForestClassifier(n_estimators=200, random_state=SEED, n_jobs=-1)
        model.fit(X.iloc[train_idx], y[train_idx])
        joblib.dump(model, f"{MODEL_DIR}/rf_fold{k}.joblib")

        X_test = X.iloc[test_idx]
        proba[test_idx] = model.predict_proba(X_test)[:, 1]
        fold[test_idx] = k

        sv = attack_shap(shap.TreeExplainer(model), X_test)
        for row, i in enumerate(test_idx):
            shap_top5[i] = top5(X_test.iloc[row].to_numpy(), sv[row])

    pred = (proba >= 0.5).astype(int)

    out = pd.DataFrame({
        "event_id": df["event_id"],
        "detector_verdict": np.where(pred == 1, "attack", "benign"),
        "detector_proba": proba.round(4),
        "detector_severity": [severity(p) for p in proba],
        "shap_top5": shap_top5,
        "fold": fold,
    })
    out.to_csv(DST, index=False)

    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    metrics = {
        "n_events": int(len(df)),
        "precision": round(precision_score(y, pred), 4),
        "recall": round(recall_score(y, pred), 4),
        "f1": round(f1_score(y, pred), 4),
        "false_positive_rate": round(fp / (fp + tn), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "recall_by_attack_type": {
            t: round(float(pred[(df["attack_type"] == t).to_numpy()].mean()), 4)
            for t in ["path_scan", "sqli", "path_traversal", "scanner_ua"]},
        "features": FEATURES,
        "model": f"RandomForestClassifier(n_estimators=200, random_state={SEED})",
        "cv": f"StratifiedGroupKFold(n_splits={N_FOLDS}), out-of-fold predictions",
    }
    os.makedirs(os.path.dirname(METRICS), exist_ok=True)
    with open(METRICS, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"Wrote {len(out)} rows to {DST}")
    print(f"Wrote metrics to {METRICS}\n")
    print(json.dumps(metrics, indent=2))
    print("\nSeverity counts:\n", out["detector_severity"].value_counts())
    print("\nExample SHAP top 5 for the first attack event:")
    print(out.loc[y == 1, "shap_top5"].iloc[0])


if __name__ == "__main__":
    main()