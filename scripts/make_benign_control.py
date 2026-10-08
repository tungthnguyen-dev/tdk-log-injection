"""Build the benign control set for the runner: 48 benign events, no payload.

Shows whether the conditions (especially C's defences) make the model call
normal traffic malicious. Detector values are the out-of-fold predictions.

Usage:
    python scripts/make_benign_control.py
"""
import pandas as pd

N_EVENTS = 48
SEED = 42
EVENTS = "data/processed/events_labelled.csv"
DETECTOR = "data/processed/detector_output_v1.csv"
DST = "data/processed/benign_control_v1.csv"

COLUMNS = ["case_id", "event_id", "attack_type", "payload_id", "payload_category",
           "target_field", "injected_raw_log", "detector_verdict", "detector_proba",
           "detector_severity", "shap_top5"]


def main():
    events = pd.read_csv(EVENTS, keep_default_na=False)
    detector = pd.read_csv(DETECTOR, keep_default_na=False)

    benign = (events[events["label"] == "benign"]
              .sample(n=N_EVENTS, random_state=SEED)
              .sort_values("event_id")
              .merge(detector, on="event_id"))

    out = pd.DataFrame({
        "case_id": benign["event_id"] + "_none",
        "event_id": benign["event_id"],
        "attack_type": "none",
        "payload_id": "none",
        "payload_category": "none",
        "target_field": "none",
        "injected_raw_log": benign["raw_log"],
        "detector_verdict": benign["detector_verdict"],
        "detector_proba": benign["detector_proba"],
        "detector_severity": benign["detector_severity"],
        "shap_top5": benign["shap_top5"],
    })[COLUMNS]

    assert len(out) == N_EVENTS and out["case_id"].is_unique
    assert (out["shap_top5"] != "").all(), "Missing detector output"
    out.to_csv(DST, index=False)

    print(f"Wrote {len(out)} benign control cases to {DST}")
    print("Detector verdicts:", out["detector_verdict"].value_counts().to_dict())


if __name__ == "__main__":
    main()