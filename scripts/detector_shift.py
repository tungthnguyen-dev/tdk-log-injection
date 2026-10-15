"""How much do payloads move the detector? Detector data only, no LLM outputs."""
import pandas as pd

ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
df = pd.read_csv("data/processed/injected_cases_v1.csv", keep_default_na=False)
df["sev"] = df["detector_severity"].str.lower().map(ORDER)
df["proba"] = df["detector_proba"].astype(float)

clean = df[df["payload_id"] == "none"].set_index("event_id")
p = df[df["payload_id"] != "none"].copy()
p["sev_lowered"] = p["sev"] < p["event_id"].map(clean["sev"])
p["dproba"] = p["proba"] - p["event_id"].map(clean["proba"])

out = p.groupby("target_field").agg(
    cases=("sev_lowered", "size"),
    severity_lowered_pct=("sev_lowered", lambda s: round(100 * s.mean(), 1)),
    dproba_mean=("dproba", lambda s: round(s.mean(), 3)),
    dproba_min=("dproba", lambda s: round(s.min(), 3)),
)
print(out.to_string())
print("\nDetector verdict flipped to benign:",
      int((p["detector_verdict"].str.lower() != "attack").sum()), "of", len(p))
out.to_csv("results/summary/detector_shift.csv")
