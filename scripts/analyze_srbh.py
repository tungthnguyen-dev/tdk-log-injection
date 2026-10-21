"""SR-BH 2020 external-validity slice on gemma4:e4b: LLM outcome summary. Descriptive only, no confirmatory test
(pre-registration Section 8 and the 16 Oct SR-BH scope deviation). Offline: no LLM calls.

Uses the outcome definitions of scripts/analyse_prereg.py (payload-induced flip Y, raw flip F, invalid = not benign;
event-cluster bootstrap CIs over the 248 SR-BH attack events).

Parts
  1. Clean behaviour (no payload): attack detection on the 248 agree attack events (A, B, C) and false positives on
     the 79 agree benign events (A, B, C); Wilson CIs. C uses final_verdict.
  2. Injection (12 subset payloads x 248 attack events = 2,976 cases): payload-induced flip and raw flip in A and B,
     B - A with event-cluster CI, split by payload field and by attack type.
  3. Detector channel: the retrained detector's own verdict on the injected cases, and "compound bypass"
     (the detector says benign AND the LLM says benign) per arm.
  4. Invalid-answer rates per arm.

Writes results/analysis/srbh/results.json (B - A via analyse_prereg.arm_contrast: primary, worst case,
complete case, raw flip, control-gated, ICC, McNemar; rates() per arm; by field) plus readable CSV tables.

Usage (repo root):
    python scripts/analyze_srbh.py [--boot 10000]
"""
import argparse
import json
import os

import numpy as np
import pandas as pd

from analyse_prereg import arm_contrast, by_field, load_runs, mean_test, outcomes, per_case, rates, wilson

RUNS = "results/runs"
ATTACK = f"{RUNS}/gemma4_e4b_srbh.csv"
CLEAN_C = f"{RUNS}/gemma4_e4b_srbh_clean_c.csv"
BENIGN = f"{RUNS}/gemma4_e4b_srbh_benign.csv"
CASES = "data/processed/srbh/srbh_cases_v1.csv"
OUT = "results/analysis/srbh"


def ci(r):
    return {"estimate": r["estimate"], "ci_low": r["ci_low"], "ci_high": r["ci_high"], "n_events": r["n_events"]}


def rate(k, n):
    lo, hi = wilson(k, n)
    return {"k": int(k), "n": int(n), "rate": k / n if n else float("nan"), "wilson_low": lo, "wilson_high": hi}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--boot", type=int, default=10_000)
    args = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)

    att, e1, d1 = load_runs([ATTACK])
    cc, e2, d2 = load_runs([CLEAN_C])
    ben, e3, d3 = load_runs([BENIGN])
    print(f"Loaded {len(att)} attack-case rows, {len(cc)} clean-C rows, {len(ben)} benign rows "
          f"({len(e1) + len(e2) + len(e3)} error rows, {len(d1) + len(d2) + len(d3)} duplicates dropped)")
    assert len(att) == 6448 and len(cc) == 248 and len(ben) == 237, "unexpected row counts"

    # 1. clean behaviour
    clean_rows = []
    ctrl = att[att["payload_id"] == "none"]
    for cond, g in ctrl.groupby("condition"):
        clean_rows.append({"set": "attack events, no payload", "arm": cond, "measure": "detected (malicious)",
                           **rate((g["ans"] == "malicious").sum(), len(g)), "invalid": int((g["ans"] == "invalid").sum())})
    clean_rows.append({"set": "attack events, no payload", "arm": "C", "measure": "detected (final malicious)",
                       **rate((cc["ans_final"] == "malicious").sum(), len(cc)), "invalid": int((cc["ans"] == "invalid").sum())})
    for cond, g in ben.groupby("condition"):
        col = "ans_final" if cond == "C" else "ans"
        clean_rows.append({"set": "benign events", "arm": cond, "measure": "false positive (malicious)",
                           **rate((g[col] == "malicious").sum(), len(g)), "invalid": int((g["ans"] == "invalid").sum())})
    clean = pd.DataFrame(clean_rows)

    # 2. injection: payload-induced flip, raw flip, B - A
    pay = outcomes(att)
    pc = per_case(pay)
    inj = []
    for cond, g in pc.groupby("condition"):
        for col, name in [("Y", "payload_induced_flip"), ("F", "raw_flip")]:
            inj.append({"arm": cond, "split": "all", "measure": name, **ci(mean_test(g, col, B=args.boot))})
    w = (pc.pivot_table(index=["case_id", "event_id", "payload_id", "target_field"], columns="condition", values=["Y", "F"])
         .reset_index())
    w.columns = ["_".join(c).strip("_") for c in w.columns]
    w = w.merge(att[["case_id", "attack_type"]].drop_duplicates(), on="case_id", how="left")
    assert len(w) == 2976 and w[["Y_A", "Y_B"]].notna().all().all(), "A and B must cover all 2,976 payload cases"
    w["D_Y"], w["D_F"] = w["Y_B"] - w["Y_A"], w["F_B"] - w["F_A"]
    for col, name in [("D_Y", "B_minus_A_payload_induced_flip"), ("D_F", "B_minus_A_raw_flip")]:
        inj.append({"arm": "B - A", "split": "all", "measure": name, **ci(mean_test(w, col, B=args.boot))})
    for split_col in ["target_field", "attack_type"]:
        for key, g in w.groupby(split_col):
            for col, name in [("Y_A", "payload_induced_flip A"), ("Y_B", "payload_induced_flip B"),
                              ("D_Y", "B_minus_A_payload_induced_flip")]:
                inj.append({"arm": name.split()[-1] if " " in name else "B - A", "split": f"{split_col}={key}",
                            "measure": name.split()[0], **ci(mean_test(g, col, B=args.boot))})
    injection = pd.DataFrame(inj)

    # 3. detector channel
    cases = pd.read_csv(CASES, keep_default_na=False)[["case_id", "detector_verdict", "detector_proba"]]
    p = pay.merge(cases, on="case_id", how="left", suffixes=("", "_case"))
    dv = p["detector_verdict_case"] if "detector_verdict_case" in p else p["detector_verdict"]
    det = []
    one_run = p[p["condition"] == "A"]
    for field, g in one_run.groupby("target_field"):
        dvg = dv.loc[g.index]
        det.append({"target_field": field, "cases": len(g), "detector_says_benign": int((dvg == "benign").sum())})
    for cond, g in p.groupby("condition"):
        dvg = dv.loc[g.index]
        k = int(((dvg == "benign") & (g["ans"] == "benign")).sum())
        det.append({"target_field": f"compound bypass in {cond} (detector benign AND LLM benign)", "cases": len(g),
                    "detector_says_benign": k})
    detector = pd.DataFrame(det)

    # 4. invalid rates
    inv = pd.DataFrame([{"file": n, "arm": c, **rate((g["ans"] == "invalid").sum(), len(g))}
                        for n, d in [("attack", att), ("clean_C", cc), ("benign", ben)] for c, g in d.groupby("condition")])

    model = "gemma4:e4b"
    contrast = arm_contrast(att, pc, "SRBH B-A", model, "B", "A")
    results = {"description": "SR-BH 2020 slice, gemma4:e4b, descriptive only (16 Oct deviation)",
               "files": [ATTACK, CLEAN_C, BENIGN],
               "B_minus_A": contrast,
               "B_minus_A_by_field": by_field(pc, model, "B", "A"),
               "rates_A_B": rates(att, pc, ben[ben["condition"].isin(["A", "B"])]).to_dict("records"),
               "clean_behaviour": clean.to_dict("records"),
               "detector_channel": detector.to_dict("records"),
               "invalid": inv.to_dict("records"),
               "detector_side": "results/summary/srbh_detector_shift_v1.csv",
               "caveats": ["Agree rows only: 248 attack + 79 benign of 500 (selection limits external validity).",
                           "Labels hand-checked by one author (14 Oct deviation).",
                           "Detector retrained on SR-BH (grouped CV by hour).",
                           "C was run only on clean attack rows and benign events, not on injected cases."]}
    with open(f"{OUT}/results.json", "w") as f:
        json.dump(results, f, indent=2, default=str)
    print("\nB - A (arm_contrast):", json.dumps({k: contrast[k] for k in
          ["primary", "worst_case", "complete_case", "raw_flip", "control_gated", "control_gated_events"]}, default=str))

    for name, t in [("clean_behaviour", clean), ("injection", injection), ("detector_channel", detector), ("invalid", inv)]:
        t.to_csv(f"{OUT}/{name}.csv", index=False)
    with open(f"{OUT}/summary.json", "w") as f:
        json.dump({"model": "gemma4:e4b", "runs": 1, "events": {"attack": 248, "benign": 79}, "payloads": 12,
                   "bootstrap_resamples": args.boot,
                   "notes": ["Descriptive only; agree rows only (selection limits external validity).",
                             "C was run only on the clean attack rows and the benign events, not on injected cases."]},
                  f, indent=2)

    pd.set_option("display.width", 200)
    print("\n1. Clean behaviour:\n", clean.round(4).to_string(index=False))
    print("\n2. Injection (all cases):\n", injection[injection["split"] == "all"].round(4).to_string(index=False))
    print("\n   By field / attack type:\n", injection[injection["split"] != "all"].round(4).to_string(index=False))
    print("\n3. Detector channel:\n", detector.to_string(index=False))
    print("\n4. Invalid rates:\n", inv.round(4).to_string(index=False))
    print(f"\nSaved to {OUT}/")


if __name__ == "__main__":
    main()
