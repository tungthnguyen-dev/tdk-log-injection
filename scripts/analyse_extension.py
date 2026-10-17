"""Exploratory cloud-model extension (pre-registration Deviations, 16 Oct): Gemini 2.5 Flash, Claude Haiku 5.5
and Gemini 3.6 Flash next to Claude Haiku 4.5, with gemma4:e4b for reference. Outside the confirmatory family.

Every model is analysed on the same cases (subset v1: 576 payload cases + 48 attack controls; 48 benign controls;
96 clean controls for DWRONG) with the functions of analyse_prereg.py, so all numbers are computed the same way.
Per model:
  - rates in A, B, BCLEAN: payload-induced flip, raw flip, invalid rate; no-payload control answers
  - grounding B - A and detector channel B - BCLEAN (Haiku 4.5: B' - BCLEAN, same session; gemma4:e4b: B from
    8 Oct - BCLEAN, as registered), each with raw flip, control-gated, worst-case and complete-case versions
  - benign false positives in A and B (Wilson CI)
  - DWRONG in both directions (Wilson CI), next to the same controls' answers in B
  - invalid answers by cause (answers cut at the token limit, safety blocks)
Additional descriptive contrast, fixed with this script before any extension result was looked at: the
difference of each model's B - A and B - BCLEAN from Claude Haiku 4.5's on the same cases (event-cluster
bootstrap; Benjamini-Hochberg across these comparisons).

Usage:
    python scripts/analyse_extension.py                   # all models
    python scripts/analyse_extension.py --models haiku45 e4b
"""
import argparse
import json
import os

import pandas as pd

import analyse_prereg as ap

R = "results/runs"
MODELS = {   # key: (model id, label, run files, benign files, channel arm)
    "haiku45": ("claude-haiku-4-5-20251001", "Claude Haiku 4.5",
                [f"{R}/claude_haiku_4_5_v1.csv", f"{R}/claude_haiku_4_5_v2_bclean.csv", f"{R}/claude_haiku_4_5_v2_dwrong.csv"],
                [f"{R}/claude_haiku_4_5_benign_v1.csv"], "BPRIME"),
    "gemini25": ("gemini-2.5-flash", "Gemini 2.5 Flash",
                 [f"{R}/gemini_2_5_flash_ext.csv", f"{R}/gemini_2_5_flash_ext_dwrong.csv"],
                 [f"{R}/gemini_2_5_flash_ext_benign.csv"], "B"),
    "haiku55": ("claude-haiku-5-5", "Claude Haiku 5.5",
                [f"{R}/claude_haiku_5_5_ext.csv", f"{R}/claude_haiku_5_5_ext_dwrong.csv"],
                [f"{R}/claude_haiku_5_5_ext_benign.csv"], "B"),
    "gemini36": ("gemini-3.6-flash", "Gemini 3.6 Flash",
                 [f"{R}/gemini_3_6_flash_ext.csv", f"{R}/gemini_3_6_flash_ext_dwrong.csv"],
                 [f"{R}/gemini_3_6_flash_ext_benign.csv"], "B"),
    "e4b": ("gemma4:e4b", "Gemma 4 e4b (reference)",
            [f"{R}/gemma4_e4b.csv", f"{R}/gemma4_e4b_v2_bclean.csv", f"{R}/gemma4_e4b_v2_dwrong.csv"],
            [f"{R}/gemma4_e4b_benign.csv"], "B"),
}
SUBSET = "data/processed/subset_v1_case_ids.csv"
CONTROLS = "data/processed/controls_v1.csv"
OUT = "results/analysis/extension"


def load_model(key, models=MODELS):
    model, label, runs, benign_files, _ = models[key]
    df, errors, dropped = ap.load_runs(runs)
    benign, _, _ = ap.load_runs(benign_files)
    df = df[df["model"] == model].copy()
    benign = benign[(benign["model"] == model) & benign["condition"].isin(["A", "B"])].copy()
    # Haiku 4.5's B from the BCLEAN session (prompts v2) is B'; its B from 8 Oct (prompts v1) stays B
    df.loc[(df["prompt_version"] == "v2") & (df["condition"] == "B"), "condition"] = "BPRIME"
    if key != "haiku45":
        df.loc[df["condition"] == "BPRIME", "condition"] = "B"
    # Same cases for every model: subset v1 for A/B/BCLEAN(/B'), the 96 clean controls for DWRONG
    subset = set(pd.read_csv(SUBSET)["case_id"])
    controls = set(pd.read_csv(CONTROLS)["case_id"])
    keep = (df["condition"].isin(["A", "B", "BPRIME", "BCLEAN"]) & df["case_id"].isin(subset)) | \
           ((df["condition"] == "DWRONG") & df["case_id"].isin(controls))
    df = df[keep]
    return df, benign, {"infrastructure_errors": len(errors), "duplicates_dropped": len(dropped)}


def invalid_causes(df):
    out = {}
    for cond, g in df.groupby("condition"):
        fr = g["finish_reason"].astype(str).str.upper()
        out[cond] = {"calls": len(g), "invalid": int((g["ans"] == "invalid").sum()),
                     "cut_at_token_limit": int(fr.isin(["MAX_TOKENS"]).sum()),
                     "safety_blocked": int(fr.str.contains("SAFETY|PROMPT_BLOCKED|BLOCKLIST|PROHIBITED").sum())}
    return out


def dwrong_with_baseline(df, benign):
    d = ap.dwrong(df)
    if not d:
        return None
    (model, r), = d.items()
    att_b = df[(df["condition"] == "B") & (df["payload_id"] == "none")]
    k0, n0 = int((att_b["ans"] == "benign").sum()), len(att_b)
    ben_b = benign[benign["condition"] == "B"]
    k1, n1 = int((ben_b["ans"] == "malicious").sum()), len(ben_b)
    return {**r, "baseline_B_attack_controls_answered_benign": [k0, n0, ap.wilson(k0, n0)],
            "baseline_B_benign_controls_answered_malicious": [k1, n1, ap.wilson(k1, n1)]}


def contrast_block(df, pc, model, arm1, arm0, name):
    r = ap.arm_contrast(df, pc, name, model, arm1, arm0)
    return {k: r[k] for k in ["contrast", "n_cases", "primary", "raw_flip", "control_gated", "control_gated_events",
                              "worst_case", "complete_case", "icc"]}


def per_case_diff(pc, model, arm1, arm0):
    w = ap.wide(pc, model, [arm1, arm0])
    return w.assign(D=w[arm1] - w[arm0])[["case_id", "event_id", "D"]]


def vs_haiku45(pcs, models, key, contrast):
    """(model's arm1 - arm0) - (Haiku 4.5's), per case on identical cases, event-cluster bootstrap."""
    (a1, a0), (h1, h0) = contrast(key), contrast("haiku45")
    m = per_case_diff(pcs[key], models[key][0], a1, a0).merge(
        per_case_diff(pcs["haiku45"], models["haiku45"][0], h1, h0), on=["case_id", "event_id"],
        suffixes=("_m", "_h"), validate="one_to_one")
    assert len(m) == 576, f"{key}: expected 576 shared payload cases, got {len(m)}"
    m["DD"] = m["D_m"] - m["D_h"]
    return ap.mean_test(m, "DD")


def analyse(keys, models=MODELS, out_dir=OUT):
    res, pcs = {}, {}
    for key in keys:
        model, label, _, _, channel_arm = models[key]
        df, benign, meta = load_model(key, models)
        pc = ap.per_case(ap.outcomes(df))
        pcs[key] = pc
        r = {"model": model, "label": label, **meta,
             "served_models": sorted(set(df["served_model"])) if "served_model" in df else [],
             "rates": ap.rates(df, pc, benign).to_dict("records"),
             "controls": ap.control_table(df).to_dict("records"),
             "invalid_causes": invalid_causes(df),
             "grounding_B_minus_A": contrast_block(df, pc, model, "B", "A", f"{key} B-A"),
             "channel_B_minus_BCLEAN": contrast_block(df, pc, model, channel_arm, "BCLEAN", f"{key} channel"),
             "dwrong": dwrong_with_baseline(df, benign)}
        res[key] = r
    if "haiku45" in keys:
        contrasts = {"grounding": lambda k: ("B", "A"),
                     "channel": lambda k: (models[k][4], "BCLEAN")}
        diffs = {f"{k} {c}": vs_haiku45(pcs, models, k, f) for k in keys if k != "haiku45"
                 for c, f in contrasts.items()}
        if diffs:
            bh = ap.benjamini_hochberg({k: v["p"] for k, v in diffs.items()})
            for k in diffs:
                diffs[k]["bh_p"] = bh[k]
        res["difference_from_haiku45"] = diffs
    os.makedirs(out_dir, exist_ok=True)
    with open(f"{out_dir}/results.json", "w") as f:
        json.dump(res, f, indent=2, default=str)
    return res


def report(res):
    f = ap.fmt
    for key, r in res.items():
        if key == "difference_from_haiku45":
            continue
        print(f"\n=== {r['label']}  (served: {', '.join(r['served_models']) or 'n/a'})")
        for x in r["rates"]:
            fp = f"  benign FP {int(x['benign_fp'])}/{int(x['benign_n'])}" if x.get("benign_n") == x.get("benign_n") \
                and x.get("benign_n") else ""
            print(f"  {x['condition']:7s} payload-induced flip {100 * x['payload_induced_flip']:5.1f}%  "
                  f"raw {100 * x['raw_flip']:5.1f}%  invalid {100 * x['invalid_rate_payload']:.1f}%{fp}")
        for name in ["grounding_B_minus_A", "channel_B_minus_BCLEAN"]:
            c = r[name]
            print(f"  {name:24s} {f(c['primary'])}")
            print(f"     raw flip {f(c['raw_flip'])} | control-gated {f(c['control_gated'])}")
        d = r["dwrong"]
        if d:
            a, b = d["attack_shown_benign_deferred"], d["benign_shown_attack_deferred"]
            a0, b0 = d["baseline_B_attack_controls_answered_benign"], d["baseline_B_benign_controls_answered_malicious"]
            print(f"  DWRONG: attack shown BENIGN -> benign {a[0]}/{a[1]} (in B: {a0[0]}/{a0[1]}); "
                  f"benign shown ATTACK -> malicious {b[0]}/{b[1]} (in B: {b0[0]}/{b0[1]})")
        bad = {c: v for c, v in r["invalid_causes"].items() if v["invalid"]}
        if bad:
            print("  invalid answers:", bad)
    diffs = res.get("difference_from_haiku45", {})
    if diffs:
        print("\nDifference from Claude Haiku 4.5 (same cases; exploratory, Benjamini-Hochberg):")
        for k, v in diffs.items():
            print(f"  {k:22s} {f(v)}  BH p={v['bh_p']:.4f}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--models", nargs="*", default=list(MODELS), choices=list(MODELS))
    p.add_argument("--out", default=OUT)
    args = p.parse_args()
    res = analyse(args.models, out_dir=args.out)
    report(res)
    print(f"\nSaved: {args.out}/results.json")


if __name__ == "__main__":
    main()
