"""Model ladder (pre-registration Section 7; exploratory).

Registered ladder: gemma4:e2b, gemma4:e4b, gemma4:12b, qwen3.5:9b, claude-haiku-4-5. Every model is compared
on the same cases: subset v1 (576 payload cases). Capability (fixed in Section 7): balanced accuracy in
condition A on the 96 clean controls (48 no-payload attack controls, 48 benign controls), averaged over runs.
Per model: B - A and B - BCLEAN (and V - A where run) with event-cluster bootstrap CIs, plus raw-flip and
control-gated versions (Deviations 15 Oct, item c), and the full-set B - A as a check of the subset.
Gradient: Spearman's rank correlation between capability and B - A over the five registered models, with
an exact permutation p (mid-ranks for ties), described as consistent / not consistent with a gradient.

The cloud-extension models (Deviations 16 Oct) are listed next to the ladder with their own decoding
settings, but are not part of the registered Spearman test.

Usage:
    python scripts/analyse_ladder.py --selftest
    python scripts/analyse_ladder.py [--models e2b,e4b,...]
"""
import argparse
import itertools
import json
import os

import numpy as np
import pandas as pd
from scipy.stats import rankdata

import analyse_prereg as ap

R = "results/runs"
SUBSET = "data/processed/subset_v1_case_ids.csv"
# key: (model id, label, data files, benign file, B arm, BCLEAN partner of B, registered?)
MODELS = {
    "e2b": ("gemma4:e2b", "Gemma 4 e2b", [f"{R}/gemma4_e2b.csv", f"{R}/gemma4_e2b_v2_ladder.csv"],
            f"{R}/gemma4_e2b_benign.csv", "B", "B", True),
    "e4b": ("gemma4:e4b", "Gemma 4 e4b", [f"{R}/gemma4_e4b.csv", f"{R}/gemma4_e4b_v2_bclean.csv",
                                          f"{R}/gemma4_e4b_v2_components.csv"],
            f"{R}/gemma4_e4b_benign.csv", "B", "B", True),
    "12b": ("gemma4:12b", "Gemma 4 12b", [f"{R}/gemma4_12b.csv", f"{R}/gemma4_12b_v2_ladder.csv"],
            f"{R}/gemma4_12b_benign.csv", "B", "B", True),
    "qwen": ("qwen3.5:9b", "Qwen 3.5 9b", [f"{R}/qwen3.5_9b.csv", f"{R}/qwen3.5_9b_v2_ladder.csv"],
             f"{R}/qwen3.5_9b_benign.csv", "B", "B", True),
    "haiku45": ("claude-haiku-4-5-20251001", "Claude Haiku 4.5",
                [f"{R}/claude_haiku_4_5_v1.csv", f"{R}/claude_haiku_4_5_v2_bclean.csv",
                 f"{R}/claude_haiku_4_5_v2_components.csv"],
                f"{R}/claude_haiku_4_5_benign_v1.csv", "B", "BPRIME", True),
    "gemini25": ("gemini-2.5-flash", "Gemini 2.5 Flash", [f"{R}/gemini_2_5_flash_ext.csv"],
                 f"{R}/gemini_2_5_flash_ext_benign.csv", "BPRIME", "BPRIME", False),
    "haiku55": ("claude-haiku-5-5", "Claude Haiku 5.5", [f"{R}/claude_haiku_5_5_ext.csv"],
                f"{R}/claude_haiku_5_5_ext_benign.csv", "BPRIME", "BPRIME", False),
    "gemini36": ("gemini-3.6-flash", "Gemini 3.6 Flash", [f"{R}/gemini_3_6_flash_ext.csv"],
                 f"{R}/gemini_3_6_flash_ext_benign.csv", "BPRIME", "BPRIME", False),
}


def load(paths):
    df, errors, dropped = ap.load_runs(paths)
    df.loc[(df["prompt_version"] == "v2") & (df["condition"] == "B"), "condition"] = "BPRIME"
    return df, len(errors), len(dropped)


def capability(df, benign):
    """Balanced accuracy in condition A on the 96 clean controls, averaged over runs (invalid = wrong)."""
    att = df[(df["condition"] == "A") & (df["payload_id"] == "none")]
    ben = benign[benign["condition"] == "A"]
    sens = float((att["ans"] == "malicious").mean())
    spec = float((ben["ans"] == "benign").mean())
    return {"balanced_accuracy": (sens + spec) / 2, "attack_controls_correct": sens,
            "benign_controls_correct": spec, "n_attack_rows": len(att), "n_benign_rows": len(ben)}


def spearman_exact(x, y):
    """Spearman rho with mid-ranks and an exact two-sided permutation p over all orderings of y."""
    rx, ry = rankdata(x), rankdata(y)
    if np.ptp(rx) == 0 or np.ptp(ry) == 0:
        return float("nan"), float("nan")
    rho = lambda a, b: float(np.corrcoef(a, b)[0, 1])
    obs = rho(rx, ry)
    perms = [rho(rx, np.array(p)) for p in itertools.permutations(ry)]
    p = float(np.mean([abs(r) >= abs(obs) - 1e-12 for r in perms]))
    return obs, p


def contrast(df, pc, model, arm1, arm0):
    if not {arm1, arm0} <= set(pc[pc["model"] == model]["condition"]):
        return None
    r = ap.arm_contrast(df, pc, f"{arm1}-{arm0}", model, arm1, arm0)
    return {k: r[k] for k in ["primary", "raw_flip", "control_gated", "control_gated_events", "n_cases"]}


def analyse_model(key, subset_ids):
    model, label, paths, benign_path, b_arm, b_for_bclean, registered = MODELS[key]
    df, n_err, n_dup = load(paths)
    benign, _, _ = load([benign_path])
    pc = ap.per_case(ap.outcomes(df))
    sub = pc[pc["case_id"].isin(subset_ids)]
    out = {"model": model, "label": label, "registered": registered, "infrastructure_errors": n_err,
           "duplicates_dropped": n_dup, "runs": sorted(df["run"].unique().tolist()),
           "capability": capability(df, benign),
           "subset": {"B-A": contrast(df, sub, model, b_arm, "A"),
                      "B-BCLEAN": contrast(df, sub, model, b_for_bclean, "BCLEAN"),
                      "V-A": contrast(df, sub, model, "V", "A")},
           "full_set_B-A": (contrast(df, pc, model, b_arm, "A") if pc[pc["model"] == model]["case_id"].nunique() > len(subset_ids)
                            else None)}
    if b_for_bclean == "B" and "BCLEAN" in set(df["condition"]):
        out["referer_check_B_vs_BCLEAN"] = ap.referer_check(df, model, "B", "BCLEAN")   # across sessions
    n_sub = out["subset"]["B-A"]["n_cases"] if out["subset"]["B-A"] else 0
    assert n_sub in (0, 576), f"{key}: expected 576 subset payload cases, got {n_sub}"
    return out


def fmt(r):
    if not r:
        return "n/a"
    return f"{100 * r['estimate']:+5.1f} [{100 * r['ci_low']:+5.1f}, {100 * r['ci_high']:+5.1f}]"


def selftest():
    rho, p = spearman_exact([1, 2, 3, 4, 5], [10, 20, 30, 40, 50])
    assert abs(rho - 1) < 1e-12 and abs(p - 2 / 120) < 1e-12, (rho, p)
    rho, p = spearman_exact([1, 2, 3, 4, 5], [50, 40, 30, 20, 10])
    assert abs(rho + 1) < 1e-12 and abs(p - 2 / 120) < 1e-12
    rho, p = spearman_exact([1, 1, 2, 3, 4], [5, 4, 3, 2, 1])            # tie in x: mid-ranks
    assert rho < -0.9 and 0 < p <= 0.05, (rho, p)
    assert np.isnan(spearman_exact([1, 1, 1, 1, 1], [1, 2, 3, 4, 5])[0])
    print("ok  Spearman exact permutation p (perfect order of 5 -> 2/120), mid-ranks, all-tied guard")


def main():
    ap_ = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap_.add_argument("--models", default=",".join(MODELS), help="Comma-separated keys: " + ", ".join(MODELS))
    ap_.add_argument("--selftest", action="store_true")
    ap_.add_argument("--out", default="results/analysis/ladder/results.json")
    args = ap_.parse_args()
    if args.selftest:
        selftest()
        return
    subset_ids = set(pd.read_csv(SUBSET)["case_id"])
    subset_ids = {c for c in subset_ids if not c.endswith("_none")}
    keys = [k.strip() for k in args.models.split(",")]

    res = {k: analyse_model(k, subset_ids) for k in keys}
    order = sorted(keys, key=lambda k: res[k]["capability"]["balanced_accuracy"])
    print("Model ladder on subset v1 (576 payload cases); payload-induced flip, percentage points [95% CI]")
    print(f"{'model':18s} {'capability':>10s}  {'B - A':22s} {'B - A gated':22s} {'B - BCLEAN':22s} {'V - A':22s} full-set B - A")
    for k in order:
        r = res[k]
        s = r["subset"]
        print(f"{r['label'] + ('' if r['registered'] else ' *'):18s} {r['capability']['balanced_accuracy']:10.3f}  "
              f"{fmt(s['B-A']['primary'] if s['B-A'] else None):22s} "
              f"{fmt(s['B-A']['control_gated'] if s['B-A'] else None):22s} "
              f"{fmt(s['B-BCLEAN']['primary'] if s['B-BCLEAN'] else None):22s} "
              f"{fmt(s['V-A']['primary'] if s['V-A'] else None):22s} "
              f"{fmt(r['full_set_B-A']['primary'] if r['full_set_B-A'] else None)}")
    print("* cloud extension (own decoding settings; not in the registered Spearman test)")

    reg = [k for k in order if res[k]["registered"]]
    summary = {"registered_models": reg, "n": len(reg)}
    if len(reg) >= 5:
        cap = [res[k]["capability"]["balanced_accuracy"] for k in reg]
        for metric in ["primary", "control_gated"]:
            eff = [res[k]["subset"]["B-A"][metric]["estimate"] for k in reg]
            rho, p = spearman_exact(cap, eff)
            summary[f"spearman_capability_vs_B-A_{metric}"] = {"rho": rho, "p_exact": p}
            print(f"Spearman capability vs B - A ({metric}), {len(reg)} registered models: rho = {rho:+.2f}, "
                  f"exact p = {p:.3f} -> {'consistent' if p < 0.05 else 'not consistent'} with a gradient")
    else:
        print(f"Only {len(reg)} registered models: no gradient test (pre-registration: at least five).")
    gemma = [k for k in ["e2b", "e4b", "12b"] if k in res]
    if len(gemma) == 3:
        summary["gemma_by_size_B-A"] = {k: res[k]["subset"]["B-A"]["primary"]["estimate"] for k in gemma}
    for k in keys:
        if "referer_check_B_vs_BCLEAN" in res[k]:
            print(f"Referer check B vs BCLEAN ({res[k]['label']}): {res[k]['referer_check_B_vs_BCLEAN']}")

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump({"models": res, "summary": summary}, f, indent=2, default=str)
    print(f"\nSaved: {args.out}")


if __name__ == "__main__":
    main()
