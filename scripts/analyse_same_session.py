"""Same-session sensitivity for H2 (Deviations 16 Oct): B' - BCLEAN from one file in which B and BCLEAN
were run interleaved per case in one session. Reported next to the registered H2; it does not replace it.

Also reports: the Referer check inside the session (identical prompts; answers and raw outputs should
match), and, with --compare, how often BCLEAN verdicts agree with an earlier BCLEAN run of the same model.

Usage:
    python scripts/analyse_same_session.py --file results/runs/gemma4_e4b_v2_bprime_bclean.csv \
        --compare results/runs/gemma4_e4b_v2_bclean.csv --out results/analysis/sensitivity/e4b_bprime.json
"""
import argparse
import json
import os

import pandas as pd

import analyse_prereg as ap


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--file", required=True)
    p.add_argument("--compare", help="An earlier BCLEAN file of the same model (session-to-session check)")
    p.add_argument("--out", required=True)
    args = p.parse_args()

    df, errors, dropped = ap.load_runs([args.file])
    df.loc[(df["prompt_version"] == "v2") & (df["condition"] == "B"), "condition"] = "BPRIME"
    models = df["model"].unique()
    assert len(models) == 1, f"One model per file expected, got {models}"
    model = models[0]
    assert {"BPRIME", "BCLEAN"} <= set(df["condition"]), "File must contain B and BCLEAN"
    pc = ap.per_case(ap.outcomes(df))
    r = ap.arm_contrast(df, pc, "same-session H2", model, "BPRIME", "BCLEAN")
    out = {"model": model, "file": args.file, "infrastructure_errors": len(errors), "duplicates_dropped": len(dropped),
           "contrast": "B' - BCLEAN (same session)",
           **{k: r[k] for k in ["primary", "worst_case", "complete_case", "raw_flip", "control_gated",
                                "control_gated_events", "icc", "mcnemar", "n_cases"]},
           "by_field": ap.by_field(pc, model, "BPRIME", "BCLEAN"),
           "referer_check": ap.referer_check(df, model, "BPRIME", "BCLEAN")}
    ref = df[(df["target_field"] == "referer")].pivot_table(index=["case_id", "run"], columns="condition",
                                                             values="raw_response", aggfunc="first").dropna()
    out["referer_raw_identical"] = [int((ref["BPRIME"] == ref["BCLEAN"]).sum()), len(ref)]

    if args.compare:
        old, _, _ = ap.load_runs([args.compare])
        cols = ["case_id", "run", "ans"]
        a = df[df["condition"] == "BCLEAN"][cols]
        b = old[old["condition"] == "BCLEAN"][cols]
        m = a.merge(b, on=["case_id", "run"], suffixes=("_new", "_old"), validate="one_to_one")
        out["bclean_session_agreement"] = [int((m["ans_new"] == m["ans_old"]).sum()), len(m)]

    print(f"{model}: {out['contrast']}")
    for k in ["primary", "worst_case", "complete_case", "raw_flip", "control_gated"]:
        print(f"  {k:15s} {ap.fmt(out[k])}")
    print(f"  by field: { {f: ap.fmt(v) for f, v in out['by_field'].items()} }")
    print(f"  Referer: same verdict {out['referer_check']['same_answer']}/{out['referer_check']['pairs']}, "
          f"raw output identical {out['referer_raw_identical'][0]}/{out['referer_raw_identical'][1]}")
    if "bclean_session_agreement" in out:
        k, n = out["bclean_session_agreement"]
        print(f"  BCLEAN verdict agreement with the earlier session: {k}/{n}")
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(out, f, indent=2, default=str)
    print(f"Saved: {args.out}")


if __name__ == "__main__":
    main()
