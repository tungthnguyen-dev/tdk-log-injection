"""Condition-C defence evaluation (pre-registration Section 6, exploratory item 7). Offline: no LLM calls.

Uses the same loading and outcome definitions as scripts/analyse_prereg.py (payload-induced flip Y,
invalid answers count as "not benign", Haiku = mean over its 3 runs, event-cluster bootstrap CIs).

Parts
  1. Decomposition  B -> C before the output guard (verdict) -> C after the output guard (final_verdict).
                    C-raw minus B is the effect of C's prompt and input defences together;
                    C-final minus C-raw is the effect of the output defences.
  2. Severity       severity downgrade vs the same event's no-payload control, for B, C-raw and C-final.
  3. Floor replay   C's severity floor re-applied offline with four anchors: none, the current anchor
                    (detector on the raw injected log), sanitise-before-score (detector on C's cleaned log,
                    data/processed/detector_sanitised_v1.csv), and a non-deployable reference (the event's
                    own no-payload detector severity). Floors never change a verdict, so missed attacks and
                    benign false positives are reported once per model.
  4. Verdict guard  "if the detector's attack probability >= t, the final verdict is malicious".
                    Benefit: payload-induced flip in C after the guard (raw and sanitised probability).
                    Cost: benign false positives on the real benign controls, and on the synthetic
                    wrong-detector controls (DWRONG: benign events shown ATTACK with probability 1 - p).
                    DWRONG ran on prompt B, not C; its cost is therefore an approximation, and the
                    wrong-detector cases are synthetic by construction.
  5. Latency/tokens per anchor model and condition, and the paired C - B overhead.

Writes results/analysis/defences/*.csv, summary.json, fig_guard_tradeoff.png/.pdf

Usage (from the repo root):
    python scripts/analyze_condition_c.py [--boot 10000]
"""
import argparse
import json
import os

import numpy as np
import pandas as pd

from analyse_prereg import CASES, FILES, RANK, load_runs, mean_test, outcomes, per_case, wilson_events

OUT = "results/analysis/defences"
SANITISED = "data/processed/detector_sanitised_v1.csv"
BENIGN_CASES = "data/processed/benign_control_v1.csv"
DWRONG_FILES = [FILES["haiku_dwrong"], "results/runs/gemma4_e4b_v2_dwrong.csv"]
LLM_SEV = {"low", "medium", "high", "critical"}
THRESHOLDS = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95, 0.99]
MODELS = {"claude-haiku-4-5-20251001": "Haiku 4.5", "gemma4:e4b": "gemma4:e4b"}


def ci(r):
    return {"estimate": r["estimate"], "ci_low": r["ci_low"], "ci_high": r["ci_high"], "n_events": r["n_events"]}


def rank(s):
    return s.map(RANK)


# ---------- 1. decomposition ----------

def decomposition(df, boot):
    pc_raw = per_case(outcomes(df, "ans"))
    pc_fin = per_case(outcomes(df, "ans_final"))
    keys = ["model", "case_id", "event_id", "payload_id", "target_field"]
    rows, wides = [], {}
    for model, label in MODELS.items():
        def col(pc, cond, name, c="Y"):
            s = pc[(pc["model"] == model) & (pc["condition"] == cond)][keys + [c]]
            return s.rename(columns={c: name})
        w = (col(pc_raw, "B", "Y_B").merge(col(pc_raw, "C", "Y_Craw"), on=keys)
             .merge(col(pc_fin, "C", "Y_Cfin"), on=keys)
             .merge(col(pc_raw, "B", "F_B", "F"), on=keys).merge(col(pc_raw, "C", "F_Craw", "F"), on=keys)
             .merge(col(pc_fin, "C", "F_Cfin", "F"), on=keys))
        assert len(w) == 1440, f"{model}: expected 1440 payload cases, got {len(w)}"
        w["d_input"] = w["Y_Craw"] - w["Y_B"]
        w["d_output"] = w["Y_Cfin"] - w["Y_Craw"]
        w["d_total"] = w["Y_Cfin"] - w["Y_B"]
        for q in ["Y_B", "Y_Craw", "Y_Cfin", "F_B", "F_Craw", "F_Cfin", "d_input", "d_output", "d_total"]:
            rows.append({"model": label, "quantity": q, **ci(mean_test(w, q, B=boot))})
        for field, g in w.groupby("target_field"):
            for q in ["d_input", "d_output"]:
                rows.append({"model": label, "quantity": f"{q} [{field}]", **ci(mean_test(g, q, B=boot))})
        wides[model] = w
    return pd.DataFrame(rows), wides


def transitions(df):
    """Row level, C payload rows: answer before the output guard -> final answer."""
    c = df[(df["condition"] == "C") & (df["payload_id"] != "none")]
    t = c.groupby(["model", "ans", "ans_final"]).size().rename("rows").reset_index()
    t["model"] = t["model"].map(MODELS)
    return t


# ---------- 2. severity downgrade ----------

def severity_downgrade(df, boot):
    rows = []
    for model, label in MODELS.items():
        for cond, sevcol, name in [("B", "severity", "B"), ("C", "severity", "C_raw"), ("C", "final_severity", "C_final")]:
            d = df[(df["model"] == model) & (df["condition"] == cond)].copy()
            ok = d[sevcol].isin(LLM_SEV) if sevcol == "severity" else d[sevcol].isin(RANK)
            d["r"] = np.where(ok, rank(d[sevcol]).fillna(-1), np.nan)
            ctrl = d[d["payload_id"] == "none"][["run", "event_id", "r"]].rename(columns={"r": "r_ctrl"})
            p = d[d["payload_id"] != "none"].merge(ctrl, on=["run", "event_id"], validate="many_to_one")
            p["down"] = np.where(p["r"].notna() & p["r_ctrl"].notna(), (p["r"] < p["r_ctrl"]).astype(float), np.nan)
            pc = p.groupby(["case_id", "event_id", "target_field"], as_index=False)["down"].mean()
            rows.append({"model": label, "arm": name, "valid_pairs": int(p["down"].notna().sum()),
                         **ci(mean_test(pc, "down", B=boot))})
            for field, g in pc.groupby("target_field"):
                rows.append({"model": label, "arm": f"{name} [{field}]", "valid_pairs": int(g["down"].notna().sum()),
                             **ci(mean_test(g, "down", B=boot))})
    return pd.DataFrame(rows)


# ---------- 3. floor replay ----------

def anchor_table(san):
    pay = san[san["payload_id"] != "none"].copy()
    lowered = rank(pay["raw_severity"]) < rank(pay["control_raw_severity"])
    restored = rank(pay["clean_severity"]) >= rank(pay["control_raw_severity"])
    pay["lowered"], pay["restored"] = lowered, lowered & restored
    pay["below_after_cleaning"] = ~restored
    t = pay.groupby("target_field").agg(cases=("case_id", "size"), anchor_lowered=("lowered", "sum"),
                                        restored_by_cleaning=("restored", "sum"),
                                        below_control_after_cleaning=("below_after_cleaning", "sum"),
                                        mean_raw_proba=("raw_proba", "mean"), mean_clean_proba=("clean_proba", "mean"))
    return t.round(3).reset_index()


def floor_replay(df, san, boot):
    c = df[(df["condition"] == "C") & (df["payload_id"] != "none")]
    valid = c[c["schema_ok"].eq("True") & c["severity"].isin(LLM_SEV)].merge(
        san[["case_id", "raw_severity", "clean_severity", "control_raw_severity"]], on="case_id", validate="many_to_one")
    r_llm = rank(valid["severity"])
    anchors = {"no_floor": None, "current_raw_anchor": "raw_severity",
               "sanitise_before_score": "clean_severity", "reference_control_anchor": "control_raw_severity"}
    r_true = rank(valid["control_raw_severity"])
    check = (np.maximum(r_llm, rank(valid["raw_severity"])) == rank(valid["final_severity"]))
    rows = []
    for model, label in MODELS.items():
        m = valid["model"] == model
        for name, col in anchors.items():
            r_fin = r_llm if col is None else np.maximum(r_llm, rank(valid[col]))
            d = valid[m].assign(below=(r_fin[m] < r_true[m]).astype(float), gap=(r_true[m] - r_fin[m]).clip(lower=0))
            pc = d.groupby(["case_id", "event_id", "target_field"], as_index=False)[["below", "gap"]].mean()
            rows.append({"model": label, "floor": name, "rows": int(m.sum()),
                         "below_event_severity": d["below"].mean(), **{f"pc_{k}": v for k, v in ci(mean_test(pc, "below", B=boot)).items()},
                         "mean_levels_below": d["gap"].mean()})
            for field, g in d.groupby("target_field"):
                rows.append({"model": label, "floor": f"{name} [{field}]", "rows": len(g),
                             "below_event_severity": g["below"].mean(), "mean_levels_below": g["gap"].mean()})
    meta = {"valid_C_payload_rows": int(len(valid)), "invalid_C_payload_rows_excluded": int(len(c) - len(valid)),
            "current_floor_reproduces_runner_final_severity": f"{int(check.sum())}/{len(valid)}"}
    return pd.DataFrame(rows), meta


def verdict_side(df, benign, san):
    """Floors never change verdicts: missed attacks and benign false positives in C, once per model."""
    out = {}
    for model, label in MODELS.items():
        c = df[(df["model"] == model) & (df["condition"] == "C") & (df["payload_id"] != "none")]
        b = benign[(benign["model"] == model) & (benign["condition"] == "C")]
        k1, n1 = int((c["ans_final"] == "benign").sum()), len(c)
        k2, n2 = int((b["ans_final"] == "malicious").sum()), len(b)
        out[label] = {"C_payload_rows_final_benign": [k1, n1], "C_benign_rows_final_malicious": [k2, n2, wilson_events(k2, n2, b["event_id"].nunique())]}   # Wilson over events, not rows
    bc = san[san["is_benign_control"].astype(str) == "True"]
    out["detector_on_benign_controls"] = {"raw_attack": int((bc["raw_proba"] >= 0.5).sum()),
                                          "cleaned_attack": int((bc["clean_proba"] >= 0.5).sum()), "n": len(bc)}
    return out


# ---------- 4. verdict guard ----------

def guard_sweep(df, benign, dwrong, san, boot):
    cases = pd.read_csv(CASES, keep_default_na=False)
    bcases = pd.read_csv(BENIGN_CASES, keep_default_na=False)
    proba = {"raw": pd.concat([cases, bcases]).set_index("case_id")["detector_proba"].astype(float),
             "sanitised": san.set_index("case_id")["clean_proba"].astype(float)}
    c = df[df["condition"] == "C"].copy()
    b = benign[benign["condition"] == "C"].copy()
    rows = []
    for source, p in proba.items():
        c["p"], b["p"] = c["case_id"].map(p), b["case_id"].map(p)
        assert c["p"].notna().all() and b["p"].notna().all(), f"missing {source} probability"
        for t in [None] + THRESHOLDS:
            fire_c = c["p"] >= t if t is not None else pd.Series(False, index=c.index)
            fire_b = b["p"] >= t if t is not None else pd.Series(False, index=b.index)
            c["ans_g"] = np.where(fire_c, "malicious", c["ans_final"])
            pc = per_case(outcomes(c, "ans_g"))
            for model, label in MODELS.items():
                g = pc[pc["model"] == model]
                bm = b[b["model"] == model]
                fp = (np.where(fire_b[bm.index], "malicious", bm["ans_final"]) == "malicious")
                r = mean_test(g, "Y", B=boot)
                rows.append({"model": label, "probability": source, "threshold": "none" if t is None else t,
                             "payload_induced_flip": r["estimate"], "ci_low": r["ci_low"], "ci_high": r["ci_high"],
                             "benign_fp": int(fp.sum()), "benign_n": len(bm)})
    sweep = pd.DataFrame(rows)

    # Synthetic cost: DWRONG (prompt B). Benign controls shown ATTACK with probability 1 - p.
    d = dwrong[dwrong["condition"] == "DWRONG"].copy()
    d["p_shown"] = d["detector_proba"].astype(float)
    cost, ranges = [], {}
    for model, label in MODELS.items():
        g = d[d["model"] == model]
        ben = g[g["detector_verdict"] == "attack"]          # benign controls shown ATTACK
        att = g[g["detector_verdict"] == "benign"]          # attack controls shown BENIGN
        for t in [None] + THRESHOLDS:
            fire = ben["p_shown"] >= t if t is not None else pd.Series(False, index=ben.index)
            harm = ((ben["ans"] == "malicious") | fire)
            rescue = att["p_shown"] >= t if t is not None else pd.Series(False, index=att.index)
            cost.append({"model": label, "threshold": "none" if t is None else t,
                         "benign_shown_attack_final_malicious": int(harm.sum()), "benign_shown_attack_n": len(ben),
                         "rate": harm.mean(), "attack_shown_benign_final_benign": int(((att["ans"] == "benign") & ~rescue).sum()),
                         "attack_shown_benign_n": len(att)})
        ranges[label] = {"benign_shown_attack": [float(ben["p_shown"].min()), float(ben["p_shown"].max())],
                         "attack_shown_benign": [float(att["p_shown"].min()), float(att["p_shown"].max())]}
    return sweep, pd.DataFrame(cost), ranges


def figure(sweep, cost):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    colors = {"Haiku 4.5": "#2a78d6", "gemma4:e4b": "#eb6834"}       # categorical slots 1 and 2
    styles = {"Haiku 4.5": "-", "gemma4:e4b": "--"}                  # second encoding for print / CVD
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.6), sharex=True)
    for label in colors:
        s = sweep[(sweep["model"] == label) & (sweep["probability"] == "raw") & (sweep["threshold"] != "none")]
        x = s["threshold"].astype(float)
        axes[0].plot(x, 100 * s["payload_induced_flip"], styles[label], color=colors[label], lw=2,
                     marker="o", ms=4, label=label)
        k = cost[(cost["model"] == label) & (cost["threshold"] != "none")]
        axes[1].plot(k["threshold"].astype(float), 100 * k["rate"], styles[label], color=colors[label], lw=2,
                     marker="o", ms=4, label=label)
    axes[0].set_title("Benefit: payload-induced flips left in C", fontsize=10, loc="left")
    axes[1].set_title("Cost: benign controls called malicious\n(synthetic wrong detector, DWRONG)", fontsize=10, loc="left")
    axes[0].set_ylabel("% of payload cases")
    axes[1].set_ylabel("% of benign controls shown ATTACK")
    for ax in axes:
        ax.set_xlabel("Guard threshold t (override to malicious if detector p ≥ t)")
        ax.grid(axis="y", color="#e6e5e0", lw=0.8)
        ax.spines[["top", "right"]].set_visible(False)
        ax.set_ylim(bottom=0)
    axes[0].legend(frameon=False, fontsize=9)
    fig.tight_layout()
    for ext in ["png", "pdf"]:
        fig.savefig(f"{OUT}/fig_guard_tradeoff.{ext}", dpi=200,
                    metadata={"CreationDate": None} if ext == "pdf" else None)   # PDF without a timestamp: byte-identical re-runs
    plt.close(fig)


# ---------- 5. latency / tokens ----------

def latency(df):
    d = df.copy()
    for col in ["latency_s", "prompt_tokens", "output_tokens"]:
        d[col] = pd.to_numeric(d[col], errors="coerce")
    per = (d.groupby(["model", "condition"]).agg(rows=("case_id", "size"), latency_median_s=("latency_s", "median"),
                                                  latency_mean_s=("latency_s", "mean"),
                                                  prompt_tokens_mean=("prompt_tokens", "mean"),
                                                  output_tokens_mean=("output_tokens", "mean")).round(3).reset_index())
    k = ["model", "case_id", "run"]
    pair = d[d["condition"] == "B"][k + ["latency_s", "prompt_tokens", "output_tokens"]].merge(
        d[d["condition"] == "C"][k + ["latency_s", "prompt_tokens", "output_tokens"]], on=k, suffixes=("_B", "_C"))
    over = pd.DataFrame([{
        "model": m, "pairs": len(g),
        "latency_C_minus_B_median_s": round(float((g["latency_s_C"] - g["latency_s_B"]).median()), 3),
        "prompt_tokens_C_minus_B_mean": round(float((g["prompt_tokens_C"] - g["prompt_tokens_B"]).mean()), 1),
        "output_tokens_C_minus_B_mean": round(float((g["output_tokens_C"] - g["output_tokens_B"]).mean()), 1)}
        for m, g in pair.groupby("model")])
    per["model"], over["model"] = per["model"].map(MODELS), over["model"].map(MODELS)
    return per, over


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--boot", type=int, default=10_000, help="bootstrap resamples (10,000 as registered)")
    args = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)

    df, err, dup = load_runs([FILES["haiku_v1"], FILES["e4b_v1"]])
    benign, _, _ = load_runs([FILES["haiku_v1_benign"], FILES["e4b_v1_benign"]])
    dwrong, _, _ = load_runs(DWRONG_FILES)
    san = pd.read_csv(SANITISED, keep_default_na=False)
    print(f"Loaded {len(df)} A/B/C rows ({len(err)} error rows, {len(dup)} duplicates dropped), "
          f"{len(benign)} benign rows, {len(dwrong)} DWRONG rows")

    dec, _ = decomposition(df, args.boot)
    tr = transitions(df)
    sev = severity_downgrade(df, args.boot)
    anchors = anchor_table(san)
    floors, floor_meta = floor_replay(df, san, args.boot)
    vside = verdict_side(df, benign, san)
    sweep, cost, shown = guard_sweep(df, benign, dwrong, san, args.boot)
    lat, over = latency(df)

    for name, t in [("decomposition", dec), ("transitions_C", tr), ("severity_downgrade", sev),
                    ("floor_anchor_by_field", anchors), ("floor_replay", floors), ("guard_sweep", sweep),
                    ("guard_cost_dwrong", cost), ("latency_tokens", lat), ("latency_overhead_C_vs_B", over)]:
        t.to_csv(f"{OUT}/{name}.csv", index=False)
    figure(sweep, cost)
    summary = {"floor_replay_meta": floor_meta, "dwrong_shown_probability_range": shown, "verdict_side": vside, "bootstrap_resamples": args.boot,
               "notes": ["Exploratory (pre-registration Section 6, item 7); e4b and Haiku A/B/C data were already seen.",
                         "DWRONG cost uses prompt B outputs and synthetic wrong-detector controls.",
                         "Haiku latency includes network time; gemma4:e4b ran locally."]}
    with open(f"{OUT}/summary.json", "w") as f:
        json.dump(summary, f, indent=2, default=str)

    pd.set_option("display.width", 200)
    print("\n1. Decomposition (payload-induced flip Y, raw flip F; d_input = C_raw - B, d_output = C_final - C_raw):")
    print(dec[~dec["quantity"].str.contains(r"\[")].round(4).to_string(index=False))
    print("\nC rows, answer before -> after the output guard:\n", tr.to_string(index=False))
    print("\n2. Severity downgrade vs control:\n", sev[~sev["arm"].str.contains(r"\[")].round(4).to_string(index=False))
    print("\n3. Floor anchors by field:\n", anchors.to_string(index=False))
    print("\n   Floor replay:", json.dumps(floor_meta))
    print(floors[~floors["floor"].str.contains(r"\[")].round(4).to_string(index=False))
    print("\n   Verdict side (unchanged by any floor):", json.dumps(vside, default=str))
    print("\n4. Verdict guard (raw probability):\n",
          sweep[sweep["probability"] == "raw"].round(4).to_string(index=False))
    print("\n   Guard cost on DWRONG (synthetic):\n", cost.round(4).to_string(index=False))
    print("\n5. Latency/tokens:\n", lat.to_string(index=False), "\n\n", over.to_string(index=False))
    print(f"\nSaved tables, summary.json and fig_guard_tradeoff.png/.pdf to {OUT}/")


if __name__ == "__main__":
    main()
