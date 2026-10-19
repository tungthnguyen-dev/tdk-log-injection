"""Checks for scripts/analyse_prereg.py on synthetic data with known answers (pre-registration Deviations,
15 Oct, item g). No result files are read.

Usage:
    python scripts/test_analyse_prereg.py            # unit checks + no-effect simulation (about 1 min)
    python scripts/test_analyse_prereg.py --quick    # unit checks only
"""
import os
import sys
import tempfile

import numpy as np
import pandas as pd

import analyse_prereg as ap

COLS = ["timestamp", "model", "prompt_version", "case_id", "event_id", "payload_id", "payload_category",
        "target_field", "condition", "run", "schema_ok", "verdict", "final_verdict", "floor_applied",
        "detector_verdict", "error"]


def row(event, payload, cond, run, verdict, ts="2026-10-01T00:00:00+00:00", ok=True, error="", model="m"):
    return {"timestamp": ts, "model": model, "prompt_version": "v1", "case_id": f"{event}_{payload}",
            "event_id": event, "payload_id": payload, "payload_category": "cat", "target_field": "user_agent",
            "condition": cond, "run": str(run), "schema_ok": str(ok), "verdict": verdict,
            "final_verdict": verdict, "floor_applied": "False", "detector_verdict": "attack", "error": error}


def load(rows):
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "r.csv")
        pd.DataFrame(rows, columns=COLS).to_csv(path, index=False)
        return ap.load_runs([path])


def test_outcomes_and_dedup():
    rows = [
        row("e1", "none", "A", 0, "malicious"), row("e1", "P01", "A", 0, "benign"),        # Y=1
        row("e1", "P02", "A", 0, "malicious"),                                             # Y=0
        row("e1", "P03", "A", 0, "", ok=False),                                            # invalid: Y=0, Yw=1
        row("e2", "none", "A", 0, "benign"), row("e2", "P01", "A", 0, "benign"),           # control benign: Y=0
        row("e3", "none", "A", 0, "", ok=False), row("e3", "P01", "A", 0, "benign"),       # control invalid
        # duplicate of e1_P02: the later row (benign) must be dropped; an error row must be ignored
        row("e1", "P02", "A", 0, "benign", ts="2026-10-02T00:00:00+00:00"),
        row("e1", "P01", "A", 0, "", ok=False, error="APIError", ts="2026-09-30T00:00:00+00:00"),
    ]
    df, errors, dropped = load(rows)
    assert len(errors) == 1 and len(dropped) == 1, (len(errors), len(dropped))
    assert dropped.iloc[0]["case_id"] == "e1_P02"
    pay = ap.outcomes(df).set_index("case_id")
    exp = {"e1_P01": (1, 1, 1, 1), "e1_P02": (0, 0, 0, 0), "e1_P03": (0, 1, np.nan, 0),
           "e2_P01": (0, 0, 0, 1), "e3_P01": (0, 1, np.nan, 1)}
    for case, (y, yw, yc, f) in exp.items():
        r = pay.loc[case]
        assert r["Y"] == y and r["Yw"] == yw and r["F"] == f, (case, r[["Y", "Yw", "F"]].tolist())
        assert (np.isnan(yc) and np.isnan(r["Yc"])) or r["Yc"] == yc, (case, r["Yc"])
    print("ok  outcomes: Y / worst / complete / raw flip, control gating, invalid kept, duplicates, errors")


def synthetic(n_events=48, n_pay=30, runs=1, rate_a=0.1, rate_b=0.3, model="m", seed=1):
    """Every control malicious; exactly rate * n_pay payloads flip per event, so the true effect is exact."""
    rows = []
    for e in range(n_events):
        ev = f"e{e:02d}"
        for cond, rate in [("A", rate_a), ("B", rate_b)]:
            for r in range(runs):
                rows.append(row(ev, "none", cond, r, "malicious", model=model))
                flips = set(np.random.default_rng(seed + e).permutation(n_pay)[:int(round(rate * n_pay))])
                for p in range(n_pay):
                    rows.append(row(ev, f"P{p + 1:02d}", cond, r, "benign" if p in flips else "malicious",
                                    model=model))
    return rows


def test_known_effect_and_sign():
    df, _, _ = load(synthetic())
    pc = ap.per_case(ap.outcomes(df))
    ba = ap.arm_contrast(df, pc, "t", "m", "B", "A")
    ab = ap.arm_contrast(df, pc, "t", "m", "A", "B")
    assert abs(ba["primary"]["estimate"] - 0.2) < 1e-12, ba["primary"]["estimate"]
    assert abs(ba["primary"]["estimate"] + ab["primary"]["estimate"]) < 1e-12
    assert abs(ba["primary"]["ci_low"] + ab["primary"]["ci_high"]) < 1e-12, "CI must mirror when arms swap"
    assert ba["control_gated_events"] == 48 and ba["n_cases"] == 48 * 30
    print("ok  known effect +20.0 pp recovered exactly; swapping arms flips the sign and mirrors the CI")


def test_group_diff_exact():
    rows = []
    for e in range(4):
        ev = f"e{e}"
        for cond in ["A", "B"]:
            rows.append(row(ev, "none", cond, 0, "malicious"))
            for p in [11, 12, 1, 2]:                 # P11, P12 in the H3 group; P01, P02 outside
                flip = cond == "B" and p in (11, 12)  # B flips only group payloads
                rows.append(row(ev, f"P{p:02d}", cond, 0, "benign" if flip else "malicious"))
    df, _, _ = load(rows)
    pc = ap.per_case(ap.outcomes(df))
    r = ap.arm_contrast(df, pc, "t", "m", "B", "A", group=ap.H3_GROUP)
    assert abs(r["primary"]["estimate"] - 1.0) < 1e-12, r["primary"]["estimate"]
    print("ok  H3 group contrast exact (group B-A = 1, rest = 0 -> 1.0)")


def test_runs_average_and_h4_shape():
    df, _, _ = load(synthetic(n_events=6, n_pay=10, runs=3))
    pay = ap.outcomes(df)
    pc, pc0 = ap.per_case(pay), ap.per_case(pay, runs=[0])
    assert len(pc) == len(pc0) == 2 * 6 * 10
    assert set(pc["Y"].unique()) <= {0.0, 1.0}
    print("ok  per-case mean over runs and first-run table have one row per case and condition")


def test_complete_case_strict():
    """One invalid run makes the whole case missing in the complete-case analysis (Deviations 19 Oct)."""
    rows = []
    for r in range(3):
        rows.append(row("e1", "none", "A", r, "malicious"))
        rows.append(row("e1", "P01", "A", r, "benign" if r < 2 else "", ok=r < 2))   # run 2 invalid
        rows.append(row("e1", "P02", "A", r, "benign"))
    df, _, _ = load(rows)
    pc = ap.per_case(ap.outcomes(df)).set_index("case_id")
    assert np.isnan(pc.loc["e1_P01", "Yc"]), "a case with an invalid run must be missing"
    assert abs(pc.loc["e1_P01", "Y"] - 2 / 3) < 1e-12, "primary still averages all runs (invalid = not benign)"
    assert pc.loc["e1_P02", "Yc"] == 1.0
    print("ok  complete case is strict: one invalid run removes the case; primary keeps all runs")


def test_small_helpers():
    adj = ap.holm({"a": 0.01, "b": 0.04, "c": 0.03})
    assert np.allclose([adj["a"], adj["c"], adj["b"]], [0.03, 0.06, 0.06])
    bh = ap.benjamini_hochberg({"a": 0.01, "b": 0.04, "c": 0.03})
    assert np.allclose([bh["a"], bh["c"], bh["b"]], [0.03, 0.04, 0.04])
    m = ap.mcnemar_midp(np.array([1] * 5 + [0] * 1 + [0] * 4), np.array([0] * 5 + [1] * 1 + [0] * 4))
    assert m["discordant_1_not_0"] == 5 and m["discordant_0_not_1"] == 1 and abs(m["mcnemar_midp"] - 0.125) < 1e-12
    d = pd.DataFrame({"event_id": ["a"] * 3 + ["b"] * 3, "x": [1, 1, 1, 0, 0, 0]})
    assert abs(ap.icc_oneway(d, "x")["icc"] - 1.0) < 1e-12
    allzero = ap.boot({"num": np.zeros(5), "den": np.ones(5)}, lambda s: s["num"] / s["den"], B=200)
    assert allzero["p"] == 1.0, "p must be capped at 1"
    print("ok  Holm, Benjamini-Hochberg, McNemar mid-p (5 vs 1 -> 0.125), ICC, p capped at 1")


def test_null_false_positive_rate(n_sims=400, B=2000):
    """Clustered data with no arm effect: the decision rule should reject at about 5%."""
    rng = np.random.default_rng(7)
    rejections = 0
    for _ in range(n_sims):
        p_event = rng.beta(2, 8, size=48)                      # events differ strongly (clustering)
        ya = rng.random((48, 30)) < p_event[:, None]
        yb = rng.random((48, 30)) < p_event[:, None]
        d = pd.DataFrame({"event_id": np.repeat(np.arange(48), 30), "D": (yb.astype(float) - ya).ravel()})
        rejections += ap.mean_test(d, "D", B=B)["p"] < 0.05
    rate = rejections / n_sims
    lo, hi = ap.wilson(rejections, n_sims)
    print(f"ok  no-effect simulation: rejected {rejections}/{n_sims} = {rate:.3f} (95% CI {lo:.3f}-{hi:.3f})")
    assert 0.02 <= rate <= 0.09, "False-positive rate far from 5%"


if __name__ == "__main__":
    test_outcomes_and_dedup()
    test_known_effect_and_sign()
    test_group_diff_exact()
    test_runs_average_and_h4_shape()
    test_complete_case_strict()
    test_small_helpers()
    if "--quick" not in sys.argv:
        test_null_false_positive_rate()
    print("All checks passed.")
