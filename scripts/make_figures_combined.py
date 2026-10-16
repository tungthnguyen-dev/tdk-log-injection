"""Combined figures, Claude Haiku 4.5 vs gemma4:e4b, from results/analysis/all/results.json.
Same drawing helpers as make_figures_haiku.py (SVG; PNG copies via macOS Quick Look).
One contrast is not stored in results.json and is computed here with analyse_prereg.py:
gemma4:e4b B - A, control-gated (the same function as every other contrast).

Usage:
    python scripts/make_figures_combined.py
"""
import json
import os
import subprocess

import analyse_prereg as ap
from make_figures_haiku import AXIS, BLUE, GRID, INK, INK2, SRC, Svg, wilson

OUT = "results/figures"
H, E = "claude-haiku-4-5-20251001", "gemma4:e4b"
YELLOW = "#eda100"    # reference palette, categorical slot 4 (yellow); blue + yellow is a colour-blind-safe pair
MODELS = [(H, "Claude Haiku 4.5", YELLOW), (E, "Gemma 4 e4b", BLUE)]
GRAY = "#9a9993"


def minus(v):
    return f"−{-v:g}" if v < 0 else (f"+{v:g}" if v > 0 else "0")


def legend(s, y, items, x=24, gap=26):
    for color, label in items:
        s.line(x, y, x + 16, y, color, 2)
        s.dot(x + 8, y, color)
        s.text(x + 24, y + 4, label, 11, INK2)
        x += 24 + 6.4 * len(label) + gap


def gated(res, key):
    r = res["exploratory"][key]
    return r["control_gated"]


def e4b_b_minus_a_gated():
    df, _, _ = ap.load_runs([ap.FILES["e4b_v1"]])
    pc = ap.per_case(ap.outcomes(df))
    return ap.arm_contrast(df, pc, "e4b B-A", E, "B", "A")["control_gated"]


def flip(r):
    """b - a from a - b: negate the estimate and mirror the CI."""
    return {"estimate": -r["estimate"], "ci_low": -r["ci_high"], "ci_high": -r["ci_low"]}


def effects(res, path):
    conf = res["confirmatory"]
    rows = [("Confirmatory and grounding overall", None),
            ("Grounding overall: B − A", {H: conf["H1"]["control_gated"], E: e4b_b_minus_a_gated()}),
            ("H2 detector channel: B − BCLEAN", {H: conf["H2-Haiku"]["control_gated"],
                                                     E: conf["H2-e4b"]["control_gated"]}),
            ("Parts of the detector block (exploratory)", None)]
    for key, label in [("V-A", "Verdict only vs no detector: V − A"),
                       ("VP-V", "Add probability: VP − V"),
                       ("VS-V", "Add SHAP: VS − V"),
                       ("PLACEBO-A", "Empty detector box: PLACEBO − A")]:
        rows.append((label, {m: gated(res, f"{m} {key}") for m, _, _ in MODELS}))
    rows.append(("Real detector content: B − PLACEBO",
                 {m: flip(gated(res, f"{m} PLACEBO-B")) for m, _, _ in MODELS}))

    W, left, right, top, row_h, head_h = 800, 330, 56, 104, 36, 30
    xmin, xmax = -32.0, 10.0
    X = lambda v: left + (v - xmin) / (xmax - xmin) * (W - left - right)
    y_end = top + sum(head_h if r is None else row_h for _, r in rows)
    s = Svg(W, y_end + 62)
    s.text(24, 30, "What the detector block does to flips: Claude Haiku 4.5 vs Gemma 4 e4b", 15, weight="bold")
    s.text(24, 50, "Control-gated difference in flip rate (events whose clean control was judged malicious in "
                   "both arms),", 11.5, INK2)
    s.text(24, 66, "percentage points, 95% event-cluster bootstrap CI", 11.5, INK2)
    legend(s, 86, [(c, name) for _, name, c in MODELS])
    for t in range(-30, 11, 10):
        s.line(X(t), top - 4, X(t), y_end, GRID if t else AXIS, 1)
        s.text(X(t), y_end + 18, minus(t), 11, INK2, "middle")
    s.text(X(xmin), y_end + 38, "← fewer flips", 11, INK2, "start")
    s.text(X(xmax), y_end + 38, "more flips →", 11, INK2, "end")
    y = top
    for label, r in rows:
        if r is None:
            s.text(24, y + 20, label, 12, INK, weight="bold")
            y += head_h
            continue
        cy = y + row_h / 2
        s.text(36, cy + 4, label, 12, INK)
        for (m, _, color), dy in zip(MODELS, (-6, 6)):
            e = r[m]
            s.line(X(100 * e["ci_low"]), cy + dy, X(100 * e["ci_high"]), cy + dy, color, 2)
            s.dot(X(100 * e["estimate"]), cy + dy, color)
        y += row_h
    s.save(path)


def dose(res, path):
    levels = [("DOSE55", 0.55), ("DOSE65", 0.65), ("DOSE75", 0.75), ("DOSE85", 0.85), ("DOSE95", 0.95), ("DOSE99", 0.99)]
    W, Hh, left, right, top, bottom = 700, 400, 70, 170, 104, 70
    X = lambda p: left + (p - 0.5) / 0.5 * (W - left - right)
    Y = lambda v: top + (1 - v / 30) * (Hh - top - bottom)
    s = Svg(W, Hh)
    s.text(24, 30, "Gemma 4 e4b reacts to the probability shown; Claude Haiku 4.5 does not", 15, weight="bold")
    s.text(24, 50, "Payload-induced flip rate when the detector says ATTACK with a fixed probability", 11.5, INK2)
    s.text(24, 66, "Subset of 576 payload cases per level; 95% event-cluster bootstrap CI", 11.5, INK2)
    legend(s, 86, [(c, name) for _, name, c in MODELS])
    for v in range(0, 31, 10):
        s.line(left, Y(v), W - right, Y(v), GRID if v else AXIS, 1)
        s.text(left - 10, Y(v) + 4, f"{v}%", 11, INK2, "end")
    for _, p in levels:
        s.text(X(p), Hh - bottom + 20, f"{p:.2f}", 11, INK2, "middle")
    s.text((left + W - right) / 2, Hh - bottom + 44, "Attack probability shown to the model", 11.5, INK2, "middle")
    for (m, name, color), dx in zip(MODELS, (-4, 4)):
        rates = {r["condition"]: r for r in res["rates"] if r["model"] == m}
        pts = [(X(p) + dx, 100 * rates[c]["payload_induced_flip"], 100 * rates[c]["payload_induced_flip_ci"][0],
                100 * rates[c]["payload_induced_flip_ci"][1]) for c, p in levels]
        s.path([(x, Y(v)) for x, v, _, _ in pts], color, 2)
        for x, v, lo, hi in pts:
            s.line(x, Y(lo), x, Y(hi), color, 2)
            s.dot(x, Y(v), color)
        d = res["dose"][m]
        trend = "flat" if d["p"] >= 0.05 else "falls"
        s.text(X(0.99) + 16, Y(pts[-1][1]) + 4, f"{name}: {trend} (p = {d['p']:.2g})", 11, INK)
    s.save(path)


def dwrong(res, path):
    rows = []
    for title, key, field in [("Real attacks: answered benign", "attack_shown_benign_deferred", "attack"),
                              ("Benign events: answered malicious", "benign_shown_attack_deferred", "benign")]:
        rows.append((title, None))
        for m, name, color in MODELS:
            ctrl = {r["condition"]: r for r in res["controls"] if r["model"] == m}["B"]
            rate = {r["condition"]: r for r in res["rates"] if r["model"] == m}["B"]
            base = (ctrl["benign"], ctrl["malicious"] + ctrl["benign"] + ctrl["invalid"]) if field == "attack" \
                else (int(rate["benign_fp"]), int(rate["benign_n"]))
            rows.append((name, (base, tuple(res["dwrong"][m][key][:2]), color)))
    W, left, right, top, row_h, head_h = 720, 250, 40, 104, 40, 30
    X = lambda v: left + v / 60 * (W - left - right)
    y_end = top + sum(head_h if r is None else row_h for _, r in rows)
    s = Svg(W, y_end + 44)
    s.text(24, 30, "Following a wrong detector: Haiku only towards benign, Gemma both ways", 15, weight="bold")
    s.text(24, 50, "Share of no-payload controls answered as the wrong detector suggests "
                   "(Haiku 48 events × 3 runs, Gemma × 1); 95% Wilson CI", 11.5, INK2)
    x = 24
    for color, label in [(GRAY, "Correct detector (condition B)"), (YELLOW, "Wrong detector, Haiku"),
                         (BLUE, "Wrong detector, Gemma")]:
        s.dot(x + 6, 76, color)
        s.text(x + 18, 80, label, 11, INK2)
        x += 18 + 6.4 * len(label) + 24
    for v in range(0, 61, 20):
        s.line(X(v), top - 4, X(v), y_end, GRID if v else AXIS, 1)
        s.text(X(v), y_end + 18, f"{v}%", 11, INK2, "middle")
    y = top
    for label, r in rows:
        if r is None:
            s.text(24, y + 20, label, 12, INK, weight="bold")
            y += head_h
            continue
        (k0, n0), (k1, n1), color = r
        cy = y + row_h / 2
        s.text(36, cy + 4, label, 12, INK)
        v0, v1 = 100 * k0 / n0, 100 * k1 / n1
        s.line(X(v0), cy, X(v1), cy, GRID, 1)
        for k, n, v, c in [(k0, n0, v0, GRAY), (k1, n1, v1, color)]:
            lo, hi = wilson(k, n)
            if hi > lo:
                s.line(X(100 * lo), cy, X(100 * hi), cy, c, 2)
            s.dot(X(v), cy, c)
        if k1 == 0 and k0 == 0:
            s.text(X(100 * wilson(k1, n1)[1]) + 8, cy + 4, f"0 of {n1} in both", 11, INK)
        else:
            s.text(X(100 * wilson(k1, n1)[1]) + 8, cy + 4, f"{v1:.0f}% ({k1}/{n1})", 11, INK)
        y += row_h
    s.save(path)


def main():
    res = json.load(open(SRC))
    os.makedirs(OUT, exist_ok=True)
    figs = {"combined_effects": effects, "combined_dose": dose, "combined_dwrong": dwrong}
    for name, fn in figs.items():
        path = f"{OUT}/{name}.svg"
        fn(res, path)
        head = open(path).read(300)
        w, h = (float(head.split(f'{k}="')[1].split('"')[0]) for k in ["width", "height"])
        try:
            subprocess.run(["qlmanage", "-t", "-s", "2000", "-o", OUT, path], check=True, capture_output=True)
            os.replace(f"{path}.png", f"{OUT}/{name}.png")
            subprocess.run(["sips", "--cropToHeightWidth", str(round(2000 * h / w)), "2000",
                            "--cropOffset", "1", "0", f"{OUT}/{name}.png"], check=True, capture_output=True)
            print("Saved:", path, "and", f"{OUT}/{name}.png")
        except (FileNotFoundError, subprocess.CalledProcessError):
            print("Saved:", path, "(PNG skipped: qlmanage/sips not available)")


if __name__ == "__main__":
    main()
