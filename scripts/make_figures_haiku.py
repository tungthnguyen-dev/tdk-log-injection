"""Figures for the Haiku 4.5 results, drawn as SVG from results/analysis/all/results.json.
No plotting library needed; PNG copies can be made with macOS Quick Look (see the end of main()).

Usage:
    python scripts/make_figures_haiku.py
"""
import json
import os
import subprocess
from xml.sax.saxutils import escape

from analyse_prereg import wilson

SRC = "results/analysis/all/results.json"
OUT = "results/figures"
H = "claude-haiku-4-5-20251001"

# Reference palette (dataviz skill): surface, text tokens, two categorical slots, blue ramp steps
SURFACE, INK, INK2, GRID, AXIS = "#ffffff", "#0b0b0b", "#52514e", "#e6e5e1", "#8f8e89"
BLUE = "#2a78d6"     # Gemma 4 e4b in the combined figures
YELLOW = "#eda100"   # Claude Haiku 4.5 (palette yellow); blue + yellow is a colour-blind-safe pair
GRAY = "#9a9993"     # de-emphasis: primary metric, correct-detector baseline
FONT = "Helvetica, Arial, sans-serif"


class Svg:
    def __init__(self, w, h):
        self.w, self.h, self.items = w, h, [f'<rect width="{w}" height="{h}" fill="{SURFACE}"/>']

    def text(self, x, y, s, size=12, color=INK, anchor="start", weight="normal"):
        self.items.append(f'<text x="{x:.1f}" y="{y:.1f}" font-family="{FONT}" font-size="{size}" '
                          f'fill="{color}" text-anchor="{anchor}" font-weight="{weight}">{escape(s)}</text>')

    def line(self, x1, y1, x2, y2, color=GRID, width=1, cap="round"):
        self.items.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{color}" '
                          f'stroke-width="{width}" stroke-linecap="{cap}"/>')

    def dot(self, x, y, color, r=4.5):
        # filled marker with a 2px surface ring
        self.items.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{r}" fill="{color}" stroke="{SURFACE}" stroke-width="2"/>')

    def path(self, pts, color, width=2):
        d = " ".join(f"{'M' if i == 0 else 'L'}{x:.1f},{y:.1f}" for i, (x, y) in enumerate(pts))
        self.items.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{width}" '
                          f'stroke-linejoin="round" stroke-linecap="round"/>')

    def save(self, path):
        with open(path, "w") as f:
            f.write(f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.w}" height="{self.h}" '
                    f'viewBox="0 0 {self.w} {self.h}">\n' + "\n".join(self.items) + "\n</svg>\n")


def pp(r):
    return 100 * r["estimate"], 100 * r["ci_low"], 100 * r["ci_high"]


def effects_figure(res, path):
    conf, ex = res["confirmatory"], res["exploratory"]
    rows = [("Pre-registered tests (Holm-adjusted p over six tests)", None),
            (f"H1  Grounding: B − A  (Holm p = {conf['H1']['holm_p']:.2f})",
             (conf["H1"]["primary"], conf["H1"]["control_gated"])),
            (f"H2  Detector channel: B′ − BCLEAN  (Holm p = {conf['H2-Haiku']['holm_p']:.2f})",
             (conf["H2-Haiku"]["primary"], conf["H2-Haiku"]["control_gated"])),
            ("Exploratory: parts of the detector block", None)]
    for key, label in [("V-A", "Verdict only vs no detector: V − A"),
                       ("VP-V", "Add probability: VP − V"),
                       ("VS-V", "Add SHAP: VS − V"),
                       ("B-VP", "Add SHAP to VP: B − VP"),
                       ("B-VS", "Add probability to VS: B − VS"),
                       ("PLACEBO-A", "Empty detector box: PLACEBO − A")]:
        r = ex[f"{H} {key}"]
        rows.append((label, (r, r["control_gated"])))

    W, left, right, top = 800, 340, 40, 108
    row_h, head_h = 34, 30
    xmin, xmax = -14.0, 8.0
    plot_w = W - left - right
    X = lambda v: left + (v - xmin) / (xmax - xmin) * plot_w
    heights = [head_h if r is None else row_h for _, r in rows]
    Hh = top + sum(heights) + 64
    s = Svg(W, Hh)
    s.text(24, 30, "Claude Haiku 4.5: effect of each part of the detector block on flips", 15, weight="bold")
    s.text(24, 50, "Difference in flip rate between two prompt arms, percentage points, with 95% event-cluster bootstrap CI",
           11.5, INK2)
    # legend
    for i, (color, label) in enumerate([(YELLOW, "Primary (pre-registered): payload-induced flip, all events"),
                                        (GRAY, "Sensitivity: control-gated, events whose clean control was judged malicious in both arms")]):
        ly = 68 + 17 * i
        s.line(24, ly, 40, ly, color, 2)
        s.dot(32, ly, color)
        s.text(48, ly + 4, label, 11, INK2)
    y0, y_end = top, top + sum(heights)
    for t in range(-12, 9, 4):
        s.line(X(t), y0 - 4, X(t), y_end, GRID if t else AXIS, 1)
        s.text(X(t), y_end + 18, (f"+{t}" if t > 0 else f"\u2212{-t}") if t else "0", 11, INK2, "middle")
    s.text(X(xmin), y_end + 38, "\u2190 fewer flips", 11, INK2, "start")
    s.text(X(0), y_end + 38, "percentage points", 11, INK2, "middle")
    s.text(X(xmax), y_end + 38, "more flips \u2192", 11, INK2, "end")
    y = y0
    for label, r in rows:
        if r is None:
            s.text(24, y + 20, label, 12, INK, weight="bold")
            y += head_h
            continue
        cy = y + row_h / 2
        s.text(36, cy + 4, label, 12, INK)
        for (est, color, dy) in [(r[0], YELLOW, -6), (r[1], GRAY, 6)]:
            if est is None:
                continue
            e, lo, hi = pp(est)
            s.line(X(lo), cy + dy, X(hi), cy + dy, color, 2)
            s.dot(X(e), cy + dy, color)
        y += row_h
    s.save(path)


def dose_figure(res, path):
    levels = [("DOSE55", 0.55), ("DOSE65", 0.65), ("DOSE75", 0.75), ("DOSE85", 0.85), ("DOSE95", 0.95), ("DOSE99", 0.99)]
    rates = {r["condition"]: r for r in res["rates"] if r["model"] == H}
    pts = [(p, 100 * rates[c]["payload_induced_flip"], 100 * rates[c]["payload_induced_flip_ci"][0],
            100 * rates[c]["payload_induced_flip_ci"][1]) for c, p in levels]
    d = res["dose"][H]
    W, Hh, left, right, top, bottom = 620, 390, 70, 30, 104, 70
    X = lambda p: left + (p - 0.5) / 0.5 * (W - left - right)
    Y = lambda v: top + (1 - v / 30) * (Hh - top - bottom)
    s = Svg(W, Hh)
    s.text(24, 30, "Claude Haiku 4.5: no detectable trend across the probability shown", 15, weight="bold")
    s.text(24, 50, "Payload-induced flip rate when the detector says ATTACK with a fixed probability", 11.5, INK2)
    s.text(24, 66, "Subset of 576 payload cases per level; 95% event-cluster bootstrap CI", 11.5, INK2)
    for v in range(0, 31, 10):
        s.line(left, Y(v), W - right, Y(v), GRID if v else AXIS, 1)
        s.text(left - 10, Y(v) + 4, f"{v}%", 11, INK2, "end")
    for p in [0.55, 0.65, 0.75, 0.85, 0.95, 0.99]:
        s.text(X(p), Hh - bottom + 20, f"{p:.2f}", 11, INK2, "middle")
    s.text((left + W - right) / 2, Hh - bottom + 44, "Attack probability shown to the model", 11.5, INK2, "middle")
    s.path([(X(p), Y(v)) for p, v, _, _ in pts], YELLOW, 2)
    for p, v, lo, hi in pts:
        s.line(X(p), Y(lo), X(p), Y(hi), YELLOW, 2)
        s.dot(X(p), Y(v), YELLOW)
    s.text(W - right, top - 12, f"Logistic slope p = {d['p']:.2f} (BH p = {d['bh_p']:.2f}): no detectable trend",
           11.5, INK, "end")
    s.save(path)


def ci_of(entry):
    """[k, n, wilson, event-cluster CI] -> the event-cluster CI; for 0 of n (degenerate bootstrap), the Wilson CI
    over events (analyse_prereg.wilson_events)."""
    k, _, w, c = entry
    return tuple(w) if k == 0 else tuple(c)


ZERO_NOTE = "For 0 counts the event-cluster bootstrap has no spread, so the Wilson 95% CI over the 48 events is shown."


def dwrong_figure(res, path):
    dw = res["dwrong"][H]
    rows = [("Real attacks: answered benign", "correct says ATTACK, wrong says BENIGN",
             dw["baseline_B_attack_controls_benign"], dw["attack_shown_benign_deferred"]),
            ("Benign events: answered malicious", "correct says BENIGN, wrong says ATTACK",
             dw["baseline_B_benign_controls_malicious"], dw["benign_shown_attack_deferred"])]
    W, Hh, left, right, top = 700, 290, 270, 40, 100
    row_h = 66
    X = lambda v: left + v / 60 * (W - left - right)
    s = Svg(W, Hh)
    s.text(24, 30, "Claude Haiku 4.5 followed a wrong detector only when it said benign", 15, weight="bold")
    s.text(24, 50, "Share of no-payload controls (48 events × 3 runs) answered as the wrong detector suggests; "
                   "95% event-cluster CI", 11.5, INK2)
    lx = 24
    for color, label in [(GRAY, "Correct detector (condition B)"), (YELLOW, "Wrong detector (DWRONG)")]:
        s.dot(lx + 6, 74, color)
        s.text(lx + 18, 78, label, 11, INK2)
        lx += 18 + 6.2 * len(label) + 26
    y_end = top + row_h * len(rows)
    for v in range(0, 61, 20):
        s.line(X(v), top - 6, X(v), y_end, GRID if v else AXIS, 1)
        s.text(X(v), y_end + 18, f"{v}%", 11, INK2, "middle")
    for i, (label, sub, e0, e1) in enumerate(rows):
        (k0, n0), (k1, n1) = e0[:2], e1[:2]
        cy = top + i * row_h + row_h / 2
        s.text(24, cy, label, 12, INK)
        s.text(24, cy + 16, sub, 10.5, INK2)
        v0, v1 = 100 * k0 / n0, 100 * k1 / n1
        s.line(X(v0), cy, X(v1), cy, GRID, 1)
        for (e, v, color) in [(e0, v0, GRAY), (e1, v1, YELLOW)]:
            lo, hi = ci_of(e)
            s.line(X(100 * lo), cy, X(100 * hi), cy, color, 2) if hi > lo else None
            s.dot(X(v), cy, color)
        if k0 == k1 == 0:
            s.text(X(0) + 12, cy - 10, "0 of 144 in both", 11, INK)
        else:
            s.text(X(v0), cy - 12, f"{v0:.0f}% ({k0}/{n0})", 11, INK, "middle")
            s.text(X(v1), cy - 12, f"{v1:.0f}% ({k1}/{n1})", 11, INK, "middle")
    if any(e[0] == 0 for _, _, e0, e1 in rows for e in (e0, e1)):
        s.text(24, y_end + 44, ZERO_NOTE, 10.5, INK2)
    s.save(path)


def main():
    res = json.load(open(SRC))
    os.makedirs(OUT, exist_ok=True)
    figs = {"haiku_effects": effects_figure, "haiku_dose": dose_figure, "haiku_dwrong": dwrong_figure}
    sizes = {}
    for name, fn in figs.items():
        path = f"{OUT}/{name}.svg"
        fn(res, path)
        head = open(path).read(300)
        sizes[name] = tuple(float(head.split(f'{k}="')[1].split('"')[0]) for k in ["width", "height"])
        print("Saved:", path)
    # PNG copies via macOS Quick Look (optional; skipped elsewhere)
    try:
        for name in figs:
            subprocess.run(["qlmanage", "-t", "-s", "2000", "-o", OUT, f"{OUT}/{name}.svg"],
                           check=True, capture_output=True)
            os.replace(f"{OUT}/{name}.svg.png", f"{OUT}/{name}.png")
            w, h = sizes[name]
            subprocess.run(["sips", "--cropToHeightWidth", str(round(2000 * h / w)), "2000",
                            "--cropOffset", "1", "0", f"{OUT}/{name}.png"], check=True, capture_output=True)
            print("Saved:", f"{OUT}/{name}.png")
    except (FileNotFoundError, subprocess.CalledProcessError):
        print("qlmanage not available: PNG copies skipped")


if __name__ == "__main__":
    main()
