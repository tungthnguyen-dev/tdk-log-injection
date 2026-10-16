"""Mixed-model sensitivity analysis (pre-registration Section 6; Deviations 15 Oct, mixed model).

The bootstrap in analyse_prereg.py treats the 30 payloads as fixed. This check treats events AND
payloads as random (crossed random effects), so it asks whether an effect would hold for payloads like
these, not only for these 30. The bootstrap decides; this is a sensitivity check.

Default: linear mixed model (REML) on the per-case contrast used by each hypothesis (e.g. D = Y_B - Y_A,
Haiku averaged over its runs), with crossed random intercepts for event and payload. Same estimand as the
bootstrap (a difference in flip rate). A random intercept on D is a random slope for the arm.

--binomial also fits the registered binomial GLMM (variational Bayes, statsmodels BinomialBayesMixedGLM,
run-level outcome, random slopes for arm, case intercept for repeated runs). On these near-deterministic
outcomes it degenerates (random-effect SDs of 6-31 on the logit scale), so it is kept only for the record.

Usage:
    python scripts/glmm_sensitivity.py --stage v1
    python scripts/glmm_sensitivity.py --stage all [--e4b-v2 FILE ...] [--binomial]
"""
import argparse
import json
import os
import warnings

import numpy as np
import statsmodels.formula.api as smf

import analyse_prereg as ap

H, E = "claude-haiku-4-5-20251001", "gemma4:e4b"
FAMILY = ["H1", "H2-e4b", "H2-Haiku", "H3-e4b", "H3-Haiku", "H4"]


# ---------- linear mixed model on per-case contrasts (default) ----------

def lmm(d, formula, term):
    """REML fit with crossed random intercepts for event and payload; Wald 95% CI for `term`."""
    d = d.assign(one=1)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        m = smf.mixedlm(formula, d, groups="one", re_formula="0",
                        vc_formula={"event": "0 + C(event_id)", "payload": "0 + C(payload_id)"})
        r = m.fit(reml=True, method=["lbfgs", "powell", "nm"])   # tried in order until one converges
    est, se = float(r.fe_params[term]), float(r.bse_fe[term])
    return {"estimate": est, "se": se, "ci_low": est - 1.96 * se, "ci_high": est + 1.96 * se,
            "converged": bool(r.converged), "n_cases": len(d),
            "sd_event": float(np.sqrt(r.vcomp[m.exog_vc.names.index("event")])),
            "sd_payload": float(np.sqrt(r.vcomp[m.exog_vc.names.index("payload")]))}


def contrast(pc, model, arm1, arm0):
    w = ap.wide(pc, model, [arm1, arm0])
    w["D"] = w[arm1] - w[arm0]
    w["group"] = w["payload_id"].isin(ap.H3_GROUP).astype(int)
    return w


def lmm_tests(pc):
    conds = {m: set(pc[pc["model"] == m]["condition"]) for m in [H, E]}
    t = {"H1": lmm(contrast(pc, H, "B", "A"), "D ~ 1", "Intercept"),
         "H3-e4b": lmm(contrast(pc, E, "B", "A"), "D ~ group", "group"),
         "H3-Haiku": lmm(contrast(pc, H, "B", "A"), "D ~ group", "group")}
    h, g = contrast(pc, H, "B", "A"), contrast(pc, E, "B", "A")
    m = h[["case_id", "event_id", "payload_id", "D"]].merge(g[["case_id", "D"]], on="case_id",
                                                            suffixes=("_h", "_g"), validate="one_to_one")
    m["DD"] = m["D_h"] - m["D_g"]
    t["H4"] = lmm(m, "DD ~ 1", "Intercept")
    if {"BPRIME", "BCLEAN"} <= conds[H]:
        t["H2-Haiku"] = lmm(contrast(pc, H, "BPRIME", "BCLEAN"), "D ~ 1", "Intercept")
    if "BCLEAN" in conds[E]:
        t["H2-e4b"] = lmm(contrast(pc, E, "B", "BCLEAN"), "D ~ 1", "Intercept")
    return t


# ---------- registered binomial GLMM (for the record) ----------

def binomial_glmm(pay):
    from statsmodels.genmod.bayes_mixed_glm import BinomialBayesMixedGLM

    def fit(d, formula, term, case_re):
        vc = {"event": "0 + C(event_id)", "payload": "0 + C(payload_id)",
              "event_arm": "0 + C(event_id):arm", "payload_arm": "0 + C(payload_id):arm"}
        if case_re:
            vc["case"] = "0 + C(case_id)"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            model = BinomialBayesMixedGLM.from_formula(formula, vc, d)
            res = model.fit_vb()
        i = list(model.fep_names).index(term)
        mean, sd = float(res.fe_mean[i]), float(res.fe_sd[i])
        return {"log_odds": mean, "ci95": [mean - 1.96 * sd, mean + 1.96 * sd],
                "re_sd_logit": {n: float(np.exp(v)) for n, v in zip(model.vcp_names, res.vcp_mean)}}

    def arm_data(model, arm1, arm0):
        d = pay[(pay["model"] == model) & pay["condition"].isin([arm1, arm0])].copy()
        d["arm"] = (d["condition"] == arm1).astype(int)
        d["group"] = d["payload_id"].isin(ap.H3_GROUP).astype(int)
        return d
    out = {"H1": fit(arm_data(H, "B", "A"), "Y ~ arm", "arm", True),
           "H3-e4b": fit(arm_data(E, "B", "A"), "Y ~ arm * group", "arm:group", False),
           "H3-Haiku": fit(arm_data(H, "B", "A"), "Y ~ arm * group", "arm:group", True)}
    both = arm_data(H, "B", "A")._append(arm_data(E, "B", "A"))
    both["haiku"] = (both["model"] == H).astype(int)
    out["H4"] = fit(both, "Y ~ arm * haiku", "arm:haiku", True)
    return out


# ---------- main ----------

def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--stage", choices=["v1", "all"], required=True)
    p.add_argument("--e4b-v2", nargs="*", default=[])
    p.add_argument("--binomial", action="store_true", help="Also fit the registered binomial GLMM (slow)")
    args = p.parse_args()

    paths = [ap.FILES["haiku_v1"], ap.FILES["e4b_v1"]]
    if args.stage == "all":
        paths += [ap.FILES["haiku_bclean"]] + [f for f in args.e4b_v2 if "benign" not in f]
    df, _, _ = ap.load_runs(paths)
    df.loc[(df["prompt_version"] == "v2") & (df["condition"] == "B"), "condition"] = "BPRIME"
    pay = ap.outcomes(df)
    pc = ap.per_case(pay)

    boot_path = f"results/analysis/{args.stage}/results.json"
    boot = json.load(open(boot_path))["confirmatory"] if os.path.exists(boot_path) else {}
    res = {"method": "linear mixed model (REML) on per-case contrasts, crossed random intercepts "
                     "for event and payload", "tests": lmm_tests(pc)}

    pct = lambda r: f"{100 * r['estimate']:+5.1f} pp [{100 * r['ci_low']:+5.1f}, {100 * r['ci_high']:+5.1f}]"
    print("Mixed-model sensitivity (events and payloads random) vs bootstrap (payloads fixed)")
    print(f"{'test':9s} {'mixed model':28s} {'bootstrap':28s} SD event / payload")
    for name in FAMILY:
        r = res["tests"].get(name)
        if r is None:
            print(f"{name:9s} not available at this stage")
            continue
        b = boot.get(name, {}).get("primary")
        excl = lambda x: x["ci_low"] > 0 or x["ci_high"] < 0
        r["bootstrap_ci_excludes_0"] = excl(b) if b else None
        r["mixed_ci_excludes_0"] = excl(r)
        print(f"{name:9s} {pct(r):28s} {pct(b) if b else 'n/a':28s} "
              f"{100 * r['sd_event']:.1f} / {100 * r['sd_payload']:.1f} pp"
              + ("" if r["converged"] else "  NOT CONVERGED"))

    if args.binomial:
        print("\nRegistered binomial GLMM (variational Bayes), for the record:")
        res["binomial_glmm"] = binomial_glmm(pay)
        for name, r in res["binomial_glmm"].items():
            sds = ", ".join(f"{k} {v:.1f}" for k, v in r["re_sd_logit"].items())
            print(f"  {name:9s} log-odds {r['log_odds']:+.2f} [{r['ci95'][0]:+.2f}, {r['ci95'][1]:+.2f}]; "
                  f"random-effect SDs (logit): {sds}")

    os.makedirs("results/analysis/glmm", exist_ok=True)
    dst = f"results/analysis/glmm/{args.stage}.json"
    with open(dst, "w") as f:
        json.dump(res, f, indent=2)
    print(f"\nSaved: {dst}")


if __name__ == "__main__":
    main()
