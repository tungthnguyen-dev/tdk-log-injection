import pandas as pd

ref = pd.read_csv("results/runs/gemma4_e4b.csv", keep_default_na=False)
ref_hashes = dict(ref.groupby("condition")["prompt_hash"].first())
for m in ["gemma4_e2b", "gemma4_12b"]:
    r = pd.read_csv(f"results/runs/{m}.csv", keep_default_na=False)
    h = dict(r.groupby("condition")["prompt_hash"].first())
    errors = (r["error"] != "").sum() if "error" in r.columns else "no error column"
    print(m, "| hashes match e4b:", h == ref_hashes, "| error rows:", errors)
