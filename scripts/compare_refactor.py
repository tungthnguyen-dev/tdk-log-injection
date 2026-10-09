import pandas as pd

new = pd.read_csv("results/runs/refactor_check.csv", keep_default_na=False)
old = pd.read_csv("results/runs/gemma4_e4b.csv", keep_default_na=False)
key = ["case_id", "condition"]
m = new.merge(old[old["run"] == 0], on=key, suffixes=("_new", "_old"))

print(f"Matched rows: {len(m)} of {len(new)}")
for col in ["prompt_hash", "raw_response", "final_verdict", "final_severity"]:
    same = (m[f"{col}_new"] == m[f"{col}_old"]).sum()
    print(f"{col:15s} identical: {same}/{len(m)}")
diff = m[m["raw_response_new"] != m["raw_response_old"]]
if len(diff):
    print("\nDifferent rows:", diff[key].values.tolist())
