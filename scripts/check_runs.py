import pandas as pd

for m in ["gemma4_e2b", "gemma4_12b"]:
    for suffix in ["", "_benign"]:
        name = m + suffix
        r = pd.read_csv(f"results/runs/{name}.csv", keep_default_na=False)
        lat = pd.to_numeric(r["latency_s"])
        q = len(lat) // 4
        print(name, "| rows:", len(r), "| cases:", r["case_id"].nunique(),
              "| conditions:", sorted(r["condition"].unique()))
        print("  latency by quarter:",
              [round(lat[i * q:(i + 1) * q].median(), 2) for i in range(4)])
        print("  prompt hashes:", r["prompt_hash"].nunique())
