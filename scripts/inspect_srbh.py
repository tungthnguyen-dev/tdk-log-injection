import pandas as pd

PATH = "data/external/srbh/data_capec_multilabel.csv"
df = pd.read_csv(PATH, nrows=20000, low_memory=False)

print(f"Columns ({len(df.columns)}):")
for c in df.columns:
    print(f"  {c!r:45s} non-null {df[c].notna().mean():6.1%}  distinct {df[c].nunique():6d}")

keys = ["agent", "refer", "status", "code", "url", "uri", "path", "query", "method", "label", "capec", "class"]
print("\nColumns that look relevant:")
for c in df.columns:
    if any(k in c.lower() for k in keys):
        print(f"\n== {c} ==")
        print(df[c].astype(str).value_counts().head(5).to_string())
