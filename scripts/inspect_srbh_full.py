import pandas as pd

PATH = "data/external/srbh/data_capec_multilabel.csv"
df = pd.read_csv(PATH, low_memory=False)
label_cols = [c for c in df.columns if c[:3].strip().isdigit()]
ours = ["000 - Normal", "66 - SQL Injection", "126 - Path Traversal",
        "310 - Scanning for Vulnerable Software"]

n_labels = df[label_cols].sum(axis=1)
print(f"Rows: {len(df)}")
print("Labels per row:", n_labels.value_counts().sort_index().to_dict())

single = df[n_labels == 1]
print("\nSingle-label rows in our classes:")
for c in ours:
    print(f"  {c:42s} {int(single[c].sum()):8d}")

print("\nUser-Agents overall:", df["request_user_agent"].nunique())
print("Referer present:", f"{df['request_referer'].notna().mean():.1%}")

print("\nSample URIs per class:")
for c in ours:
    s = single[single[c] == 1]["request_http_request"].sample(3, random_state=42)
    print(f"\n== {c} ==")
    for u in s:
        print("  ", str(u)[:150])

normal = single[single["000 - Normal"] == 1]
suspect = normal["request_user_agent"].str.contains("nmap|sqlmap|nikto", case=False, na=False) | \
          normal["request_http_request"].str.contains(r"\.\./|union.*select|%27", case=False, na=False, regex=True)
print(f"\n'Normal' rows with obvious attack patterns: {suspect.sum()} of {len(normal)} ({suspect.mean():.1%})")
