import sys
import pandas as pd
sys.path.insert(0, "scripts")
import _old_runner as old
import run_experiment as new

cases = pd.read_csv("data/processed/injected_cases_v1.csv")
conds = ["A", "B", "C"]
t_old = old.load_templates("prompts/v1", conds)
t_new = new.load_templates("prompts/v1", conds)

total = same = 0
for _, case in cases.iterrows():
    for c in conds:
        defended = c == "C"
        log_old = old.sanitize_log(case["injected_raw_log"]) if defended else case["injected_raw_log"]
        log_new = new.sanitize_log(case["injected_raw_log"]) if defended else case["injected_raw_log"]
        p_old = (t_old[c][0], old.fill(t_old[c][1], case, log_old))
        det = new.detector_output(case, "injected", {})
        p_new = (t_new[c][0], new.fill(t_new[c][1], det, log_new))
        total += 1
        same += p_old == p_new
print(f"Identical prompts: {same}/{total}")
