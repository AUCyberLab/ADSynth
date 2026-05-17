"""inspect_real_graph.py — dump labels/edges from one real Week10 run."""
import sys, os
from collections import Counter
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from week10_experiments import _run_one_experiment, CONDITIONS
from adsynth.ADSynth import MainMenu as ADSynth
from adsynth.DATABASE import NODES, EDGES

# Run one PHS run exactly the way week10 does
adsynth = ADSynth()
phs_condition = next(c for c in CONDITIONS if c["id"] == "PHS")
metrics = _run_one_experiment(adsynth, phs_condition, seed=42)

print(f"\n=== Final graph: {len(NODES)} nodes, {len(EDGES)} edges ===\n")

print("=== Node label counts ===")
labels = Counter()
for n in NODES:
    lbl = (n.get("labels") or [""])[-1]
    labels[lbl] += 1
for lbl, cnt in labels.most_common():
    print(f"  {lbl:<30} {cnt:>5}")

print("\n=== Edge label counts ===")
edge_labels = Counter(e.get("label", "") for e in EDGES)
for lbl, cnt in edge_labels.most_common():
    print(f"  {lbl:<30} {cnt:>5}")

# Find any node that looks like a role/admin/privilege target
print("\n=== Searching for cloud privilege targets ===")
priv_keywords = ["role", "admin", "priv", "global", "owner"]
for i, n in enumerate(NODES):
    lbl = (n.get("labels") or [""])[-1]
    props = n.get("properties", n)
    name = props.get("name", "") or ""
    name_lower = str(name).lower()
    if any(kw in name_lower for kw in priv_keywords) and lbl.startswith("AZ"):
        print(f"  [{lbl}] {name}")
        if i > 30:
            break

# What labels does the real S3 see?
print("\n=== What entry/target/seam sets does compute_s3 actually see? ===")
from adsynth.hybrid_system.seam_metrics import (
    _ENTRY_LABELS, _TARGET_LABELS, _SEAM_LABELS, _collect_node_sets
)
print(f"  _ENTRY_LABELS  = {_ENTRY_LABELS}")
print(f"  _TARGET_LABELS = {_TARGET_LABELS}")
print(f"  _SEAM_LABELS   = {_SEAM_LABELS}")
entry, target, seam = _collect_node_sets({n["id"]: i for i, n in enumerate(NODES)})
print(f"  -> entry_count = {len(entry)}")
print(f"  -> target_count = {len(target)}")
print(f"  -> seam_count = {len(seam)}")

# Print metrics for sanity
import json
print("\n=== S3 from this run ===")
print(json.dumps(metrics["s3"], indent=2))
print("\n=== P3 from this run ===")
print(json.dumps(metrics["p3"], indent=2))