"""
week10_experiments.py
=====================
Week 10 — Full experimental runs + results tables/plots.

Sweeps the full (B4) hybrid model across four sync-mode conditions for n=10
seeds at T=3 tenants, then aggregates metrics and emits paper-ready tables
and figures.

Conditions (Section 7.1 of the paper):
  PHS-only     PHS=100, PTA=0,   ADFS=0,   Mixed=0
  PTA-only     PHS=0,   PTA=100, ADFS=0,   Mixed=0
  ADFS-only    PHS=0,   PTA=0,   ADFS=100, Mixed=0     (only if I3 passes)
  Mixed        PHS=60,  PTA=20,  ADFS=10,  Mixed=10    (default distribution)

Outputs (under generated_datasets/week10/<timestamp>/):
  raw_results.json           — per-run full metric dicts
  summary.json               — per-condition mean + std for every metric
  summary.csv                — same, flat CSV for paper tables
  table_invariants.csv       — Table: I1-I4 pass rates per condition
  table_s1_cross_boundary.csv
  table_s2_multitenant.csv
  table_s3_seam_chokepoint.csv
  table_p2_nhi_contribution.csv
  table_p3_misconfig.csv
  fig_*.png                  — one bar chart per headline metric
  variance_notes.md          — CV analysis + seed-sensitivity flags

Usage:
  PYTHONPATH=. python3 week10_experiments.py
  PYTHONPATH=. python3 week10_experiments.py --seeds 5         # quick test
  PYTHONPATH=. python3 week10_experiments.py --no-adfs         # skip ADFS
  PYTHONPATH=. python3 week10_experiments.py --no-figures      # skip plots
"""

import argparse
import copy
import csv
import json
import os
import random
import sys
from datetime import datetime
from timeit import default_timer as timer
from typing import Any, Dict, List, Optional, Tuple


# ============================================================
# Configuration
# ============================================================

# Default n=10 seeds (Section 7.1)
DEFAULT_SEEDS = [42, 137, 2025, 9001, 31337, 7, 256, 1024, 4096, 65535]

# T=3 tenants is the paper default scenario
N_TENANTS = 3

# Conditions to run
CONDITIONS = [
    {
        "id":          "PHS",
        "name":        "PHS-only",
        "description": "Password Hash Synchronization only",
        "syncModeDistribution": {"PHS": 100, "PTA": 0, "ADFS": 0, "Mixed": 0},
    },
    {
        "id":          "PTA",
        "name":        "PTA-only",
        "description": "Pass-Through Authentication only",
        "syncModeDistribution": {"PHS": 0, "PTA": 100, "ADFS": 0, "Mixed": 0},
    },
    {
        "id":          "ADFS",
        "name":        "ADFS-only",
        "description": "Active Directory Federation Services only",
        "syncModeDistribution": {"PHS": 0, "PTA": 0, "ADFS": 100, "Mixed": 0},
    },
    {
        "id":          "MIXED",
        "name":        "Mixed",
        "description": "Default distribution (PHS=60, PTA=20, ADFS=10, Mixed=10)",
        "syncModeDistribution": {"PHS": 60, "PTA": 20, "ADFS": 10, "Mixed": 10},
    },
]

OUTPUT_BASE = "generated_datasets/week10"


# ============================================================
# Pipeline runner — reuses Week 9 helpers structurally but
# without the baseline patches (which were Week 9 specific)
# ============================================================

def _reset_and_generate_ad(adsynth_instance) -> Tuple[List[Dict], int]:
    """Phase 1: on-prem AD generation. Reuses ADSynth.generate_data()."""
    from adsynth.DATABASE import NODES, reset_DB
    reset_DB()
    adsynth_instance.generate_data()
    seed_val = adsynth_instance.parameters.get("seed", 1)

    domain_nodes = [n for n in NODES if n.get("labels", [""])[-1] == "Domain"]
    domains = []
    for n in domain_nodes:
        props = n.get("properties", n)
        domains.append({
            "name": props.get("name", adsynth_instance.domain),
            "id":   props.get("objectid", adsynth_instance.base_sid),
            "sid":  props.get("objectid", adsynth_instance.base_sid),
        })
    if not domains:
        domains = [{
            "name": adsynth_instance.domain,
            "id":   adsynth_instance.base_sid,
            "sid":  adsynth_instance.base_sid,
        }]
    return domains, seed_val


def _create_tenants(adsynth_instance, seed_val: int) -> List[Dict]:
    """Phase 2: create T=3 Entra tenants with posture/orgType."""
    from adsynth.azure_ad_system.az_default_tenants import az_create_tenant
    from adsynth.DATABASE import TENANT_METADATA

    hybrid_cfg = adsynth_instance.parameters.get("hybrid", {})
    n_tenants  = hybrid_cfg.get("nTenants", N_TENANTS)
    posture_dist = hybrid_cfg.get("postureDistribution", {
        "good": 40, "average": 40, "poor": 20
    })

    rng = random.Random(seed_val ^ 0x99)
    base_name = adsynth_instance.domain.split(".")[0]
    tenants = []

    for i in range(n_tenants):
        t_name = (f"{base_name}.onmicrosoft.com" if i == 0
                  else f"{base_name}{i+1}.onmicrosoft.com")
        org_type = "parent" if i == 0 else "subsidiary"
        posture  = rng.choices(
            list(posture_dist.keys()),
            weights=list(posture_dist.values()), k=1
        )[0]
        tenant_id = az_create_tenant(t_name)
        TENANT_METADATA[tenant_id] = {"orgType": org_type, "posture": posture}
        tenants.append({"id": tenant_id, "name": t_name})

    return tenants


def _run_one_experiment(
    adsynth_instance,
    condition: Dict,
    seed: int,
) -> Dict[str, Any]:
    """
    Run the full B4 pipeline for one (condition, seed) pair.
    Returns the full metrics dict.
    """
    from adsynth.DATABASE import NODES, reset_DB
    from adsynth.synthesizer.hybrid_seam import (
        create_sync_links, create_user_synced_to_edges,
    )
    from adsynth.synthesizer.nhi import create_non_humans, create_delegation_edges
    from adsynth.synthesizer.permissions_hybrid import run_hybrid_permissions_phase
    from adsynth.hybrid_system.seam_metrics import compute_seam_metrics

    # Override the sync mode distribution for this condition
    adsynth_instance.parameters["seed"] = seed
    if "hybrid" not in adsynth_instance.parameters:
        adsynth_instance.parameters["hybrid"] = {}
    adsynth_instance.parameters["hybrid"]["syncModeDistribution"] = (
        condition["syncModeDistribution"]
    )
    # Make sure T=3 is set
    adsynth_instance.parameters["hybrid"]["nTenants"] = N_TENANTS

    # Phase 1: on-prem AD
    domains, seed_val = _reset_and_generate_ad(adsynth_instance)

    # Phase 2: tenants
    tenants = _create_tenants(adsynth_instance, seed_val)

    # Phase 2b: Create Azure roles per tenant.
    # Matches do_generate_hybrid_v2's Phase 2b. Without this, AZRole nodes
    # are never created — which means permissions_hybrid.assign_nhi_roles
    # produces 0 HAS_AZ_ROLE edges, and seam_metrics._TARGET_LABELS={"AZRole"}
    # finds 0 targets, collapsing S3 / P2 to 0.
    from adsynth.azure_ad_system.az_default_roles import az_create_roles
    for t in tenants:
        az_create_roles(t["id"], adsynth_instance.parameters)

    # Phase 3: sync links + bridge components
    links = create_sync_links(
        domains, tenants, adsynth_instance.parameters, seed_val
    )

    # Phase 4: NHI
    users_per_tenant = {}
    for t in tenants:
        count = sum(
            1 for n in NODES
            if n.get("labels", [""])[-1] == "AZUser"
            and n.get("properties", n).get("tenantid") == t["id"]
        )
        users_per_tenant[t["id"]] = count if count > 0 else 50

    nhi_result = create_non_humans(
        domains, tenants, users_per_tenant,
        adsynth_instance.parameters, seed_val
    )

    # Phase 5: SYNCED_TO + delegation edges
    rng_sync = random.Random(seed_val ^ 0xC0FFEE)
    for lnk in links:
        create_user_synced_to_edges(
            lnk["domain_name"], lnk["tenant_id"],
            adsynth_instance.parameters, rng_sync,
        )
    rng_deleg = random.Random(seed_val ^ 0xDE16)
    create_delegation_edges(nhi_result["sp_by_tenant"], rng_deleg)

    # Phase 6: permissions + misconfigs
    run_hybrid_permissions_phase(
        domains=domains,
        tenants=tenants,
        config=adsynth_instance.parameters,
        seed=seed_val,
    )

    # Phase 7: metrics
    metrics = compute_seam_metrics(domains, tenants)
    metrics["condition"] = condition["id"]
    metrics["seed"]      = seed
    metrics["link_modes"] = [lnk["sync_mode"] for lnk in links]
    return metrics


# ============================================================
# Aggregation — same shape as Week 9 but kept independent so
# we can change paper tables without disturbing the baseline runner.
# ============================================================

def _extract_key_metrics(m: Dict) -> Dict[str, Any]:
    """Pull headline numbers from a full metrics dict."""
    inv = m.get("invariants", {})
    inv_detail = inv.get("detail", {})
    return {
        "condition":             m.get("condition", "?"),
        "seed":                  m.get("seed", 0),
        "total_nodes":           m.get("graph_summary", {}).get("total_nodes", 0),
        "total_edges":           m.get("graph_summary", {}).get("total_edges", 0),

        # Invariants (I1-I4)
        "I1_pass":               inv_detail.get("I1_sync_identity",  {}).get("passed", False),
        "I2_pass":               inv_detail.get("I2_pta_mode",       {}).get("passed", False),
        "I3_pass":               inv_detail.get("I3_adfs_mode",      {}).get("passed", False),
        "I4_pass":               inv_detail.get("I4_phs_mode",       {}).get("passed", False),
        "invariant_pass_rate":   inv.get("pass_rate", 0.0),
        "invariant_all_pass":    inv.get("all_pass",  False),

        # S1
        "s1_cross_boundary_ratio": m.get("s1", {}).get("cross_boundary_ratio", 0.0),
        "s1_total_cross_boundary": m.get("s1", {}).get("total_cross_boundary", 0),

        # S2
        "s2_n_sync_links":       m.get("s2", {}).get("n_sync_links", 0),
        "s2_tpd_mean":           m.get("s2", {}).get("tenants_per_domain", {}).get("mean", 0.0),
        "s2_tpd_max":            m.get("s2", {}).get("tenants_per_domain", {}).get("max", 0),
        "s2_dpt_mean":           m.get("s2", {}).get("domains_per_tenant", {}).get("mean", 0.0),
        "s2_mass_ge2":           m.get("s2", {}).get("mass_ge2_tenants_per_domain", 0.0),

        # S3
        "s3_seam_coverage":      m.get("s3", {}).get("seam_path_coverage", 0.0),
        "s3_paths_computed":     m.get("s3", {}).get("total_paths_computed", 0),
        "s3_paths_through_seam": m.get("s3", {}).get("paths_through_seam", 0),
        "s3_seam_node_count":    m.get("s3", {}).get("seam_node_count", 0),

        # P2
        "p2_pr_nhi":             m.get("p2", {}).get("pr_path_contains_nhi", 0.0),
        "p2_pr_sync_id":         m.get("p2", {}).get("pr_path_contains_sync_identity", 0.0),

        # P3
        "p3_misconfig_density":  m.get("p3", {}).get("misconfig_density", 0.0),
        "p3_total_misconfig":    m.get("p3", {}).get("total_misconfig_edges", 0),
    }


def _aggregate(rows: List[Dict]) -> Dict[str, Any]:
    """Compute mean and std across seeds for every numeric/bool field."""
    if not rows:
        return {}

    result = {"n_runs": len(rows)}
    keys = [k for k in rows[0].keys() if k not in ("condition", "seed")]

    for k in keys:
        vals = [r.get(k) for r in rows]
        # Coerce booleans to 0/1
        vals_num = []
        for v in vals:
            if isinstance(v, bool):
                vals_num.append(1.0 if v else 0.0)
            elif isinstance(v, (int, float)):
                vals_num.append(float(v))
        if not vals_num:
            continue
        mean = sum(vals_num) / len(vals_num)
        var  = sum((v - mean) ** 2 for v in vals_num) / len(vals_num)
        std  = var ** 0.5
        cv   = (std / mean) if mean != 0 else 0.0
        result[f"{k}_mean"] = round(mean, 4)
        result[f"{k}_std"]  = round(std,  4)
        result[f"{k}_cv"]   = round(cv,   4)

    return result


# ============================================================
# Table writers — one CSV per paper table (Section 7.3)
# ============================================================

def _write_csv(path: str, header: List[str], rows: List[List]) -> None:
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        for r in rows:
            w.writerow(r)


def _fmt(val, places=4):
    if isinstance(val, float):
        return f"{val:.{places}f}"
    return str(val)


def write_table_invariants(summary: Dict, conditions: List[Dict], out_dir: str) -> str:
    """I1–I4 pass rates per condition."""
    path = os.path.join(out_dir, "table_invariants.csv")
    header = ["Condition", "I1_pass_rate", "I2_pass_rate",
              "I3_pass_rate", "I4_pass_rate", "All_pass_rate"]
    rows = []
    for c in conditions:
        s = summary.get(c["id"], {})
        rows.append([
            c["name"],
            _fmt(s.get("I1_pass_mean", 0)),
            _fmt(s.get("I2_pass_mean", 0)),
            _fmt(s.get("I3_pass_mean", 0)),
            _fmt(s.get("I4_pass_mean", 0)),
            _fmt(s.get("invariant_all_pass_mean", 0)),
        ])
    _write_csv(path, header, rows)
    return path


def write_table_s1(summary: Dict, conditions: List[Dict], out_dir: str) -> str:
    """S1 cross-boundary connectivity."""
    path = os.path.join(out_dir, "table_s1_cross_boundary.csv")
    header = ["Condition", "Cross_boundary_ratio_mean",
              "Cross_boundary_ratio_std", "Total_cross_boundary_mean",
              "Total_edges_mean"]
    rows = []
    for c in conditions:
        s = summary.get(c["id"], {})
        rows.append([
            c["name"],
            _fmt(s.get("s1_cross_boundary_ratio_mean", 0)),
            _fmt(s.get("s1_cross_boundary_ratio_std", 0)),
            _fmt(s.get("s1_total_cross_boundary_mean", 0), 1),
            _fmt(s.get("total_edges_mean", 0), 1),
        ])
    _write_csv(path, header, rows)
    return path


def write_table_s2(summary: Dict, conditions: List[Dict], out_dir: str) -> str:
    """S2 multi-tenant mapping statistics."""
    path = os.path.join(out_dir, "table_s2_multitenant.csv")
    header = ["Condition", "Sync_links_mean", "Tenants_per_domain_mean",
              "Tenants_per_domain_max", "Mass_ge2_mean", "Mass_ge2_std"]
    rows = []
    for c in conditions:
        s = summary.get(c["id"], {})
        rows.append([
            c["name"],
            _fmt(s.get("s2_n_sync_links_mean", 0), 1),
            _fmt(s.get("s2_tpd_mean_mean", 0)),
            _fmt(s.get("s2_tpd_max_mean", 0), 1),
            _fmt(s.get("s2_mass_ge2_mean", 0)),
            _fmt(s.get("s2_mass_ge2_std", 0)),
        ])
    _write_csv(path, header, rows)
    return path


def write_table_s3(summary: Dict, conditions: List[Dict], out_dir: str) -> str:
    """S3 seam chokepoint metrics (Algorithm 2)."""
    path = os.path.join(out_dir, "table_s3_seam_chokepoint.csv")
    header = ["Condition", "Seam_coverage_mean", "Seam_coverage_std",
              "Paths_computed_mean", "Paths_through_seam_mean",
              "Seam_nodes_mean"]
    rows = []
    for c in conditions:
        s = summary.get(c["id"], {})
        rows.append([
            c["name"],
            _fmt(s.get("s3_seam_coverage_mean", 0)),
            _fmt(s.get("s3_seam_coverage_std", 0)),
            _fmt(s.get("s3_paths_computed_mean", 0), 1),
            _fmt(s.get("s3_paths_through_seam_mean", 0), 1),
            _fmt(s.get("s3_seam_node_count_mean", 0), 1),
        ])
    _write_csv(path, header, rows)
    return path


def write_table_p2(summary: Dict, conditions: List[Dict], out_dir: str) -> str:
    """P2 non-human contribution to paths."""
    path = os.path.join(out_dir, "table_p2_nhi_contribution.csv")
    header = ["Condition", "Pr_path_NHI_mean", "Pr_path_NHI_std",
              "Pr_path_SyncIdentity_mean", "Pr_path_SyncIdentity_std"]
    rows = []
    for c in conditions:
        s = summary.get(c["id"], {})
        rows.append([
            c["name"],
            _fmt(s.get("p2_pr_nhi_mean", 0)),
            _fmt(s.get("p2_pr_nhi_std", 0)),
            _fmt(s.get("p2_pr_sync_id_mean", 0)),
            _fmt(s.get("p2_pr_sync_id_std", 0)),
        ])
    _write_csv(path, header, rows)
    return path


def write_table_p3(summary: Dict, conditions: List[Dict], out_dir: str) -> str:
    """P3 misconfig density (lived-in vs too-clean)."""
    path = os.path.join(out_dir, "table_p3_misconfig.csv")
    header = ["Condition", "Misconfig_density_mean", "Misconfig_density_std",
              "Total_misconfig_edges_mean"]
    rows = []
    for c in conditions:
        s = summary.get(c["id"], {})
        rows.append([
            c["name"],
            _fmt(s.get("p3_misconfig_density_mean", 0)),
            _fmt(s.get("p3_misconfig_density_std", 0)),
            _fmt(s.get("p3_total_misconfig_mean", 0), 1),
        ])
    _write_csv(path, header, rows)
    return path


# ============================================================
# Print comparison table
# ============================================================

def print_comparison_table(summary: Dict, conditions: List[Dict]) -> None:
    sep  = "=" * 86
    thin = "-" * 86
    print(f"\n{sep}")
    print("  Week 10 — Paper Results: Per-condition mean (std) over n seeds, T=3 tenants")
    print(sep)

    metrics = [
        ("Total nodes",                "total_nodes_mean",              "total_nodes_std"),
        ("Total edges",                "total_edges_mean",              "total_edges_std"),
        ("Invariant pass rate",        "invariant_pass_rate_mean",      "invariant_pass_rate_std"),
        ("S1 cross-boundary ratio",    "s1_cross_boundary_ratio_mean",  "s1_cross_boundary_ratio_std"),
        ("S2 mass(tenants≥2/domain)",  "s2_mass_ge2_mean",              "s2_mass_ge2_std"),
        ("S3 seam coverage",           "s3_seam_coverage_mean",         "s3_seam_coverage_std"),
        ("P2 Pr[path ∋ NHI]",          "p2_pr_nhi_mean",                "p2_pr_nhi_std"),
        ("P2 Pr[path ∋ SyncIdentity]", "p2_pr_sync_id_mean",            "p2_pr_sync_id_std"),
        ("P3 misconfig density",       "p3_misconfig_density_mean",     "p3_misconfig_density_std"),
    ]

    header = f"  {'Metric':<32}"
    for c in conditions:
        header += f"  {c['id']:<14}"
    print(header)
    print(thin)

    for label, mean_key, std_key in metrics:
        row = f"  {label:<32}"
        for c in conditions:
            s = summary.get(c["id"], {})
            mean = s.get(mean_key, 0.0)
            std  = s.get(std_key,  0.0)
            if isinstance(mean, (int, float)):
                cell = f"{mean:.3f}({std:.3f})"
            else:
                cell = str(mean)
            row += f"  {cell:<14}"
        print(row)

    print(f"\n{sep}\n")


# ============================================================
# Variance analysis — flag seed-sensitive metrics (CV > 0.3)
# ============================================================

def write_variance_notes(
    summary: Dict, conditions: List[Dict], out_dir: str, n_seeds: int
) -> str:
    """Produce variance_notes.md flagging high-CV metrics."""
    path = os.path.join(out_dir, "variance_notes.md")

    headline_metrics = [
        "s1_cross_boundary_ratio",
        "s2_mass_ge2",
        "s3_seam_coverage",
        "p2_pr_nhi",
        "p2_pr_sync_id",
        "p3_misconfig_density",
    ]

    lines = [
        "# Variance Analysis — Week 10",
        "",
        f"- Seeds per condition: n={n_seeds}",
        f"- Tenants: T={N_TENANTS}",
        "",
        "Coefficient of variation (CV = std/mean) per condition and metric.",
        "Metrics with CV > 0.3 are flagged as seed-sensitive and should be ",
        "reported with explicit error bars in the paper.",
        "",
        "## CV table",
        "",
        "| Metric | " + " | ".join(c["id"] for c in conditions) + " |",
        "|" + "---|" * (len(conditions) + 1),
    ]

    flagged = []
    for metric in headline_metrics:
        row = [metric]
        for c in conditions:
            cv = summary.get(c["id"], {}).get(f"{metric}_cv", 0.0)
            mark = "⚠ " if cv > 0.3 else ""
            row.append(f"{mark}{cv:.3f}")
            if cv > 0.3:
                flagged.append((metric, c["id"], cv))
        lines.append("| " + " | ".join(row) + " |")

    lines.append("")
    if flagged:
        lines.append("## Flagged (CV > 0.3)")
        lines.append("")
        for m, cid, cv in flagged:
            lines.append(f"- `{m}` under condition **{cid}**: CV = {cv:.3f}")
    else:
        lines.append("## Flagged (CV > 0.3)")
        lines.append("")
        lines.append("None — all headline metrics have CV ≤ 0.3 across n seeds.")

    lines.extend([
        "",
        "## Methodology notes",
        "",
        "- Path metrics (S3, P2) are computed over a BFS sample capped at 50 entry",
        "  nodes per run (see `seam_metrics._collect_node_sets`). Higher caps would",
        "  reduce variance but increase compute cost roughly linearly.",
        "- Misconfig density (P3) variance reflects the configured injection",
        "  percentages in `hybrid_misconfig` and is bounded by the underlying",
        "  privilege-edge count.",
        "- Invariant pass rates are 0 or 1 per run; their std reflects whether the",
        "  invariant ever fires, not measurement noise.",
    ])

    with open(path, "w") as f:
        f.write("\n".join(lines))
    return path


# ============================================================
# Figures (matplotlib) — bar charts with error bars per condition
# ============================================================

def make_figures(
    summary: Dict, conditions: List[Dict], out_dir: str
) -> List[str]:
    """Generate one bar chart per headline metric. Returns list of file paths."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("  matplotlib not available — skipping figures")
        print("  install with: pip3 install matplotlib")
        return []

    figs_to_make = [
        ("fig_s1_cross_boundary.png",
         "S1: Cross-boundary edge ratio",
         "s1_cross_boundary_ratio"),
        ("fig_s2_multitenant.png",
         "S2: Mass of domains with ≥2 tenants",
         "s2_mass_ge2"),
        ("fig_s3_seam_coverage.png",
         "S3: Seam path coverage (Algorithm 2)",
         "s3_seam_coverage"),
        ("fig_p2_nhi_contribution.png",
         "P2: Pr[path ∋ NonHumanIdentity]",
         "p2_pr_nhi"),
        ("fig_p2_sync_identity.png",
         "P2: Pr[path ∋ SyncIdentity]",
         "p2_pr_sync_id"),
        ("fig_p3_misconfig_density.png",
         "P3: Misconfig density",
         "p3_misconfig_density"),
        ("fig_invariants.png",
         "Invariant pass rate (all of I1-I4)",
         "invariant_all_pass"),
    ]

    out_paths = []
    for fname, title, metric_key in figs_to_make:
        labels = [c["id"] for c in conditions]
        means  = [summary.get(c["id"], {}).get(f"{metric_key}_mean", 0.0)
                  for c in conditions]
        stds   = [summary.get(c["id"], {}).get(f"{metric_key}_std",  0.0)
                  for c in conditions]

        fig, ax = plt.subplots(figsize=(6, 4))
        x = range(len(labels))
        ax.bar(x, means, yerr=stds, capsize=5,
               color=["#4C72B0", "#55A868", "#C44E52", "#8172B2"][:len(labels)],
               edgecolor="black", alpha=0.85)
        ax.set_xticks(list(x))
        ax.set_xticklabels(labels)
        ax.set_ylabel(metric_key)
        ax.set_title(title)
        ax.grid(axis="y", alpha=0.3)

        # Annotate values above bars
        for i, (m, s) in enumerate(zip(means, stds)):
            ax.text(i, m + s + 0.005, f"{m:.3f}",
                    ha="center", va="bottom", fontsize=9)

        plt.tight_layout()
        path = os.path.join(out_dir, fname)
        plt.savefig(path, dpi=150)
        plt.close(fig)
        out_paths.append(path)

    return out_paths


# ============================================================
# Save raw + summary
# ============================================================

def save_raw_and_summary(
    all_runs: List[Dict],
    summary: Dict,
    out_dir: str,
) -> Tuple[str, str, str]:
    raw_path = os.path.join(out_dir, "raw_results.json")
    with open(raw_path, "w") as f:
        json.dump(all_runs, f, indent=2, default=str)

    summary_json_path = os.path.join(out_dir, "summary.json")
    with open(summary_json_path, "w") as f:
        json.dump(summary, f, indent=2, default=str)

    # Flat summary CSV — every aggregated key, one row per condition
    csv_path = os.path.join(out_dir, "summary.csv")
    if summary:
        any_cond = next(iter(summary.values()))
        keys = sorted(any_cond.keys())
        with open(csv_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["condition"] + keys)
            for cid, agg in summary.items():
                row = [cid] + [agg.get(k, "") for k in keys]
                w.writerow(row)

    return raw_path, summary_json_path, csv_path


# ============================================================
# Main entry point
# ============================================================

def run_week10(
    seeds: List[int],
    skip_adfs: bool = False,
    no_figures: bool = False,
    debug_failure: bool = False,
) -> Dict[str, Any]:
    """Main runner. Returns the aggregated summary dict."""

    # Import ADSynth
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from adsynth.ADSynth import MainMenu as ADSynth
    except ImportError as e:
        print(f"Error importing ADSynth: {e}")
        print("Run with: PYTHONPATH=. python3 week10_experiments.py")
        sys.exit(1)

    # Filter conditions
    conditions = list(CONDITIONS)
    if skip_adfs:
        conditions = [c for c in conditions if c["id"] != "ADFS"]

    # Output dir per timestamp
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    out_dir = os.path.join(OUTPUT_BASE, ts)
    os.makedirs(out_dir, exist_ok=True)

    print("=" * 72)
    print("  Week 10 — Full Experimental Sweep")
    print(f"  Conditions: {[c['id'] for c in conditions]}")
    print(f"  Seeds:      {seeds}")
    print(f"  T:          {N_TENANTS}")
    print(f"  Output:     {out_dir}")
    print("=" * 72)

    all_runs: List[Dict] = []
    per_cond: Dict[str, List[Dict]] = {c["id"]: [] for c in conditions}
    failures: List[Tuple[str, int, str]] = []
    debug_dumped = False  # dump full traceback for the first failure only

    for cond in conditions:
        print(f"\n{'─'*72}")
        print(f"  {cond['id']} — {cond['name']}")
        print(f"  {cond['description']}")
        print(f"{'─'*72}")

        for i, seed in enumerate(seeds):
            print(f"\n  [Run {i+1}/{len(seeds)}] {cond['id']} seed={seed}")
            t0 = timer()
            try:
                # Fresh ADSynth per run — prevents in-memory state from a prior
                # run's tenant/group naming leaking into this run's permission
                # phase (root cause of "T2_IT Local Admins N@... not exist").
                adsynth = ADSynth()
                metrics = _run_one_experiment(adsynth, cond, seed)
                key = _extract_key_metrics(metrics)
                all_runs.append(metrics)
                per_cond[cond["id"]].append(key)

                inv_mark = "✓" if key["invariant_all_pass"] else "✗"
                print(f"    nodes={key['total_nodes']}  "
                      f"edges={key['total_edges']}  "
                      f"inv={inv_mark}  "
                      f"S1={key['s1_cross_boundary_ratio']:.3f}  "
                      f"S3={key['s3_seam_coverage']:.3f}  "
                      f"P2(NHI)={key['p2_pr_nhi']:.3f}  "
                      f"P3={key['p3_misconfig_density']:.3f}  "
                      f"({timer()-t0:.1f}s)")
            except Exception as e:
                print(f"    [!] Run failed: {e}")
                failures.append((cond["id"], seed, str(e)))
                if debug_failure and not debug_dumped:
                    import traceback
                    print("    --- traceback (first failure only) ---")
                    traceback.print_exc()
                    print("    --- end traceback ---")
                    debug_dumped = True

    # Aggregate
    summary: Dict[str, Any] = {}
    for c in conditions:
        summary[c["id"]] = _aggregate(per_cond[c["id"]])

    # Print + save
    print_comparison_table(summary, conditions)

    raw_path, summary_json, csv_path = save_raw_and_summary(
        all_runs, summary, out_dir
    )
    print(f"  Raw results:     {raw_path}")
    print(f"  Summary JSON:    {summary_json}")
    print(f"  Summary CSV:     {csv_path}")

    # Per-table CSVs
    print("\n  Paper tables:")
    print(f"    {write_table_invariants(summary, conditions, out_dir)}")
    print(f"    {write_table_s1(summary, conditions, out_dir)}")
    print(f"    {write_table_s2(summary, conditions, out_dir)}")
    print(f"    {write_table_s3(summary, conditions, out_dir)}")
    print(f"    {write_table_p2(summary, conditions, out_dir)}")
    print(f"    {write_table_p3(summary, conditions, out_dir)}")

    # Variance notes
    var_path = write_variance_notes(summary, conditions, out_dir, len(seeds))
    print(f"  Variance notes:  {var_path}")

    # Figures
    if not no_figures:
        print("\n  Figures:")
        figs = make_figures(summary, conditions, out_dir)
        for p in figs:
            print(f"    {p}")

    # Failure summary
    if failures:
        print("\n" + "=" * 72)
        print(f"  FAILURES: {len(failures)} run(s) did not complete")
        print("=" * 72)
        for cid, seed, err in failures:
            print(f"  {cid} seed={seed}: {err[:120]}")
        fail_path = os.path.join(out_dir, "failures.json")
        with open(fail_path, "w") as f:
            json.dump([{"condition": c, "seed": s, "error": e}
                       for c, s, e in failures], f, indent=2)
        print(f"\n  Saved to: {fail_path}")

    print(f"\nWeek 10 complete. Output: {out_dir}\n")
    return summary


# ============================================================
# CLI
# ============================================================

def parse_args():
    p = argparse.ArgumentParser(
        description="Week 10 — Full experimental sweep for the paper"
    )
    p.add_argument("--seeds", type=int, default=10,
                   help="Number of seeds per condition (default: 10)")
    p.add_argument("--no-adfs", action="store_true",
                   help="Skip the ADFS-only condition (use if I3 fails)")
    p.add_argument("--no-figures", action="store_true",
                   help="Skip matplotlib figure generation")
    p.add_argument("--seed-list", type=int, nargs="+",
                   help="Use a specific list of seeds instead of the default")
    p.add_argument("--debug-failure", action="store_true",
                   help="Print full traceback for the first failed run")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()

    if args.seed_list:
        seeds = args.seed_list
    elif args.seeds <= len(DEFAULT_SEEDS):
        seeds = DEFAULT_SEEDS[:args.seeds]
    else:
        # Extend deterministically if user asks for more than 10
        seeds = list(DEFAULT_SEEDS)
        rng = random.Random(0xBEEF)
        while len(seeds) < args.seeds:
            seeds.append(rng.randint(1, 1_000_000))

    run_week10(
        seeds=seeds,
        skip_adfs=args.no_adfs,
        no_figures=args.no_figures,
        debug_failure=args.debug_failure,
    )
