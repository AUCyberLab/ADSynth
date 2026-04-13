"""
adsynth/hybrid_system/seam_metrics.py
======================================
Week 8 — Evaluation metric implementation (seam realism + attack-path utility).

Implements the metric suite from Section 7.3 of the paper:

  Semantic validity (already handled by invariant_validators.py — reused here
  for pass-rate reporting, not re-implemented):
    I1/I2/I3  — invariant pass rates (delegated to existing validate_graph_invariants)

  Seam realism metrics:
    S1  — Cross-boundary connectivity: counts and ratios of cross-boundary edges
    S2  — Multi-tenant mapping statistics: tenants-per-domain and domains-per-tenant
    S3  — Seam chokepoint metrics: seam betweenness + seam path coverage (Algorithm 2)

  Attack-path utility metrics:
    P2  — Non-human contribution to paths: Pr[path contains NHI / SyncIdentity]
    P3  — "Too-clean" vs lived-in: misconfig density (isMisconfig edges / privilege edges)

All metrics are computed read-only over the in-memory graph (NODES, EDGES, NODE_GROUPS,
SYNC_IDENTITY_NODES, TENANT_METADATA from DATABASE.py). No new nodes or edges are created.

Entry point:
    compute_seam_metrics(domains, tenants) -> dict
    print_seam_metrics_report(metrics)

Safe framing: structural and semantic analysis only. No exploit instructions.
"""

import json
import os
from collections import deque, defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

from adsynth.DATABASE import (
    NODES, EDGES, NODE_GROUPS,
    SYNC_IDENTITY_NODES, TENANT_METADATA,
)


# ============================================================
# Internal helpers — reuse _props pattern from permissions_hybrid
# ============================================================

def _props(node: dict) -> dict:
    """Return properties dict regardless of node storage format."""
    if "properties" in node:
        return node["properties"]
    return {k: v for k, v in node.items() if k not in ("id", "labels", "type")}


def _get_node(idx: int) -> Optional[dict]:
    if 0 <= idx < len(NODES):
        return NODES[idx]
    return None


def _node_id(idx: int) -> str:
    """Return the Neo4j id string for a node index."""
    n = _get_node(idx)
    return n["id"] if n else ""


def _label(idx: int) -> str:
    """Return the primary label of a node."""
    n = _get_node(idx)
    if not n:
        return ""
    labels = n.get("labels", [])
    return labels[-1] if labels else ""


def _node_plane(idx: int) -> str:
    """Return plane property (AD / Entra / Hybrid)."""
    n = _get_node(idx)
    if not n:
        return ""
    return _props(n).get("plane", "")


def _is_nhi(idx: int) -> bool:
    """Return True if node is any NonHumanIdentity subtype."""
    lbl = _label(idx)
    return lbl in {
        "AZServicePrincipal", "ManagedIdentity", "AutomationAccount",
        "SyncIdentity", "ConnectorHost", "PTAAgentHost", "ADFSServer",
        "AIAgent",
    }


def _is_sync_identity(idx: int) -> bool:
    return _label(idx) == "SyncIdentity"


# ============================================================
# Build adjacency list for BFS (directed, follows edge direction)
# ============================================================

def _build_adjacency() -> Tuple[Dict[str, List[str]], Dict[str, int]]:
    """
    Build a directed adjacency list from EDGES.
    Returns:
      adj: { neo4j_id -> [neo4j_id, ...] }
      id_to_idx: { neo4j_id -> NODES index }
    """
    id_to_idx: Dict[str, int] = {n["id"]: i for i, n in enumerate(NODES)}
    adj: Dict[str, List[str]] = defaultdict(list)

    for e in EDGES:
        src = e.get("start", {}).get("id", "")
        tgt = e.get("end", {}).get("id", "")
        if src and tgt:
            adj[src].append(tgt)

    return dict(adj), id_to_idx


def _bfs_shortest_path(
    adj: Dict[str, List[str]],
    source: str,
    targets: Set[str],
) -> Optional[List[str]]:
    """
    BFS from source, return first shortest path reaching any node in targets.
    Returns list of neo4j id strings (inclusive of source and target),
    or None if no path exists.
    """
    if not source or source not in adj and source not in {n["id"] for n in NODES}:
        return None
    if source in targets:
        return [source]

    visited = {source}
    queue = deque([[source]])

    while queue:
        path = queue.popleft()
        current = path[-1]
        for neighbor in adj.get(current, []):
            if neighbor in targets:
                return path + [neighbor]
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(path + [neighbor])
    return None


# ============================================================
# S1 — Cross-boundary connectivity
# Paper: count and ratio of SYNC_LINK, SYNCED_TO, IS_FEDERATED_WITH,
#        HAS_PTA_AGENT edges; normalise by total edges.
# ============================================================

_CROSS_BOUNDARY_EDGE_TYPES = {
    "SYNC_LINK", "SYNCED_TO", "IS_FEDERATED_WITH", "HAS_PTA_AGENT",
    # Also count the seam privilege edges we created in Week 6
    "HAS_AD_RIGHT", "GetChanges", "GetChangesAll",
}


def compute_s1(total_edges: int) -> Dict[str, Any]:
    """
    S1: Cross-boundary connectivity.
    Returns raw counts per edge type + total + ratio to all edges.
    """
    counts: Dict[str, int] = defaultdict(int)

    for e in EDGES:
        lbl = e.get("label", "")
        if lbl in _CROSS_BOUNDARY_EDGE_TYPES:
            counts[lbl] += 1

    total_cb = sum(counts.values())
    ratio = round(total_cb / total_edges, 4) if total_edges > 0 else 0.0

    return {
        "edge_counts":         dict(counts),
        "total_cross_boundary": total_cb,
        "total_edges":          total_edges,
        "cross_boundary_ratio": ratio,
    }


# ============================================================
# S2 — Multi-tenant mapping statistics
# Paper: tenants-per-domain distribution, domains-per-tenant,
#        mass at ≥2 tenants per domain.
# ============================================================

def compute_s2(domains: List[Dict], tenants: List[Dict]) -> Dict[str, Any]:
    """
    S2: Multi-tenant mapping statistics.
    Uses SYNC_IDENTITY_NODES (keyed by (domain_name, tenant_id)) to derive
    the actual domain↔tenant sync mapping without touching SYNC_LINK edges
    directly (since our graph uses SyncIdentity per link as the primary record).
    """
    # Count tenants per domain and domains per tenant from sync links
    tenants_per_domain: Dict[str, Set[str]] = defaultdict(set)
    domains_per_tenant: Dict[str, Set[str]] = defaultdict(set)

    for (domain_name, tenant_id) in SYNC_IDENTITY_NODES.keys():
        tenants_per_domain[domain_name].add(tenant_id)
        domains_per_tenant[tenant_id].add(domain_name)

    # Distribution: how many domains have k tenants
    tpd_counts = [len(v) for v in tenants_per_domain.values()]
    dpt_counts = [len(v) for v in domains_per_tenant.values()]

    n_domains = len(tenants_per_domain)
    n_multi_tenant_domains = sum(1 for c in tpd_counts if c >= 2)
    mass_ge2 = round(n_multi_tenant_domains / n_domains, 4) if n_domains > 0 else 0.0

    return {
        "n_domains":                  n_domains,
        "n_tenants":                  len(tenants),
        "n_sync_links":               len(SYNC_IDENTITY_NODES),
        "tenants_per_domain": {
            "values":                 tpd_counts,
            "mean":                   round(sum(tpd_counts) / len(tpd_counts), 3)
                                      if tpd_counts else 0.0,
            "max":                    max(tpd_counts) if tpd_counts else 0,
        },
        "domains_per_tenant": {
            "values":                 dpt_counts,
            "mean":                   round(sum(dpt_counts) / len(dpt_counts), 3)
                                      if dpt_counts else 0.0,
            "max":                    max(dpt_counts) if dpt_counts else 0,
        },
        "mass_ge2_tenants_per_domain": mass_ge2,
        "multi_tenant_domains":        n_multi_tenant_domains,
    }


# ============================================================
# S3 — Seam chokepoint metrics (Algorithm 2 from the paper)
# Paper: SeamCoverage = |{p ∈ P | p ∩ S ≠ ∅}| / |P|
#   E = entry set: on-prem principals (User, Computer, Group in AD plane)
#   T = target set: cloud-privileged targets (AZRole nodes)
#   S = seam node set: SyncIdentity + ConnectorHost + PTAAgentHost + ADFSServer
#
# Seam betweenness: how often seam nodes appear on shortest paths E→T.
# ============================================================

# On-prem entry node labels
_ENTRY_LABELS = {"User", "Computer", "Group"}
# Cloud-privileged target labels
_TARGET_LABELS = {"AZRole"}
# Seam node labels (bridge components)
_SEAM_LABELS   = {"SyncIdentity", "ConnectorHost", "PTAAgentHost", "ADFSServer"}


def _collect_node_sets(id_to_idx: Dict[str, int]) -> Tuple[
    List[str], Set[str], Set[str]
]:
    """
    Return (entry_ids, target_ids_set, seam_ids_set) as Neo4j id strings.
    Limits entry set to max 50 nodes to keep BFS tractable on 1700-node graph.
    """
    entry_ids: List[str] = []
    target_ids: Set[str] = set()
    seam_ids:   Set[str] = set()

    for i, node in enumerate(NODES):
        lbl = (node.get("labels") or [""])[-1]
        nid = node["id"]
        if lbl in _ENTRY_LABELS and _node_plane(i) in ("AD", ""):
            entry_ids.append(nid)
        if lbl in _TARGET_LABELS:
            target_ids.add(nid)
        if lbl in _SEAM_LABELS:
            seam_ids.add(nid)

    # Limit entry set for performance — sample evenly
    if len(entry_ids) > 50:
        step = len(entry_ids) // 50
        entry_ids = entry_ids[::step][:50]

    return entry_ids, target_ids, seam_ids


def compute_s3() -> Dict[str, Any]:
    """
    S3: Seam chokepoint metrics.
    Implements Algorithm 2 from the paper (SeamCoverage).

    For each entry e and each reachable target t, find shortest path.
    SeamCoverage = fraction of those paths that pass through at least one seam node.
    Seam betweenness = per-seam-node count of paths it appears on.
    """
    adj, id_to_idx = _build_adjacency()
    entry_ids, target_ids, seam_ids = _collect_node_sets(id_to_idx)

    if not target_ids or not entry_ids:
        return {
            "seam_path_coverage":   0.0,
            "total_paths_computed": 0,
            "paths_through_seam":   0,
            "seam_betweenness":     {},
            "seam_node_count":      len(seam_ids),
            "entry_node_count":     len(entry_ids),
            "target_node_count":    len(target_ids),
        }

    total_paths = 0
    paths_through_seam = 0
    betweenness: Dict[str, int] = defaultdict(int)  # seam_id -> count

    for e_id in entry_ids:
        path = _bfs_shortest_path(adj, e_id, target_ids)
        if path is None:
            continue
        total_paths += 1
        path_seam_nodes = seam_ids.intersection(path)
        if path_seam_nodes:
            paths_through_seam += 1
            for sn in path_seam_nodes:
                betweenness[sn] += 1

    coverage = (
        round(paths_through_seam / total_paths, 4)
        if total_paths > 0 else 0.0
    )

    # Map seam node ids back to names for readability
    named_betweenness: Dict[str, int] = {}
    for nid, count in betweenness.items():
        idx = id_to_idx.get(nid)
        if idx is not None:
            name = _props(NODES[idx]).get("name", nid[:8])
        else:
            name = nid[:8]
        named_betweenness[name] = count

    return {
        "seam_path_coverage":   coverage,
        "total_paths_computed": total_paths,
        "paths_through_seam":   paths_through_seam,
        "seam_betweenness":     named_betweenness,
        "seam_node_count":      len(seam_ids),
        "entry_node_count":     len(entry_ids),
        "target_node_count":    len(target_ids),
    }


# ============================================================
# P2 — Non-human contribution to paths
# Paper: Pr[path contains NonHumanIdentity] and Pr[path contains SyncIdentity]
# Uses same BFS infrastructure as S3 but counts NHI appearances.
# ============================================================

def compute_p2() -> Dict[str, Any]:
    """
    P2: Non-human contribution to attack paths.
    Same entry/target sets as S3.
    Reports:
      - Pr[path contains any NHI]
      - Pr[path contains SyncIdentity specifically]
    """
    adj, id_to_idx = _build_adjacency()
    entry_ids, target_ids, _ = _collect_node_sets(id_to_idx)

    # Build NHI id sets
    nhi_ids: Set[str] = set()
    sync_ids: Set[str] = set()

    for i, node in enumerate(NODES):
        lbl = (node.get("labels") or [""])[-1]
        nid = node["id"]
        if _is_nhi(i):
            nhi_ids.add(nid)
        if _is_sync_identity(i):
            sync_ids.add(nid)

    if not target_ids or not entry_ids:
        return {
            "total_paths":                      0,
            "paths_with_any_nhi":               0,
            "paths_with_sync_identity":         0,
            "pr_path_contains_nhi":             0.0,
            "pr_path_contains_sync_identity":   0.0,
        }

    total = 0
    with_nhi = 0
    with_sync = 0

    for e_id in entry_ids:
        path = _bfs_shortest_path(adj, e_id, target_ids)
        if path is None:
            continue
        total += 1
        path_set = set(path)
        if path_set & nhi_ids:
            with_nhi += 1
        if path_set & sync_ids:
            with_sync += 1

    return {
        "total_paths":                    total,
        "paths_with_any_nhi":             with_nhi,
        "paths_with_sync_identity":       with_sync,
        "pr_path_contains_nhi":           round(with_nhi / total, 4)
                                          if total > 0 else 0.0,
        "pr_path_contains_sync_identity": round(with_sync / total, 4)
                                          if total > 0 else 0.0,
    }


# ============================================================
# P3 — "Too-clean" vs lived-in comparison
# Paper: ratio of isMisconfig=True edges to total privilege edges
# Privilege edges: HAS_AZ_ROLE, DELEGATED_RIGHT, HAS_AD_RIGHT, ADMIN_TO
# ============================================================

_PRIVILEGE_EDGE_TYPES = {
    "HAS_AZ_ROLE", "DELEGATED_RIGHT", "HAS_AD_RIGHT", "ADMIN_TO",
    "GetChanges", "GetChangesAll",
}


def compute_p3() -> Dict[str, Any]:
    """
    P3: "Too-clean" vs lived-in comparison.
    Misconfig density = |edges with isMisconfig=True| / |privilege edges|.
    Also breaks down by misconfig type.
    """
    total_priv = 0
    total_misconfig = 0
    misconfig_by_type: Dict[str, int] = defaultdict(int)

    for e in EDGES:
        lbl = e.get("label", "")
        if lbl not in _PRIVILEGE_EDGE_TYPES:
            continue
        total_priv += 1
        props = e.get("properties", {})
        if props.get("isMisconfig"):
            total_misconfig += 1
            mc_type = props.get("misconfigType", "unknown")
            misconfig_by_type[mc_type] += 1

    density = (
        round(total_misconfig / total_priv, 4)
        if total_priv > 0 else 0.0
    )

    return {
        "total_privilege_edges":  total_priv,
        "total_misconfig_edges":  total_misconfig,
        "misconfig_density":      density,
        "misconfig_by_type":      dict(misconfig_by_type),
    }


# ============================================================
# Invariant pass-rate wrapper (reuses existing invariant_validators)
# ============================================================

def compute_invariant_pass_rates() -> Dict[str, Any]:
    """
    Collect I1-I4 pass rates by delegating to the existing
    validate_graph_invariants() in invariant_validators.py.

    validate_graph_invariants() returns a dict of the form:
        { invariant_name: [violation_strings] }
    Empty list = PASS, non-empty list = FAIL.
    """
    from adsynth.hybrid_system.invariant_validators import validate_graph_invariants

    results = validate_graph_invariants()  # dict: {name -> [violations]}

    detail = {}
    passed_names = []
    failed_names = []

    for name, violations in results.items():
        passed = len(violations) == 0
        detail[name] = {"passed": passed, "violations": violations}
        if passed:
            passed_names.append(name)
        else:
            failed_names.append(name)

    total = len(results)
    pass_rate = round(len(passed_names) / total, 4) if total > 0 else 0.0

    return {
        "total_invariants": total,
        "passed":           len(passed_names),
        "failed":           len(failed_names),
        "pass_rate":        pass_rate,
        "all_pass":         len(failed_names) == 0,
        "passed_names":     passed_names,
        "failed_names":     failed_names,
        "detail":           detail,
    }


# ============================================================
# Main entry point: compute_seam_metrics
# ============================================================

def compute_seam_metrics(
    domains: List[Dict[str, Any]],
    tenants: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Compute all Week 8 metrics over the current in-memory graph.

    Parameters
    ----------
    domains : list of {name, id, sid} dicts (from do_generate_hybrid_v2)
    tenants : list of {id, name} dicts

    Returns
    -------
    Full metrics dict with keys: invariants, s1, s2, s3, p2, p3
    """
    total_edges = len(EDGES)
    total_nodes = len(NODES)

    print("  Computing invariant pass rates...")
    inv = compute_invariant_pass_rates()

    print("  Computing S1 (cross-boundary connectivity)...")
    s1 = compute_s1(total_edges)

    print("  Computing S2 (multi-tenant mapping statistics)...")
    s2 = compute_s2(domains, tenants)

    print("  Computing S3 (seam chokepoint metrics — BFS)...")
    s3 = compute_s3()

    print("  Computing P2 (NHI contribution to paths)...")
    p2 = compute_p2()

    print("  Computing P3 (misconfig density)...")
    p3 = compute_p3()

    return {
        "graph_summary": {
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "n_domains":   len(domains),
            "n_tenants":   len(tenants),
        },
        "invariants": inv,
        "s1": s1,
        "s2": s2,
        "s3": s3,
        "p2": p2,
        "p3": p3,
    }


# ============================================================
# Print report
# ============================================================

def print_seam_metrics_report(metrics: Dict[str, Any]) -> None:
    """Print a human-readable metrics report to stdout."""
    sep = "=" * 60
    thin = "-" * 60

    print(f"\n{sep}")
    print("  Week 8 Seam Metrics Report")
    print(sep)

    gs = metrics["graph_summary"]
    print(f"  Graph:  {gs['total_nodes']} nodes, {gs['total_edges']} edges")
    print(f"          {gs['n_domains']} domain(s), {gs['n_tenants']} tenant(s)")

    # Invariants
    print(f"\n{thin}")
    print("  Invariant pass rates")
    print(thin)
    inv = metrics["invariants"]
    status = "ALL PASS" if inv["all_pass"] else f"{inv['failed']} FAILED"
    print(f"  {inv['passed']}/{inv['total_invariants']} invariants passed  [{status}]")
    for name, detail in inv["detail"].items():
        mark = "✓" if detail["passed"] else "✗"
        vcount = len(detail["violations"])
        suffix = f"  ({vcount} violations)" if not detail["passed"] else ""
        print(f"    {mark} {name}{suffix}")

    # S1
    print(f"\n{thin}")
    print("  S1  Cross-boundary connectivity")
    print(thin)
    s1 = metrics["s1"]
    for etype, cnt in sorted(s1["edge_counts"].items()):
        print(f"    {etype:<28} {cnt:>5}")
    print(f"    {'Total cross-boundary':<28} {s1['total_cross_boundary']:>5}")
    print(f"    {'Ratio (cross/total)':<28} {s1['cross_boundary_ratio']:>8.4f}")

    # S2
    print(f"\n{thin}")
    print("  S2  Multi-tenant mapping statistics")
    print(thin)
    s2 = metrics["s2"]
    print(f"    Sync links:               {s2['n_sync_links']}")
    print(f"    Tenants/domain — mean:    {s2['tenants_per_domain']['mean']:.3f}  "
          f"max: {s2['tenants_per_domain']['max']}")
    print(f"    Domains/tenant — mean:    {s2['domains_per_tenant']['mean']:.3f}  "
          f"max: {s2['domains_per_tenant']['max']}")
    print(f"    Mass(tenants≥2/domain):   {s2['mass_ge2_tenants_per_domain']:.4f}  "
          f"({s2['multi_tenant_domains']} of {s2['n_domains']} domains)")

    # S3
    print(f"\n{thin}")
    print("  S3  Seam chokepoint metrics  (Algorithm 2)")
    print(thin)
    s3 = metrics["s3"]
    print(f"    Entry nodes sampled:      {s3['entry_node_count']}")
    print(f"    Target nodes (AZRole):    {s3['target_node_count']}")
    print(f"    Seam nodes (bridges):     {s3['seam_node_count']}")
    print(f"    Paths computed:           {s3['total_paths_computed']}")
    print(f"    Paths through seam:       {s3['paths_through_seam']}")
    print(f"    SeamCoverage:             {s3['seam_path_coverage']:.4f}")
    if s3["seam_betweenness"]:
        print("    Seam betweenness (top nodes on paths):")
        top = sorted(s3["seam_betweenness"].items(), key=lambda x: -x[1])[:5]
        for name, cnt in top:
            print(f"      {name:<36} {cnt:>3}")

    # P2
    print(f"\n{thin}")
    print("  P2  Non-human contribution to paths")
    print(thin)
    p2 = metrics["p2"]
    print(f"    Paths computed:                 {p2['total_paths']}")
    print(f"    Paths with any NHI:             {p2['paths_with_any_nhi']}")
    print(f"    Paths with SyncIdentity:        {p2['paths_with_sync_identity']}")
    print(f"    Pr[path ∋ NHI]:                 {p2['pr_path_contains_nhi']:.4f}")
    print(f"    Pr[path ∋ SyncIdentity]:        {p2['pr_path_contains_sync_identity']:.4f}")

    # P3
    print(f"\n{thin}")
    print("  P3  Misconfig density  (lived-in vs too-clean)")
    print(thin)
    p3 = metrics["p3"]
    print(f"    Total privilege edges:    {p3['total_privilege_edges']}")
    print(f"    Misconfig edges:          {p3['total_misconfig_edges']}")
    print(f"    Misconfig density:        {p3['misconfig_density']:.4f}")
    if p3["misconfig_by_type"]:
        print("    Breakdown by type:")
        for mtype, cnt in sorted(p3["misconfig_by_type"].items()):
            print(f"      {mtype:<36} {cnt:>3}")

    print(f"\n{sep}\n")


# ============================================================
# JSON export (for paper reproducibility bundle)
# ============================================================

def export_metrics_json(
    metrics: Dict[str, Any],
    output_dir: str = "generated_datasets",
    filename_prefix: str = "seam_metrics",
) -> str:
    """
    Write metrics dict to a JSON file in output_dir.
    Returns the filepath.
    """
    os.makedirs(output_dir, exist_ok=True)
    from datetime import datetime
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filepath = os.path.join(output_dir, f"{filename_prefix}_{ts}.json")
    with open(filepath, "w") as f:
        json.dump(metrics, f, indent=2, default=str)
    return filepath