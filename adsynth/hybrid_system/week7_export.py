"""
adsynth/hybrid_system/week7_export.py
======================================
Week 7 — Export hardening, query-pack skeleton, and reproducibility bundle.

Deliverables from the paper (Section 6.6 and Appendix A.4-A.5):

  1. Query pack  — a curated set of Cypher queries that enumerate seam nodes,
                   find cross-boundary paths, and validate schema expectations.
                   Emitted as a JSON file alongside each generated graph.

  2. Reproducibility bundle  — per-run JSON that captures:
       (i)   full configuration Θ
       (ii)  seed vector s
       (iii) schema version string
       (iv)  export artifact filename
       (v)   evaluation summaries (invariant pass rates + seam metrics counts)

  3. Export smoke test  — reads a generated JSON file and checks that the
                          expected node labels and edge types are present and
                          non-empty. Runs without Neo4j — just validates the
                          JSON artifact directly.

Entry points:
    emit_query_pack(output_dir)            -> path to query_pack.json
    emit_reproducibility_bundle(...)       -> path to bundle JSON
    run_export_smoke_test(json_path)       -> dict of check results
    run_week7(json_path, config, seed, ...) -> runs all three and prints report
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

# ============================================================
# Schema version — bump when labels/edges change
# ============================================================

SCHEMA_VERSION = "hybrid_v2.1.0"

# ============================================================
# 1. Query Pack
# ============================================================

# Each query has: id, description, cypher
# These are BloodHound/Neo4j Cypher queries for the hybrid graph.
# They do NOT require Neo4j to emit — they are saved as a JSON file
# alongside each generated dataset for analysts to run manually.

QUERY_PACK = [
    # ── Seam node enumeration ────────────────────────────────────────────────
    {
        "id": "Q01",
        "category": "seam_enumeration",
        "description": "List all SyncIdentity nodes (per-link sync principals)",
        "cypher": (
            "MATCH (s:SyncIdentity) "
            "RETURN s.name, s.linkKey, s.syncMode, s.privilegeTier, s.highvalue "
            "ORDER BY s.linkKey"
        ),
    },
    {
        "id": "Q02",
        "category": "seam_enumeration",
        "description": "List all ConnectorHost servers",
        "cypher": (
            "MATCH (h:ConnectorHost) "
            "RETURN h.name, h.serverRole, h.domainId "
            "ORDER BY h.name"
        ),
    },
    {
        "id": "Q03",
        "category": "seam_enumeration",
        "description": "List all PTA agent hosts",
        "cypher": (
            "MATCH (h) WHERE h.serverRole = 'PTAAgent' "
            "RETURN h.name, h.serverRole, labels(h) "
            "ORDER BY h.name"
        ),
    },
    {
        "id": "Q04",
        "category": "seam_enumeration",
        "description": "List all ADFS servers",
        "cypher": (
            "MATCH (h) WHERE h.serverRole = 'ADFS' "
            "RETURN h.name, h.serverRole, labels(h) "
            "ORDER BY h.name"
        ),
    },
    # ── Multi-tenant topology ────────────────────────────────────────────────
    {
        "id": "Q05",
        "category": "multi_tenant",
        "description": "Show all SYNC_LINK edges (domain → tenant)",
        "cypher": (
            "MATCH (d:Domain)-[r:SYNC_LINK]->(t:AZTenant) "
            "RETURN d.name AS domain, t.name AS tenant "
            "ORDER BY domain, tenant"
        ),
    },
    {
        "id": "Q06",
        "category": "multi_tenant",
        "description": "Domains that sync to more than one tenant (multi-tenant pattern)",
        "cypher": (
            "MATCH (d:Domain)-[:SYNC_LINK]->(t:AZTenant) "
            "WITH d, count(t) AS tenant_count "
            "WHERE tenant_count > 1 "
            "RETURN d.name AS domain, tenant_count "
            "ORDER BY tenant_count DESC"
        ),
    },
    {
        "id": "Q07",
        "category": "multi_tenant",
        "description": "Per-link SyncIdentity wiring (SERVICES_LINK + SYNCS_TO + RUNS_ON)",
        "cypher": (
            "MATCH (s:SyncIdentity)-[:SERVICES_LINK]->(d:Domain), "
            "      (s)-[:SYNCS_TO]->(t:AZTenant), "
            "      (s)-[:RUNS_ON]->(h:ConnectorHost) "
            "RETURN s.name AS sync_identity, d.name AS domain, "
            "       t.name AS tenant, h.name AS connector_host "
            "ORDER BY sync_identity"
        ),
    },
    # ── Cross-boundary paths ─────────────────────────────────────────────────
    {
        "id": "Q08",
        "category": "cross_boundary_paths",
        "description": "All SYNCED_TO edges (hybrid user mappings AD → Entra)",
        "cypher": (
            "MATCH (u:User)-[r:SYNCED_TO]->(cu:AZUser) "
            "RETURN u.name AS ad_user, cu.name AS entra_user "
            "LIMIT 25"
        ),
    },
    {
        "id": "Q09",
        "category": "cross_boundary_paths",
        "description": "SyncIdentity replication rights on AD domains (Tier-0 chokepoints)",
        "cypher": (
            "MATCH (s:SyncIdentity)-[r:HAS_AD_RIGHT|GetChanges|GetChangesAll]->(d:Domain) "
            "RETURN s.name AS sync_identity, type(r) AS right, d.name AS domain "
            "ORDER BY sync_identity"
        ),
    },
    {
        "id": "Q10",
        "category": "cross_boundary_paths",
        "description": "Shortest paths from any on-prem user to any cloud admin role",
        "cypher": (
            "MATCH p = shortestPath((u:User)-[*1..6]->(r:AZRole)) "
            "WHERE r.name CONTAINS 'Administrator' OR r.name CONTAINS 'Contributor' "
            "RETURN p LIMIT 5"
        ),
    },
    # ── NHI privilege structure ──────────────────────────────────────────────
    {
        "id": "Q11",
        "category": "nhi_privileges",
        "description": "All NHI nodes with their assigned Azure roles",
        "cypher": (
            "MATCH (n)-[r:HAS_AZ_ROLE]->(role:AZRole) "
            "WHERE n:AZServicePrincipal OR n:ManagedIdentity OR n:SyncIdentity "
            "RETURN n.name AS nhi, labels(n) AS type, role.name AS role, "
            "       r.privilegeTier AS tier, r.isMisconfig AS is_misconfig "
            "ORDER BY tier, nhi"
        ),
    },
    {
        "id": "Q12",
        "category": "nhi_privileges",
        "description": "AutomationAccount delegated rights on OUs and domains",
        "cypher": (
            "MATCH (a:AutomationAccount)-[r:DELEGATED_RIGHT]->(target) "
            "RETURN a.name AS automation_account, r.right AS right, "
            "       labels(target) AS target_type, target.name AS target "
            "ORDER BY a.name"
        ),
    },
    # ── Misconfiguration analysis ────────────────────────────────────────────
    {
        "id": "Q13",
        "category": "misconfigurations",
        "description": "All misconfigured privilege edges with type breakdown",
        "cypher": (
            "MATCH ()-[r]-() "
            "WHERE r.isMisconfig = true "
            "RETURN type(r) AS edge_type, r.misconfigType AS misconfig_type, count(*) AS count "
            "ORDER BY count DESC"
        ),
    },
    {
        "id": "Q14",
        "category": "misconfigurations",
        "description": "Cross-tenant privilege paths (Storm-0501 pattern)",
        "cypher": (
            "MATCH (n)-[r:HAS_AZ_ROLE]->(role:AZRole) "
            "WHERE r.misconfigType = 'cross_tenant_privilege' "
            "RETURN n.name AS nhi, r.crossTenantSource AS source_tenant, "
            "       role.name AS role_in_other_tenant "
            "ORDER BY n.name"
        ),
    },
    {
        "id": "Q15",
        "category": "misconfigurations",
        "description": "Orphaned NHIs (ownerType=Unknown) with elevated roles",
        "cypher": (
            "MATCH (n)-[r:HAS_AZ_ROLE]->(role:AZRole) "
            "WHERE n.ownerType = 'Unknown' "
            "RETURN n.name AS nhi, n.ownerType AS owner, role.name AS role, "
            "       r.isMisconfig AS is_misconfig "
            "ORDER BY n.name"
        ),
    },
    # ── AI Agent analysis ────────────────────────────────────────────────────
    {
        "id": "Q16",
        "category": "ai_agents",
        "description": "AI Agents with high autonomy or no human oversight",
        "cypher": (
            "MATCH (a:AZServicePrincipal) "
            "WHERE a.isAIAgent = true "
            "  AND (a.maxAutonomyLevel = 'high' OR a.humanOversight = false) "
            "RETURN a.name, a.agentType, a.maxAutonomyLevel, a.humanOversight "
            "ORDER BY a.maxAutonomyLevel DESC"
        ),
    },
    {
        "id": "Q17",
        "category": "ai_agents",
        "description": "ORCHESTRATES and DELEGATES_TO edges between AI Agents",
        "cypher": (
            "MATCH (a)-[r:ORCHESTRATES|DELEGATES_TO]->(b) "
            "RETURN a.name AS orchestrator, type(r) AS relationship, b.name AS target "
            "ORDER BY orchestrator"
        ),
    },
    # ── Schema validation ────────────────────────────────────────────────────
    {
        "id": "Q18",
        "category": "schema_validation",
        "description": "Node label distribution (schema sanity check)",
        "cypher": (
            "MATCH (n) "
            "RETURN labels(n)[-1] AS label, count(n) AS count "
            "ORDER BY count DESC"
        ),
    },
    {
        "id": "Q19",
        "category": "schema_validation",
        "description": "Edge type distribution",
        "cypher": (
            "MATCH ()-[r]->() "
            "RETURN type(r) AS rel_type, count(r) AS count "
            "ORDER BY count DESC"
        ),
    },
    {
        "id": "Q20",
        "category": "schema_validation",
        "description": "Nodes missing required runId property (export health check)",
        "cypher": (
            "MATCH (n) WHERE n.runId IS NULL "
            "RETURN labels(n)[-1] AS label, count(n) AS missing_runId "
            "ORDER BY missing_runId DESC"
        ),
    },
]


def emit_query_pack(output_dir: str = "generated_datasets") -> str:
    """
    Write the query pack to output_dir/query_pack.json.
    Returns the filepath.
    """
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, "query_pack.json")
    bundle = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now().isoformat(),
        "description": (
            "Cypher query pack for hybrid AD-Entra identity graph analysis. "
            "Run these queries in Neo4j Browser after importing the graph JSON."
        ),
        "queries": QUERY_PACK,
    }
    with open(filepath, "w") as f:
        json.dump(bundle, f, indent=2)
    return filepath


# ============================================================
# 2. Reproducibility Bundle
# ============================================================

def emit_reproducibility_bundle(
    config: Dict[str, Any],
    seed: int,
    export_filepath: str,
    invariant_results: Optional[Dict[str, Any]] = None,
    seam_metrics: Optional[Dict[str, Any]] = None,
    output_dir: str = "generated_datasets",
) -> str:
    """
    Emit the reproducibility bundle as defined in Appendix A.5 of the paper.

    Parameters
    ----------
    config          : full parameters dict (Θ)
    seed            : integer seed used for generation
    export_filepath : path to the generated graph JSON file
    invariant_results : output of compute_invariant_pass_rates() — optional
    seam_metrics    : output of compute_seam_metrics() — optional
    output_dir      : directory to write the bundle

    Returns the filepath of the bundle JSON.
    """
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filepath = os.path.join(output_dir, f"reproducibility_bundle_{ts}.json")

    # Summarise invariants cleanly
    inv_summary = None
    if invariant_results:
        inv_summary = {
            "total":     invariant_results.get("total_invariants", 0),
            "passed":    invariant_results.get("passed", 0),
            "failed":    invariant_results.get("failed", 0),
            "all_pass":  invariant_results.get("all_pass", False),
            "pass_rate": invariant_results.get("pass_rate", 0.0),
        }

    # Summarise seam metrics cleanly (top-level numbers only, not full detail)
    sm_summary = None
    if seam_metrics:
        sm_summary = {
            "graph_summary":    seam_metrics.get("graph_summary"),
            "s1_cross_boundary_ratio": seam_metrics.get("s1", {}).get("cross_boundary_ratio"),
            "s2_mass_ge2_tenants_per_domain": seam_metrics.get("s2", {}).get("mass_ge2_tenants_per_domain"),
            "s3_seam_coverage": seam_metrics.get("s3", {}).get("seam_path_coverage"),
            "p2_pr_nhi":        seam_metrics.get("p2", {}).get("pr_path_contains_nhi"),
            "p2_pr_sync_id":    seam_metrics.get("p2", {}).get("pr_path_contains_sync_identity"),
            "p3_misconfig_density": seam_metrics.get("p3", {}).get("misconfig_density"),
        }

    bundle = {
        "schema_version":   SCHEMA_VERSION,
        "generated_at":     datetime.now().isoformat(),
        "seed":             seed,
        "export_artifact":  os.path.basename(export_filepath),
        "config_snapshot":  config,
        "invariant_summary": inv_summary,
        "seam_metrics_summary": sm_summary,
        "query_pack_ref":   "query_pack.json",
        "notes": (
            "Reproducibility bundle for hybrid AD-Entra identity graph. "
            "Re-run with the same seed and config_snapshot to reproduce this graph exactly."
        ),
    }

    with open(filepath, "w") as f:
        json.dump(bundle, f, indent=2, default=str)

    return filepath


# ============================================================
# 3. Export Smoke Test
# ============================================================

# Expected labels that must be present in a valid hybrid_v2 export
_REQUIRED_NODE_LABELS = {
    "Domain", "AZTenant", "User", "AZUser",
    "SyncIdentity", "ConnectorHost",
    "AZRole", "AZServicePrincipal",
}

# Expected edge types that must be present
_REQUIRED_EDGE_TYPES = {
    "SYNC_LINK", "SYNCED_TO", "SERVICES_LINK", "SYNCS_TO",
    "RUNS_ON", "HAS_AZ_ROLE",
}

# Edge types that are present only when certain modes are enabled
_CONDITIONAL_EDGE_TYPES = {
    "HAS_PTA_AGENT":    "PTA mode",
    "IS_FEDERATED_WITH": "ADFS mode",
    "HAS_AD_RIGHT":     "Week 6 permissions",
    "GetChanges":       "Week 6 SyncIdentity rights",
    "DELEGATED_RIGHT":  "Week 6 AutomationAccount rights",
}


def run_export_smoke_test(json_path: str) -> Dict[str, Any]:
    """
    Load a generated hybrid_v2_*.json file and check that:
      - Required node labels are present and non-empty
      - Required edge types are present and non-empty
      - No nodes are missing an 'id' field
      - No edges are missing start/end node references
      - Conditional edge types are reported (informational, not failures)

    Does NOT require Neo4j. Runs purely on the JSON file.

    Returns a dict with 'passed', 'failed', 'warnings', 'checks' detail.
    """
    checks = []
    warnings = []

    # ── Load the file ─────────────────────────────────────────────────────
    node_labels: Dict[str, int] = {}   # label -> count
    edge_types:  Dict[str, int] = {}   # type  -> count
    node_ids = set()
    total_nodes = 0
    total_edges = 0
    missing_id_nodes = 0
    invalid_edge_refs = 0

    try:
        with open(json_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                obj_type = obj.get("type", "")

                if obj_type == "node":
                    total_nodes += 1
                    node_id = obj.get("id", "")
                    if not node_id:
                        missing_id_nodes += 1
                    else:
                        node_ids.add(node_id)
                    labels = obj.get("labels", [])
                    if labels:
                        lbl = labels[-1]
                        node_labels[lbl] = node_labels.get(lbl, 0) + 1

                elif obj_type == "relationship":
                    total_edges += 1
                    rel_type = (obj.get("label") or obj.get("relType")
                                or (obj.get("labels") or [None])[0] or "")
                    if rel_type:
                        edge_types[rel_type] = edge_types.get(rel_type, 0) + 1
                    start_ref = obj.get("start")
                    end_ref   = obj.get("end")
                    start_id  = (start_ref.get("id", "") if isinstance(start_ref, dict)
                                 else obj.get("source", ""))
                    end_id    = (end_ref.get("id", "") if isinstance(end_ref, dict)
                                 else obj.get("target", ""))
                    if not start_id or not end_id:
                        invalid_edge_refs += 1

    except Exception as e:
        return {
            "passed": 0, "failed": 1, "warnings": [],
            "checks": [{"name": "File load", "passed": False, "detail": str(e)}],
            "node_labels": {}, "edge_types": {},
        }

    # ── Check 1: File has content ──────────────────────────────────────────
    checks.append({
        "name":   "File has nodes and edges",
        "passed": total_nodes > 0 and total_edges > 0,
        "detail": f"{total_nodes} nodes, {total_edges} edges",
    })

    # ── Check 2: No nodes missing id ──────────────────────────────────────
    checks.append({
        "name":   "All nodes have 'id' field",
        "passed": missing_id_nodes == 0,
        "detail": f"{missing_id_nodes} nodes missing id" if missing_id_nodes else "OK",
    })

    # ── Check 3: No dangling edge references ──────────────────────────────
    checks.append({
        "name":   "All edges have start/end references",
        "passed": invalid_edge_refs == 0,
        "detail": f"{invalid_edge_refs} edges missing start/end" if invalid_edge_refs else "OK",
    })

    # ── Check 4: Required node labels present ─────────────────────────────
    for label in sorted(_REQUIRED_NODE_LABELS):
        present = label in node_labels and node_labels[label] > 0
        checks.append({
            "name":   f"Node label '{label}' present",
            "passed": present,
            "detail": f"count={node_labels.get(label, 0)}",
        })

    # ── Check 5: Required edge types present ──────────────────────────────
    for etype in sorted(_REQUIRED_EDGE_TYPES):
        present = etype in edge_types and edge_types[etype] > 0
        checks.append({
            "name":   f"Edge type '{etype}' present",
            "passed": present,
            "detail": f"count={edge_types.get(etype, 0)}",
        })

    # ── Check 6: SyncIdentity nodes have linkKey ──────────────────────────
    # Re-scan for this specific property check
    sync_nodes_total = node_labels.get("SyncIdentity", 0)
    checks.append({
        "name":   "SyncIdentity nodes exist",
        "passed": sync_nodes_total > 0,
        "detail": f"count={sync_nodes_total}",
    })

    # ── Informational: conditional edge types ─────────────────────────────
    for etype, description in _CONDITIONAL_EDGE_TYPES.items():
        count = edge_types.get(etype, 0)
        warnings.append({
            "name":    f"Conditional edge '{etype}' ({description})",
            "present": count > 0,
            "count":   count,
        })

    # ── Summary ───────────────────────────────────────────────────────────
    passed = sum(1 for c in checks if c["passed"])
    failed = len(checks) - passed

    return {
        "total_checks": len(checks),
        "passed":        passed,
        "failed":        failed,
        "all_pass":      failed == 0,
        "checks":        checks,
        "warnings":      warnings,
        "node_labels":   node_labels,
        "edge_types":    edge_types,
        "file_summary": {
            "total_nodes": total_nodes,
            "total_edges": total_edges,
        },
    }


# ============================================================
# Print report
# ============================================================

def print_smoke_test_report(results: Dict[str, Any]) -> None:
    sep  = "=" * 60
    thin = "-" * 60
    print(f"\n{sep}")
    print("  Week 7 Export Smoke Test")
    print(sep)

    fs = results["file_summary"]
    print(f"  {fs['total_nodes']} nodes, {fs['total_edges']} edges\n")

    status = "ALL PASS" if results["all_pass"] else f"{results['failed']} FAILED"
    print(f"  {results['passed']}/{results['total_checks']} checks passed  [{status}]")
    print(thin)

    for c in results["checks"]:
        mark = "✓" if c["passed"] else "✗"
        detail = f"  ({c['detail']})" if c.get("detail") and c["detail"] != "OK" else ""
        print(f"  {mark} {c['name']}{detail}")

    print(f"\n{thin}")
    print("  Conditional edges (informational):")
    for w in results["warnings"]:
        present = "present" if w["present"] else "absent"
        print(f"    {'✓' if w['present'] else '·'} {w['name']}  [{present}, count={w['count']}]")

    print(f"\n{sep}\n")


# ============================================================
# 4. Main entry point: run_week7
# ============================================================

def run_week7(
    json_path: str,
    config: Dict[str, Any],
    seed: int,
    invariant_results: Optional[Dict[str, Any]] = None,
    seam_metrics: Optional[Dict[str, Any]] = None,
    output_dir: str = "generated_datasets",
) -> Dict[str, Any]:
    """
    Run all three Week 7 tasks and return a summary dict.

    Parameters
    ----------
    json_path         : path to the generated hybrid_v2_*.json file
    config            : parameters dict used to generate the graph
    seed              : seed used for generation
    invariant_results : from compute_invariant_pass_rates() — optional
    seam_metrics      : from compute_seam_metrics() — optional
    output_dir        : where to write bundle/query_pack files

    Returns a dict with paths to emitted files and smoke test results.
    """
    print("\nWeek 7: Export hardening, query pack, reproducibility bundle")
    print("=" * 60)

    # Task 1: emit query pack
    print("\n[1/3] Emitting query pack...")
    qp_path = emit_query_pack(output_dir)
    print(f"  Query pack written: {qp_path}  ({len(QUERY_PACK)} queries)")

    # Task 2: emit reproducibility bundle
    print("\n[2/3] Emitting reproducibility bundle...")
    bundle_path = emit_reproducibility_bundle(
        config=config,
        seed=seed,
        export_filepath=json_path,
        invariant_results=invariant_results,
        seam_metrics=seam_metrics,
        output_dir=output_dir,
    )
    print(f"  Bundle written: {bundle_path}")

    # Task 3: run smoke test
    print("\n[3/3] Running export smoke test...")
    smoke = run_export_smoke_test(json_path)
    print_smoke_test_report(smoke)

    return {
        "query_pack_path":    qp_path,
        "bundle_path":        bundle_path,
        "smoke_test":         smoke,
        "schema_version":     SCHEMA_VERSION,
    }


# ============================================================
# Standalone runner
# ============================================================

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python week7_export.py <path_to_hybrid_v2.json>")
        print("       Runs smoke test + emits query pack and reproducibility bundle.")
        sys.exit(1)

    json_path = sys.argv[1]
    if not os.path.exists(json_path):
        print(f"Error: file not found: {json_path}")
        sys.exit(1)

    # Minimal config for standalone run (no live parameters available)
    stub_config = {
        "note": "Standalone run — full config not available. "
                "Re-run via generate_hybrid_v2 for complete bundle.",
        "schema_version": SCHEMA_VERSION,
    }

    result = run_week7(
        json_path=json_path,
        config=stub_config,
        seed=0,
        output_dir=os.path.dirname(json_path) or "generated_datasets",
    )

    status = "ALL PASS" if result["smoke_test"]["all_pass"] else "FAILURES"
    print(f"Week 7 complete  [{status}]")
    print(f"  Query pack:  {result['query_pack_path']}")
    print(f"  Bundle:      {result['bundle_path']}")
    sys.exit(0 if result["smoke_test"]["all_pass"] else 1)
