"""
test_week2.py — Week 2 topology generation tests
=================================================
Run with:  python tests/test_week2.py   (from repo root)

Tests:
  1.  Domain generator: correct node count, SID format, FQDN naming
  2.  Domain generator: trust edges created correctly
  3.  Tenant generator: correct node count, orgType, posture values
  4.  Tenant generator: first tenant is always 'parent'
  5.  Sync link generator: at least one link per tenant
  6.  Sync link generator: every link has a SyncIdentity node
  7.  Sync link generator: SyncIdentity linkKey matches domain→tenant ids
  8.  Sync link generator: every SyncIdentity RUNS_ON an EntraConnect server
  9.  Sync link generator: PTA mode produces HAS_PTA_AGENT edge + PTAAgent server
  10. Sync link generator: ADFS mode produces IS_FEDERATED_WITH + ADFS server
  11. Invariant validators: all invariants pass on a full generated topology
  12. Multi-tenant: p_domain_multisync=1.0 forces extra sync links
  13. Determinism: same seed → identical graph (node count, edge count, ids)
  14. run.py CLI: end-to-end produces non-empty graph + valid bundle
"""

import copy
import json
import os
import subprocess
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adsynth.hybrid_system.export_writer import (
    reset_graph, HYBRID_NODES, HYBRID_EDGES,
)
from adsynth.hybrid_system.schema_registry import NodeLabel, RelType, Plane
from adsynth.hybrid_system.invariant_validators import (
    validate_graph_invariants, print_validation_report,
)
from adsynth.hybrid_system.hybrid_config import DEFAULT_HYBRID_CONFIG
from adsynth.generators.domain_generator import create_domains, create_trusts
from adsynth.generators.tenant_generator import create_tenants
from adsynth.generators.sync_link_generator import create_sync_links


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PASS_S = "\033[32mPASS\033[0m"
FAIL_S = "\033[31mFAIL\033[0m"
_results = []

def check(name: str, condition: bool, detail: str = "") -> bool:
    status = PASS_S if condition else FAIL_S
    msg = f"  [{status}] {name}"
    if not condition and detail:
        msg += f"\n         → {detail}"
    print(msg)
    _results.append((name, condition))
    return condition


BASE_SEED = {"domainSeed": 42, "tenantSeed": 99, "syncSeed": 77, "globalSeed": 1}
BASE_CFG  = copy.deepcopy(DEFAULT_HYBRID_CONFIG)


def fresh_topology(cfg=None, seed=None, run_id="test"):
    """Reset graph and run full topology generation. Returns (domains, tenants, links)."""
    reset_graph()
    c = cfg or copy.deepcopy(BASE_CFG)
    s = dict(seed or BASE_SEED)
    s.setdefault("_run_id", run_id)
    domains = create_domains(c, s, run_id)
    create_trusts(domains, c, s, run_id)
    tenants = create_tenants(c, s, run_id)
    links   = create_sync_links(domains, tenants, c, s, run_id)
    return domains, tenants, links


def nodes_by_label(label: NodeLabel):
    return [n for n in HYBRID_NODES if n["labels"][0] == label.value]


def edges_by_type(rel: RelType):
    return [e for e in HYBRID_EDGES if e["relType"] == rel.value]


# ---------------------------------------------------------------------------
# Test groups
# ---------------------------------------------------------------------------

def test_domain_generator():
    print("\n── Domain Generator ──────────────────────────────────────────")

    cfg = copy.deepcopy(BASE_CFG)
    cfg["Domain"]["nDomains"] = 3
    cfg["Domain"]["nDomainTrusts"] = 2

    domains, _, _ = fresh_topology(cfg=cfg)

    check("Correct domain count", len(domains) == 3,
          f"expected 3, got {len(domains)}")

    domain_nodes = nodes_by_label(NodeLabel.ADDomain)
    check("ADDomain nodes in graph", len(domain_nodes) == 3)

    # SID format check
    sids_valid = all(
        n["properties"]["sid"].startswith("S-1-5-21-")
        for n in domain_nodes
    )
    check("All domain SIDs are valid format", sids_valid)

    # FQDN naming: first is corp.local, second is corp2.local
    fqdns = sorted(d["fqdn"] for d in domains)
    check("First domain FQDN is corp.local", "corp.local" in fqdns)
    check("Second domain FQDN is corp2.local", "corp2.local" in fqdns)

    # plane = AD
    check("All domains have plane=AD",
          all(n["properties"]["plane"] == Plane.AD.value for n in domain_nodes))

    # Trust edges
    trust_edges = edges_by_type(RelType.DOMAIN_TRUSTS)
    check("Trust edges created", len(trust_edges) == 2,
          f"expected 2, got {len(trust_edges)}")


def test_tenant_generator():
    print("\n── Tenant Generator ──────────────────────────────────────────")

    cfg = copy.deepcopy(BASE_CFG)
    cfg["Domain"]["nDomains"] = 1
    cfg["Tenant"]["nTenantsPerDomain"] = 3   # → 3 tenants

    _, tenants, _ = fresh_topology(cfg=cfg)

    check("Correct tenant count", len(tenants) == 3,
          f"expected 3, got {len(tenants)}")

    tenant_nodes = nodes_by_label(NodeLabel.Tenant)
    check("Tenant nodes in graph", len(tenant_nodes) == 3)

    # First tenant is parent
    first = tenants[0]
    check("First tenant orgType is parent", first["orgType"] == "parent",
          f"got {first['orgType']}")

    # Rest are subsidiaries
    rest_types = [t["orgType"] for t in tenants[1:]]
    check("Remaining tenants are subsidiaries",
          all(o == "subsidiary" for o in rest_types), str(rest_types))

    # Posture values
    valid_postures = {"good", "average", "poor"}
    check("All tenants have valid posture",
          all(t["posture"] in valid_postures for t in tenants))

    # plane = Entra
    check("All tenants have plane=Entra",
          all(n["properties"]["plane"] == Plane.Entra.value for n in tenant_nodes))

    # tenantGuid is a UUID-formatted string
    import re
    uuid_re = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )
    check("All tenants have UUID-format tenantGuid",
          all(uuid_re.match(t["tenantGuid"]) for t in tenants))


def test_sync_links():
    print("\n── Sync Link Generator ───────────────────────────────────────")

    cfg = copy.deepcopy(BASE_CFG)
    cfg["Domain"]["nDomains"] = 2
    cfg["Tenant"]["nTenantsPerDomain"] = 2
    cfg["Domain"]["p_domain_multisync"] = 0.0   # no extra links for predictability

    domains, tenants, links = fresh_topology(cfg=cfg)

    check("At least one sync link created", len(links) >= 1,
          f"got {len(links)}")

    sync_link_edges = edges_by_type(RelType.SYNC_LINK)
    check("SYNC_LINK edges match link count",
          len(sync_link_edges) == len(links),
          f"edges={len(sync_link_edges)}, links={len(links)}")

    # Every link has a SyncIdentity
    sync_id_nodes = nodes_by_label(NodeLabel.SyncIdentity)
    check("One SyncIdentity per link",
          len(sync_id_nodes) == len(links),
          f"sync_ids={len(sync_id_nodes)}, links={len(links)}")

    # linkKey matches domain→tenant id format
    for lnk in links:
        expected_lk = f"{lnk['domain']['id']}->{lnk['tenant']['id']}"
        node = next(
            (n for n in sync_id_nodes
             if n["properties"].get("linkKey") == expected_lk), None
        )
        check(f"SyncIdentity linkKey correct for link {lnk['domain']['name']}→{lnk['tenant']['name']}",
              node is not None, f"expected linkKey='{expected_lk}'")

    # Every SyncIdentity RUNS_ON an EntraConnect server
    runs_on_edges = edges_by_type(RelType.RUNS_ON)
    ec_servers = [
        n for n in nodes_by_label(NodeLabel.Server)
        if n["properties"].get("serverRole") == "EntraConnect"
    ]
    check("One EntraConnect server per link",
          len(ec_servers) == len(links),
          f"ec_servers={len(ec_servers)}, links={len(links)}")
    check("RUNS_ON edges exist (sync→ec)",
          len(runs_on_edges) >= len(links),
          f"runs_on_edges={len(runs_on_edges)}")

    # SERVICES_LINK and SYNCS_TO
    svc_edges    = edges_by_type(RelType.SERVICES_LINK)
    syncs_to_edges = edges_by_type(RelType.SYNCS_TO)
    check("SERVICES_LINK edges (sync→domain)",
          len(svc_edges) == len(links))
    check("SYNCS_TO edges (sync→tenant)",
          len(syncs_to_edges) == len(links))


def test_mode_specific_bridges():
    print("\n── Mode-Specific Bridge Components ──────────────────────────")

    # Force PTA mode for all links
    cfg = copy.deepcopy(BASE_CFG)
    cfg["Domain"]["nDomains"] = 1
    cfg["Tenant"]["nTenantsPerDomain"] = 1
    cfg["SyncMode"] = {"PHS": 0, "PTA": 100, "ADFS": 0, "Mixed": 0}
    cfg["Domain"]["p_domain_multisync"] = 0.0

    domains, tenants, links = fresh_topology(cfg=cfg)

    pta_servers = [
        n for n in nodes_by_label(NodeLabel.Server)
        if n["properties"].get("serverRole") == "PTAAgent"
    ]
    pta_edges = edges_by_type(RelType.HAS_PTA_AGENT)
    check("PTA mode: PTAAgent server created", len(pta_servers) >= 1)
    check("PTA mode: HAS_PTA_AGENT edge created", len(pta_edges) >= 1)

    # Force ADFS mode for all links
    cfg2 = copy.deepcopy(BASE_CFG)
    cfg2["Domain"]["nDomains"] = 1
    cfg2["Tenant"]["nTenantsPerDomain"] = 1
    cfg2["SyncMode"] = {"PHS": 0, "PTA": 0, "ADFS": 100, "Mixed": 0}
    cfg2["Domain"]["p_domain_multisync"] = 0.0

    domains2, tenants2, links2 = fresh_topology(cfg=cfg2)

    adfs_servers = [
        n for n in nodes_by_label(NodeLabel.Server)
        if n["properties"].get("serverRole") == "ADFS"
    ]
    fed_edges = edges_by_type(RelType.IS_FEDERATED_WITH)
    check("ADFS mode: ADFS server created", len(adfs_servers) >= 1)
    check("ADFS mode: IS_FEDERATED_WITH edge created", len(fed_edges) >= 1)


def test_invariants():
    print("\n── Semantic Invariant Validation ─────────────────────────────")

    # Default config — mixed modes
    domains, tenants, links = fresh_topology()
    results = validate_graph_invariants()
    violations = [v for vlist in results.values() for v in vlist]
    check("Default topology: all invariants pass",
          len(violations) == 0, "\n  ".join(violations))

    # PHS only
    cfg = copy.deepcopy(BASE_CFG)
    cfg["SyncMode"] = {"PHS": 100, "PTA": 0, "ADFS": 0, "Mixed": 0}
    fresh_topology(cfg=cfg)
    results = validate_graph_invariants()
    violations = [v for vlist in results.values() for v in vlist]
    check("PHS-only topology: all invariants pass",
          len(violations) == 0, "\n  ".join(violations))

    # PTA only
    cfg["SyncMode"] = {"PHS": 0, "PTA": 100, "ADFS": 0, "Mixed": 0}
    fresh_topology(cfg=cfg)
    results = validate_graph_invariants()
    violations = [v for vlist in results.values() for v in vlist]
    check("PTA-only topology: all invariants pass",
          len(violations) == 0, "\n  ".join(violations))

    # ADFS only
    cfg["SyncMode"] = {"PHS": 0, "PTA": 0, "ADFS": 100, "Mixed": 0}
    fresh_topology(cfg=cfg)
    results = validate_graph_invariants()
    violations = [v for vlist in results.values() for v in vlist]
    check("ADFS-only topology: all invariants pass",
          len(violations) == 0, "\n  ".join(violations))


def test_multitenant():
    print("\n── Multi-Tenant Topology ─────────────────────────────────────")

    # p_domain_multisync=1.0 means every domain gets an extra tenant link
    cfg = copy.deepcopy(BASE_CFG)
    cfg["Domain"]["nDomains"] = 2
    cfg["Tenant"]["nTenantsPerDomain"] = 2
    cfg["Domain"]["p_domain_multisync"] = 1.0

    domains, tenants, links = fresh_topology(cfg=cfg)

    # With 2 domains + 4 tenants and p=1.0, we expect more links than domains
    check("Multi-sync: more links than domains",
          len(links) > len(domains),
          f"domains={len(domains)}, links={len(links)}")

    # Each tenant should be reachable from at least one domain
    tenant_ids_in_links = {lnk["tenant"]["id"] for lnk in links}
    check("All tenants have at least one sync link",
          len(tenant_ids_in_links) == len(tenants),
          f"tenants={len(tenants)}, in_links={len(tenant_ids_in_links)}")


def test_determinism():
    print("\n── Determinism ───────────────────────────────────────────────")

    run1_domains, run1_tenants, run1_links = fresh_topology(run_id="det-run")
    n_nodes_1 = len(HYBRID_NODES)
    n_edges_1 = len(HYBRID_EDGES)
    ids_1 = {n["id"] for n in HYBRID_NODES}

    # Second run with same seed
    run2_domains, run2_tenants, run2_links = fresh_topology(run_id="det-run")
    n_nodes_2 = len(HYBRID_NODES)
    n_edges_2 = len(HYBRID_EDGES)
    ids_2 = {n["id"] for n in HYBRID_NODES}

    check("Same seed → same node count", n_nodes_1 == n_nodes_2,
          f"{n_nodes_1} vs {n_nodes_2}")
    check("Same seed → same edge count", n_edges_1 == n_edges_2,
          f"{n_edges_1} vs {n_edges_2}")
    check("Same seed → same node ids", ids_1 == ids_2)


def test_cli():
    print("\n── CLI End-to-End ────────────────────────────────────────────")
    import tempfile

    script = os.path.join(os.path.dirname(os.path.dirname(__file__)), "run.py")

    with tempfile.TemporaryDirectory() as tmpdir:
        result = subprocess.run(
            [sys.executable, script,
             "--seed", "42",
             "--output-dir", tmpdir,
             "--run-id", "week2-cli-test"],
            capture_output=True, text=True
        )
        check("CLI exits with code 0", result.returncode == 0,
              result.stderr[:400] if result.returncode != 0 else "")

        run_dir = os.path.join(tmpdir, "week2-cli-test")
        stats_path = os.path.join(run_dir, "graph_stats.json")
        check("Stats file written", os.path.exists(stats_path))

        if os.path.exists(stats_path):
            with open(stats_path) as f:
                stats = json.load(f)
            check("Graph is non-empty (nodes > 0)",
                  stats["total_nodes"] > 0,
                  f"total_nodes={stats['total_nodes']}")
            check("Graph has edges",
                  stats["total_edges"] > 0,
                  f"total_edges={stats['total_edges']}")
            check("ADDomain nodes present",
                  stats["nodes_by_label"].get("ADDomain", 0) >= 1)
            check("Tenant nodes present",
                  stats["nodes_by_label"].get("Tenant", 0) >= 1)
            check("SyncIdentity nodes present",
                  stats["nodes_by_label"].get("SyncIdentity", 0) >= 1)
            check("Server nodes present",
                  stats["nodes_by_label"].get("Server", 0) >= 1)
            check("SYNC_LINK edges present",
                  stats["edges_by_relType"].get("SYNC_LINK", 0) >= 1)

        # Invariants must pass (run.py checks and reports)
        check("CLI output mentions invariants pass",
              "ALL INVARIANTS PASS" in result.stdout,
              result.stdout[-500:])


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def main():
    print("\n" + "="*60)
    print("  Week 2 Topology Generation Test Suite")
    print("  Hybrid AD-Entra Identity Graph Generator")
    print("="*60)

    test_domain_generator()
    test_tenant_generator()
    test_sync_links()
    test_mode_specific_bridges()
    test_invariants()
    test_multitenant()
    test_determinism()
    test_cli()

    passed = sum(1 for _, ok in _results if ok)
    total  = len(_results)
    failed = total - passed

    print(f"\n{'='*60}")
    print(f"  Results: {passed}/{total} tests passed", end="")
    if failed:
        print(f"  ({failed} FAILED)")
    else:
        print("  ✓ ALL PASS")
    print(f"{'='*60}\n")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
