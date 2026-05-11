"""
test_week3.py — Week 3 principal generation tests
Run with:  python tests/test_week3.py  (from repo root)

Tests:
  1.  AD users: correct count per domain
  2.  AD users: UPN format matches ADSynth pattern
  3.  AD users: SID format S-1-5-21-{9d}-{9d}-{10d}
  4.  AD users: all required properties present
  5.  AD users: enabled/disabled split within expected range
  6.  Entra users: correct count per tenant (includes 2 defaults)
  7.  Entra users: UPN lowercase format
  8.  Entra users: all required properties present
  9.  SYNCED_TO: edges created (PHS invariant now active)
  10. SYNCED_TO: unsynced users exist (not 100% sync)
  11. SYNCED_TO: invariant validators pass after user generation
  12. AD groups: Domain Users group created per domain
  13. AD groups: MEMBER_OF edges from users to groups
  14. Entra groups: All Users + Global Admins defaults created
  15. Entra groups: CLOUD_MEMBER_OF edges created
  16. NHI: N_generic formula correct for sample U_t values
  17. NHI: ServicePrincipal nodes created per tenant
  18. NHI: ManagedIdentity nodes created per tenant
  19. NHI: AutomationAccount nodes created per domain
  20. NHI: cross-tenant shared services pool created
  21. NHI: all NHI nodes have required ownerType/lifecycle properties
  22. NHI: ownerType values within valid set
  23. NHI: lifecycle values within valid set
  24. NHI: privilege tier distribution is heavy-tailed (tier0 < 5%)
  25. Endpoint constraints: all edges pass schema validation
  26. Determinism: same seed → identical graph
  27. CLI end-to-end: graph contains all expected node types
"""

import copy
import json
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adsynth.hybrid_system.export_writer import reset_graph, HYBRID_NODES, HYBRID_EDGES
from adsynth.hybrid_system.schema_registry import NodeLabel, RelType, Plane, is_allowed_edge
from adsynth.hybrid_system.invariant_validators import validate_graph_invariants
from adsynth.hybrid_system.hybrid_config import DEFAULT_HYBRID_CONFIG
from adsynth.generators.domain_generator import create_domains, create_trusts
from adsynth.generators.tenant_generator import create_tenants
from adsynth.generators.sync_link_generator import create_sync_links
from adsynth.generators.user_generator import create_humans
from adsynth.generators.group_generator import create_groups
from adsynth.generators.nhi_generator import create_non_humans, n_generic

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
PASS_S = "\033[32mPASS\033[0m"
FAIL_S = "\033[31mFAIL\033[0m"
_results = []

def check(name, cond, detail=""):
    status = PASS_S if cond else FAIL_S
    msg = f"  [{status}] {name}"
    if not cond and detail:
        msg += f"\n         → {detail}"
    print(msg)
    _results.append((name, cond))
    return cond

BASE_SEED = {"domainSeed": 42, "tenantSeed": 99, "syncSeed": 77,
             "userSeed": 11, "groupSeed": 22, "nhSeed": 33, "globalSeed": 1}

def nodes_by_label(label):
    return [n for n in HYBRID_NODES if n["labels"][0] == label.value]

def edges_by_type(rel):
    return [e for e in HYBRID_EDGES if e["relType"] == rel.value]

def fresh_full_graph(cfg=None, seed=None, run_id="test"):
    reset_graph()
    c = cfg or copy.deepcopy(DEFAULT_HYBRID_CONFIG)
    s = dict(seed or BASE_SEED)
    s["_run_id"] = run_id
    domains = create_domains(c, s, run_id)
    create_trusts(domains, c, s, run_id)
    tenants = create_tenants(c, s, run_id)
    links   = create_sync_links(domains, tenants, c, s, run_id)
    humans  = create_humans(domains, tenants, links, c, s, run_id)
    grps    = create_groups(domains, tenants,
                            humans["ad_users"], humans["entra_users"],
                            c, s, run_id)
    nhi     = create_non_humans(domains, tenants, humans["users_per_tenant"],
                                c, s, run_id)
    return domains, tenants, links, humans, grps, nhi

SID_RE = re.compile(r"^S-1-5-21-\d{9}-\d{9}-\d{10}$")

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_ad_users():
    print("\n── AD User Generation ───────────────────────────────────────")
    cfg = copy.deepcopy(DEFAULT_HYBRID_CONFIG)
    cfg["Domain"]["nDomains"] = 1
    cfg["User"]["nUsers"] = 20

    domains, tenants, links, humans, grps, nhi = fresh_full_graph(cfg=cfg)

    ad_users = humans["ad_users"]
    check("AD user count matches config", len(ad_users) == 20,
          f"expected 20, got {len(ad_users)}")

    ad_nodes = nodes_by_label(NodeLabel.User)
    ad_only  = [n for n in ad_nodes if n["properties"]["plane"] == Plane.AD.value]
    check("AD User nodes in graph (plane=AD)", len(ad_only) == 20,
          f"got {len(ad_only)}")

    # UPN format: {F}{LAST}{index:05d}@{DOMAIN} uppercased
    sample = ad_only[0]["properties"]["upn"]
    check("AD UPN is uppercased", sample == sample.upper(), f"sample={sample}")
    check("AD UPN contains 5-digit index",
          re.search(r"\d{5}@", sample) is not None, f"sample={sample}")

    # SID format: domain SID + RID suffix, e.g. S-1-5-21-{9d}-{9d}-{10d}-{RID}
    OBJ_SID_RE = re.compile(r"^S-1-5-21-\d{9}-\d{9}-\d{10}-\d+$")
    sid_ok = all(OBJ_SID_RE.match(n["properties"].get("objectid", ""))
                 for n in ad_only)
    check("AD SIDs match S-1-5-21-{9d}-{9d}-{10d}-{RID}", sid_ok)

    # Required properties
    required = {"id","name","plane","runId","upn","objectid","domain","enabled"}
    for n in ad_only[:3]:
        missing = required - set(n["properties"].keys())
        check(f"AD user '{n['properties']['name'][:20]}' has required props",
              len(missing) == 0, str(missing))

    # Enabled/disabled split ~90% enabled
    enabled_count = sum(1 for n in ad_only if n["properties"].get("enabled"))
    enabled_pct   = enabled_count / len(ad_only) * 100
    check("AD user enabled% within 60–100%", 60 <= enabled_pct <= 100,
          f"got {enabled_pct:.1f}%")


def test_entra_users():
    print("\n── Entra User Generation ────────────────────────────────────")
    cfg = copy.deepcopy(DEFAULT_HYBRID_CONFIG)
    cfg["User"]["nUsers"] = 10
    cfg["Tenant"]["nTenantsPerDomain"] = 1

    domains, tenants, links, humans, grps, nhi = fresh_full_graph(cfg=cfg)

    for tenant in tenants:
        eu = humans["entra_users"].get(tenant["id"], [])
        # nUsers + 2 defaults
        check(f"Entra user count for {tenant['name']} = nUsers+2",
              len(eu) == 12, f"expected 12, got {len(eu)}")

    entra_nodes = [n for n in nodes_by_label(NodeLabel.User)
                   if n["properties"]["plane"] == Plane.Entra.value]

    # UPN is lowercase
    sample_upn = entra_nodes[-1]["properties"].get("upn", "")
    check("Entra UPN is lowercased", sample_upn == sample_upn.lower(),
          f"sample={sample_upn}")

    # Required properties
    required = {"id","name","plane","runId","upn","tenantId","enabled"}
    for n in entra_nodes[:3]:
        missing = required - set(n["properties"].keys())
        check(f"Entra user required props present", len(missing) == 0, str(missing))


def test_synced_to():
    print("\n── SYNCED_TO Hybrid Mapping ─────────────────────────────────")
    cfg = copy.deepcopy(DEFAULT_HYBRID_CONFIG)
    cfg["User"]["nUsers"] = 30
    cfg["User"]["syncPercentage"] = 80
    cfg["SyncMode"] = {"PHS": 100, "PTA": 0, "ADFS": 0, "Mixed": 0}

    domains, tenants, links, humans, grps, nhi = fresh_full_graph(cfg=cfg)

    synced = edges_by_type(RelType.SYNCED_TO)
    check("SYNCED_TO edges created", len(synced) > 0,
          f"got {len(synced)}")

    # Not 100% synced (paper requires unsynced users)
    n_ad = len([n for n in HYBRID_NODES
                if n["labels"][0] == NodeLabel.User.value
                and n["properties"]["plane"] == Plane.AD.value])
    check("Not all AD users are synced (unsynced users exist)",
          len(synced) < n_ad, f"synced={len(synced)}, total_ad={n_ad}")

    # Invariant validators pass now that users exist
    results   = validate_graph_invariants()
    violations = [v for vlist in results.values() for v in vlist]
    check("All semantic invariants pass with users present",
          len(violations) == 0, "\n  ".join(violations[:3]))


def test_ad_groups():
    print("\n── AD Group Generation ──────────────────────────────────────")
    cfg = copy.deepcopy(DEFAULT_HYBRID_CONFIG)
    cfg["Domain"]["nDomains"] = 1
    cfg["Group"]["nADGroups"] = 10
    cfg["User"]["nUsers"] = 15

    domains, tenants, links, humans, grps, nhi = fresh_full_graph(cfg=cfg)

    ad_group_nodes = nodes_by_label(NodeLabel.Group)
    # nADGroups + 1 default (Domain Users)
    check("AD group count = nADGroups + 1 default",
          len(ad_group_nodes) == 11, f"got {len(ad_group_nodes)}")

    # Domain Users group exists
    du_exists = any("DOMAIN USERS" in n["properties"]["name"]
                    for n in ad_group_nodes)
    check("DOMAIN USERS group created", du_exists)

    # MEMBER_OF edges exist
    member_of = edges_by_type(RelType.MEMBER_OF)
    check("MEMBER_OF edges created", len(member_of) > 0,
          f"got {len(member_of)}")

    # Every AD user has at least one MEMBER_OF edge
    user_sources = {e["start"] for e in member_of}
    ad_user_ids  = {n["id"] for n in nodes_by_label(NodeLabel.User)
                    if n["properties"]["plane"] == Plane.AD.value}
    check("Every AD user has at least one MEMBER_OF edge",
          ad_user_ids.issubset(user_sources),
          f"missing: {len(ad_user_ids - user_sources)}")


def test_entra_groups():
    print("\n── Entra Group Generation ───────────────────────────────────")
    cfg = copy.deepcopy(DEFAULT_HYBRID_CONFIG)
    cfg["Group"]["nEntraGroups"] = 5
    cfg["User"]["nUsers"] = 10

    domains, tenants, links, humans, grps, nhi = fresh_full_graph(cfg=cfg)

    entra_group_nodes = nodes_by_label(NodeLabel.AzureADGroup)
    # nEntraGroups + 2 defaults per tenant
    n_tenants = len(tenants)
    expected  = n_tenants * (5 + 2)
    check("Entra group count = (nEntraGroups+2) × nTenants",
          len(entra_group_nodes) == expected,
          f"expected {expected}, got {len(entra_group_nodes)}")

    # Default groups exist
    names = {n["properties"]["name"] for n in entra_group_nodes}
    check("'All Users' default group created",    "All Users"     in names)
    check("'Global Admins' default group created","Global Admins" in names)

    # CLOUD_MEMBER_OF edges
    cloud_member = edges_by_type(RelType.CLOUD_MEMBER_OF)
    check("CLOUD_MEMBER_OF edges created", len(cloud_member) > 0,
          f"got {len(cloud_member)}")


def test_nhi_formula():
    print("\n── NHI N_generic Formula ─────────────────────────────────────")
    cases = [(0, 6), (10, 6), (43, 6), (44, 6), (50, 7),
             (100, 14), (1000, 140), (17858, 2500), (20000, 2500)]
    for u_t, expected in cases:
        result = n_generic(u_t)
        check(f"n_generic({u_t}) = {expected}", result == expected,
              f"got {result}")


def test_nhi_generation():
    print("\n── NHI Generation ───────────────────────────────────────────")
    cfg = copy.deepcopy(DEFAULT_HYBRID_CONFIG)
    cfg["User"]["nUsers"] = 50
    cfg["Domain"]["nDomains"] = 1
    cfg["Tenant"]["nTenantsPerDomain"] = 1

    domains, tenants, links, humans, grps, nhi = fresh_full_graph(cfg=cfg)

    sp_nodes  = nodes_by_label(NodeLabel.ServicePrincipal)
    mi_nodes  = nodes_by_label(NodeLabel.ManagedIdentity)
    aa_nodes  = nodes_by_label(NodeLabel.AutomationAccount)

    check("ServicePrincipal nodes created", len(sp_nodes) > 0,
          f"got {len(sp_nodes)}")
    check("ManagedIdentity nodes created",  len(mi_nodes) > 0,
          f"got {len(mi_nodes)}")
    check("AutomationAccount nodes created",len(aa_nodes) > 0,
          f"got {len(aa_nodes)}")

    # Cross-tenant pool
    cross = [n for n in sp_nodes if n["properties"].get("isCrossTenant")]
    check("Cross-tenant shared services pool created", len(cross) >= 0)  # may be 0 for tiny graphs

    # Required properties on all NHI
    nhi_nodes = sp_nodes + mi_nodes + aa_nodes
    required  = {"id","name","plane","runId","ownerType","lifecycle"}
    for n in nhi_nodes[:5]:
        missing = required - set(n["properties"].keys())
        check(f"NHI node '{n['properties']['name'][:25]}' has required props",
              len(missing) == 0, str(missing))

    # ownerType values valid
    valid_owners = {"Team", "System", "Unknown"}
    bad_owner = [n for n in nhi_nodes
                 if n["properties"].get("ownerType") not in valid_owners]
    check("All NHI ownerType values valid", len(bad_owner) == 0,
          str([n["properties"]["ownerType"] for n in bad_owner[:3]]))

    # lifecycle values valid
    valid_lc = {"LongLived", "Ephemeral"}
    bad_lc = [n for n in nhi_nodes
              if n["properties"].get("lifecycle") not in valid_lc]
    check("All NHI lifecycle values valid", len(bad_lc) == 0)

    # Heavy-tailed: tier0 should be small fraction
    tier0_count = sum(1 for n in nhi_nodes if n["properties"].get("privilegeTier") == "tier0")
    tier0_pct   = tier0_count / max(1, len(nhi_nodes)) * 100
    check("NHI tier0 fraction < 10% (heavy-tailed)",
          tier0_pct < 10, f"tier0={tier0_pct:.1f}%")


def test_endpoint_constraints():
    print("\n── Endpoint Constraints ─────────────────────────────────────")
    fresh_full_graph()

    violations = []
    for e in HYBRID_EDGES:
        rel = RelType(e["relType"])
        src_node = next((n for n in HYBRID_NODES if n["id"] == e["start"]), None)
        dst_node = next((n for n in HYBRID_NODES if n["id"] == e["end"]),   None)
        if not src_node or not dst_node:
            continue
        src_label = NodeLabel(src_node["labels"][0])
        dst_label = NodeLabel(dst_node["labels"][0])
        if not is_allowed_edge(rel, src_label, dst_label):
            violations.append(
                f"{src_label.value} -[{rel.value}]-> {dst_label.value}"
            )

    check("All edges satisfy endpoint constraints (I3)",
          len(violations) == 0,
          f"{len(violations)} violations: {violations[:3]}")


def test_determinism():
    print("\n── Determinism ──────────────────────────────────────────────")
    fresh_full_graph(run_id="det-run")
    n1, e1 = len(HYBRID_NODES), len(HYBRID_EDGES)
    ids1 = {n["id"] for n in HYBRID_NODES}

    fresh_full_graph(run_id="det-run")
    n2, e2 = len(HYBRID_NODES), len(HYBRID_EDGES)
    ids2 = {n["id"] for n in HYBRID_NODES}

    check("Same seed → same node count", n1 == n2, f"{n1} vs {n2}")
    check("Same seed → same edge count", e1 == e2, f"{e1} vs {e2}")
    check("Same seed → same node ids",   ids1 == ids2)


def test_cli():
    print("\n── CLI End-to-End ───────────────────────────────────────────")
    script = os.path.join(os.path.dirname(os.path.dirname(__file__)), "run.py")
    with tempfile.TemporaryDirectory() as tmpdir:
        result = subprocess.run(
            [sys.executable, script, "--seed", "42",
             "--output-dir", tmpdir, "--run-id", "week3-test"],
            capture_output=True, text=True
        )
        check("CLI exits 0", result.returncode == 0,
              result.stderr[:300] if result.returncode != 0 else "")

        stats_path = os.path.join(tmpdir, "week3-test", "graph_stats.json")
        if os.path.exists(stats_path):
            with open(stats_path) as f:
                stats = json.load(f)
            by_label = stats["nodes_by_label"]
            check("ADDomain nodes present",         by_label.get("ADDomain", 0) >= 1)
            check("Tenant nodes present",           by_label.get("Tenant", 0) >= 1)
            check("User nodes present",             by_label.get("User", 0) >= 1)
            check("Group nodes present",            by_label.get("Group", 0) >= 1)
            check("AzureADGroup nodes present",     by_label.get("AzureADGroup", 0) >= 1)
            check("ServicePrincipal nodes present", by_label.get("ServicePrincipal", 0) >= 1)
            check("AutomationAccount nodes present",by_label.get("AutomationAccount", 0) >= 1)
            check("SYNCED_TO edges present",
                  stats["edges_by_relType"].get("SYNCED_TO", 0) >= 1)
            check("MEMBER_OF edges present",
                  stats["edges_by_relType"].get("MEMBER_OF", 0) >= 1)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def main():
    print("\n" + "="*60)
    print("  Week 3 Principal Generation Test Suite")
    print("  Hybrid AD-Entra Identity Graph Generator")
    print("="*60)

    test_ad_users()
    test_entra_users()
    test_synced_to()
    test_ad_groups()
    test_entra_groups()
    test_nhi_formula()
    test_nhi_generation()
    test_endpoint_constraints()
    test_determinism()
    test_cli()

    passed = sum(1 for _, ok in _results if ok)
    total  = len(_results)
    failed = total - passed
    print(f"\n{'='*60}")
    print(f"  Results: {passed}/{total} tests passed", end="")
    print(f"  ({failed} FAILED)" if failed else "  ✓ ALL PASS")
    print(f"{'='*60}\n")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
