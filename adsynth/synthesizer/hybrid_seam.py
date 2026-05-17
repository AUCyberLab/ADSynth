"""
adsynth/synthesizer/hybrid_seam.py
===================================
Hybrid seam infrastructure generation.
Ported from adsynth/generators/sync_link_generator.py but writes
through the original DATABASE.py node_operation / edge_operation
instead of the parallel export_writer.py.

Paper contributions implemented here:
  - Per-link SyncIdentity node (one per domain-tenant sync link)
  - ConnectorHost (Entra Connect Sync server) per link
  - PTAAgentHost server per PTA-mode link
  - ADFSServer per ADFS-mode link
  - SYNC_LINK, SERVICES_LINK, SYNCS_TO, RUNS_ON, HAS_PTA_AGENT,
    IS_FEDERATED_WITH edge types

Called from ADSynth.py do_generate_hybrid_v2() after the on-prem
generate_data() pipeline has already run for each domain.
"""

import random
import uuid
from typing import Any, Dict, List, Tuple

from adsynth.DATABASE import (
    NODES, EDGES, NODE_GROUPS,
    DATABASE_ID, dict_edges,
    SYNC_LINKS, SYNC_IDENTITY_NODES,
    CONNECTOR_HOST_NODES, PTA_AGENT_NODES,
    ADFS_SERVER_NODES, TENANT_HYBRID_MODE,
    DOMAIN_TENANT_MAPPING, NHI_NODE_INDICES,
    TENANT_METADATA, RUN_ID,
    node_operation, edge_operation, get_node_index,
    ridcount,
)


# ============================================================
# Sync mapping builder
# ============================================================

def build_sync_mapping(
    domains: List[Dict[str, Any]],
    tenants: List[Dict[str, Any]],
    config: Dict[str, Any],
    rng: random.Random,
) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """
    Build the bipartite sync mapping L ⊆ D × T.

    Every tenant gets at least one domain.
    p_domain_multisync controls probability of a domain syncing to
    an extra tenant (Storm-0501 multi-tenant pattern).

    Returns list of (domain_dict, tenant_dict) pairs.
    domain_dict: {"name": fqdn, "sid": sid, "id": objectid}
    tenant_dict: {"id": tenant_id, "name": tenant_name}
    """
    n_domains = len(domains)
    n_tenants = len(tenants)

    if n_domains == 0 or n_tenants == 0:
        return []

    p_multisync = config.get("hybrid", {}).get("p_domain_multisync", 0.15)

    mapping: List[Tuple[Dict, Dict]] = []
    seen = set()

    # Step 1: guarantee every tenant is covered
    shuffled = list(domains)
    rng.shuffle(shuffled)
    for i, tenant in enumerate(tenants):
        domain = shuffled[i % len(shuffled)]
        key = (domain["name"], tenant["id"])
        if key not in seen:
            mapping.append((domain, tenant))
            seen.add(key)

    # Step 2: ensure every domain has at least one link
    covered = {d["name"] for d, _ in mapping}
    for domain in domains:
        if domain["name"] not in covered:
            tenant = tenants[len(mapping) % n_tenants]
            key = (domain["name"], tenant["id"])
            if key not in seen:
                mapping.append((domain, tenant))
                seen.add(key)

    # Step 3: multi-sync — some domains get an extra tenant link
    for domain in domains:
        if rng.random() < p_multisync and n_tenants > 1:
            current = {t["id"] for d, t in mapping if d["name"] == domain["name"]}
            extras = [t for t in tenants if t["id"] not in current]
            if extras:
                extra = rng.choice(extras)
                key = (domain["name"], extra["id"])
                if key not in seen:
                    mapping.append((domain, extra))
                    seen.add(key)

    return mapping


# ============================================================
# Sync mode sampling
# ============================================================

def _sample_sync_mode(rng: random.Random, config: Dict[str, Any]) -> str:
    """
    Sample a sync mode for one link from the configured distribution.
    Config key: config["hybrid"]["syncModeDistribution"]
    Defaults: PHS=60, PTA=20, ADFS=10, Mixed=10
    """
    dist = config.get("hybrid", {}).get("syncModeDistribution", {
        "PHS": 60, "PTA": 20, "ADFS": 10, "Mixed": 10
    })
    modes = list(dist.keys())
    weights = [dist[m] for m in modes]
    return rng.choices(modes, weights=weights, k=1)[0]


# ============================================================
# ConnectorHost server creation
# ============================================================

def _create_connector_host(
    domain: Dict[str, Any],
    tenant_id: str,
    rng: random.Random,
) -> int:
    """
    Create an Entra Connect Sync server node.
    Returns node index in NODES.
    """
    rid = ridcount[0]
    ridcount[0] += 1
    server_sid = f"{domain['sid']}-{rid}"

    hostname = f"ECSVR-{domain['name'].split('.')[0].upper()}-{rng.randint(1, 99):02d}@{domain['name']}"

    keys = [
        "labels", "name", "objectid", "plane", "runId",
        "domainId", "tenantId",
        "hostname", "serverRole",
        "operatingsystem", "highvalue",
    ]
    values = [
        "ConnectorHost", hostname, server_sid, "AD", RUN_ID,
        domain["id"], tenant_id,
        hostname.split("@")[0],
        "EntraConnect",
        rng.choice(["Windows Server 2019", "Windows Server 2022"]),
        True,
    ]

    idx = node_operation("ConnectorHost", keys, values, server_sid)

    # Track per tenant
    if tenant_id not in CONNECTOR_HOST_NODES:
        CONNECTOR_HOST_NODES[tenant_id] = []
    CONNECTOR_HOST_NODES[tenant_id].append(idx)

    # Place in domain via Contains edge
    domain_idx = get_node_index(domain["name"] + "_Domain", "name")
    if domain_idx != -1:
        edge_operation(domain_idx, idx, "Contains", ["isacl"], [False])

    # Realism patch: privileged on-prem groups have AdminTo on the
    # ConnectorHost server, matching default AD admin rights on any
    # domain-joined server. This is what enables an attacker who has
    # compromised an on-prem admin principal to reach the ConnectorHost
    # in the directed attack graph.
    for admin_group in ("DOMAIN ADMINS", "ADMINISTRATORS", "ENTERPRISE ADMINS"):
        gname = f"{admin_group}@{domain['name']}_Group"
        admin_idx = get_node_index(gname, "name")
        if admin_idx != -1:
            edge_operation(
                admin_idx, idx, "AdminTo",
                ["isacl", "isInherited"],
                [False, False]
            )
 
    return idx


# ============================================================
# SyncIdentity node creation — paper core contribution
# ============================================================

def _create_sync_identity(
    domain: Dict[str, Any],
    tenant_id: str,
    sync_mode: str,
    connector_idx: int,
    rng: random.Random,
) -> int:
    """
    Create exactly one SyncIdentity node per (domain, tenant) sync link.

    Required edges (paper §4.2.3):
      SyncIdentity --SERVICES_LINK--> ADDomain
      SyncIdentity --SYNCS_TO-------> Tenant
      SyncIdentity --RUNS_ON--------> ConnectorHost

    Returns node index in NODES.
    """
    # Deterministic ID based on domain+tenant pair
    link_key = f"{domain['id']}->{tenant_id}"
    sync_objectid = f"sync:{domain['id']}:{tenant_id}"

    lifecycle = rng.choices(["LongLived", "Ephemeral"], weights=[90, 10])[0]
    display_name = (
        f"SyncIdentity_{domain['name'].split('.')[0]}_"
        f"{tenant_id[:8]}"
    )

    keys = [
        "labels", "name", "objectid", "plane", "runId",
        "domainId", "tenantId",
        # NHI required properties
        "ownerType", "lifecycle",
        # SyncIdentity required properties
        "syncMode", "linkKey",
        # Realism
        "highvalue",
    ]
    values = [
        "SyncIdentity", display_name, sync_objectid, "Hybrid", RUN_ID,
        domain["id"], tenant_id,
        "System", lifecycle,
        sync_mode, link_key,
        True,
    ]

    idx = node_operation("SyncIdentity", keys, values, sync_objectid)
    NHI_NODE_INDICES.append(idx)

    # Track per link — this is the invariant mapping
    SYNC_IDENTITY_NODES[(domain["name"], tenant_id)] = idx

    # --- Three mandatory seam edges ---

    # 1. SERVICES_LINK: SyncIdentity -> ADDomain
    domain_idx = get_node_index(domain["name"] + "_Domain", "name")
    if domain_idx != -1:
        edge_operation(idx, domain_idx, "SERVICES_LINK", ["isacl"], [False])

    # 2. SYNCS_TO: SyncIdentity -> Tenant
    tenant_idx = get_node_index(tenant_id, "objectid")
    if tenant_idx != -1:
        edge_operation(idx, tenant_idx, "SYNCS_TO", ["isacl"], [False])

    # 3. RUNS_ON: SyncIdentity -> ConnectorHost
    if connector_idx != -1:
        edge_operation(idx, connector_idx, "RUNS_ON", ["isacl"], [False])

    # Semantics: compromise of the ConnectorHost yields the sync
    # service account's credentials, which in our schema is the
    # SyncIdentity. This is the inbound edge that makes the
    # SyncIdentity reachable in directed attack-graph BFS and lets
    # the paper's "participates in attack-path computations" claim
    # hold at the metric level.
    #
    # Direction matches BloodHound's HasSession convention:
    # asset -> principal means "compromise of asset yields principal".
    if connector_idx != -1:
        edge_operation(
            connector_idx, idx, "HOSTS_PRINCIPAL",
            ["isacl", "viaHostCompromise"],
            [False, True]
        )

    return idx


# ============================================================
# PTA agent server creation
# ============================================================

def _create_pta_server(
    domain: Dict[str, Any],
    tenant_id: str,
    rng: random.Random,
) -> int:
    """
    Create a PTA agent server node.
    Returns node index in NODES.
    """
    rid = ridcount[0]
    ridcount[0] += 1
    server_sid = f"{domain['sid']}-{rid}"

    hostname = f"PTASVR-{domain['name'].split('.')[0].upper()}-{rng.randint(1, 99):02d}@{domain['name']}"

    keys = [
        "labels", "name", "objectid", "plane", "runId",
        "domainId", "tenantId",
        "hostname", "serverRole",
        "operatingsystem", "highvalue",
    ]
    values = [
        "PTAAgentHost", hostname, server_sid, "AD", RUN_ID,
        domain["id"], tenant_id,
        hostname.split("@")[0],
        "PTAAgent",
        rng.choice(["Windows Server 2019", "Windows Server 2022"]),
        True,
    ]

    idx = node_operation("PTAAgentHost", keys, values, server_sid)

    if tenant_id not in PTA_AGENT_NODES:
        PTA_AGENT_NODES[tenant_id] = []
    PTA_AGENT_NODES[tenant_id].append(idx)

    # HAS_PTA_AGENT: Tenant -> PTAAgentHost
    tenant_idx = get_node_index(tenant_id, "objectid")
    if tenant_idx != -1:
        edge_operation(tenant_idx, idx, "HAS_PTA_AGENT", ["isacl"], [False])

    # Also place in domain
    domain_idx = get_node_index(domain["name"] + "_Domain", "name")
    if domain_idx != -1:
        edge_operation(domain_idx, idx, "Contains", ["isacl"], [False])

    # ── Realism patch: admin groups have AdminTo on PTA agent host
    for admin_group in ("DOMAIN ADMINS", "ADMINISTRATORS", "ENTERPRISE ADMINS"):
        gname = f"{admin_group}@{domain['name']}_Group"
        admin_idx = get_node_index(gname, "name")
        if admin_idx != -1:
            edge_operation(
                admin_idx, idx, "AdminTo",
                ["isacl", "isInherited"],
                [False, False]
            )
 
    # ── Realism patch: PTA agent host hosts the sync principal for
    # this link (same semantics as ConnectorHost case).
    sync_idx = SYNC_IDENTITY_NODES.get((domain["name"], tenant_id))
    if sync_idx is not None:
        edge_operation(
            idx, sync_idx, "HOSTS_PRINCIPAL",
            ["isacl", "viaHostCompromise"],
            [False, True]
        )
 
    return idx


# ============================================================
# ADFS server creation
# ============================================================

def _create_adfs_server(
    domain: Dict[str, Any],
    tenant_id: str,
    rng: random.Random,
) -> int:
    """
    Create an AD FS server node.
    Returns node index in NODES.
    """
    rid = ridcount[0]
    ridcount[0] += 1
    server_sid = f"{domain['sid']}-{rid}"

    hostname = f"ADFS-{domain['name'].split('.')[0].upper()}-{rng.randint(1, 99):02d}@{domain['name']}"

    keys = [
        "labels", "name", "objectid", "plane", "runId",
        "domainId", "tenantId",
        "hostname", "serverRole",
        "operatingsystem", "highvalue",
    ]
    values = [
        "ADFSServer", hostname, server_sid, "AD", RUN_ID,
        domain["id"], tenant_id,
        hostname.split("@")[0],
        "ADFS",
        rng.choice(["Windows Server 2019", "Windows Server 2022"]),
        True,
    ]

    idx = node_operation("ADFSServer", keys, values, server_sid)

    if tenant_id not in ADFS_SERVER_NODES:
        ADFS_SERVER_NODES[tenant_id] = []
    ADFS_SERVER_NODES[tenant_id].append(idx)

    # IS_FEDERATED_WITH: ADDomain -> Tenant
    domain_idx = get_node_index(domain["name"] + "_Domain", "name")
    tenant_idx = get_node_index(tenant_id, "objectid")
    if domain_idx != -1 and tenant_idx != -1:
        edge_operation(domain_idx, tenant_idx, "IS_FEDERATED_WITH",
                       ["federationType", "isacl"], ["ADFS", False])

    # Place in domain
    if domain_idx != -1:
        edge_operation(domain_idx, idx, "Contains", ["isacl"], [False])

    # ── Realism patch: admin groups have AdminTo on ADFS server
    for admin_group in ("DOMAIN ADMINS", "ADMINISTRATORS", "ENTERPRISE ADMINS"):
        gname = f"{admin_group}@{domain['name']}_Group"
        admin_idx = get_node_index(gname, "name")
        if admin_idx != -1:
            edge_operation(
                admin_idx, idx, "AdminTo",
                ["isacl", "isInherited"],
                [False, False]
            )
 
    # ── Realism patch: ADFS server hosts the sync principal for this link
    sync_idx = SYNC_IDENTITY_NODES.get((domain["name"], tenant_id))
    if sync_idx is not None:
        edge_operation(
            idx, sync_idx, "HOSTS_PRINCIPAL",
            ["isacl", "viaHostCompromise"],
            [False, True]
        )
 
    return idx


# ============================================================
# SYNC_LINK edge between domain and tenant
# ============================================================

def _create_sync_link_edge(
    domain: Dict[str, Any],
    tenant_id: str,
    sync_mode: str,
) -> None:
    """
    Add SYNC_LINK edge: ADDomain -> Tenant.
    This declares that domain d synchronizes to tenant t.
    """
    domain_idx = get_node_index(domain["name"] + "_Domain", "name")
    tenant_idx = get_node_index(tenant_id, "objectid")

    if domain_idx != -1 and tenant_idx != -1:
        edge_operation(domain_idx, tenant_idx, "SYNC_LINK",
                       ["syncMode", "isacl"], [sync_mode, False])


# ============================================================
# SYNCED_TO user mapping per link
# ============================================================

def create_user_synced_to_edges(
    domain_name: str,
    tenant_id: str,
    config: Dict[str, Any],
    rng: random.Random,
) -> int:
    """
    For a given sync link, create SYNCED_TO(AD_user -> Entra_user) edges
    for syncPercentage% of enabled AD users in that domain.

    Creates corresponding Entra user nodes on the fly for synced users
    since az_create_users is not called in the hybrid v2 pipeline.

    Returns count of SYNCED_TO edges created.
    """
    import uuid as _uuid

    sync_perc = config.get("hybrid", {}).get("syncPercentage", 80)

    # Find enabled AD users in this domain
    # Note: do NOT filter by plane — not all users have it yet (Step 2 pending)
    ad_user_indices = [
        idx for idx in NODE_GROUPS["User"]
        if NODES[idx]["properties"].get("domain", "").upper() == domain_name.upper()
        and NODES[idx]["properties"].get("enabled", True)
    ]

    if not ad_user_indices:
        return 0

    n_to_sync = max(1, int(len(ad_user_indices) * sync_perc / 100))
    to_sync = rng.sample(ad_user_indices, min(n_to_sync, len(ad_user_indices)))

    # Get tenant name for UPN generation
    tenant_node = None
    for n in NODES:
        if n["properties"].get("objectid") == tenant_id:
            tenant_node = n
            break
    tenant_name = tenant_node["properties"].get("name", "tenant.onmicrosoft.com") if tenant_node else "tenant.onmicrosoft.com"

    edges_created = 0
    for ad_idx in to_sync:
        ad_props = NODES[ad_idx]["properties"]
        ad_name = ad_props.get("name", "")
        display_name = ad_props.get("displayname", ad_name.split("@")[0])

        # Build Entra UPN from AD name
        local_part = ad_name.split("@")[0].lower()
        entra_upn = f"{local_part}@{tenant_name}".lower()
        entra_objectid = str(_uuid.uuid4()).upper()

        # Create corresponding Entra user node
        entra_keys = [
            "labels", "name", "objectid", "plane", "runId",
            "tenantId", "tenantid",
            "displayName", "enabled",
            "syncedFromOnPremises",
        ]
        entra_values = [
            "AZUser", entra_upn, entra_objectid, "Entra", RUN_ID,
            tenant_id, tenant_id,
            display_name, True,
            True,
        ]
        entra_idx = node_operation("AZUser", entra_keys, entra_values, entra_objectid)

        # SYNCED_TO: AD user -> Entra user
        edge_operation(ad_idx, entra_idx, "SYNCED_TO", ["isacl"], [False])
        edges_created += 1

    return edges_created


# ============================================================
# Main entry point: create_sync_links
# ============================================================

def create_sync_links(
    domains: List[Dict[str, Any]],
    tenants: List[Dict[str, Any]],
    config: Dict[str, Any],
    seed: int,
) -> List[Dict[str, Any]]:
    """
    Full hybrid seam infrastructure generation.

    For each (domain, tenant) sync link:
      1. SYNC_LINK edge
      2. SyncIdentity node + SERVICES_LINK + SYNCS_TO
      3. ConnectorHost node + RUNS_ON
      4. If PTA: PTAAgentHost + HAS_PTA_AGENT
      5. If ADFS: ADFSServer + IS_FEDERATED_WITH

    Parameters
    ----------
    domains : list of domain dicts with keys: name, sid, id
              (built from the domains generated in do_generate_hybrid_v2)
    tenants : list of tenant dicts with keys: id, name
              (built from az_create_tenant calls)
    config  : full parameters dict (merged hybrid config)
    seed    : integer seed for reproducibility

    Returns
    -------
    List of link record dicts for downstream use and metrics.
    """
    rng_topo = random.Random(seed ^ 0xABCD1234)
    rng_bridge = random.Random(seed ^ 0xFF00FF)

    # Build mapping
    mapping = build_sync_mapping(domains, tenants, config, rng_topo)

    links = []

    for domain, tenant in mapping:
        tenant_id = tenant["id"]
        sync_mode = _sample_sync_mode(rng_topo, config)

        # Track mode per tenant
        TENANT_HYBRID_MODE[tenant_id] = sync_mode

        # Track domain -> tenant mapping
        if domain["name"] not in DOMAIN_TENANT_MAPPING:
            DOMAIN_TENANT_MAPPING[domain["name"]] = []
        DOMAIN_TENANT_MAPPING[domain["name"]].append(tenant_id)

        # Track sync link
        SYNC_LINKS.append((domain["name"], tenant_id))

        # 1. SYNC_LINK edge
        _create_sync_link_edge(domain, tenant_id, sync_mode)

        # 2. ConnectorHost server
        connector_idx = _create_connector_host(domain, tenant_id, rng_bridge)

        # 3. SyncIdentity node + 3 seam edges
        sync_idx = _create_sync_identity(
            domain, tenant_id, sync_mode, connector_idx, rng_bridge
        )

        link_record = {
            "domain_name": domain["name"],
            "tenant_id": tenant_id,
            "sync_mode": sync_mode,
            "sync_identity_idx": sync_idx,
            "connector_host_idx": connector_idx,
        }

        # 4. PTA bridge
        if sync_mode in ("PTA", "Mixed"):
            pta_idx = _create_pta_server(domain, tenant_id, rng_bridge)
            link_record["pta_server_idx"] = pta_idx

        # 5. ADFS bridge
        if sync_mode in ("ADFS", "Mixed"):
            adfs_idx = _create_adfs_server(domain, tenant_id, rng_bridge)
            link_record["adfs_server_idx"] = adfs_idx

        links.append(link_record)

    return links