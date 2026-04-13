"""
adsynth/synthesizer/permissions_hybrid.py
==========================================
Week 6 — Hybrid permissions and misconfiguration injection.

This module handles privilege edges and "lived-in" misconfigurations
for the hybrid AD-Entra identity graph. It is designed to complement
the existing on-prem permissions pipeline (permissions.py, misconfig.py)
and the Azure permissions pipeline (az_default_permissions.py,
az_default_relationships.py) by filling the gap specifically for:

  1. NHI role assignments  (HAS_AZ_ROLE based on privilegeTier)
  2. SyncIdentity domain rights  (HAS_AD_RIGHT on ADDomain)
  3. AutomationAccount delegated rights  (DELEGATED_RIGHT on OUs/domains)
  4. AI Agent elevated permissions  (high autonomy -> elevated roles)
  5. Hybrid misconfig injection  (orphaned NHI, overbroad SyncIdentity,
     cross-tenant privilege paths, long rotation tail)

All edges are created via the existing DATABASE.py edge_operation so
they are consistent with the rest of the graph.

Safe framing: only structural identity/permission relationships are
modelled. No exploit instructions or operational guidance.
"""

import random
import math
from typing import Any, Dict, List, Optional

from adsynth.DATABASE import (
    NODES, EDGES, NODE_GROUPS,
    NHI_NODE_INDICES, AI_AGENT_NODE_INDICES,
    SYNC_IDENTITY_NODES, TENANT_METADATA,
    edge_operation, get_node_index,
)


# ============================================================
# Internal helpers
# ============================================================

def _get_node(idx: int) -> Optional[Dict[str, Any]]:
    if 0 <= idx < len(NODES):
        return NODES[idx]
    return None


def _props(node: dict) -> dict:
    """
    Return the properties dict of a node regardless of format.
    node_operation() nodes: node["properties"] (nested dict)
    az_create_*() nodes:    top-level keys (no "properties" key)
    """
    if "properties" in node:
        return node["properties"]
    return {k: v for k, v in node.items()
            if k not in ("id", "labels", "type")}


def _get_node_objectid(node: dict) -> str:
    """Return objectid from a node regardless of storage format."""
    return _props(node).get("objectid", "")


def _get_node_tenantid(node: dict) -> str:
    """Return tenantid from a node regardless of storage format."""
    p = _props(node)
    return p.get("tenantid", p.get("tenantId", ""))


def _find_role_nodes_for_tenant(tenant_id: str) -> List[int]:
    """
    Return node indices for AzureADRole nodes belonging to a tenant.

    NODE_GROUPS["AZRole"] may contain either:
      - integer indices (used by the hybrid v2 pipeline via node_operation)
      - string objectids (used by az_create_roles via direct append)

    This function handles both cases and always returns integer indices
    into NODES.
    """
    role_indices = []
    for entry in NODE_GROUPS.get("AZRole", []):
        # Resolve entry to a node index
        if isinstance(entry, int):
            idx = entry
        else:
            # entry is a string objectid — look it up in DATABASE_ID
            from adsynth.DATABASE import DATABASE_ID
            idx = DATABASE_ID.get("objectid", {}).get(entry, -1)
            if idx == -1:
                # fallback: search NODES directly by objectid
                # handles both flat (az_create_*) and nested (node_operation) formats
                idx = next(
                    (i for i, n in enumerate(NODES)
                     if _get_node_objectid(n) == entry),
                    -1
                )
        if idx == -1:
            continue
        node = _get_node(idx)
        if node is None:
            continue
        if _get_node_tenantid(node) == tenant_id:
            role_indices.append(idx)
    return role_indices


def _find_role_by_name(tenant_id: str, name_fragment: str) -> Optional[int]:
    """
    Find a role node index by partial name match within a tenant.
    Handles both flat (az_create_*) and nested (node_operation) node formats.
    """
    for idx in _find_role_nodes_for_tenant(tenant_id):
        node = _get_node(idx)
        if node is None:
            continue
        # Handle both flat and nested node formats
        if "properties" in node:
            name = _props(node).get("name", "")
        else:
            name = node.get("name", "")
        if name_fragment.lower() in name.lower():
            return idx
    return None


def _find_ou_nodes_for_domain(domain_name: str) -> List[int]:
    """
    Return node indices for OU nodes belonging to a domain.
    """
    ou_indices = []
    for idx in NODE_GROUPS.get("OU", []):
        node = _get_node(idx)
        if node is None:
            continue
        if domain_name.upper() in _props(node).get("name", "").upper():
            ou_indices.append(idx)
    return ou_indices


def _find_domain_node(domain_name: str) -> Optional[int]:
    """Find the ADDomain node index for a given domain FQDN."""
    idx = get_node_index(domain_name + "_Domain", "name")
    if idx != -1:
        return idx
    # Fallback: search by name property
    for i in NODE_GROUPS.get("Domain", []):
        node = _get_node(i)
        if node and _props(node).get("name", "").upper() == domain_name.upper():
            return i
    return None


def _edge_exists_between(start_idx: int, end_idx: int, rel_type: str,
                          pair_only: bool = False) -> bool:
    """
    Check if an edge already exists to avoid duplicates.

    pair_only=True: checks if ANY edge of rel_type exists between the
    pair regardless of properties (used for DELEGATED_RIGHT where the
    right attribute varies but we still want only one edge per pair).
    """
    if start_idx < 0 or end_idx < 0:
        return False
    start_neo4j_id = NODES[start_idx]["id"]
    end_neo4j_id   = NODES[end_idx]["id"]
    for e in EDGES:
        if (e.get("label") == rel_type
                and e.get("start", {}).get("id") == start_neo4j_id
                and e.get("end", {}).get("id") == end_neo4j_id):
            return True
    return False


# ============================================================
# Function 1: NHI Role Assignments (HAS_AZ_ROLE)
# ============================================================

# Role name mapping by privilege tier
_TIER_ROLE_MAP = {
    "tier0": "Global Administrator",
    "tier1": "Contributor",
    "standard": "Reader",
}


def assign_nhi_roles(
    tenants: List[Dict[str, Any]],
    config: Dict[str, Any],
    rng: random.Random,
) -> int:
    """
    Assign HAS_AZ_ROLE edges to NHI nodes (ServicePrincipal,
    ManagedIdentity, SyncIdentity) based on their privilegeTier.

    tier0  -> Global Administrator role
    tier1  -> Contributor role
    standard -> Reader role (with probability, not all standard NHIs
                             get a role to avoid over-assignment)

    AI Agents with maxAutonomyLevel=high are treated as elevated
    and receive Contributor or higher even if tier=standard.

    Returns count of HAS_AZ_ROLE edges created.
    """
    edges_created = 0

    # Probability that a standard-tier NHI gets any role at all
    standard_assign_prob = config.get("hybrid", {}).get(
        "hybrid_misconfig", {}
    ).get("standard_nhi_role_prob", 0.40)

    for tenant in tenants:
        tenant_id = tenant["id"]
        role_indices = _find_role_nodes_for_tenant(tenant_id)
        if not role_indices:
            continue

        # Build role lookup by tier
        role_by_tier: Dict[str, Optional[int]] = {}
        for tier, role_name in _TIER_ROLE_MAP.items():
            role_by_tier[tier] = _find_role_by_name(tenant_id, role_name)
            # Fallback to any available role if specific one not found
            if role_by_tier[tier] is None and role_indices:
                role_by_tier[tier] = rng.choice(role_indices)

        # Assign roles to all NHI nodes in this tenant
        nhi_types = ["AZServicePrincipal", "ManagedIdentity", "SyncIdentity"]
        for label in nhi_types:
            for idx in NODE_GROUPS.get(label, []):
                node = _get_node(idx)
                if node is None:
                    continue
                props = _props(node)

                # Only assign roles to NHI in this tenant
                if (props.get("tenantId", props.get("tenantid", "")) != tenant_id
                        and props.get("plane") != "Hybrid"):
                    # SyncIdentity is Hybrid plane — check linkKey for tenant match
                    if label == "SyncIdentity":
                        link_key = props.get("linkKey", "")
                        if tenant_id not in link_key:
                            continue
                    else:
                        continue

                tier = props.get("privilegeTier", "standard")

                # AI Agent autonomy override — treat high-autonomy as tier1 minimum
                is_ai_agent = props.get("isAIAgent", False)
                autonomy    = props.get("maxAutonomyLevel", "low")
                if is_ai_agent and autonomy == "high" and tier == "standard":
                    tier = "tier1"

                # Determine which role to assign
                if tier == "standard":
                    if rng.random() > standard_assign_prob:
                        continue  # not all standard NHIs get a role
                    role_idx = role_by_tier.get("standard")
                elif tier == "tier1":
                    role_idx = role_by_tier.get("tier1")
                else:  # tier0
                    role_idx = role_by_tier.get("tier0")

                if role_idx is None:
                    continue
                if _edge_exists_between(idx, role_idx, "HAS_AZ_ROLE"):
                    continue

                edge_operation(
                    idx, role_idx, "HAS_AZ_ROLE",
                    ["isacl", "privilegeTier", "assignedToNHI"],
                    [False, tier, True]
                )
                edges_created += 1

    return edges_created


# ============================================================
# Function 2: SyncIdentity Domain Rights (HAS_AD_RIGHT)
# ============================================================

def assign_sync_identity_rights(
    domains: List[Dict[str, Any]],
    config: Dict[str, Any],
    rng: random.Random,
) -> int:
    """
    Assign HAS_AD_RIGHT edges from SyncIdentity nodes to their
    corresponding ADDomain nodes.

    This reflects the real-world requirement that the Entra Connect
    Sync account needs replication rights (GetChanges, GetChangesAll)
    on the domain to synchronize password hashes and directory objects.

    These are Tier-0 level rights and are the primary reason
    SyncIdentity nodes are marked highvalue=True.

    Returns count of HAS_AD_RIGHT edges created.
    """
    edges_created = 0

    for (domain_name, tenant_id), sync_idx in SYNC_IDENTITY_NODES.items():
        sync_node = _get_node(sync_idx)
        if sync_node is None:
            continue

        domain_idx = _find_domain_node(domain_name)
        if domain_idx is None:
            continue

        # HAS_AD_RIGHT: SyncIdentity -> ADDomain
        # This represents GetChanges + GetChangesAll replication rights
        for right in ["GetChanges", "GetChangesAll"]:
            if not _edge_exists_between(sync_idx, domain_idx, right):
                edge_operation(
                    sync_idx, domain_idx, right,
                    ["isacl", "isinherited", "fromSync"],
                    [True, False, True]
                )
                edges_created += 1

        # Generic HAS_AD_RIGHT edge for attack-path traversal
        if not _edge_exists_between(sync_idx, domain_idx, "HAS_AD_RIGHT"):
            edge_operation(
                sync_idx, domain_idx, "HAS_AD_RIGHT",
                ["isacl", "right", "fromSync"],
                [False, "SyncReplication", True]
            )
            edges_created += 1

    return edges_created


# ============================================================
# Function 3: AutomationAccount Delegated Rights (DELEGATED_RIGHT)
# ============================================================

def assign_automation_delegated_rights(
    domains: List[Dict[str, Any]],
    config: Dict[str, Any],
    rng: random.Random,
) -> int:
    """
    Assign DELEGATED_RIGHT edges from AutomationAccount nodes to
    OUs or ADDomain nodes within their domain.

    This models realistic automation scenarios where service accounts
    and scheduled tasks are granted delegated admin rights over
    specific OUs (e.g., password reset delegation, computer management).

    Privilege tier drives how broad the delegation is:
      tier0    -> DELEGATED_RIGHT on ADDomain (domain-wide)
      tier1    -> DELEGATED_RIGHT on Tier 0/1 OUs
      standard -> DELEGATED_RIGHT on lower-tier OUs only

    Returns count of DELEGATED_RIGHT edges created.
    """
    edges_created = 0

    # How many OUs an automation account can be delegated over
    max_ous_tier0    = config.get("hybrid", {}).get("hybrid_misconfig", {}).get("max_ous_tier0", 3)
    max_ous_tier1    = config.get("hybrid", {}).get("hybrid_misconfig", {}).get("max_ous_tier1", 5)
    max_ous_standard = config.get("hybrid", {}).get("hybrid_misconfig", {}).get("max_ous_standard", 2)

    for domain in domains:
        domain_name = domain["name"]
        domain_idx  = _find_domain_node(domain_name)
        ou_indices  = _find_ou_nodes_for_domain(domain_name)

        # All AutomationAccounts in this domain
        aa_indices = [
            idx for idx in NODE_GROUPS.get("AutomationAccount", [])
            if _get_node(idx) is not None
            and _props(_get_node(idx)).get("domainId") == domain.get("id")
            or (domain_name.upper() in
                _props(_get_node(idx)).get("domain", "").upper()
                if _get_node(idx) else False)
        ]

        for aa_idx in aa_indices:
            aa_node = _get_node(aa_idx)
            if aa_node is None:
                continue
            tier = _props(aa_node).get("privilegeTier", "standard")

            if tier == "tier0" and domain_idx is not None:
                # Domain-wide delegated right
                if not _edge_exists_between(aa_idx, domain_idx, "DELEGATED_RIGHT",
                                            pair_only=True):
                    edge_operation(
                        aa_idx, domain_idx, "DELEGATED_RIGHT",
                        ["isacl", "right", "isinherited"],
                        [True, "GenericAll", False]
                    )
                    edges_created += 1

                # Also delegate over some OUs
                if ou_indices:
                    sample_size = min(max_ous_tier0, len(ou_indices))
                    for ou_idx in rng.sample(ou_indices, sample_size):
                        if not _edge_exists_between(aa_idx, ou_idx, "DELEGATED_RIGHT",
                                                    pair_only=True):
                            edge_operation(
                                aa_idx, ou_idx, "DELEGATED_RIGHT",
                                ["isacl", "right", "isinherited"],
                                [True, "GenericAll", True]
                            )
                            edges_created += 1

            elif tier == "tier1" and ou_indices:
                sample_size = min(max_ous_tier1, len(ou_indices))
                for ou_idx in rng.sample(ou_indices, sample_size):
                    if not _edge_exists_between(aa_idx, ou_idx, "DELEGATED_RIGHT",
                                                pair_only=True):
                        right = rng.choice(["GenericWrite", "WriteOwner", "WriteDacl"])
                        edge_operation(
                            aa_idx, ou_idx, "DELEGATED_RIGHT",
                            ["isacl", "right", "isinherited"],
                            [True, right, True]
                        )
                        edges_created += 1

            elif tier == "standard" and ou_indices:
                # Standard automation gets narrow delegation
                sample_size = min(max_ous_standard, len(ou_indices))
                for ou_idx in rng.sample(ou_indices, sample_size):
                    if not _edge_exists_between(aa_idx, ou_idx, "DELEGATED_RIGHT",
                                                pair_only=True):
                        right = rng.choice(["ForceChangePassword", "ReadLAPSPassword"])
                        edge_operation(
                            aa_idx, ou_idx, "DELEGATED_RIGHT",
                            ["isacl", "right", "isinherited"],
                            [True, right, True]
                        )
                        edges_created += 1

    return edges_created


# ============================================================
# Function 4: AI Agent Elevated Permissions
# ============================================================

def assign_ai_agent_permissions(
    tenants: List[Dict[str, Any]],
    config: Dict[str, Any],
    rng: random.Random,
) -> int:
    """
    Assign elevated permissions to AI Agents based on their
    autonomy level and tool access list.

    This models realistic over-provisioning misconfigs where
    AI agents running with high autonomy accumulate broad permissions.

    high autonomy   -> may receive Contributor or Global Admin role
    medium autonomy -> Contributor role to relevant resources
    low autonomy    -> Reader or scoped role only

    Returns count of additional edges created.
    """
    edges_created = 0

    for tenant in tenants:
        tenant_id   = tenant["id"]
        role_indices = _find_role_nodes_for_tenant(tenant_id)
        if not role_indices:
            continue

        ga_role  = _find_role_by_name(tenant_id, "Global Administrator")
        contrib  = _find_role_by_name(tenant_id, "Contributor")
        reader   = _find_role_by_name(tenant_id, "Reader")

        for ai_idx in AI_AGENT_NODE_INDICES:
            node = _get_node(ai_idx)
            if node is None:
                continue
            props = _props(node)

            # Only process agents in this tenant
            if (props.get("tenantId", props.get("tenantid", "")) != tenant_id):
                continue

            autonomy     = props.get("maxAutonomyLevel", "low")
            tool_access  = props.get("toolAccess", [])
            agent_type   = props.get("agentType", "Standalone")
            human_oversight = props.get("humanOversight", True)

            # Orchestrators without human oversight are high risk
            is_ungoverned = (agent_type == "Orchestrator" and not human_oversight)

            if autonomy == "high" or is_ungoverned:
                # High risk: assign GA role (misconfig)
                target_role = ga_role or contrib or (rng.choice(role_indices) if role_indices else None)
                if target_role is not None and not _edge_exists_between(ai_idx, target_role, "HAS_AZ_ROLE"):
                    edge_operation(
                        ai_idx, target_role, "HAS_AZ_ROLE",
                        ["isacl", "isAIAgentMisconfig", "autonomyLevel"],
                        [False, True, autonomy]
                    )
                    edges_created += 1

            elif autonomy == "medium":
                target_role = contrib or (rng.choice(role_indices) if role_indices else None)
                if target_role is not None and not _edge_exists_between(ai_idx, target_role, "HAS_AZ_ROLE"):
                    edge_operation(
                        ai_idx, target_role, "HAS_AZ_ROLE",
                        ["isacl", "isAIAgentMisconfig", "autonomyLevel"],
                        [False, False, autonomy]
                    )
                    edges_created += 1

            elif autonomy == "low" and reader is not None:
                if not _edge_exists_between(ai_idx, reader, "HAS_AZ_ROLE"):
                    edge_operation(
                        ai_idx, reader, "HAS_AZ_ROLE",
                        ["isacl", "isAIAgentMisconfig", "autonomyLevel"],
                        [False, False, autonomy]
                    )
                    edges_created += 1

            # Tool access -> ADMIN_TO on VMs if CodeExecution in toolAccess
            if "CodeExecution" in tool_access:
                vm_indices = [
                    idx for idx in NODE_GROUPS.get("AZVM", [])
                    if _get_node(idx) is not None
                    and (_props(_get_node(idx)).get("tenantid") == tenant_id
                         or _props(_get_node(idx)).get("tenantId") == tenant_id)
                ]
                if vm_indices:
                    target_vm = rng.choice(vm_indices)
                    if not _edge_exists_between(ai_idx, target_vm, "AZVMContributor"):
                        edge_operation(
                            ai_idx, target_vm, "AZVMContributor",
                            ["isacl", "fromToolAccess"],
                            [False, True]
                        )
                        edges_created += 1

    return edges_created


# ============================================================
# Function 5: Hybrid Misconfig Injection
# ============================================================

def inject_hybrid_misconfigs(
    domains: List[Dict[str, Any]],
    tenants: List[Dict[str, Any]],
    config: Dict[str, Any],
    rng: random.Random,
) -> Dict[str, int]:
    """
    Inject "lived-in" hybrid misconfigurations as structural graph
    properties. These make the graph realistic rather than
    unrealistically clean.

    Four misconfig patterns (all safe — no exploit instructions):

    1. Orphaned NHI  — NHI with ownerType=Unknown gets elevated role
       (models ungoverned service accounts accumulating permissions)

    2. Overbroad SyncIdentity  — SyncIdentity gets ADMIN_TO on
       ConnectorHost server beyond its own (cross-link privilege)

    3. Cross-tenant privilege path  — NHI in one tenant gets a role
       in another tenant (models shared service account misconfig)

    4. Long rotation tail  — NHI with rotationCadenceDays > 365
       gets an extra role assignment (models stale credential risk)

    Rates are controlled by hybrid_misconfig section of config.

    Returns dict of {misconfig_type: count_injected}.
    """
    hybrid_mc = config.get("hybrid", {}).get("hybrid_misconfig", {})

    orphaned_nhi_perc       = hybrid_mc.get("orphaned_nhi_perc", 10)
    overbroad_sync_perc     = hybrid_mc.get("overbroad_sync_perc", 8)
    cross_tenant_perc       = hybrid_mc.get("cross_tenant_perc", 3)
    long_rotation_perc      = hybrid_mc.get("long_rotation_perc", 12)

    counts = {
        "orphaned_nhi":      0,
        "overbroad_sync":    0,
        "cross_tenant":      0,
        "long_rotation":     0,
    }

    # ── Misconfig 1: Orphaned NHI gets elevated role ──────────────────
    all_nhi_types = ["AZServicePrincipal", "ManagedIdentity", "AutomationAccount"]
    all_nhi_indices = []
    for label in all_nhi_types:
        all_nhi_indices.extend(NODE_GROUPS.get(label, []))

    orphaned = [
        idx for idx in all_nhi_indices
        if _get_node(idx) is not None
        and _props(_get_node(idx)).get("ownerType") == "Unknown"
    ]
    n_orphaned_misconfig = max(1, int(len(orphaned) * orphaned_nhi_perc / 100))

    for idx in rng.sample(orphaned, min(n_orphaned_misconfig, len(orphaned))):
        node = _get_node(idx)
        if node is None:
            continue
        t_id = _props(node).get("tenantId",
               _props(node).get("tenantid", ""))
        role_indices = _find_role_nodes_for_tenant(t_id)
        if not role_indices:
            continue
        contrib = _find_role_by_name(t_id, "Contributor")
        target  = contrib or rng.choice(role_indices)
        if not _edge_exists_between(idx, target, "HAS_AZ_ROLE"):
            edge_operation(
                idx, target, "HAS_AZ_ROLE",
                ["isacl", "isMisconfig", "misconfigType"],
                [False, True, "orphaned_nhi_elevated"]
            )
            counts["orphaned_nhi"] += 1

    # ── Misconfig 2: Overbroad SyncIdentity ───────────────────────────
    sync_indices = list(SYNC_IDENTITY_NODES.values())
    n_overbroad  = max(1, int(len(sync_indices) * overbroad_sync_perc / 100))

    # Gather all ConnectorHost server indices
    connector_hosts = NODE_GROUPS.get("ConnectorHost", [])

    for sync_idx in rng.sample(sync_indices, min(n_overbroad, len(sync_indices))):
        if not connector_hosts:
            break
        # Give SyncIdentity ADMIN_TO on a connector host it doesn't own
        target_host = rng.choice(connector_hosts)
        if not _edge_exists_between(sync_idx, target_host, "ADMIN_TO"):
            edge_operation(
                sync_idx, target_host, "ADMIN_TO",
                ["isacl", "isMisconfig", "misconfigType"],
                [False, True, "overbroad_sync_identity"]
            )
            counts["overbroad_sync"] += 1

    # ── Misconfig 3: Cross-tenant privilege path ──────────────────────
    if len(tenants) > 1:
        # Find NHI nodes marked isCrossTenant or pick random subset
        cross_candidates = [
            idx for idx in NODE_GROUPS.get("AZServicePrincipal", [])
            if _get_node(idx) is not None
            and _props(_get_node(idx)).get("isCrossTenant", False)
        ]
        # If not enough cross-tenant SPs, pick random NHIs
        if len(cross_candidates) < 2:
            cross_candidates = [
                idx for idx in NODE_GROUPS.get("AZServicePrincipal", [])
                if _get_node(idx) is not None
            ]

        n_cross = max(1, int(len(cross_candidates) * cross_tenant_perc / 100))

        for idx in rng.sample(cross_candidates, min(n_cross, len(cross_candidates))):
            node = _get_node(idx)
            if node is None:
                continue
            own_tenant = _props(node).get("tenantId",
                         _props(node).get("tenantid", ""))

            # Find a different tenant
            other_tenants = [t for t in tenants if t["id"] != own_tenant]
            if not other_tenants:
                continue
            other_tenant = rng.choice(other_tenants)
            other_roles  = _find_role_nodes_for_tenant(other_tenant["id"])
            if not other_roles:
                continue
            # Assign Reader role in other tenant (cross-tenant path)
            reader = _find_role_by_name(other_tenant["id"], "Reader")
            target = reader or rng.choice(other_roles)
            if not _edge_exists_between(idx, target, "HAS_AZ_ROLE"):
                edge_operation(
                    idx, target, "HAS_AZ_ROLE",
                    ["isacl", "isMisconfig", "misconfigType", "crossTenantSource"],
                    [False, True, "cross_tenant_privilege", own_tenant]
                )
                counts["cross_tenant"] += 1

    # ── Misconfig 4: Long rotation tail ──────────────────────────────
    stale_cred_nhi = [
        idx for idx in all_nhi_indices
        if _get_node(idx) is not None
        and _props(_get_node(idx)).get("rotationCadenceDays", 0) > 365
    ]
    n_stale = max(1, int(len(stale_cred_nhi) * long_rotation_perc / 100))

    for idx in rng.sample(stale_cred_nhi, min(n_stale, len(stale_cred_nhi))):
        node = _get_node(idx)
        if node is None:
            continue
        t_id = _props(node).get("tenantId",
               _props(node).get("tenantid", ""))
        role_indices = _find_role_nodes_for_tenant(t_id)
        if not role_indices:
            continue
        contrib = _find_role_by_name(t_id, "Contributor")
        target  = contrib or rng.choice(role_indices)
        if not _edge_exists_between(idx, target, "HAS_AZ_ROLE"):
            edge_operation(
                idx, target, "HAS_AZ_ROLE",
                ["isacl", "isMisconfig", "misconfigType", "rotationCadenceDays"],
                [False, True, "stale_credential_elevated",
                 _props(node).get("rotationCadenceDays", 0)]
            )
            counts["long_rotation"] += 1

    return counts


# ============================================================
# Main entry point: run_hybrid_permissions_phase
# ============================================================

def run_hybrid_permissions_phase(
    domains: List[Dict[str, Any]],
    tenants: List[Dict[str, Any]],
    config: Dict[str, Any],
    seed: int,
) -> Dict[str, Any]:
    """
    Phase 6 entry point called from do_generate_hybrid_v2().

    Runs all five permission and misconfig functions in order:
      1. NHI role assignments
      2. SyncIdentity domain rights
      3. AutomationAccount delegated rights
      4. AI Agent elevated permissions
      5. Hybrid misconfig injection

    Parameters
    ----------
    domains : list of domain dicts {name, sid, id}
    tenants : list of tenant dicts {id, name}
    config  : full parameters dict
    seed    : integer seed for reproducibility

    Returns
    -------
    Summary dict with counts of all edges created per category.
    """
    # Each function gets its own rng derived from the seed so that
    # skipping edges in one function never shifts the rng state seen
    # by subsequent functions — this is what guarantees determinism.
    rng_roles   = random.Random(seed ^ 0xFEED01)
    rng_sync    = random.Random(seed ^ 0xFEED02)
    rng_deleg   = random.Random(seed ^ 0xFEED03)
    rng_ai      = random.Random(seed ^ 0xFEED04)
    rng_misconf = random.Random(seed ^ 0xFEED05)

    print("  Assigning NHI roles (HAS_AZ_ROLE)...")
    nhi_role_edges = assign_nhi_roles(tenants, config, rng_roles)
    print(f"    HAS_AZ_ROLE edges created: {nhi_role_edges}")

    print("  Assigning SyncIdentity domain rights (HAS_AD_RIGHT)...")
    sync_right_edges = assign_sync_identity_rights(domains, config, rng_sync)
    print(f"    HAS_AD_RIGHT + replication edges created: {sync_right_edges}")

    print("  Assigning AutomationAccount delegated rights (DELEGATED_RIGHT)...")
    deleg_edges = assign_automation_delegated_rights(domains, config, rng_deleg)
    print(f"    DELEGATED_RIGHT edges created: {deleg_edges}")

    print("  Assigning AI Agent elevated permissions...")
    ai_perm_edges = assign_ai_agent_permissions(tenants, config, rng_ai)
    print(f"    AI Agent permission edges created: {ai_perm_edges}")

    print("  Injecting hybrid misconfigurations...")
    misconfig_counts = inject_hybrid_misconfigs(domains, tenants, config, rng_misconf)
    total_misconfig = sum(misconfig_counts.values())
    print(f"    Misconfig edges injected: {total_misconfig}")
    for mtype, count in misconfig_counts.items():
        print(f"      {mtype}: {count}")

    summary = {
        "nhi_role_edges":    nhi_role_edges,
        "sync_right_edges":  sync_right_edges,
        "deleg_edges":       deleg_edges,
        "ai_perm_edges":     ai_perm_edges,
        "misconfig_counts":  misconfig_counts,
        "total_misconfig":   total_misconfig,
    }

    return summary