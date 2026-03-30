"""
adsynth/synthesizer/nhi.py
===========================
Non-Human Identity generation.
Ported from adsynth/generators/nhi_generator.py but writes
through the original DATABASE.py node_operation / edge_operation.

Paper §5 — N_generic(t) formula:
  N_generic(t) = clamp(floor(0.14 · U_t), 6, 2500)
  Split: cloud 55% / on-prem 45%
  Cloud:   70% ServicePrincipal, 30% ManagedIdentity
  On-prem: 100% AutomationAccount

Paper §5.5 — Cross-tenant shared services pool:
  N_cross = floor(0.03 · sum_t(N_generic(t)))

Appendix B.4 — Hygiene priors:
  ownerType:  Team 60-75%, System 15-25%, Unknown 5-15%
  lifecycle:  LongLived ~75%, Ephemeral ~25%

Appendix B.5 — Privilege bands (heavy-tailed):
  Tier-0: 0.7-1.5% of generic automation per tenant
  Tier-1: 4-8%
  Remainder: standard/scoped

All SyncIdentity nodes are Tier-0 by construction (set in hybrid_seam.py).
"""

import math
import random
import uuid
from typing import Any, Dict, List

from adsynth.DATABASE import (
    NODES, NODE_GROUPS,
    DATABASE_ID, RUN_ID,
    NHI_NODE_INDICES,
    AI_AGENT_NODE_INDICES,
    TENANT_METADATA,
    node_operation, edge_operation, get_node_index,
    ridcount,
)


# ============================================================
# N_generic formula (paper §5.5)
# ============================================================

def n_generic(u_t: int) -> int:
    """N_generic(t) = clamp(floor(0.14 * U_t), 6, 2500)"""
    return max(6, min(2500, math.floor(0.14 * u_t)))


# ============================================================
# Hygiene sampling helpers (Appendix B.4 + B.6)
# ============================================================

def _sample_owner_type(rng: random.Random, posture: str) -> str:
    if posture == "good":
        dist = {"Team": 75, "System": 20, "Unknown": 5}
    elif posture == "average":
        dist = {"Team": 65, "System": 22, "Unknown": 13}
    else:  # poor
        dist = {"Team": 55, "System": 18, "Unknown": 27}
    keys = list(dist.keys())
    weights = [dist[k] for k in keys]
    return rng.choices(keys, weights=weights, k=1)[0]


def _sample_lifecycle(rng: random.Random) -> str:
    return rng.choices(["LongLived", "Ephemeral"], weights=[75, 25], k=1)[0]


def _sample_rotation_cadence(rng: random.Random, posture: str) -> int:
    """Appendix B.6 rotation tail."""
    long_tail_prob = {"poor": 20, "average": 12, "good": 6}.get(posture, 12)
    if rng.randint(1, 100) <= long_tail_prob:
        return rng.randint(366, 730)
    return rng.randint(30, 365)


def _sample_privilege_tier(rng: random.Random, posture: str) -> str:
    """Appendix B.5 heavy-tailed privilege bands."""
    roll = rng.random() * 100
    t0_ceil = 1.5 if posture != "poor" else 2.5
    t1_ceil = 8.0 if posture != "poor" else 10.0
    if roll < t0_ceil:
        return "tier0"
    if roll < t1_ceil:
        return "tier1"
    return "standard"


# ============================================================
# AI Agent sampling helpers (Week 4 extension)
# Real enterprise distributions based on Azure AI deployments
# ============================================================

# Frameworks actually used in enterprise Azure AI deployments
_AI_FRAMEWORKS = ["CopilotStudio", "SemanticKernel", "AutoGen",
                   "AzureAIFoundry", "LangChain", "Custom"]
_AI_FRAMEWORK_WEIGHTS = [30, 20, 15, 20, 10, 5]

# Agent types in multi-agent systems
_AGENT_TYPES = ["Orchestrator", "Subagent", "Standalone"]
_AGENT_TYPE_WEIGHTS = [20, 20, 60]

# LLM backends
_LLM_BACKENDS = ["GPT4o", "GPT4", "Claude", "Gemini", "Custom"]
_LLM_BACKEND_WEIGHTS = [40, 20, 15, 10, 15]

# Tools an AI agent can access — each is a potential attack surface
_TOOL_ACCESS_OPTIONS = [
    "GraphAPI", "KeyVault", "EmailSend", "CodeExecution",
    "BlobStorage", "SharePoint", "TeamsAPI", "SQLDatabase"
]


def _sample_ai_agent_probability(posture: str) -> float:
    """
    Probability that a given ServicePrincipal is an AI agent.
    Higher under poor posture — ungoverned tenants have more
    ungoverned AI deployments.
    """
    return {"good": 0.08, "average": 0.15, "poor": 0.28}.get(posture, 0.15)


def _sample_tool_access(rng: random.Random, posture: str) -> list:
    """
    Sample which tools the AI agent can access.
    Poor posture agents tend to have broader tool access (over-provisioned).
    """
    if posture == "good":
        n_tools = rng.randint(1, 2)
    elif posture == "average":
        n_tools = rng.randint(1, 4)
    else:  # poor
        n_tools = rng.randint(2, 6)
    return rng.sample(_TOOL_ACCESS_OPTIONS, min(n_tools, len(_TOOL_ACCESS_OPTIONS)))


def _sample_human_oversight(rng: random.Random, posture: str) -> bool:
    """
    Whether a human approves the agent's actions.
    Poor posture → more agents running without oversight.
    """
    oversight_prob = {"good": 0.80, "average": 0.55, "poor": 0.25}.get(posture, 0.55)
    return rng.random() < oversight_prob


def _sample_max_autonomy(rng: random.Random, posture: str) -> str:
    if posture == "good":
        dist = {"low": 60, "medium": 35, "high": 5}
    elif posture == "average":
        dist = {"low": 35, "medium": 45, "high": 20}
    else:  # poor
        dist = {"low": 15, "medium": 35, "high": 50}
    keys = list(dist.keys())
    weights = [dist[k] for k in keys]
    return rng.choices(keys, weights=weights, k=1)[0]


# ============================================================
# ServicePrincipal (cloud, plane=Entra)
# May be promoted to AI Agent based on posture probability
# ============================================================

def _create_service_principal(
    index: int,
    tenant_id: str,
    tenant_name: str,
    rng: random.Random,
    is_cross_tenant: bool = False,
    force_ai_agent: bool = False,
) -> int:
    """
    Create one ServicePrincipal node.
    With probability based on tenant posture, promotes to AI Agent
    by adding isAIAgent=True and agent-specific properties.
    Returns node index.
    """
    posture = TENANT_METADATA.get(tenant_id, {}).get("posture", "average")

    sp_objectid = str(uuid.uuid4()).upper()
    short_name = tenant_name.split(".")[0]

    # Decide if this SP is an AI agent
    is_ai_agent = force_ai_agent or (
        rng.random() < _sample_ai_agent_probability(posture)
    )

    if is_ai_agent:
        agent_type = rng.choices(
            _AGENT_TYPES, weights=_AGENT_TYPE_WEIGHTS, k=1
        )[0]
        display_name = f"AIAgent_{agent_type}_{short_name}_{index}"
    else:
        agent_type = None
        display_name = f"SP_{short_name}_{index}"

    priv_tier = _sample_privilege_tier(rng, posture)

    # Orchestrator agents have elevated privilege probability —
    # they coordinate other agents so they need broader access
    if is_ai_agent and agent_type == "Orchestrator" and priv_tier == "standard":
        priv_tier = rng.choices(
            ["tier0", "tier1", "standard"], weights=[5, 40, 55], k=1
        )[0]

    keys = [
        "labels", "name", "objectid", "plane", "runId",
        "tenantId", "domainId",
        # NHI required
        "ownerType", "lifecycle",
        # SP required
        "appId",
        # Hygiene
        "credentialType", "rotationCadenceDays",
        # Privilege
        "privilegeTier", "highvalue",
        # Cross-tenant flag
        "isCrossTenant",
        # AI Agent flag — always present, False for regular SPs
        "isAIAgent",
    ]
    values = [
        "AZServicePrincipal", display_name, sp_objectid, "Entra", RUN_ID,
        tenant_id, None,
        _sample_owner_type(rng, posture),
        _sample_lifecycle(rng),
        str(uuid.uuid4()).upper(),
        rng.choices(["secret", "cert", "managed"], weights=[50, 35, 15], k=1)[0],
        _sample_rotation_cadence(rng, posture),
        priv_tier,
        priv_tier == "tier0",
        is_cross_tenant,
        is_ai_agent,
    ]

    idx = node_operation("AZServicePrincipal", keys, values, sp_objectid)

    # Add AI agent specific properties if applicable
    if is_ai_agent:
        NODES[idx]["properties"]["agentType"] = agent_type
        NODES[idx]["properties"]["agentFramework"] = rng.choices(
            _AI_FRAMEWORKS, weights=_AI_FRAMEWORK_WEIGHTS, k=1
        )[0]
        NODES[idx]["properties"]["llmBackend"] = rng.choices(
            _LLM_BACKENDS, weights=_LLM_BACKEND_WEIGHTS, k=1
        )[0]
        NODES[idx]["properties"]["humanOversight"] = _sample_human_oversight(
            rng, posture
        )
        NODES[idx]["properties"]["toolAccess"] = _sample_tool_access(rng, posture)
        NODES[idx]["properties"]["maxAutonomyLevel"] = _sample_max_autonomy(
            rng, posture
        )
        # Track in AIAgent group and NODE_GROUPS
        AI_AGENT_NODE_INDICES.append(idx)
        NODE_GROUPS["AIAgent"].append(idx)

    NHI_NODE_INDICES.append(idx)

    # Contain in tenant
    tenant_idx = get_node_index(tenant_id, "objectid")
    if tenant_idx != -1:
        edge_operation(tenant_idx, idx, "AZContains", ["isacl"], [False])

    return idx


# ============================================================
# ManagedIdentity (cloud, plane=Entra)
# ============================================================

def _create_managed_identity(
    index: int,
    tenant_id: str,
    tenant_name: str,
    rng: random.Random,
) -> int:
    """Create one ManagedIdentity node. Returns node index."""
    posture = TENANT_METADATA.get(tenant_id, {}).get("posture", "average")

    mi_objectid = str(uuid.uuid4()).upper()
    short_name = tenant_name.split(".")[0]
    display_name = f"MI_{short_name}_{index}"

    mi_type = rng.choices(
        ["SystemAssigned", "UserAssigned"], weights=[70, 30], k=1
    )[0]

    keys = [
        "labels", "name", "objectid", "plane", "runId",
        "tenantId", "domainId",
        "ownerType", "lifecycle",
        "miType",
        "rotationCadenceDays", "privilegeTier", "highvalue",
    ]
    values = [
        "ManagedIdentity", display_name, mi_objectid, "Entra", RUN_ID,
        tenant_id, None,
        _sample_owner_type(rng, posture),
        _sample_lifecycle(rng),
        mi_type,
        _sample_rotation_cadence(rng, posture),
        _sample_privilege_tier(rng, posture),
        False,
    ]

    idx = node_operation("ManagedIdentity", keys, values, mi_objectid)
    NODES[idx]["properties"]["highvalue"] = (
        NODES[idx]["properties"]["privilegeTier"] == "tier0"
    )
    NHI_NODE_INDICES.append(idx)

    tenant_idx = get_node_index(tenant_id, "objectid")
    if tenant_idx != -1:
        edge_operation(tenant_idx, idx, "AZContains", ["isacl"], [False])

    return idx


# ============================================================
# AutomationAccount (on-prem, plane=AD)
# ============================================================

def _create_automation_account(
    index: int,
    domain_name: str,
    domain_sid: str,
    rng: random.Random,
) -> int:
    """Create one AutomationAccount node. Returns node index."""
    rid = ridcount[0]
    ridcount[0] += 1
    aa_sid = f"{domain_sid}-{rid}"

    short_name = domain_name.split(".")[0]
    display_name = f"AA_{short_name}_{index}@{domain_name}"

    kind = rng.choices(
        ["service", "scheduled-task", "deployment", "script"],
        weights=[40, 30, 20, 10], k=1
    )[0]

    keys = [
        "labels", "name", "objectid", "plane", "runId",
        "tenantId", "domainId",
        "domain",
        "ownerType", "lifecycle",
        "automationKind",
        "rotationCadenceDays", "privilegeTier", "highvalue",
    ]
    values = [
        "AutomationAccount", display_name, aa_sid, "AD", RUN_ID,
        None, domain_name,
        domain_name,
        _sample_owner_type(rng, "average"),
        _sample_lifecycle(rng),
        kind,
        _sample_rotation_cadence(rng, "average"),
        _sample_privilege_tier(rng, "average"),
        False,
    ]

    idx = node_operation("AutomationAccount", keys, values, aa_sid)
    NODES[idx]["properties"]["highvalue"] = (
        NODES[idx]["properties"]["privilegeTier"] == "tier0"
    )
    NHI_NODE_INDICES.append(idx)

    # Place in domain
    domain_idx = get_node_index(domain_name + "_Domain", "name")
    if domain_idx != -1:
        edge_operation(domain_idx, idx, "Contains", ["isacl"], [False])

    return idx


# ============================================================
# Cross-tenant shared services pool (paper §5.5)
# ============================================================

def _create_cross_tenant_pool(
    total_generic: int,
    tenants: List[Dict[str, Any]],
    rng: random.Random,
) -> List[int]:
    """
    N_cross = floor(0.03 * total_generic)
    ServicePrincipals marked isCrossTenant=True, assigned to parent tenant.
    """
    n_cross = math.floor(0.03 * total_generic)
    if not tenants or n_cross == 0:
        return []

    parent = next(
        (t for t in tenants
         if TENANT_METADATA.get(t["id"], {}).get("orgType") == "parent"),
        tenants[0]
    )

    ids = []
    for i in range(n_cross):
        idx = _create_service_principal(
            index=10000 + i,
            tenant_id=parent["id"],
            tenant_name=parent["name"],
            rng=rng,
            is_cross_tenant=True,
        )
        ids.append(idx)

    return ids


# ============================================================
# AI Agent relationship generation (Week 4)
# Three new edge types: ORCHESTRATES, DELEGATES_TO, HAS_TOOL_ACCESS
# ============================================================

def create_agent_orchestration_edges(
    sp_by_tenant: Dict[str, List[int]],
    rng: random.Random,
) -> int:
    """
    ORCHESTRATES: AIAgent(Orchestrator) -> AIAgent(Subagent)

    For each Orchestrator-type agent, create edges to a random
    subset of Subagent-type agents in the same tenant.

    Returns count of edges created.
    """
    edges_created = 0

    for tenant_id, sp_indices in sp_by_tenant.items():
        # Split agents in this tenant by type
        orchestrators = [
            idx for idx in sp_indices
            if NODES[idx]["properties"].get("isAIAgent")
            and NODES[idx]["properties"].get("agentType") == "Orchestrator"
        ]
        subagents = [
            idx for idx in sp_indices
            if NODES[idx]["properties"].get("isAIAgent")
            and NODES[idx]["properties"].get("agentType") == "Subagent"
        ]

        if not orchestrators or not subagents:
            continue

        for orch_idx in orchestrators:
            # Each orchestrator directs 1-3 subagents
            n_subs = rng.randint(1, min(3, len(subagents)))
            targets = rng.sample(subagents, n_subs)
            for sub_idx in targets:
                edge_operation(
                    orch_idx, sub_idx, "ORCHESTRATES",
                    ["isacl", "isAIRelationship"],
                    [False, True]
                )
                edges_created += 1

    return edges_created


def create_delegation_edges(
    sp_by_tenant: Dict[str, List[int]],
    rng: random.Random,
) -> int:
    """
    DELEGATES_TO: User(Entra) -> AIAgent(ServicePrincipal)

    When a user authorizes a Copilot agent or grants OAuth consent,
    they delegate their identity context to the agent.
    The agent can then act on behalf of the user.

    Percentage of users who delegate controlled by tenant posture —
    poor posture tenants have more ungoverned delegations.

    Returns count of edges created.
    """
    edges_created = 0

    for tenant_id, sp_indices in sp_by_tenant.items():
        posture = TENANT_METADATA.get(tenant_id, {}).get("posture", "average")

        # Only delegate to non-Subagent AI agents
        # (users delegate to Orchestrators and Standalone agents)
        delegate_targets = [
            idx for idx in sp_indices
            if NODES[idx]["properties"].get("isAIAgent")
            and NODES[idx]["properties"].get("agentType") != "Subagent"
        ]

        if not delegate_targets:
            continue

        # Find Entra users in this tenant
        entra_users = [
            idx for idx in NODE_GROUPS["AZUser"]
            if (NODES[idx]["properties"].get("tenantid", "")  == tenant_id
            or  NODES[idx]["properties"].get("tenantId", "")  == tenant_id
            or  NODES[idx]["properties"].get("TenantId", "")  == tenant_id)
        ]

        if not entra_users:
            continue

        # Delegation probability per user based on posture
        deleg_prob = {"good": 0.10, "average": 0.25, "poor": 0.45}.get(posture, 0.25)

        for user_idx in entra_users:
            if rng.random() < deleg_prob:
                # Delegate to one random AI agent
                agent_idx = rng.choice(delegate_targets)
                edge_operation(
                    user_idx, agent_idx, "DELEGATES_TO",
                    ["isacl", "isAIRelationship", "consentType"],
                    [False, True, rng.choice(["AllPrincipals", "Principal"])]
                )
                edges_created += 1

    return edges_created


def create_tool_access_edges(
    sp_by_tenant: Dict[str, List[int]],
    rng: random.Random,
) -> int:
    """
    HAS_TOOL_ACCESS: AIAgent -> Resource (KeyVault, AZVM, etc.)

    Captures which cloud resources the AI agent can directly access.
    This is the agent's operational capability surface and is distinct
    from role-based access.

    Returns count of edges created.
    """
    edges_created = 0

    # Resource node types that AI agents can access
    resource_labels = ["AZKeyVault", "AZVM", "AZApp"]

    for tenant_id, sp_indices in sp_by_tenant.items():
        ai_agents = [
            idx for idx in sp_indices
            if NODES[idx]["properties"].get("isAIAgent")
        ]

        if not ai_agents:
            continue

        # Collect available resources in this tenant
        available_resources = []
        for label in resource_labels:
            for idx in NODE_GROUPS.get(label, []):
                if NODES[idx]["properties"].get("tenantid") == tenant_id:
                    available_resources.append(idx)

        if not available_resources:
            available_resources = [
                idx for idx in NODE_GROUPS["AZTenant"]
                if NODES[idx]["properties"].get("objectid") == tenant_id
            ]

        if not available_resources:
            continue

        for agent_idx in ai_agents:
            tool_access = NODES[agent_idx]["properties"].get("toolAccess", [])
            if not tool_access:
                continue

            # Connect to 1-2 actual resource nodes matching tool access
            n_resources = rng.randint(1, min(2, len(available_resources)))
            targets = rng.sample(available_resources, n_resources)
            for res_idx in targets:
                edge_operation(
                    agent_idx, res_idx, "HAS_TOOL_ACCESS",
                    ["isacl", "isAIRelationship"],
                    [False, True]
                )
                edges_created += 1
            

    return edges_created
def _force_ai_agent(idx: int, agent_type: str, tenant_id: str, rng: random.Random) -> None:
    """Force an existing ServicePrincipal node to become an AI agent of a specific type."""
    posture = TENANT_METADATA.get(tenant_id, {}).get("posture", "average")
    NODES[idx]["properties"]["isAIAgent"] = True
    NODES[idx]["properties"]["agentType"] = agent_type
    NODES[idx]["properties"]["agentFramework"] = rng.choices(
        _AI_FRAMEWORKS, weights=_AI_FRAMEWORK_WEIGHTS, k=1
    )[0]
    NODES[idx]["properties"]["llmBackend"] = rng.choices(
        _LLM_BACKENDS, weights=_LLM_BACKEND_WEIGHTS, k=1
    )[0]
    NODES[idx]["properties"]["humanOversight"] = _sample_human_oversight(rng, posture)
    NODES[idx]["properties"]["toolAccess"] = _sample_tool_access(rng, posture)
    NODES[idx]["properties"]["maxAutonomyLevel"] = _sample_max_autonomy(rng, posture)
    NODES[idx]["properties"]["name"] = f"AIAgent_{agent_type}_{NODES[idx]['properties']['name']}"
    if idx not in AI_AGENT_NODE_INDICES:
        AI_AGENT_NODE_INDICES.append(idx)
    if idx not in NODE_GROUPS["AIAgent"]:
        NODE_GROUPS["AIAgent"].append(idx)

# ============================================================
# Main entry point: create_non_humans
# ============================================================

def create_non_humans(
    domains: List[Dict[str, Any]],
    tenants: List[Dict[str, Any]],
    users_per_tenant: Dict[str, int],
    config: Dict[str, Any],
    seed: int,
) -> Dict[str, Any]:
    """
    Generate all NonHumanIdentity nodes using paper priors,
    including AI Agent extensions (Week 4).

    Parameters
    ----------
    domains           : list of {name, sid, id} dicts
    tenants           : list of {id, name} dicts
    users_per_tenant  : {tenant_id: U_t} from user generation
    config            : full parameters dict
    seed              : integer seed

    Returns
    -------
    {
      "sp_by_tenant":   {tenant_id: [node_indices]},
      "mi_by_tenant":   {tenant_id: [node_indices]},
      "aa_by_domain":   {domain_name: [node_indices]},
      "cross_pool":     [node_indices],
      "total_generic":  int,
      "ai_agents":      [node_indices],
      "orchestrates_edges": int,
      "delegates_to_edges": int,
      "tool_access_edges":  int,
    }
    """
    rng = random.Random(seed ^ 0xFF00AA)

    sp_by_tenant: Dict[str, List[int]] = {}
    mi_by_tenant: Dict[str, List[int]] = {}
    aa_by_domain: Dict[str, List[int]] = {}
    total_generic = 0

    for tenant in tenants:
        t_id = tenant["id"]
        u_t = users_per_tenant.get(t_id, config.get("AZUser", {}).get("nUsers", 50))
        n_gen = n_generic(u_t)
        total_generic += n_gen

        # Cloud: 55% of n_gen
        n_cloud = round(n_gen * 0.55)
        n_sp = round(n_cloud * 0.70)
        n_mi = n_cloud - n_sp

        sp_ids = []
        for i in range(n_sp):
            sp_ids.append(
                _create_service_principal(i, t_id, tenant["name"], rng)
            )
        sp_by_tenant[t_id] = sp_ids

        mi_ids = []
        for i in range(n_mi):
            mi_ids.append(
                _create_managed_identity(i, t_id, tenant["name"], rng)
            )
        mi_by_tenant[t_id] = mi_ids

        # Guarantee at least one Orchestrator and one Subagent per tenant
        tenant_ai_agents = [
            idx for idx in sp_ids
            if NODES[idx]["properties"].get("isAIAgent")
        ]

        has_orchestrator = any(
            NODES[idx]["properties"].get("agentType") == "Orchestrator"
            for idx in tenant_ai_agents
        )
        has_subagent = any(
            NODES[idx]["properties"].get("agentType") == "Subagent"
            for idx in tenant_ai_agents
        )

        # Force Orchestrator if missing
        if not has_orchestrator and len(sp_ids) >= 1:
            idx = sp_ids[0]
            _force_ai_agent(idx, "Orchestrator", t_id, rng)

        # Force Subagent if missing  
        if not has_subagent and len(sp_ids) >= 2:
            idx = sp_ids[1]
            _force_ai_agent(idx, "Subagent", t_id, rng)

    
        if not tenant_ai_agents and sp_ids:
            # Force the first SP to become an AI agent
            idx = sp_ids[0]
            posture = TENANT_METADATA.get(t_id, {}).get("posture", "average")
            agent_type = rng.choices(
                _AGENT_TYPES, weights=_AGENT_TYPE_WEIGHTS, k=1
            )[0]
            NODES[idx]["properties"]["isAIAgent"] = True
            NODES[idx]["properties"]["agentType"] = agent_type
            NODES[idx]["properties"]["agentFramework"] = rng.choices(
                _AI_FRAMEWORKS, weights=_AI_FRAMEWORK_WEIGHTS, k=1
            )[0]
            NODES[idx]["properties"]["llmBackend"] = rng.choices(
                _LLM_BACKENDS, weights=_LLM_BACKEND_WEIGHTS, k=1
            )[0]
            NODES[idx]["properties"]["humanOversight"] = _sample_human_oversight(rng, posture)
            NODES[idx]["properties"]["toolAccess"] = _sample_tool_access(rng, posture)
            NODES[idx]["properties"]["maxAutonomyLevel"] = _sample_max_autonomy(rng, posture)
            NODES[idx]["properties"]["name"] = f"AIAgent_{agent_type}_{NODES[idx]['properties']['name']}"
            AI_AGENT_NODE_INDICES.append(idx)
            NODE_GROUPS["AIAgent"].append(idx)

        # On-prem: 45% distributed across domains
        n_onprem_total = round(total_generic * 0.45)
        n_per_domain = max(1, n_onprem_total // max(1, len(domains)))

    for domain in domains:
        aa_ids = []
        for i in range(n_per_domain):
            aa_ids.append(
                _create_automation_account(
                    i, domain["name"], domain["sid"], rng
                )
            )
        aa_by_domain[domain["name"]] = aa_ids

    # Cross-tenant pool
    cross_pool = _create_cross_tenant_pool(total_generic, tenants, rng)

    # --------------------------------------------------------
    # AI Agent relationship edges (Week 4)
    # --------------------------------------------------------
    rng_edges = random.Random(seed ^ 0xA1A1A1)

    orch_edges = create_agent_orchestration_edges(sp_by_tenant, rng_edges)
    deleg_edges = 0  # called externally after Phase 5 when AZUser nodes exist
    tool_edges = create_tool_access_edges(sp_by_tenant, rng_edges)

    return {
        "sp_by_tenant":       sp_by_tenant,
        "mi_by_tenant":       mi_by_tenant,
        "aa_by_domain":       aa_by_domain,
        "cross_pool":         cross_pool,
        "total_generic":      total_generic,
        "ai_agents":          list(AI_AGENT_NODE_INDICES),
        "orchestrates_edges": orch_edges,
        "delegates_to_edges": deleg_edges,
        "tool_access_edges":  tool_edges,
    }