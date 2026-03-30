import copy
import sys
import warnings

def update_DATABASE_ID(label, NODES_index):
    identifiers = ["name", "objectid"]
    for identifier in identifiers:
        if identifier in NODES[NODES_index]["properties"]:
            check_data = NODES[NODES_index]["properties"][identifier]
            if identifier == "name":
                check_data += "_" + label

            if check_data not in DATABASE_ID[identifier]:
                DATABASE_ID[identifier][check_data] = NODES_index

def node_operation(label, keys, values, id_lookup, identifier = "objectid", is_domain = False):
    global neo4j_id
    NODES_index = -1
    new_node = dict()

    if identifier == "name":
        id_lookup += "_" + label

    if id_lookup in DATABASE_ID[identifier]:
        NODES_index = DATABASE_ID[identifier][id_lookup]
    else:
        if not is_domain:
            new_node = copy.deepcopy(AD_NODE)
        else:
            new_node = copy.deepcopy(AD_NODE_ADMIN)

        NODES_index = len(NODES)
        NODES.append(new_node)
        DATABASE_ID[identifier][id_lookup] = NODES_index
        NODE_GROUPS[label].append(NODES_index)
        NODES[NODES_index]["id"] = str(neo4j_id)
        neo4j_id += 1

    for i in range(len(keys)):
        if keys[i] == "labels":
            if values[i] not in NODES[NODES_index][keys[i]]:
                NODES[NODES_index][keys[i]].append(values[i])
        else:
            NODES[NODES_index]["properties"][keys[i]] = values[i]

    if label == "User" or "Computer":
        NODES[NODES_index]["properties"]["owned"] = False

    update_DATABASE_ID(label, NODES_index)

    return NODES_index

def edge_operation(start_index, end_index, relationship_type, props = [], values = []):
    hashed_id_edge = str(start_index) + relationship_type + str(end_index)
    EDGES_index = -1
    new_edge = dict()

    if hashed_id_edge not in dict_edges:
        new_edge = copy.deepcopy(AD_EDGE)
        EDGES_index = len(EDGES)
        EDGES.append(new_edge)
        dict_edges[hashed_id_edge] = EDGES_index
        EDGES[EDGES_index]["id"] = "r_" + str(EDGES_index)
        EDGES[EDGES_index]["label"] = relationship_type

        EDGES[EDGES_index]["start"]["id"] = NODES[start_index]["id"]
        EDGES[EDGES_index]["start"]["labels"] = NODES[start_index]["labels"]
        EDGES[EDGES_index]["end"]["id"] = NODES[end_index]["id"]
        EDGES[EDGES_index]["end"]["labels"] = NODES[end_index]["labels"]

        if NODES[start_index]["labels"][-1] == "GPO" and NODES[end_index]["labels"][-1] == "OU":
            GPLINK_OUS.append(end_index)

    else:
        EDGES_index = dict_edges[hashed_id_edge]

    for i in range(len(props)):
        if isinstance(values[i], (dict, list)):
            import json
            EDGES[EDGES_index]["properties"][props[i]] = json.dumps(values[i])
        else:
            EDGES[EDGES_index]["properties"][props[i]] = values[i]

def get_node_index(id_lookup, identifier):
    if id_lookup in DATABASE_ID[identifier]:
        return DATABASE_ID[identifier][id_lookup]

    warnings.simplefilter('error', UserWarning)
    warnings.warn(f"Node not exisit: {id_lookup} - {identifier}")
    return -1


# ============================================================
# Core graph storage — unchanged from original
# ============================================================

NODES = []
EDGES = []

neo4j_id = 0

DATABASE_ID = {
    "name": dict(),
    "objectid": dict()
}

dict_edges = dict()

AD_NODE = {
    "id":"",
    "labels":["Base"],
    "properties": {
    }
}

AD_NODE_ADMIN = {
    "id":"",
    "labels":[],
    "properties": {
    }
}

AD_EDGE = {
    "type": "relationship",
    "id": "",
    "label": "",
    "properties": {},
    "start": {},
    "end": {}
}

# ============================================================
# NODE_GROUPS — extended with hybrid node types
# ============================================================

NODE_GROUPS = {
    # --- Original on-prem types ---
    "User": list(),
    "Computer": list(),
    "GPO": list(),
    "Group": list(),
    "Domain": list(),
    "OU": list(),
    "Container": list(),

    # --- Original Azure types ---
    "AZUser": list(),
    "AZGroup": list(),
    "AZTenant": list(),
    "AZSubscription": list(),
    "AZRole": list(),
    "AZServicePrincipal": list(),
    "AZApp": list(),
    "AZManagementGroup": list(),
    "AZKeyVault": list(),
    "AZVM": list(),

    # --- NEW: Hybrid seam node types (Week 1-3 merge) ---
    "SyncIdentity": list(),       # Per-link sync principal (paper core contribution)
    "ConnectorHost": list(),      # Entra Connect Sync server
    "PTAAgentHost": list(),       # PTA agent server
    "ADFSServer": list(),         # AD FS server

    # --- NEW: Typed NonHumanIdentity subtypes (Week 3 merge) ---
    "ManagedIdentity": list(),    # Azure managed identity
    "AutomationAccount": list(),  # On-prem automation account

    # --- NEW: AI Agent tracking (Week 4 extension) ---
    # AI agents are ServicePrincipals with isAIAgent=True
    # Node label in graph stays AZServicePrincipal
    # AIAgent here is a logical tracking group for metrics/invariants
    "AIAgent": list(),
}

# ============================================================
# Original tracking structures — unchanged
# ============================================================

GPLINK_OUS = []
GROUP_MEMBERS = dict()
SECURITY_GROUPS = list()
ADMIN_USERS = list()
ENABLED_USERS = list()
DISABLED_USERS = list()
PAW_TIERS = list()
S_TIERS = list()
S_TIERS_LOCATIONS = list()
WS_TIERS = list()
WS_TIERS_LOCATIONS = list()
COMPUTERS = list()
ridcount = list()
KERBEROASTABLES = list()
FOLDERS = list()
DISTRIBUTION_GROUPS = list()
SEC_DIST_GROUPS = list()
LOCAL_ADMINS = list()

# ============================================================
# NEW: Hybrid tracking structures (not in original DATABASE.py)
# ============================================================

# List of (domain_name, tenant_id) tuples representing every sync link
SYNC_LINKS = []

# Maps (domain_name, tenant_id) -> node_index of SyncIdentity node
# Key invariant: exactly one entry per sync link
SYNC_IDENTITY_NODES = {}

# Maps tenant_id -> list of ConnectorHost node indices
CONNECTOR_HOST_NODES = {}

# Maps tenant_id -> list of PTAAgentHost node indices
PTA_AGENT_NODES = {}

# Maps tenant_id -> list of ADFSServer node indices
ADFS_SERVER_NODES = {}

# Maps tenant_id -> hybrid mode string: "PHS" | "PTA" | "ADFS" | "Mixed"
TENANT_HYBRID_MODE = {}

# Maps domain_name -> list of tenant_ids it syncs to
DOMAIN_TENANT_MAPPING = {}

# List of all NonHumanIdentity node indices (SyncIdentity, SP, MI, AA)
NHI_NODE_INDICES = []

# List of AI Agent node indices (subset of NHI_NODE_INDICES)
# These are ServicePrincipals with isAIAgent=True
AI_AGENT_NODE_INDICES = []

# Maps tenant_id -> {"posture": str, "orgType": str}
TENANT_METADATA = {}

# The run identifier for reproducibility — set at generation start
RUN_ID = ""


# ============================================================
# reset_DB — extended to clear new structures
# ============================================================

def reset_DB():
    NODES.clear()
    EDGES.clear()

    for item in DATABASE_ID:
        DATABASE_ID[item].clear()

    dict_edges.clear()

    for item in NODE_GROUPS:
        NODE_GROUPS[item].clear()

    GPLINK_OUS.clear()
    GROUP_MEMBERS.clear()
    SECURITY_GROUPS.clear()
    ADMIN_USERS.clear()
    ENABLED_USERS.clear()
    DISABLED_USERS.clear()
    PAW_TIERS.clear()
    S_TIERS.clear()
    WS_TIERS.clear()
    COMPUTERS.clear()
    ridcount.clear()
    KERBEROASTABLES.clear()

    # NEW: clear hybrid tracking structures
    SYNC_LINKS.clear()
    SYNC_IDENTITY_NODES.clear()
    CONNECTOR_HOST_NODES.clear()
    PTA_AGENT_NODES.clear()
    ADFS_SERVER_NODES.clear()
    TENANT_HYBRID_MODE.clear()
    DOMAIN_TENANT_MAPPING.clear()
    NHI_NODE_INDICES.clear()
    AI_AGENT_NODE_INDICES.clear()
    TENANT_METADATA.clear()

    global RUN_ID
    RUN_ID = ""