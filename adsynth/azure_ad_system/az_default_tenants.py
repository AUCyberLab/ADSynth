import uuid
from adsynth.DATABASE import node_operation, NODE_GROUPS, TENANT_METADATA, RUN_ID


def az_create_tenant(tenant_name):

    tenant_id = str(uuid.uuid4()).upper()

    # Pull metadata if pre-populated by do_generate_hybrid_v2
    meta = TENANT_METADATA.get(tenant_id, {})

    keys = [
        "labels", "name", "objectid", "displayName",
        "plane", "runId",
        "orgType", "posture",
    ]
    values = [
        "AZTenant", tenant_name, tenant_id, tenant_name,
        "Entra", RUN_ID,
        meta.get("orgType", "parent"),
        meta.get("posture", "average"),
    ]

    # node_operation writes to NODES and updates DATABASE_ID["objectid"]
    # so get_node_index(tenant_id, "objectid") will work after this call
    node_operation("AZTenant", keys, values, tenant_id)

    return tenant_id