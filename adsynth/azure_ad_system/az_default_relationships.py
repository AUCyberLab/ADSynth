from adsynth.DATABASE import NODES, EDGES
from adsynth.utils.parameters import get_int_param_value, get_perc_param_value
import random

def az_assign_group_memberships(groups, users, params):

    n_members_per_group = get_int_param_value("AZGroup", "nMembersPerGroup", params)

    for group_id in groups:
        num_members = random.randint(n_members_per_group[0], n_members_per_group[1])
        for user_id in random.sample(users, min(num_members, len(users))):
            EDGES.append({
                "source": user_id,
                "target": group_id,
                "type": "AZMemberOf",
                "labels": ["AZMemberOf"]
            })

def az_assign_roles(users, groups, service_principals, roles, tenant_id, subscription_id, params):

    assign_chance_users = get_perc_param_value("AZRole", "assignChanceUsers", params)
    assign_chance_groups = get_perc_param_value("AZRole", "assignChanceGroups", params)
    assign_chance_sps = get_perc_param_value("AZRole", "assignChanceServicePrincipals", params)
    overprivileged_users = get_perc_param_value("AZMisconfig", "overprivileged_users", params)

    # Node schema is mid-migration: tenant nodes use node_operation() (properties.*)
    # while role and user nodes still write flat top-level keys. Handle both.
    def _name(n): return n.get("name") or n.get("properties", {}).get("name")
    def _objid(n): return n.get("id") or n.get("objectid") or n.get("properties", {}).get("objectid")

    global_admin_role = next(
        (r for r in roles if any(_name(n) == "Global Administrator" and _objid(n) == r for n in NODES)),
        None,
    )
    global_admin_user = next(
        (u for u in users if any(_name(n) == "Global Admin" and _objid(n) == u for n in NODES)),
        None,
    )
    # Assign roles to users (excluding the default Global Admin user)
    for user_id in [u for u in users if u != global_admin_user]:
        if random.random() * 100 < assign_chance_users:
            role_id = random.choice([r for r in roles if r != global_admin_role])
            scope = subscription_id  # Contributor, Reader use subscription scope
            EDGES.append({
                "source": user_id,
                "target": role_id,
                "type": "AZHasRole",
                "labels": ["AZHasRole"],
                "scope": scope
            })

    # Assign Global Administrator to the overprivileged users (excluding the default Global Admin user)
    eligible_users = [u for u in users if u != global_admin_user]
    num_overprivileged = min(int(len(users) * (overprivileged_users / 100)), len(eligible_users))
    for user_id in random.sample(eligible_users, num_overprivileged):
        if global_admin_role:
            EDGES.append({
                "source": user_id,
                "target": global_admin_role,
                "type": "AZHasRole",
                "labels": ["AZHasRole"],
                "scope": tenant_id  # Global Administrator uses tenant scope
            })

    # Assign roles to groups
    for group_id in groups:
        if random.random() * 100 < assign_chance_groups:
            role_id = random.choice(roles)
            scope = tenant_id if role_id == global_admin_role else subscription_id
            EDGES.append({
                "source": group_id,
                "target": role_id,
                "type": "AZHasRole",
                "labels": ["AZHasRole"],
                "scope": scope
            })

    # Assign roles to service principals
    for sp_id in service_principals:
        if random.random() * 100 < assign_chance_sps:
            role_id = random.choice([r for r in roles if r != global_admin_role])
            EDGES.append({
                "source": sp_id,
                "target": role_id,
                "type": "AZHasRole",
                "labels": ["AZHasRole"],
                "scope": subscription_id
            })

    return len(EDGES)