"""
Hybrid Identity Graph — Default Configuration (Θ)
==================================================
Defines the configuration object Θ described in the paper.

Θ controls:
  - Domain topology (number of domains, trust relationships)
  - Tenant topology (number of tenants per domain, sync modes)
  - Principal counts (users, groups, SPs, MIs, AutomationAccounts)
  - Non-human identity parameters (ownerType distribution, lifecycle distribution)
  - Sync mode distribution per domain-tenant pair
  - Multi-tenant options (single domain → multiple tenants)

This module also provides helpers to load Θ from JSON or environment variables.
"""

import json
import os
from typing import Any, Dict, List, Optional

# Default configuration Θ

DEFAULT_HYBRID_CONFIG: Dict[str, Any] = {

    

    # Domain topology 
    "Domain": {
        "nDomains": 1,                        # Number of AD domains to generate
        "nDomainTrusts": 0,                   # DOMAIN_TRUSTS edges between domains
        "domainNamePrefix": "corp",           # e.g. corp.local, corp2.local …
        "domainSuffix": "local",
    },

    # Tenant topology 
    "Tenant": {
        "nTenantsPerDomain": 1,               # Per paper: multi-tenant = 1 domain → N tenants
        "tenantNamePrefix": "contoso",        # e.g. contoso.onmicrosoft.com
    },

    # Sync mode distribution 
    # For each domain-tenant SYNC_LINK, pick mode according to this distribution.
    # Values must sum to 100.
    "SyncMode": {
        "PHS":  60,   # Password Hash Sync (most common)
        "PTA":  20,   # Pass-Through Authentication
        "ADFS": 10,   # Active Directory Federation Services
        "Mixed": 10,  # Multiple modes simultaneously
    },

    # User principal counts ─
    "User": {
        "nUsers": 100,           # On-prem AD users
        "syncPercentage": 80,    # % of AD users synced to Entra (via SYNCED_TO)
        "enabled": 90,           # % of users that are enabled
    },

    # Group principal counts 
    "Group": {
        "nADGroups": 20,           # On-prem AD security groups
        "nEntraGroups": 10,        # Entra ID (AzureADGroup) cloud groups
    },

    # Non-human identity counts 
    "NonHumanIdentity": {
        # ServicePrincipal: cloud app registrations
        "nServicePrincipals": 5,

        # ManagedIdentity: Azure-managed identities
        "nManagedIdentities": 3,
        "miTypeDistribution": {
            "SystemAssigned": 70,
            "UserAssigned": 30,
        },

        # AutomationAccount: on-prem automation (scripts, pipelines)
        "nAutomationAccounts": 2,
        "automationKindDistribution": {
            "service": 40,
            "scheduled-task": 30,
            "deployment": 20,
            "script": 10,
        },

        # ownerType distribution (shared across all NHI subtypes)
        "ownerTypeDistribution": {
            "Team":    60,
            "System":  30,
            "Unknown": 10,
        },

        # lifecycle distribution (shared across all NHI subtypes)
        "lifecycleDistribution": {
            "LongLived":  75,
            "Ephemeral":  25,
        },
    },

    # ── Server topology 
    # How many servers of each role to generate per domain-tenant link.
    "Server": {
        "nDomainControllers": 1,    # Role: DomainController
        "nEntraConnectServers": 1,  # Role: EntraConnect  (required: 1 per SYNC_LINK)
        "nPTAAgentServers": 1,      # Role: PTAAgent      (required if PTA enabled)
        "nADFSServers": 1,          # Role: ADFS          (required if ADFS enabled)
    },

    # ── Attack-path realism ───
    "Misconfig": {
        "percentageSyncedToMultipleTenants": 10,   # % of users synced to >1 tenant
        "percentageNHIWithHighPrivilege": 5,        # % of NHI with HAS_AZ_ROLE to GA
        "percentageOrphanedNHI": 10,               # % of NHI with no clear owner (Unknown)
    },

    
    # ── Output / reproducibility 
    "Output": {
        "format": "jsonl",     # only "jsonl" supported in Week 1
        "outputDir": "generated_datasets",
    },
        "hybrid": {
        "nTenants": 3,
        "p_domain_multisync": 0.15,
        "syncPercentage": 80,
        "syncModeDistribution": {
            "PHS": 60, "PTA": 20, "ADFS": 10, "Mixed": 10
        },
 
        # ── Week 6: Permissions and misconfig knobs ──────────────
        "hybrid_misconfig": {
            # Probability a standard-tier NHI gets any role at all
            "standard_nhi_role_prob": 0.40,
 
            # Max OUs an AutomationAccount can be delegated over
            "max_ous_tier0":    3,
            "max_ous_tier1":    5,
            "max_ous_standard": 2,
 
            # Misconfig injection rates (percentage of eligible NHIs)
            # Orphaned NHI (ownerType=Unknown) -> elevated role
            "orphaned_nhi_perc": 10,
 
            # SyncIdentity -> ADMIN_TO on connector hosts it doesn't own
            "overbroad_sync_perc": 8,
 
            # NHI in one tenant gets role in another tenant
            "cross_tenant_perc": 3,
 
            # Stale credential NHI (rotation > 365 days) -> elevated role
            "long_rotation_perc": 12,
        },}
    
    
}

WEEK6_HYBRID_MISCONFIG_DEFAULTS = {
    "standard_nhi_role_prob": 0.40,
    "max_ous_tier0":    3,
    "max_ous_tier1":    5,
    "max_ous_standard": 2,
    "orphaned_nhi_perc":    10,
    "overbroad_sync_perc":   8,
    "cross_tenant_perc":     3,
    "long_rotation_perc":   12,
}
 


# Merge helpers

def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge override into base.
    Override values take precedence; nested dicts are merged, not replaced.
    """
    result = dict(base)
    for key, val in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(val, dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def load_hybrid_config(json_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load a hybrid configuration from a JSON file, merging with defaults.

    If json_path is None, returns DEFAULT_HYBRID_CONFIG unchanged.
    Unknown keys in the JSON file are preserved (future extensibility).
    """
    if json_path is None:
        return dict(DEFAULT_HYBRID_CONFIG)

    if not os.path.isfile(json_path):
        raise FileNotFoundError(f"Config file not found: {json_path}")

    with open(json_path, "r", encoding="utf-8") as fh:
        user_config = json.load(fh)

    return _deep_merge(DEFAULT_HYBRID_CONFIG, user_config)


def validate_config(config: Dict[str, Any]) -> List[str]:
    """
    Basic structural validation of a configuration dict.
    Returns a list of warning/error strings (empty = all good).
    """
    errors = []

    # SyncMode probabilities must sum to 100
    sync_probs = config.get("SyncMode", {})
    total = sum(sync_probs.get(k, 0) for k in ("PHS", "PTA", "ADFS", "Mixed"))
    if abs(total - 100) > 1:
        errors.append(f"SyncMode probabilities sum to {total}, expected 100")

    # ownerType distribution must sum to 100
    owner_probs = config.get("NonHumanIdentity", {}).get("ownerTypeDistribution", {})
    if owner_probs:
        total = sum(owner_probs.values())
        if abs(total - 100) > 1:
            errors.append(f"ownerTypeDistribution sums to {total}, expected 100")

    # lifecycleDistribution must sum to 100
    lc_probs = config.get("NonHumanIdentity", {}).get("lifecycleDistribution", {})
    if lc_probs:
        total = sum(lc_probs.values())
        if abs(total - 100) > 1:
            errors.append(f"lifecycleDistribution sums to {total}, expected 100")

    # nDomains must be positive
    n_domains = config.get("Domain", {}).get("nDomains", 1)
    if not isinstance(n_domains, int) or n_domains < 1:
        errors.append(f"Domain.nDomains must be a positive integer, got {n_domains!r}")

    # nTenantsPerDomain must be positive
    n_tenants = config.get("Tenant", {}).get("nTenantsPerDomain", 1)
    if not isinstance(n_tenants, int) or n_tenants < 1:
        errors.append(f"Tenant.nTenantsPerDomain must be a positive integer, got {n_tenants!r}")

    return errors


if __name__ == "__main__":
    import json as _json

    cfg = load_hybrid_config()
    errs = validate_config(cfg)
    print("Default config validation:", "PASS" if not errs else f"FAIL: {errs}")
    print("\nDefault config Θ:")
    print(_json.dumps(cfg, indent=2))
