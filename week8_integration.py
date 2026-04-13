#===============================================
# Standalone runner — computes metrics from an existing
# generated JSON file (for post-hoc analysis)
# ============================================================

import json
import os
import sys

def run_metrics_standalone(json_path: str) -> None:
    """
    Load a generated hybrid_v2_*.json file into the DATABASE and
    run the seam metrics on it.

    Usage:
        python week8_integration.py generated_datasets/hybrid_v2_2026-04-06_18-49-45-760.json
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    from adsynth.DATABASE import NODES, EDGES, NODE_GROUPS, reset_DB
    from adsynth.hybrid_system.seam_metrics import (
        compute_seam_metrics, print_seam_metrics_report, export_metrics_json
    )

    reset_DB()

    # Load nodes and edges from the JSON file
    with open(json_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if obj.get("type") == "node":
                obj.pop("type", None)
                NODES.append(obj)
                # Rebuild NODE_GROUPS
                labels = obj.get("labels", [])
                if labels:
                    lbl = labels[-1]
                    if lbl not in NODE_GROUPS:
                        NODE_GROUPS[lbl] = []
                    NODE_GROUPS[lbl].append(len(NODES) - 1)
            elif obj.get("type") == "relationship":
                obj.pop("type", None)
                EDGES.append(obj)

    print(f"Loaded: {len(NODES)} nodes, {len(EDGES)} edges from {json_path}")

    # Reconstruct minimal domains/tenants lists from graph
    domains = []
    tenants = []
    for n in NODES:
        labels = n.get("labels", [])
        if not labels:
            continue
        lbl = labels[-1]
        props = n.get("properties", n)
        if lbl == "Domain":
            domains.append({
                "name": props.get("name", "unknown"),
                "id":   props.get("objectid", ""),
                "sid":  props.get("objectid", ""),
            })
        elif lbl == "AZTenant":
            tenants.append({
                "id":   props.get("objectid", ""),
                "name": props.get("name", ""),
            })

        # Reconstruct SYNC_IDENTITY_NODES
        if lbl == "SyncIdentity":
            from adsynth.DATABASE import SYNC_IDENTITY_NODES
            domain_id = props.get("domainId", "")
            tenant_id = props.get("tenantId", props.get("tenantid", ""))
            if domain_id and tenant_id:
                SYNC_IDENTITY_NODES[(domain_id, tenant_id)] = len(NODES) - 1

    print(f"  Domains: {len(domains)}, Tenants: {len(tenants)}")

    metrics = compute_seam_metrics(domains, tenants)
    print_seam_metrics_report(metrics)
    path = export_metrics_json(metrics)
    print(f"Metrics saved to: {path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python week8_integration.py <path_to_hybrid_v2.json>")
        sys.exit(1)
    run_metrics_standalone(sys.argv[1])