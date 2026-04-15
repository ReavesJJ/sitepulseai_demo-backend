import os
from generate_certificate import generate_certificate
from datetime import datetime

# =========================
# Tenant Registry (Memory-based for now)
# =========================

TENANT_REGISTRY = {}


def register_tenant(client_id, domains):
    """
    Registers a client and their domains in the monitoring system
    """
    TENANT_REGISTRY[client_id] = {
        "domains": domains,
        "created_at": datetime.utcnow().isoformat()
    }

    print(f"[ROUTER] Tenant registered: {client_id}")
    print(f"[ROUTER] Domains: {len(domains)}")


# =========================
# Monitoring Router Core
# =========================

def route_monitoring_event(client_id):
    """
    Routes all domains under a tenant into the certificate generator
    """

    if client_id not in TENANT_REGISTRY:
        raise Exception("Tenant not registered")

    domains = TENANT_REGISTRY[client_id]["domains"]

    print(f"\n[ROUTER] Starting monitoring cycle for: {client_id}")
    print(f"[ROUTER] Domains detected: {len(domains)}")

    results = []

    for domain in domains:

        print(f"\n[ROUTER] Processing domain: {domain}")

        # Call your EXISTING system (no logic changes)
        result = generate_certificate(domain)

        results.append({
            "domain": domain,
            "status": "processed"
        })

    print("\n[ROUTER] Monitoring cycle complete")

    return results


# =========================
# Example Execution
# =========================

if __name__ == "__main__":

    # Example: 25–100 domains client simulation
    client_id = "CLIENT_ALPHA"

    domains = [
        "sitepulseai.com",
        "example.com",
        "testsite.org",
        "demoapp.io"
    ]

    register_tenant(client_id, domains)

    route_monitoring_event(client_id)