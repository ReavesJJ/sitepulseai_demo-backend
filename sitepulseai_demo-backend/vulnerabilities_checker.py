import random

def scan_vulnerabilities(domain: str):
    """
    Minimal stub: simulate port/vulnerability scan
    """
    # Simulate some open ports
    open_ports = random.sample([21, 22, 23, 80, 443, 3306, 8080], k=random.randint(0, 3))
    return {
        "domain": domain,
        "ports": {"open_ports": open_ports},
        "status": "ok" if not open_ports else "warn"
    }
