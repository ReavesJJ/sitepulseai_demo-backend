from datetime import datetime
import requests
from vulnerabilities import scan_domain as vuln_scan
import ssl
import socket

# -----------------------------
# Uptime + Response
# -----------------------------
def get_metrics(domain):
    try:
        start = datetime.utcnow()
        r = requests.get(f"https://{domain}", timeout=5)
        end = datetime.utcnow()

        response_time = int((end - start).total_seconds() * 1000)

        return {
            "status": "Online" if r.status_code == 200 else "Degraded",
            "response_time_ms": response_time
        }
    except:
        return {
            "status": "Offline",
            "response_time_ms": None
        }

# -----------------------------
# SSL Inspector
# -----------------------------
def get_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            cert = s.getpeercert()

        expires_at = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        days_remaining = (expires_at - datetime.utcnow()).days

        status = "valid"
        if days_remaining <= 0:
            status = "expired"
        elif days_remaining <= 7:
            status = "critical"
        elif days_remaining <= 30:
            status = "warning"

        return {
            "days_remaining": days_remaining,
            "status": status
        }

    except:
        return {
            "days_remaining": None,
            "status": "error"
        }

# -----------------------------
# UNIFIED RISK PIPELINE
# -----------------------------
def build_risk(domain):
    domain = domain.lower().strip()

    metrics = get_metrics(domain)
    ssl_data = get_ssl(domain)
    vuln = vuln_scan(domain)

    counts = vuln.get("counts", {})

    total = sum(counts.values())

    return {
        "domain": domain,
        "status": metrics["status"],
        "response_time_ms": metrics["response_time_ms"],
        "ssl": ssl_data,
        "vulnerabilities": {
            "total": total,
            **counts
        },
        "last_checked": datetime.utcnow().timestamp(),
        "source": vuln.get("source", "live")
    }