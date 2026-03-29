# sitepulseai_demo-backend/vulnerabilities_checkers.py




import socket
import ssl
from datetime import datetime


def get_ssl_expiry(domain: str):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        expiry_str = cert.get('notAfter')
        expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")

        days_remaining = (expiry_date - datetime.utcnow()).days

        if days_remaining < 7:
            risk = "Critical"
        elif days_remaining < 30:
            risk = "Warning"
        else:
            risk = "Healthy"

        return {
            "ssl_expiry": expiry_date.strftime("%Y-%m-%d"),
            "days_remaining": days_remaining,
            "ssl_status": risk
        }

    except Exception as e:
        return {
            "ssl_expiry": None,
            "days_remaining": None,
            "ssl_status": "Unknown",
            "ssl_error": str(e)
        }


async def scan_domain(domain: str):
    findings = []

    # 🔐 SSL CHECK
    ssl_info = get_ssl_expiry(domain)

    # 🔥 Generate vulnerability findings from SSL state
    if ssl_info["ssl_status"] == "Critical":
        findings.append({
            "type": "SSL certificate expiring soon",
            "severity": "Critical"
        })
    elif ssl_info["ssl_status"] == "Warning":
        findings.append({
            "type": "SSL certificate nearing expiration",
            "severity": "Medium"
        })

    # 🔢 Count severities
    counts = {
        "critical": sum(1 for f in findings if f["severity"] == "Critical"),
        "high": sum(1 for f in findings if f["severity"] == "High"),
        "medium": sum(1 for f in findings if f["severity"] == "Medium"),
        "low": sum(1 for f in findings if f["severity"] == "Low"),
    }

    # 🔥 Risk scoring (tuned for visibility)
    risk_score = (
        counts["critical"] * 10 +
        counts["high"] * 7 +
        counts["medium"] * 4 +
        counts["low"] * 1
    )

    total_vulns = len(findings)

    # 🚨 THIS IS THE KEY FIX → match frontend structure
    return {
        "domain": domain,

        # ✅ what your dashboard likely expects
        "vulnerabilities": {
            "findings": findings,
            "counts": counts,
            "risk_score": risk_score,
            "total": total_vulns
        },

        # ✅ keep SSL at top level for SSL card
        "ssl_expiry": ssl_info["ssl_expiry"],
        "days_remaining": ssl_info["days_remaining"],
        "ssl_status": ssl_info["ssl_status"]
    }