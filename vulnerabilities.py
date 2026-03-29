# sitepulseai_demo-backend/vulnerabilities.py

import requests
import ssl
import socket
from datetime import datetime
import json
from pathlib import Path
import asyncio



def get_vulnerabilities_data(domain: str):
    # Your logic to fetch vulnerability info
    return {"domain": domain, "vulnerabilities": []}


CACHE_FILE = Path("vuln_cache.json")

# -----------------------------
# Cache Helpers
# -----------------------------
def load_cache():
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_cache(cache):
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f)
    except Exception:
        pass

# -----------------------------
# Findings Summary
# -----------------------------
def summarize_findings(findings):
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f.get("severity", "").lower()
        if sev in summary:
            summary[sev] += 1
    return summary

# -----------------------------
# SSL / TLS Scan
# -----------------------------
def scan_ssl(domain: str):
    findings = []
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3.0)
            s.connect((domain, 443))
            cert = s.getpeercert()
        expires_at = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        days_remaining = (expires_at - datetime.utcnow()).days

        if days_remaining <= 0:
            findings.append({"type": "SSL certificate expired", "severity": "Critical"})
        elif days_remaining <= 7:
            findings.append({"type": f"SSL expires in {days_remaining} days", "severity": "High"})
    except Exception:
        findings.append({"type": "SSL inspection failed", "severity": "High"})

    return findings

# -----------------------------
# HTTP Header Scan
# -----------------------------
def scan_headers(domain: str):
    findings = []
    try:
        response = requests.get(f"https://{domain}", timeout=5, allow_redirects=True)
        headers = response.headers

        if "X-Frame-Options" not in headers:
            findings.append({"type": "X-Frame-Options missing", "severity": "Medium"})
        if "Content-Security-Policy" not in headers:
            findings.append({"type": "Content-Security-Policy missing", "severity": "High"})
        if "Strict-Transport-Security" not in headers:
            findings.append({"type": "HSTS not enforced", "severity": "High"})
        if "X-Content-Type-Options" not in headers:
            findings.append({"type": "X-Content-Type-Options missing", "severity": "Low"})
        if "Referrer-Policy" not in headers:
            findings.append({"type": "Referrer-Policy missing", "severity": "Low"})
    except Exception:
        findings.append({"type": "Header inspection failed", "severity": "Medium"})

    return findings

# -----------------------------
# Unified Scan + Cache (Async-Friendly)
# -----------------------------
async def scan_domain(domain: str, license_level: str = "free"):
    domain = domain.lower().strip()
    cache = load_cache()

    # Return cached if available
    if domain in cache:
        cached = cache[domain]
        # Add risk_score if missing
        if "risk_score" not in cached:
            counts = cached.get("counts", {})
            cached["risk_score"] = (
                counts.get("critical", 0) * 5 +
                counts.get("high", 0) * 3 +
                counts.get("medium", 0) * 2 +
                counts.get("low", 0) * 1
            )
        return cached

    findings = []

    # Run blocking scans in a separate thread for async safety
    findings_ssl, findings_headers = await asyncio.gather(
        asyncio.to_thread(scan_ssl, domain),
        asyncio.to_thread(scan_headers, domain)
    )
    findings += findings_ssl
    findings += findings_headers

    # Optionally: license-gated deep scans could go here

    counts = summarize_findings(findings)
    risk_score = (
        counts.get("critical", 0) * 5 +
        counts.get("high", 0) * 3 +
        counts.get("medium", 0) * 2 +
        counts.get("low", 0) * 1
    )

    result = {
        "domain": domain,
        "findings": findings,
        "counts": counts,
        "risk_score": risk_score
    }

    # Cache for offline / fast reload
    cache[domain] = result
    save_cache(cache)

    return result




import random

def check_uptime(domain):
    # Replace with real uptime monitoring
    return "Online" if random.random() > 0.05 else "Offline"

def check_response_time(domain):
    # Replace with real HTTP ping logic
    return round(random.uniform(100, 500), 2)  # ms

def check_seo(domain):
    return random.randint(40, 90)

def check_ssl(domain):
    return {
        "status": "Valid",
        "managed": True,
        "expires_in_days": 66
    }

def check_traffic(domain):
    return random.randint(500, 5000)  # example visits

def check_vulnerabilities(domain):
    # Replace with real scan
    return ["XSS", "SQLi"] if random.random() > 0.5 else []




