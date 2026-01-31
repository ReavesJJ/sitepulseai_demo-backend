# sitepulseai_demo-backend/vulnerabilities.py
# sitepulseai_demo-backend/vulnerabilities.py

import requests
import ssl
import socket
from datetime import datetime
import json
import os
from pathlib import Path

CACHE_FILE = Path("vuln_cache.json")

# -----------------------------
# Utility Functions
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

def summarize_findings(findings):
    """
    Converts array of findings into severity counts for the card.
    """
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        sev = f["severity"].lower()
        if sev in summary:
            summary[sev] += 1
    return summary

# -----------------------------
# SSL / TLS Scanner
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
# HTTP Header Scanner
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
# Unified Vulnerability Scan
# -----------------------------

def scan_domain(domain: str, license_level: str = "free"):
    """
    Combines SSL + header findings.
    Optional license gating for advanced checks.
    Includes offline caching.
    """
    domain = domain.lower().strip()
    cache = load_cache()

    # Return cached if recent (offline ready)
    if domain in cache:
        return cache[domain]

    findings = []

    # SSL always scanned
    findings += scan_ssl(domain)

    # Header scanning is free tier
    findings += scan_headers(domain)

    # Here you can implement license-gated deep scan
    # Example: if license_level == "pro": findings += deep_scan(domain)

    counts = summarize_findings(findings)

    result = {"domain": domain, "findings": findings, "counts": counts}

    # Cache result for offline use
    cache[domain] = result
    save_cache(cache)

    return result
