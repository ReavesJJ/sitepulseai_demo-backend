import socket
import ssl
import requests
import time
from datetime import datetime
from bs4 import BeautifulSoup
# monitoring_registry.py
import time

MONITORED_DOMAINS = {}

def add_domain(domain: str):
    MONITORED_DOMAINS[domain] = time.time()

def remove_domain(domain: str):
    MONITORED_DOMAINS.pop(domain, None)

def get_domains():
    return list(MONITORED_DOMAINS.keys())


# 1) SSL CHECK
def check_ssl_state(domain: str):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_remaining = (not_after - datetime.utcnow()).days

        return {
            "status": "Valid" if days_remaining > 0 else "Invalid",
            "days_remaining": days_remaining,
            "issuer": dict(x[0] for x in cert["issuer"]).get("organizationName"),
            "expires_at": not_after.isoformat()
        }

    except Exception as e:
        return {
            "status": "Invalid",
            "days_remaining": None,
            "error": str(e)
        }


# 2) UPTIME CHECK
def check_uptime(url: str):
    try:
        r = requests.get(url, timeout=5)
        return {
            "status": "Online",
            "http_status": r.status_code,
            "checked_at": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "status": "Offline",
            "error": str(e),
            "checked_at": datetime.utcnow().isoformat()
        }


# 3) RESPONSE TIME
def check_response_time(url: str):
    try:
        start = time.time()
        r = requests.get(url, timeout=5)
        latency_ms = int((time.time() - start) * 1000)

        return {
            "latency_ms": latency_ms
        }

    except Exception as e:
        return {
            "latency_ms": None,
            "error": str(e)
        }


# 4) BASIC VULNERABILITY SIGNALS
def scan_headers(url: str):
    try:
        r = requests.get(url, timeout=5)

        headers = r.headers
        missing = []

        required = [
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Content-Security-Policy"
        ]

        for h in required:
            if h not in headers:
                missing.append(h)

        return {
            "uses_https": url.startswith("https://"),
            "missing_headers_count": len(missing),
            "missing_headers": missing
        }

    except Exception as e:
        return {
            "error": str(e)
        }


# 5) SEO SIGNALS
def scan_seo(url: str):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")

        title = soup.title.string.strip() if soup.title else None
        meta_desc_tag = soup.find("meta", attrs={"name": "description"})
        meta_desc = meta_desc_tag["content"].strip() if meta_desc_tag else None
        h1_tag = soup.find("h1")

        robots_url = url.rstrip("/") + "/robots.txt"
        robots_ok = False
        try:
            rr = requests.get(robots_url, timeout=5)
            robots_ok = rr.status_code == 200
        except:
            robots_ok = False

        return {
            "title_length": len(title) if title else 0,
            "meta_description_present": bool(meta_desc),
            "h1_present": bool(h1_tag),
            "robots_txt_found": robots_ok
        }

    except Exception as e:
        return {
            "error": str(e)
        }
    

    
