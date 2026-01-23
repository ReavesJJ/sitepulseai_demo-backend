# ssl_utils.py
import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
from typing import Optional, Dict
from ssl_state import update_ssl_observation

# -----------------------------
# Domain Utilities
# -----------------------------
def normalize_domain(url: str) -> str:
    """
    Extracts the hostname from a URL.
    """
    parsed = urlparse(url)
    return parsed.hostname or url

# -----------------------------
# SSL Inspection
# -----------------------------
def inspect_ssl(domain: str, port: int = 443) -> Dict[str, Optional[str]]:
    """
    Returns SSL status and expiry date for a domain.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                update_ssl_observation(domain, ssl_status="valid", expiry_date=expiry_date.isoformat())
                return {
                    "domain": domain,
                    "ssl_status": "valid",
                    "expiry_date": expiry_date.isoformat()
                }
    except Exception:
        # Mark invalid SSL in the state
        update_ssl_observation(domain, ssl_status="invalid")
        return {
            "domain": domain,
            "ssl_status": "invalid",
            "expiry_date": None
        }
