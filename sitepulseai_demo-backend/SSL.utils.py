# ssl_utils.py
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

def normalize_domain(url: str) -> str:
    """
    Extracts the hostname from a URL.
    """
    parsed = urlparse(url)
    return parsed.hostname or url.strip()

def check_ssl_validity_and_expiry(domain: str) -> dict:
    """
    Checks SSL validity, issuer, expiry, and days remaining.
    Returns dict with:
    {
        "valid": bool,
        "issuer": str,
        "expires_at": ISO string,
        "days_remaining": int
    }
    """
    hostname = domain.replace("https://", "").replace("http://", "").strip()

    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(6)
            s.connect((hostname, 443))
            cert = s.getpeercert()
    except Exception:
        return {
            "valid": False,
            "issuer": None,
            "expires_at": None,
            "days_remaining": 0
        }

    expires_at_str = cert.get("notAfter")
    expires_at = datetime.strptime(expires_at_str, "%b %d %H:%M:%S %Y %Z")
    days_remaining = (expires_at - datetime.utcnow()).days

    # Extract organizationName from issuer
    issuer = dict(x[0] for x in cert.get("issuer", [])).get("organizationName")

    return {
        "valid": True,
        "issuer": issuer,
        "expires_at": expires_at.isoformat(),
        "days_remaining": days_remaining
    }
