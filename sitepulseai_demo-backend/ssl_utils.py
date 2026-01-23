# ssl_utils.py
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse


def normalize_domain(url_or_domain: str) -> str:
    """
    Accepts full URLs or bare domains and returns a clean hostname.
    """
    parsed = urlparse(url_or_domain)
    return parsed.hostname or url_or_domain.replace("https://", "").replace("http://", "").split("/")[0]


def fetch_ssl_certificate(domain: str) -> dict:
    """
    Fetch raw SSL certificate details for a domain.
    """
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=domain) as sock:
        sock.settimeout(6)
        sock.connect((domain, 443))
        cert = sock.getpeercert()

    return cert


def parse_certificate(cert: dict) -> dict:
    """
    Extract issuer, expiry date, and compute days remaining.
    """
    not_after_str = cert.get("notAfter")
    expires_at = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")

    issuer_parts = cert.get("issuer", [])
    issuer = " ".join("=".join(x) for part in issuer_parts for x in part)

    days_remaining = (expires_at - datetime.utcnow()).days

    return {
        "issuer": issuer,
        "expires_at": expires_at.isoformat(),
        "days_remaining": days_remaining,
        "ssl_valid": days_remaining > 0
    }


def inspect_ssl(domain_or_url: str) -> dict:
    """
    Canonical SSL inspection entrypoint.
    Returns a structured SSL status object.
    """
    domain = normalize_domain(domain_or_url)

    try:
        cert = fetch_ssl_certificate(domain)
        parsed = parse_certificate(cert)

        return {
            "domain": domain,
            "status": "valid" if parsed["ssl_valid"] else "expired",
            **parsed
        }

    except Exception as e:
        return {
            "domain": domain,
            "status": "error",
            "error": str(e),
            "ssl_valid": False,
            "issuer": None,
            "expires_at": None,
            "days_remaining": None
        }
