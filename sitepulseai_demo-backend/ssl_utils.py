# ssl_utils.py
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse


def normalize_domain(url_or_domain: str) -> str:
    """
    Normalize input into a bare hostname.
    """
    if not url_or_domain:
        return ""

    parsed = urlparse(url_or_domain)

    if parsed.hostname:
        return parsed.hostname.lower()

    return url_or_domain.replace("https://", "").replace("http://", "").strip("/").lower()


def inspect_ssl(domain: str) -> dict:
    """
    Inspect live SSL certificate and return structured facts.
    """
    domain = normalize_domain(domain)

    result = {
        "domain": domain,
        "valid": False,
        "issuer": None,
        "expiry_date": None,
        "days_remaining": None,
        "error": None,
    }

    try:
        ctx = ssl.create_default_context()

        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(6)
            s.connect((domain, 443))
            cert = s.getpeercert()

        not_after = cert.get("notAfter")
        issuer = cert.get("issuer")

        expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_remaining = (expiry_date - datetime.utcnow()).days

        result.update(
            {
                "valid": True,
                "issuer": str(issuer),
                "expiry_date": expiry_date.isoformat(),
                "days_remaining": days_remaining,
            }
        )

    except Exception as e:
        result["error"] = str(e)

    return result
