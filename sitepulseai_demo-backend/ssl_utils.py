# ssl_utils.py
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse


def normalize_domain(url_or_domain: str) -> str:
    """
    Normalize a URL or domain into a bare hostname.
    """
    if not url_or_domain:
        return ""

    if url_or_domain.startswith("http://") or url_or_domain.startswith("https://"):
        parsed = urlparse(url_or_domain)
        return parsed.hostname or url_or_domain

    return url_or_domain.replace("/", "").strip()


def inspect_ssl(domain: str) -> dict:
    """
    Inspect SSL certificate details for a given domain.
    Returns a dict with validity + expiry metadata.
    """
    result = {
        "domain": domain,
        "valid": False,
        "expires_at": None,
        "days_remaining": None,
        "issuer": None,
        "error": None,
        "last_checked_at": datetime.utcnow().isoformat()
    }

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(6)
            s.connect((domain, 443))
            cert = s.getpeercert()

        not_after = cert.get("notAfter")
        if not not_after:
            raise Exception("Certificate missing expiry date")

        expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_remaining = (expires_at - datetime.utcnow()).days

        issuer = None
        if "issuer" in cert:
            issuer = " ".join([x[0][1] for x in cert["issuer"]])

        result.update({
            "valid": True,
            "expires_at": expires_at.isoformat(),
            "days_remaining": days_remaining,
            "issuer": issuer
        })

    except Exception as e:
        result["error"] = str(e)

    return result
