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


# ssl_utils.py

import ssl
import socket
from datetime import datetime
from typing import Dict, Any


def fetch_ssl_certificate_info(domain: str) -> Dict[str, Any]:
    """
    Fetch SSL certificate details for a domain.
    Returns a normalized dict used across the platform.
    """

    context = ssl.create_default_context()
    result = {
        "valid": False,
        "expires_in_days": None,
        "issuer": None,
        "not_after": None,
        "error": None,
    }

    try:
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        not_after_str = cert.get("notAfter")
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        expires_in_days = (not_after - datetime.utcnow()).days

        issuer_parts = cert.get("issuer", [])
        issuer = ", ".join("=".join(x) for part in issuer_parts for x in part)

        result.update(
            {
                "valid": expires_in_days > 0,
                "expires_in_days": expires_in_days,
                "issuer": issuer,
                "not_after": not_after_str,
            }
        )

        return result

    except Exception as e:
        result["error"] = str(e)
        return result


import ssl
import socket
from datetime import datetime

def get_ssl_certificate(domain: str) -> dict:
    """
    Fetch SSL certificate details for a domain.
    Returns structured certificate metadata for policy + state layers.
    """

    context = ssl.create_default_context()

    try:
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        not_after = cert.get("notAfter")
        expires_at = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        expires_in_days = (expires_at - datetime.utcnow()).days

        issuer = " ".join(x[0][1] for x in cert.get("issuer", []))
        subject = " ".join(x[0][1] for x in cert.get("subject", []))

        return {
            "domain": domain,
            "valid": True,
            "issuer": issuer,
            "subject": subject,
            "expires_at": expires_at.isoformat(),
            "expires_in_days": expires_in_days,
            "raw": cert,
        }

    except Exception as e:
        return {
            "domain": domain,
            "valid": False,
            "error": str(e),
        }
