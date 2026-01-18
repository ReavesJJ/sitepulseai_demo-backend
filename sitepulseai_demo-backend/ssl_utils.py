# ssl_utils.py
# SSL inspection utilities for SitePulseAI

import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse

from ssl_state import set_ssl_state, set_renewal_mode


def check_ssl_validity(url: str) -> dict:
    """
    Check SSL certificate validity for a given URL.
    Returns a consistent dict structure required by main.py.
    """
    try:
        parsed = urlparse(url if url.startswith("http") else f"https://{url}")
        hostname = parsed.hostname

        if not hostname:
            raise ValueError("Invalid hostname")

        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        issuer = dict(x[0] for x in cert.get("issuer", []))
        issued_by = issuer.get("organizationName")

        expires_raw = cert.get("notAfter")
        expires_at = datetime.strptime(
            expires_raw, "%b %d %H:%M:%S %Y %Z"
        )

        days_remaining = (expires_at - datetime.utcnow()).days
        valid = days_remaining > 0

        return {
            "valid": valid,
            "status": "Valid" if valid else "Expired",
            "issuer": issued_by,
            "expires_at": expires_at.isoformat(),
            "days_remaining": days_remaining,
        }

    except Exception as e:
        return {
            "valid": False,
            "status": "Error",
            "issuer": None,
            "expires_at": None,
            "days_remaining": None,
            "error": str(e),
        }


def update_ssl_state(domain: str) -> dict:
    """
    Check SSL status and persist it using ssl_state.
    """
    ssl_status = check_ssl_validity(domain)

    set_ssl_state(
        domain=domain,
        ssl_valid=ssl_status.get("valid"),
        issuer=ssl_status.get("issuer"),
        expires_at=ssl_status.get("expires_at"),
        days_remaining=ssl_status.get("days_remaining"),
    )

    return ssl_status


def enable_auto_renewal(domain: str) -> dict:
    """
    Enable automatic SSL renewal mode.
    """
    set_renewal_mode(domain, "auto")

    return {
        "domain": domain,
        "auto_renewal": True,
        "status": "enabled",
    }


def disable_auto_renewal(domain: str) -> dict:
    """
    Disable automatic SSL renewal mode.
    """
    set_renewal_mode(domain, "manual")

    return {
        "domain": domain,
        "auto_renewal": False,
        "status": "disabled",
    }
