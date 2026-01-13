
from datetime import datetime

# ssl_utils.py
import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
from ssl_state import set_ssl_state

from ssl_state import (
    get_ssl_state,
    set_ssl_state,
    set_renewal_mode,
)



def check_ssl_validity(domain: str) -> dict:
    """
    Checks SSL certificate validity for a domain.
    Returns structured SSL status data.
    """
    context = ssl.create_default_context()

    try:
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        not_after = cert.get("notAfter")
        expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_remaining = (expiry_date - datetime.utcnow()).days

        status = {
            "domain": domain,
            "valid": True,
            "expires_on": expiry_date.isoformat(),
            "days_remaining": days_remaining,
        }

    except Exception as e:
        status = {
            "domain": domain,
            "valid": False,
            "error": str(e),
        }

    return status


def update_ssl_state(domain: str) -> dict:
    """
    Checks SSL status and persists it to ssl_state.
    """
    ssl_status = check_ssl_validity(domain)

    current_state = get_ssl_state()
    current_state[domain] = ssl_status

    set_ssl_state(current_state)

    return ssl_status


def enable_auto_renewal(domain: str) -> dict:
    """
    Enables SSL auto-renewal mode for a domain.
    """
    set_renewal_mode(domain, enabled=True)

    return {
        "domain": domain,
        "auto_renewal": True,
        "status": "enabled",
    }


def disable_auto_renewal(domain: str) -> dict:
    """
    Disables SSL auto-renewal mode for a domain.
    """
    set_renewal_mode(domain, enabled=False)

    return {
        "domain": domain,
        "auto_renewal": False,
        "status": "disabled",
    }