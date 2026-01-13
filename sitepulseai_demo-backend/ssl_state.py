# ssl_state.py
# Centralized SSL state handling for SitePulseAI

from datetime import datetime


def mark_assisted_renewal(domain: str, renewed: bool = True) -> dict:
    """
    Marks a domain as having been renewed with assistance.
    """
    return {
        "domain": domain,
        "assisted_renewal": renewed
    }



# ssl_state.py
def load_ssl_state():


    ...


# ssl_state.py

def update_ssl_state(domain: str, ssl_info: dict) -> dict:
    """
    Updates SSL state for a domain.
    """
    return {
        "domain": domain,
        "status": ssl_info.get("status", "unknown"),
        "issuer": ssl_info.get("issuer"),
        "expires_at": ssl_info.get("expires_at"),
    }


# In-memory store (can later be swapped for Redis / DB)
_ssl_state_store = {}


def get_ssl_state(domain: str) -> dict:
    """
    Retrieve SSL state information for a domain.
    Returns defaults if domain not yet tracked.
    """
    return _ssl_state_store.get(domain, {
        "domain": domain,
        "ssl_valid": None,
        "issuer": None,
        "expires_at": None,
        "days_remaining": None,
        "renewal_mode": "auto",
        "last_checked": None,
    })


def set_ssl_state(
    domain: str,
    ssl_valid: bool,
    issuer: str = None,
    expires_at: str = None,
    days_remaining: int = None
) -> dict:
    """
    Update SSL scan results for a domain.
    """
    state = get_ssl_state(domain)

    state.update({
        "ssl_valid": ssl_valid,
        "issuer": issuer,
        "expires_at": expires_at,
        "days_remaining": days_remaining,
        "last_checked": datetime.utcnow().isoformat(),
    })

    _ssl_state_store[domain] = state
    return state


def set_renewal_mode(domain: str, mode: str) -> dict:
    """
    Set SSL renewal mode.
    Allowed values: auto, assisted, manual
    """
    if mode not in {"auto", "assisted", "manual"}:
        raise ValueError("Invalid renewal mode")

    state = get_ssl_state(domain)
    state["renewal_mode"] = mode
    _ssl_state_store[domain] = state

    return state
