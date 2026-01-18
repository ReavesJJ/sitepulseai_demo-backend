# ssl_state.py
# Centralized SSL state management for SitePulseAI

from datetime import datetime
from typing import Dict, Optional

# In-memory SSL state store (can be replaced with Redis / DB later)
_ssl_state_store: Dict[str, dict] = {}


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
        "renewal_mode": "auto",  # auto | assisted | manual
        "last_checked": None,
        "last_renewed_by": None,
        "last_renewed_at": None,
    })


def set_ssl_state(
    domain: str,
    ssl_valid: bool,
    issuer: Optional[str] = None,
    expires_at: Optional[str] = None,
    days_remaining: Optional[int] = None
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
        "last_checked": datetime.utcnow().isoformat()
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


def mark_assisted_renewal(domain: str) -> dict:
    """
    Mark a domain as renewed by SitePulseAI assistance.
    """
    state = get_ssl_state(domain)

    state.update({
        "renewal_mode": "assisted",
        "last_renewed_by": "SitePulseAI",
        "last_renewed_at": datetime.utcnow().isoformat()
    })

    _ssl_state_store[domain] = state
    return state


def reset_ssl_state(domain: str) -> dict:
    """
    Clear SSL tracking data for a domain.
    """
    _ssl_state_store.pop(domain, None)
    return {"domain": domain, "status": "reset"}
