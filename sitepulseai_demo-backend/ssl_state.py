# ssl_state.py
"""
Phase 2A — SSL State Store (Stub / In-Memory)
Locking the persistence contract for the autonomous SSL repair agent.
"""

from datetime import datetime
from typing import Dict, Optional

# ----------------------------
# In-memory state store (Phase 2A stub)
# ----------------------------

_SSL_STATE: Dict[str, Dict] = {}


# ----------------------------
# Core State Accessors
# ----------------------------

def get_ssl_state(domain: str) -> Dict:
    """
    Returns the current SSL state for a domain.
    If no state exists yet, returns a default skeleton.
    """

    state = _SSL_STATE.get(domain)

    if not state:
        state = {
            "domain": domain,
            "ssl_status": None,
            "expiry_date": None,
            "last_checked_at": None,
            "retry_count": 0,
            "last_attempt": None,
            "cooldown_until": None,
            "renewal_mode": "autonomous",  # autonomous | assisted | monitor_only
        }

        _SSL_STATE[domain] = state

    return state


# ----------------------------
# Observation Recorder (used by ssl_automation)
# ----------------------------

def update_ssl_observation(domain: str, ssl_status: str, expiry_date: Optional[str]):
    """
    Records the latest observed SSL status for a domain.

    Contract locked for Phase 2A:
      - domain
      - ssl_status
      - expiry_date
      - last_checked_at

    This function does NOT attempt renewal.
    It only records observed facts.
    """

    now = datetime.utcnow().isoformat()

    state = get_ssl_state(domain)

    state["ssl_status"] = ssl_status
    state["expiry_date"] = expiry_date
    state["last_checked_at"] = now

    _SSL_STATE[domain] = state

    return state


# ----------------------------
# Renewal Mode Controls
# ----------------------------

def set_renewal_mode(domain: str, mode: str) -> Dict:
    """
    Sets renewal mode for a domain.

    Valid modes:
      - autonomous
      - assisted
      - monitor_only
    """

    if mode not in {"autonomous", "assisted", "monitor_only"}:
        raise ValueError("Invalid renewal mode")

    state = get_ssl_state(domain)
    state["renewal_mode"] = mode

    _SSL_STATE[domain] = state

    return state


# ----------------------------
# Assisted Renewal Marker
# ----------------------------

def mark_assisted_renewal(domain: str) -> Dict:
    """
    Marks that a human-approved assisted renewal was triggered.
    This does NOT run certbot yet (Phase 2A stub).
    """

    now = datetime.utcnow().isoformat()

    state = get_ssl_state(domain)

    state["last_attempt"] = now
    state["retry_count"] = state.get("retry_count", 0) + 1

    _SSL_STATE[domain] = state

    return state


# ----------------------------
# Autonomous Attempt Marker
# ----------------------------

def mark_autonomous_attempt(domain: str) -> Dict:
    """
    Records that an autonomous renewal attempt was made.
    """

    now = datetime.utcnow().isoformat()

    state = get_ssl_state(domain)

    state["last_attempt"] = now
    state["retry_count"] = state.get("retry_count", 0) + 1

    _SSL_STATE[domain] = state

    return state


# ----------------------------
# Cooldown Controller
# ----------------------------

def set_cooldown(domain: str, until_iso: str) -> Dict:
    """
    Sets a cooldown window after failed renewals.
    """

    state = get_ssl_state(domain)
    state["cooldown_until"] = until_iso

    _SSL_STATE[domain] = state

    return state
