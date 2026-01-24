# ssl_state.py
from datetime import datetime
from typing import Dict

# In-memory persistence (Phase 2A)
_SSL_STATE_DB: Dict[str, dict] = {}


# -----------------------------
# Internal Helpers
# -----------------------------

def _get_or_create_domain_state(domain: str) -> dict:
    domain = domain.lower()

    if domain not in _SSL_STATE_DB:
        _SSL_STATE_DB[domain] = {
            "domain": domain,
            "renewal_mode": "monitor_only",  # monitor_only | assisted | autonomous
            "observations": [],
            "repair_attempts": [],
            "last_observed_at": None,
            "last_known_expiry": None,
            "last_known_days_remaining": None,
            "last_repair_status": None,
            "last_repair_at": None,
        }

    return _SSL_STATE_DB[domain]


def _persist_state(domain: str, state: dict):
    _SSL_STATE_DB[domain.lower()] = state


# -----------------------------
# Read APIs
# -----------------------------

def get_ssl_state(domain: str) -> dict:
    state = _get_or_create_domain_state(domain)
    return state


# -----------------------------
# Mode Control
# -----------------------------

def set_renewal_mode(domain: str, mode: str) -> dict:
    if mode not in ("monitor_only", "assisted", "autonomous"):
        raise ValueError("Invalid renewal mode")

    state = _get_or_create_domain_state(domain)
    state["renewal_mode"] = mode
    _persist_state(domain, state)

    return {"domain": domain, "renewal_mode": mode}


def mark_assisted_renewal(domain: str) -> dict:
    state = _get_or_create_domain_state(domain)

    state["last_repair_status"] = "approved"
    state["last_repair_at"] = datetime.utcnow().isoformat()

    _persist_state(domain, state)

    return {"status": "approved", "domain": domain}


# -----------------------------
# Observation Logging
# -----------------------------

def update_ssl_observation(
    domain: str,
    observation_type: str,
    details: str = "",
):
    state = _get_or_create_domain_state(domain)

    obs = {
        "timestamp": datetime.utcnow().isoformat(),
        "type": observation_type,
        "details": details,
    }

    state["observations"].append(obs)
    state["last_observed_at"] = obs["timestamp"]

    _persist_state(domain, state)

    return {"status": "logged", "observation": obs}


# -----------------------------
# Repair Attempt Logging
# -----------------------------

def update_ssl_repair_attempt(
    domain: str,
    status: str,
    reason: str = None,
    error: str = None,
    expiry_date: str = None,
    days_remaining: int = None,
):
    """
    Persist the outcome or status of an SSL repair attempt.
    """
    state = _get_or_create_domain_state(domain)

    attempt = {
        "timestamp": datetime.utcnow().isoformat(),
        "status": status,
        "reason": reason,
        "error": error,
        "expiry_date": expiry_date,
        "days_remaining": days_remaining,
    }

    state["repair_attempts"].append(attempt)

    state["last_repair_status"] = status
    state["last_repair_at"] = attempt["timestamp"]

    if expiry_date:
        state["last_known_expiry"] = expiry_date

    if days_remaining is not None:
        state["last_known_days_remaining"] = days_remaining

    _persist_state(domain, state)

    return {"status": "logged", "attempt": attempt}
