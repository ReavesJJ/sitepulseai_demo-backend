# ssl_state.py
from typing import Optional, Dict
from datetime import datetime

# In-memory SSL state store
ssl_store: Dict[str, dict] = {}

def get_ssl_state(domain: str) -> dict:
    """Retrieve current SSL state for a domain."""
    return ssl_store.get(domain, {
        "renewal_mode": "monitor_only",
        "last_observation": None,
        "last_assisted_renewal": None,
        "consecutive_failures": 0,
        "cooldown_until": None,
        "repair_disabled": False,
        "escalation_level": 0,
    })

def set_renewal_mode(domain: str, mode: str) -> dict:
    """Set renewal mode: monitor_only or assisted."""
    state = ssl_store.setdefault(domain, {})
    state["renewal_mode"] = mode
    return state

def mark_assisted_renewal(domain: str) -> dict:
    """Mark that an assisted renewal has been approved."""
    state = ssl_store.setdefault(domain, {})
    state["last_assisted_renewal"] = datetime.utcnow().isoformat()
    return state

def update_ssl_observation(domain: str, status: str, expiry_date: Optional[str] = None) -> dict:
    """Record latest SSL observation."""
    state = ssl_store.setdefault(domain, {})
    state["last_observation"] = {
        "status": status,
        "expiry_date": expiry_date,
        "timestamp": datetime.utcnow().isoformat()
    }
    return state

def record_repair_attempt(domain: str, success: bool) -> dict:
    """Track repair attempts, handle consecutive failures."""
    state = ssl_store.setdefault(domain, {})
    failures = state.get("consecutive_failures", 0)

    if success:
        state["consecutive_failures"] = 0
        state["cooldown_until"] = None
    else:
        state["consecutive_failures"] = failures + 1
        # Apply exponential backoff cooldown (minutes)
        backoff = min(60 * (2 ** failures), 1440)  # max 1 day
        state["cooldown_until"] = datetime.utcnow().timestamp() + backoff * 60

        # Escalation if failures exceed 3
        state["escalation_level"] = state.get("escalation_level", 0)
        if state["consecutive_failures"] > 3:
            state["repair_disabled"] = True
            state["escalation_level"] += 1

    return state
