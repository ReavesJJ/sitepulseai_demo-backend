# ssl_state.py
import json
import os
from datetime import datetime

STATE_FILE = "ssl_state.json"


def _load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_state(state: dict):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def get_ssl_state(domain: str):
    state = _load_state()
    return state.get(domain, {
        "domain": domain,
        "ssl_status": "unknown",
        "expiry_date": None,
        "days_remaining": None,
        "renewal_mode": "auto",   # auto | assisted | manual
        "last_checked": None,
        "last_updated": None
    })


def update_ssl_state(domain: str, ssl_status: str, expiry_date=None, days_remaining=None):
    state = _load_state()
    state[domain] = {
        "domain": domain,
        "ssl_status": ssl_status,
        "expiry_date": expiry_date,
        "days_remaining": days_remaining,
        "renewal_mode": state.get(domain, {}).get("renewal_mode", "auto"),
        "last_checked": datetime.utcnow().isoformat(),
        "last_updated": datetime.utcnow().isoformat()
    }
    _save_state(state)
    return state[domain]


def set_renewal_mode(domain: str, mode: str):
    """
    mode: auto | assisted | manual
    """
    if mode not in ["auto", "assisted", "manual"]:
        raise ValueError("Invalid renewal mode. Must be auto, assisted, or manual.")

    state = _load_state()
    current = state.get(domain, {})

    current.update({
        "domain": domain,
        "renewal_mode": mode,
        "last_updated": datetime.utcnow().isoformat()
    })

    state[domain] = current
    _save_state(state)
    return current


def mark_assisted_renewal(domain: str, reason: str = None):
    state = _load_state()
    current = state.get(domain, {})

    current.update({
        "domain": domain,
        "renewal_mode": "assisted",
        "assisted_reason": reason or "Manual intervention required",
        "last_updated": datetime.utcnow().isoformat()
    })

    state[domain] = current
    _save_state(state)
    return current
