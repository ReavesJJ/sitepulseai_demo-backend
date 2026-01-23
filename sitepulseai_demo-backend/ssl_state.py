# ssl_state.py
import json
import os
from datetime import datetime

STATE_FILE = "ssl_state.json"


def _load_state() -> dict:
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


def get_ssl_state(domain: str) -> dict:
    state = _load_state()
    return state.get(domain, {
        "domain": domain,
        "renewal_mode": "monitor_only",
        "last_checked_at": None,
        "last_renewed_at": None,
        "last_ssl_observation": None
    })


def set_renewal_mode(domain: str, mode: str) -> dict:
    state = _load_state()
    entry = get_ssl_state(domain)
    entry["renewal_mode"] = mode
    entry["updated_at"] = datetime.utcnow().isoformat()
    state[domain] = entry
    _save_state(state)
    return entry


def mark_assisted_renewal(domain: str) -> dict:
    state = _load_state()
    entry = get_ssl_state(domain)
    entry["last_renewed_at"] = datetime.utcnow().isoformat()
    entry["updated_at"] = datetime.utcnow().isoformat()
    state[domain] = entry
    _save_state(state)
    return entry


def update_ssl_observation(domain: str, ssl_info: dict) -> dict:
    state = _load_state()
    entry = get_ssl_state(domain)

    entry["last_checked_at"] = datetime.utcnow().isoformat()
    entry["last_ssl_observation"] = ssl_info
    entry["updated_at"] = datetime.utcnow().isoformat()

    state[domain] = entry
    _save_state(state)
    return entry
