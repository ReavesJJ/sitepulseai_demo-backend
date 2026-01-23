# ssl_state.py
import json
import os
from datetime import datetime
from typing import Dict, Any

STATE_FILE = os.path.join("data", "ssl_state.json")

DEFAULT_STATE = {
    "domains": {}
}


def _ensure_state_file():
    os.makedirs("data", exist_ok=True)
    if not os.path.exists(STATE_FILE):
        with open(STATE_FILE, "w") as f:
            json.dump(DEFAULT_STATE, f, indent=2)


def _load_state() -> Dict[str, Any]:
    _ensure_state_file()
    with open(STATE_FILE, "r") as f:
        return json.load(f)


def _save_state(state: Dict[str, Any]):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def _now() -> str:
    return datetime.utcnow().isoformat()


def init_domain(domain: str):
    state = _load_state()

    if domain not in state["domains"]:
        state["domains"][domain] = {
            "domain": domain,
            "ssl_valid": None,
            "issuer": None,
            "expires_at": None,
            "days_remaining": None,
            "last_checked_at": None,

            "renewal_mode": "monitor_only",  # monitor_only | assisted | autonomous
            "last_renewed_at": None,

            "assisted_approvals": [],
            "renewal_history": []
        }

        _save_state(state)


def get_ssl_state(domain: str) -> Dict[str, Any]:
    init_domain(domain)
    state = _load_state()
    return state["domains"][domain]


def update_ssl_observation(
    domain: str,
    ssl_valid: bool,
    issuer: str,
    expires_at: str,
    days_remaining: int
):
    init_domain(domain)
    state = _load_state()

    record = state["domains"][domain]
    record["ssl_valid"] = ssl_valid
    record["issuer"] = issuer
    record["expires_at"] = expires_at
    record["days_remaining"] = days_remaining
    record["last_checked_at"] = _now()

    _save_state(state)
    return record


def set_renewal_mode(domain: str, mode: str):
    if mode not in ["monitor_only", "assisted", "autonomous"]:
        raise ValueError("Invalid renewal mode")

    init_domain(domain)
    state = _load_state()

    record = state["domains"][domain]
    record["renewal_mode"] = mode

    _save_state(state)
    return record


def mark_assisted_approval(domain: str):
    init_domain(domain)
    state = _load_state()

    record = state["domains"][domain]
    record["assisted_approvals"].append(_now())

    _save_state(state)
    return record


def mark_renewal(domain: str, success: bool, message: str = None):
    init_domain(domain)
    state = _load_state()

    record = state["domains"][domain]
    record["last_renewed_at"] = _now()

    record["renewal_history"].append({
        "timestamp": _now(),
        "success": success,
        "message": message
    })

    _save_state(state)
    return record
