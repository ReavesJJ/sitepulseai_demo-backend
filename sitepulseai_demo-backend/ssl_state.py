# ssl_state.py
# Centralized SSL state management for SitePulseAI
# ssl_state.py
import json
import os
from datetime import datetime
from threading import Lock

STATE_FILE = "ssl_state.json"
lock = Lock()

def load_ssl_state() -> dict:
    """
    Loads the SSL state from file.
    Returns a dict of domains.
    """
    if not os.path.exists(STATE_FILE):
        return {}
    with lock:
        with open(STATE_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}

def save_ssl_state(state: dict):
    """
    Saves the SSL state to file atomically.
    """
    with lock:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)

def get_ssl_state(domain: str) -> dict:
    """
    Returns the SSL state for a domain.
    """
    state = load_ssl_state()
    return state.get(domain)

def update_ssl_state(
    domain: str,
    ssl_valid=None,
    issuer=None,
    expires_at=None,
    days_remaining=None,
    renewal_mode=None,
    last_renewed_at=None,
    last_autofix_attempt=None,
    last_autofix_result=None,
    audit_note=None
):
    """
    Update the SSL state for a domain with new values.
    Creates entry if missing.
    """
    state = load_ssl_state()

    if domain not in state:
        state[domain] = {}

    entry = state[domain]

    if ssl_valid is not None:
        entry["ssl_valid"] = ssl_valid
    if issuer is not None:
        entry["issuer"] = issuer
    if expires_at is not None:
        entry["expires_at"] = expires_at
    if days_remaining is not None:
        entry["days_remaining"] = days_remaining
    if renewal_mode is not None:
        entry["renewal_mode"] = renewal_mode
    if last_renewed_at is not None:
        entry["last_renewed_at"] = last_renewed_at
    if last_autofix_attempt is not None:
        entry["last_autofix_attempt"] = last_autofix_attempt
    if last_autofix_result is not None:
        entry["last_autofix_result"] = last_autofix_result
    if audit_note is not None:
        entry.setdefault("audit_log", []).append({
            "timestamp": datetime.utcnow().isoformat(),
            "note": audit_note
        })

    state[domain] = entry
    save_ssl_state(state)
