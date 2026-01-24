# ssl_state.py
import json
import os
from datetime import datetime, timedelta
from threading import Lock

STATE_FILE = "ssl_state_store.json"
_state_lock = Lock()


def _load_all_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, "r") as f:
        return json.load(f)


def _persist_all_state(state: dict):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def _get_or_create_domain_state(domain: str) -> dict:
    with _state_lock:
        all_state = _load_all_state()

        if domain not in all_state:
            all_state[domain] = {
                "domain": domain,
                "renewal_mode": "monitor_only",
                "last_checked_at": None,
                "last_renewed_at": None,
                "expiry_date": None,
                "days_remaining": None,
                "ssl_status": "unknown",

                # Phase 2A Step 6 fields
                "consecutive_failures": 0,
                "last_failure_at": None,
                "cooldown_until": None,
                "repair_disabled": False,
                "escalation_level": "none",

                # Audit trail
                "repair_attempts": [],
                "observations": [],
            }

            _persist_all_state(all_state)

        return all_state[domain]


def _persist_state(domain: str, domain_state: dict):
    with _state_lock:
        all_state = _load_all_state()
        all_state[domain] = domain_state
        _persist_all_state(all_state)


# -----------------------------
# Public API
# -----------------------------

def get_ssl_state(domain: str) -> dict:
    return _get_or_create_domain_state(domain)


def set_renewal_mode(domain: str, mode: str) -> dict:
    state = _get_or_create_domain_state(domain)
    state["renewal_mode"] = mode
    _persist_state(domain, state)
    return state


def update_ssl_observation(domain: str, expiry_date: str, status: str) -> dict:
    state = _get_or_create_domain_state(domain)

    obs = {
        "observed_at": datetime.utcnow().isoformat(),
        "expiry_date": expiry_date,
        "ssl_status": status,
    }

    state["last_checked_at"] = obs["observed_at"]
    state["expiry_date"] = expiry_date
    state["ssl_status"] = status
    state["observations"].append(obs)

    _persist_state(domain, state)
    return state


def update_ssl_repair_attempt(
    domain: str,
    status: str,
    reason: str,
    expiry_date: str | None = None,
    days_remaining: int | None = None,
    error: str | None = None,
) -> dict:
    state = _get_or_create_domain_state(domain)

    attempt = {
        "attempted_at": datetime.utcnow().isoformat(),
        "status": status,
        "reason": reason,
        "expiry_date": expiry_date,
        "days_remaining": days_remaining,
        "error": error,
    }

    state["repair_attempts"].append(attempt)

    if status == "success":
        state["last_renewed_at"] = attempt["attempted_at"]
        state["expiry_date"] = expiry_date
        state["days_remaining"] = days_remaining
        state["ssl_status"] = "valid"

    _persist_state(domain, state)
    return state


# -----------------------------
# Phase 2A Step 6 Logic
# -----------------------------

def update_ssl_failure(domain: str, error: str) -> dict:
    state = _get_or_create_domain_state(domain)

    now = datetime.utcnow()
    state["consecutive_failures"] = state.get("consecutive_failures", 0) + 1
    state["last_failure_at"] = now.isoformat()

    # Cooldown after 2 failures
    if state["consecutive_failures"] == 2:
        state["cooldown_until"] = (now + timedelta(minutes=15)).isoformat()

    # Escalate to assisted after 3 failures
    if state["consecutive_failures"] >= 3:
        state["renewal_mode"] = "assisted"
        state["escalation_level"] = "assisted"

    # Disable automation after 4 failures
    if state["consecutive_failures"] >= 4:
        state["repair_disabled"] = True
        state["escalation_level"] = "manual_required"

    _persist_state(domain, state)
    return state


def reset_ssl_failures(domain: str) -> dict:
    state = _get_or_create_domain_state(domain)

    state["consecutive_failures"] = 0
    state["last_failure_at"] = None
    state["cooldown_until"] = None
    state["repair_disabled"] = False
    state["escalation_level"] = "none"

    _persist_state(domain, state)
    return state


def is_ssl_in_cooldown(domain: str) -> bool:
    state = _get_or_create_domain_state(domain)
    until = state.get("cooldown_until")
    if not until:
        return False
    return datetime.utcnow() < datetime.fromisoformat(until)


def is_ssl_repair_disabled(domain: str) -> bool:
    state = _get_or_create_domain_state(domain)
    return bool(state.get("repair_disabled"))
