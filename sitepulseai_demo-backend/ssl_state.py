# ssl_state.py
import json
import os
from datetime import datetime
from typing import Dict, Any

from ssl_utils import normalize_domain

STATE_FILE = "ssl_state.json"
_STATE: Dict[str, Dict[str, Any]] = {}


# -------------------------
# Internal Helpers
# -------------------------

def _default_state(domain: str) -> Dict[str, Any]:
    return {
        "domain": domain,
        "status": "unknown",
        "last_checked_at": None,
        "last_observed_expiry": None,
        "last_observed_status": None,

        # Renewal governance
        "renewal_mode": "auto",  # auto | assisted | manual

        # Repair tracking
        "repair_attempts": [],
        "last_repair_attempt_at": None,
        "last_repair_success_at": None,
        "last_repair_error": None,

        # Retry / backoff
        "retry_count": 0,
        "next_retry_at": None,

        # Escalation tracking
        "escalations": [],
        "last_escalation_reason": None,
        "last_escalation_at": None,

        # 🔒 Phase 3 — Policy engine tracking
        "policy_decisions": [],
        "last_policy_decision": None,
        "last_policy_decision_reason": None,
        "last_policy_decision_at": None,
    }


def _persist_state() -> None:
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(_STATE, f, indent=2)
    except Exception:
        # Never crash backend due to persistence failure
        pass


def _load_state() -> None:
    global _STATE
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                _STATE = json.load(f)
        except Exception:
            _STATE = {}


_load_state()


# -------------------------
# Public Read API
# -------------------------

def get_ssl_state(domain: str) -> Dict[str, Any]:
    domain = normalize_domain(domain)
    state = _STATE.get(domain) or _default_state(domain)
    _STATE[domain] = state
    return state


# -------------------------
# Observation Logging
# -------------------------

def update_ssl_observation(domain: str, observation: Dict[str, Any]) -> Dict[str, Any]:
    """
    Log a fresh SSL observation (expiry, validity, status).
    """
    domain = normalize_domain(domain)
    state = _STATE.get(domain) or _default_state(domain)

    now = datetime.utcnow().isoformat()

    state["last_checked_at"] = now
    state["last_observed_expiry"] = observation.get("expiry_date")
    state["last_observed_status"] = observation.get("status")
    state["status"] = observation.get("status", state["status"])

    _STATE[domain] = state
    _persist_state()

    return {
        "domain": domain,
        "observed": True,
        "status": state["status"],
        "checked_at": now,
    }


# -------------------------
# Renewal Mode Control
# -------------------------

def set_renewal_mode(domain: str, mode: str) -> Dict[str, Any]:
    """
    Set renewal mode: auto | assisted | manual
    """
    if mode not in {"auto", "assisted", "manual"}:
        raise ValueError("Invalid renewal mode")

    domain = normalize_domain(domain)
    state = _STATE.get(domain) or _default_state(domain)

    state["renewal_mode"] = mode

    _STATE[domain] = state
    _persist_state()

    return {
        "domain": domain,
        "renewal_mode": mode,
    }


# -------------------------
# Repair Attempt Tracking
# -------------------------

def record_repair_attempt(domain: str, result: str, error: str = None) -> Dict[str, Any]:
    """
    Record a single repair attempt outcome.
    """
    domain = normalize_domain(domain)
    state = _STATE.get(domain) or _default_state(domain)

    now = datetime.utcnow().isoformat()

    attempt = {
        "timestamp": now,
        "result": result,
        "error": error,
    }

    state["repair_attempts"].append(attempt)
    state["last_repair_attempt_at"] = now
    state["last_repair_error"] = error

    if result == "success":
        state["last_repair_success_at"] = now
        state["retry_count"] = 0
        state["next_retry_at"] = None
        state["status"] = "healthy"

    elif result == "failure":
        state["status"] = "repair_failed"

    _STATE[domain] = state
    _persist_state()

    return {
        "domain": domain,
        "attempt_recorded": True,
        "result": result,
        "timestamp": now,
    }


# -------------------------
# Retry + Backoff Engine
# -------------------------

def schedule_retry(domain: str, backoff_seconds: int) -> Dict[str, Any]:
    """
    Schedule the next retry attempt using exponential backoff.
    """
    domain = normalize_domain(domain)
    state = _STATE.get(domain) or _default_state(domain)

    now = datetime.utcnow()
    next_retry = now.timestamp() + backoff_seconds

    state["retry_count"] += 1
    state["next_retry_at"] = datetime.utcfromtimestamp(next_retry).isoformat()
    state["status"] = "retry_scheduled"

    _STATE[domain] = state
    _persist_state()

    return {
        "domain": domain,
        "retry_count": state["retry_count"],
        "next_retry_at": state["next_retry_at"],
    }


# -------------------------
# Escalation Logging
# -------------------------

def record_escalation(domain: str, reason: str = "unspecified") -> Dict[str, Any]:
    """
    Record an escalation event when automated repair fails or is blocked.
    """
    domain = normalize_domain(domain)
    state = _STATE.get(domain) or _default_state(domain)

    now = datetime.utcnow().isoformat()

    escalation_event = {
        "timestamp": now,
        "reason": reason,
    }

    state["escalations"].append(escalation_event)
    state["last_escalation_reason"] = reason
    state["last_escalation_at"] = now
    state["status"] = "escalated"

    _STATE[domain] = state
    _persist_state()

    return {
        "domain": domain,
        "escalated": True,
        "reason": reason,
        "timestamp": now,
    }


# -------------------------
# 🔒 Phase 3 — Policy Decision Logging
# -------------------------

def record_policy_decision(domain: str, decision: str, reason: str = None) -> Dict[str, Any]:
    """
    Record a policy engine decision (allow, block, escalate, defer).
    """
    domain = normalize_domain(domain)
    state = _STATE.get(domain) or _default_state(domain)

    now = datetime.utcnow().isoformat()

    decision_event = {
        "timestamp": now,
        "decision": decision,
        "reason": reason,
    }

    # Forward safety for legacy states
    if "policy_decisions" not in state:
        state["policy_decisions"] = []

    state["policy_decisions"].append(decision_event)
    state["last_policy_decision"] = decision
    state["last_policy_decision_reason"] = reason
    state["last_policy_decision_at"] = now

    _STATE[domain] = state
    _persist_state()

    return {
        "domain": domain,
        "decision": decision,
        "reason": reason,
        "timestamp": now,
    }
