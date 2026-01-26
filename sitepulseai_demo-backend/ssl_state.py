# ssl_state.py

from typing import Dict, Any
from datetime import datetime

# In-memory fallback store (can later be swapped for DB / Redis)
_SSL_STATE_STORE: Dict[str, Dict[str, Any]] = {}


def update_ssl_state(domain: str, ssl_result: Dict[str, Any]) -> None:
    """
    Persist the latest SSL state for a domain.
    """

    record = {
        "domain": domain,
        "ssl_valid": ssl_result.get("ssl_valid"),
        "expires_in_days": ssl_result.get("expires_in_days"),
        "issuer": ssl_result.get("issuer"),
        "policy_compliant": ssl_result.get("policy_compliant"),
        "repair_attempted": ssl_result.get("repair_attempted"),
        "repair_success": ssl_result.get("repair_success"),
        "error": ssl_result.get("error"),
        "last_checked": datetime.utcnow().isoformat(),
    }

    _SSL_STATE_STORE[domain] = record


def get_ssl_state(domain: str) -> Dict[str, Any] | None:
    """
    Retrieve the last known SSL state for a domain.
    """

    return _SSL_STATE_STORE.get(domain)


def can_attempt_repair(domain: str) -> bool:
    """
    Guardrail to prevent infinite or abusive repair attempts.
    """

    state = _SSL_STATE_STORE.get(domain)

    if not state:
        return True

    # If a successful repair already occurred, do not retry
    if state.get("repair_success"):
        return False

    # If a repair was attempted very recently, do not retry
    # (simple guard — can be expanded later)
    if state.get("repair_attempted"):
        return False

    return True


def record_policy_decision(domain: str, policy_result: dict) -> None:
    """
    Persist the latest SSL policy compliance decision for a domain.
    """

    state = _SSL_STATE_STORE.get(domain, {})

    state.update({
        "policy_compliant": policy_result.get("policy_compliant"),
        "policy_level": policy_result.get("policy_level"),
        "policy_reasons": policy_result.get("policy_reasons"),
        "policy_checked_at": datetime.utcnow().isoformat(),
    })

    _SSL_STATE_STORE[domain] = state

