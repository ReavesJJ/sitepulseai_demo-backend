# ssl_policy.py
from datetime import datetime, timedelta
from typing import Tuple, Optional
from ssl_state import get_ssl_state


REPAIR_EXPIRY_THRESHOLD_DAYS = 30
REPAIR_COOLDOWN_HOURS = 24
FAILURE_LOCKOUT_HOURS = 48


def evaluate_ssl_repair_policy(domain: str) -> Tuple[bool, str]:
    """
    Returns:
      (allowed: bool, reason: str)
    """

    state = get_ssl_state(domain)

    if not state:
        return False, "No SSL state available for domain"

    mode = state.get("renewal_mode", "monitor_only")
    days_remaining = state.get("days_remaining")
    last_attempt = state.get("last_repair_attempt_at")
    last_status = state.get("last_repair_status")
    approved = state.get("assisted_approved", False)

    now = datetime.utcnow()

    # Rule 1 — Mode gate
    if mode == "monitor_only":
        return False, "Repair blocked: domain in monitor_only mode"

    if mode == "assisted" and not approved:
        return False, "Repair blocked: awaiting human approval"

    # Rule 2 — Expiry threshold
    if days_remaining is None:
        return False, "Repair blocked: unknown certificate expiry"

    if days_remaining > REPAIR_EXPIRY_THRESHOLD_DAYS:
        return False, f"Repair blocked: {days_remaining} days remaining exceeds threshold"

    # Rule 3 — Cooldown window
    if last_attempt:
        last_attempt_dt = _parse_iso(last_attempt)
        if last_attempt_dt and now - last_attempt_dt < timedelta(hours=REPAIR_COOLDOWN_HOURS):
            return False, "Repair blocked: cooldown window active"

    # Rule 4 — Failure lockout
    if last_status == "failed" and last_attempt:
        last_attempt_dt = _parse_iso(last_attempt)
        if last_attempt_dt and now - last_attempt_dt < timedelta(hours=FAILURE_LOCKOUT_HOURS):
            return False, "Repair blocked: failure lockout active"

    # Rule 5 — Reserved for domain allow/deny lists
    # Stubbed for now

    return True, "Repair permitted by policy"


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None
