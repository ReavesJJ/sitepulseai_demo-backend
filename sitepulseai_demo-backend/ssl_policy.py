# ssl_policy.py
from datetime import datetime, timedelta
from typing import Dict

from ssl_state import (
    get_ssl_state,
    record_policy_decision,
)

MAX_ATTEMPTS_24H = 3
COOLDOWN_MINUTES = 30

def evaluate_ssl_repair_policy(domain: str, severity: str = "CRITICAL") -> Dict:
    """
    Returns a decision dict:
    {
        allowed: bool,
        reason: str,
        mode: str
    }
    """

    state = get_ssl_state(domain)

    mode = state.get("renewal_mode", "auto")
    attempts = state.get("repair_attempts", [])
    last_repair_ts = state.get("last_repair_ts")

    now = datetime.utcnow()

    # 1) Mode rule
    if mode in ("manual", "locked"):
        decision = {
            "allowed": False,
            "reason": f"Repair blocked: mode={mode}",
            "mode": mode,
        }
        record_policy_decision(domain, decision)
        return decision

    # 2) Retry safety rule (24h window)
    last_24h_attempts = [
        a for a in attempts
        if datetime.fromisoformat(a["timestamp"]) > now - timedelta(hours=24)
    ]

    if len(last_24h_attempts) >= MAX_ATTEMPTS_24H:
        decision = {
            "allowed": False,
            "reason": "Too many repair attempts in last 24h",
            "mode": mode,
        }
        record_policy_decision(domain, decision)
        return decision

    # 3) Cooldown rule
    if last_repair_ts:
        last_repair = datetime.fromisoformat(last_repair_ts)
        if now - last_repair < timedelta(minutes=COOLDOWN_MINUTES):
            decision = {
                "allowed": False,
                "reason": "Cooldown window active",
                "mode": mode,
            }
            record_policy_decision(domain, decision)
            return decision

    # 4) Severity rule
    if mode == "auto" and severity not in ("CRITICAL", "HIGH"):
        decision = {
            "allowed": False,
            "reason": f"Severity {severity} not eligible for auto-repair",
            "mode": mode,
        }
        record_policy_decision(domain, decision)
        return decision

    # Allowed
    decision = {
        "allowed": True,
        "reason": "Policy allows repair",
        "mode": mode,
    }

    record_policy_decision(domain, decision)
    return decision
