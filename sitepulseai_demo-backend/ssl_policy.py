# ssl_policy.py
from datetime import datetime, timedelta
from typing import Dict

from ssl_state import (
    get_ssl_state,
    record_policy_decision,
)

from datetime import datetime

def evaluate_ssl_policy(domain: str, ssl_data: dict) -> dict:
    """
    Evaluate SSL certificate data against SitePulseAI security policy.
    Returns a structured compliance decision.
    """

    reasons = []
    policy_level = "strict"
    compliant = True

    if not ssl_data:
        compliant = False
        reasons.append("No SSL certificate data available.")
    else:
        if not ssl_data.get("valid"):
            compliant = False
            reasons.append("SSL certificate is invalid.")

        expires_in_days = ssl_data.get("expires_in_days")
        if expires_in_days is None:
            compliant = False
            reasons.append("SSL expiration date missing.")
        elif expires_in_days < 7:
            compliant = False
            reasons.append("SSL certificate expires in less than 7 days.")
        elif expires_in_days < 30:
            reasons.append("SSL certificate expires in less than 30 days.")

        issuer = ssl_data.get("issuer", "").lower()
        if "let's encrypt" not in issuer and "digicert" not in issuer and "globalsign" not in issuer:
            reasons.append("SSL issuer is not in trusted CA list.")

    return {
        "domain": domain,
        "policy_compliant": compliant,
        "policy_level": policy_level,
        "policy_reasons": reasons,
        "evaluated_at": datetime.utcnow().isoformat(),
    }



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
