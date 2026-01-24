# ssl_automation.py
from datetime import datetime
from fastapi import APIRouter, Query, HTTPException
from typing import Dict

from ssl_utils import normalize_domain, inspect_ssl
from ssl_state import (
    get_ssl_state,
    set_renewal_mode,
    mark_assisted_renewal,
    update_ssl_observation,
    update_ssl_repair_attempt,
)
from ssl_policy import evaluate_ssl_repair_policy


router = APIRouter(prefix="/ssl", tags=["SSL Automation"])


# -----------------------------
# Core Helpers
# -----------------------------

def log_ssl_event(domain: str, event: str, message: str = ""):
    update_ssl_observation(
        domain=domain,
        observation_type=event,
        details=message,
    )


def classify_ssl_state(domain: str) -> Dict:
    """
    Inspect live SSL cert and classify its current state.
    """
    result = inspect_ssl(domain)

    if not result["valid"]:
        state = "invalid"
    elif result["days_remaining"] is not None and result["days_remaining"] <= 15:
        state = "expiring_soon"
    else:
        state = "ok"

    return {
        "state": state,
        "expiry_date": result.get("expiry_date"),
        "days_remaining": result.get("days_remaining"),
        "valid": result.get("valid"),
    }


async def perform_ssl_repair(domain: str) -> Dict:
    """
    Stubbed autonomous repair logic.
    Replace with certbot / ACME integration later.
    """
    # ---- STUB MODE (Phase 2A) ----
    return {
        "success": True,
        "message": "Stub renewal executed successfully",
    }


async def verify_ssl_repair(domain: str) -> Dict:
    """
    Post-repair verification: re-inspect cert and confirm validity.
    """
    result = inspect_ssl(domain)

    if not result["valid"]:
        return {
            "verified": False,
            "reason": "Certificate still invalid after repair attempt",
        }

    if result["expiry_date"] is None:
        return {
            "verified": False,
            "reason": "No expiry date detected after repair",
        }

    return {
        "verified": True,
        "expiry_date": result["expiry_date"],
        "days_remaining": result["days_remaining"],
    }


# -----------------------------
# Autonomous Repair Brain
# -----------------------------

async def autonomous_ssl_repair(domain: str) -> Dict:
    domain = normalize_domain(domain)

    # 1) Inspect + classify
    classification = classify_ssl_state(domain)

    update_ssl_observation(
        domain=domain,
        observation_type="ssl_inspected",
        details=f"State={classification['state']} DaysRemaining={classification['days_remaining']}",
    )

    # 2) Evaluate policy
    allowed, reason = evaluate_ssl_repair_policy(domain)

    if not allowed:
        log_ssl_event(domain, "repair_blocked", reason)
        update_ssl_repair_attempt(domain, status="blocked", reason=reason)

        return {
            "status": "blocked",
            "reason": reason,
            "classification": classification,
        }

    # 3) Execute repair
    log_ssl_event(domain, "repair_authorized", "Policy engine approved repair")
    update_ssl_repair_attempt(domain, status="in_progress")

    repair_result = await perform_ssl_repair(domain)

    if not repair_result.get("success"):
        error = repair_result.get("error", "Unknown repair failure")

        log_ssl_event(domain, "repair_failed", error)
        update_ssl_repair_attempt(domain, status="failed", error=error)

        return {
            "status": "failed",
            "error": error,
        }

    # 4) Post-repair verification
    verification = await verify_ssl_repair(domain)

    if not verification["verified"]:
        reason = verification["reason"]

        log_ssl_event(domain, "repair_verification_failed", reason)
        update_ssl_repair_attempt(domain, status="failed", error=reason)

        return {
            "status": "failed_verification",
            "reason": reason,
        }

    # 5) Success path
    log_ssl_event(
        domain,
        "repair_verified",
        f"Expiry={verification['expiry_date']} DaysRemaining={verification['days_remaining']}",
    )

    update_ssl_repair_attempt(
        domain,
        status="success",
        expiry_date=verification["expiry_date"],
        days_remaining=verification["days_remaining"],
    )

    return {
        "status": "repaired",
        "expiry_date": verification["expiry_date"],
        "days_remaining": verification["days_remaining"],
    }


# -----------------------------
# API Endpoints
# -----------------------------

@router.get("/state")
def get_ssl_state_endpoint(domain: str = Query(...)):
    domain = normalize_domain(domain)
    return get_ssl_state(domain)


@router.post("/enable-assisted")
def enable_assisted(domain: str = Query(...)):
    domain = normalize_domain(domain)
    return set_renewal_mode(domain, "assisted")


@router.post("/assisted-renew")
def assisted_renew(domain: str = Query(...)):
    domain = normalize_domain(domain)
    mark_assisted_renewal(domain)
    return {"status": "approved"}


@router.post("/autonomous-repair")
async def autonomous_repair_endpoint(domain: str = Query(...)):
    domain = normalize_domain(domain)
    result = await autonomous_ssl_repair(domain)
    return result


@router.post("/dry-run")
async def ssl_dry_run(domain: str = Query(...)):
    """
    Dry-run = policy + inspection only. No repair execution.
    """
    domain = normalize_domain(domain)

    classification = classify_ssl_state(domain)
    allowed, reason = evaluate_ssl_repair_policy(domain)

    return {
        "classification": classification,
        "policy_allowed": allowed,
        "policy_reason": reason,
    }
