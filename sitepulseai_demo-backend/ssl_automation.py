# ssl_automation.py

from fastapi import APIRouter, Query
from datetime import datetime
from ssl_utils import normalize_domain, inspect_ssl
from ssl_state import (
    get_ssl_state,
    set_renewal_mode,
    mark_assisted_renewal,
    update_ssl_observation
)
from certbot_utils import certbot_dry_run, run_certbot_renew

# -----------------------------
# State Constants
# -----------------------------
STATE_OK = "ok"
STATE_EXPIRING_SOON = "expiring_soon"
STATE_AUTO_RENEW_ATTEMPTED = "auto_renew_attempted"
STATE_RENEWED_SUCCESS = "renewed_success"
STATE_RENEWED_FAILURE = "renewed_failure"
STATE_ASSISTED_REQUIRED = "assisted_required"

router = APIRouter(prefix="/ssl", tags=["SSL Automation"])

# -----------------------------
# Core Observation + Classification
# -----------------------------

def classify_ssl_state(domain: str) -> str:
    ssl_info = inspect_ssl(domain)

    status = ssl_info.get("status")
    days_left = ssl_info.get("days_left")

    if status != "valid":
        return STATE_EXPIRING_SOON

    if days_left is not None and days_left <= 15:
        return STATE_EXPIRING_SOON

    return STATE_OK


# -----------------------------
# Post-Repair Verification
# -----------------------------

async def verify_ssl_repair(domain: str) -> dict:
    ssl_info = inspect_ssl(domain)

    status = ssl_info.get("status")
    expiry_date = ssl_info.get("expiry_date")

    if status == "valid" and expiry_date:
        return {
            "success": True,
            "expiry_date": expiry_date.isoformat()
        }

    return {
        "success": False,
        "reason": "SSL still invalid or expiry date missing"
    }


# -----------------------------
# Autonomous Repair Loop
# -----------------------------

async def autonomous_ssl_repair(domain: str) -> dict:
    domain = normalize_domain(domain)

    current_state = classify_ssl_state(domain)
    update_ssl_observation(domain, current_state)

    if current_state == STATE_OK:
        return {"status": "ok", "message": "SSL is healthy"}

    # Attempt auto-renew
    update_ssl_observation(domain, STATE_AUTO_RENEW_ATTEMPTED)
    renew_result = run_certbot_renew(domain)

    if renew_result.get("success"):
        verify_result = await verify_ssl_repair(domain)

        if verify_result.get("success"):
            update_ssl_observation(domain, STATE_RENEWED_SUCCESS)
            return {
                "status": "repaired",
                "message": "SSL renewed and verified",
                "expiry_date": verify_result.get("expiry_date")
            }
        else:
            update_ssl_observation(domain, STATE_RENEWED_FAILURE)
            return {
                "status": "failed",
                "message": "Renew attempted but SSL still invalid",
                "details": verify_result
            }

    update_ssl_observation(domain, STATE_RENEWED_FAILURE)
    return {
        "status": "failed",
        "message": "Certbot renewal failed",
        "details": renew_result
    }


# -----------------------------
# API Endpoints
# -----------------------------

@router.get("/state")
def ssl_state(domain: str = Query(...)):
    domain = normalize_domain(domain)
    return get_ssl_state(domain)


@router.post("/enable-assisted")
def enable_assisted(domain: str = Query(...)):
    domain = normalize_domain(domain)
    return set_renewal_mode(domain, "assisted")


@router.post("/assisted-renew")
def assisted_renew(domain: str = Query(...)):
    domain = normalize_domain(domain)
    return mark_assisted_renewal(domain)


@router.post("/dry-run")
def ssl_dry_run(domain: str = Query(...)):
    domain = normalize_domain(domain)
    return certbot_dry_run(domain)


@router.post("/autonomous-repair")
async def trigger_autonomous_repair(domain: str = Query(...)):
    domain = normalize_domain(domain)
    return await autonomous_ssl_repair(domain)
