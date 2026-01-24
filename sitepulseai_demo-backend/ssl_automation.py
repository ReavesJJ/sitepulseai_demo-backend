# ssl_automation.py
import asyncio
from fastapi import APIRouter, Query

from ssl_utils import normalize_domain, inspect_ssl
from ssl_state import (
    get_ssl_state,
    set_renewal_mode,
    update_ssl_observation,
    update_ssl_repair_attempt,
    update_ssl_failure,
    reset_ssl_failures,
    is_ssl_in_cooldown,
    is_ssl_repair_disabled,
)

router = APIRouter(prefix="/ssl", tags=["SSL Automation"])


# -----------------------------
# Certbot Stub (safe for Render)
# -----------------------------

async def run_certbot_renew(domain: str) -> dict:
    await asyncio.sleep(1)  # simulate execution latency
    return {"success": True, "message": f"Simulated certbot renew for {domain}"}


# -----------------------------
# Core Repair Engine
# -----------------------------

async def execute_ssl_repair(domain: str, reason: str = "policy_triggered"):
    domain = normalize_domain(domain)

    if is_ssl_repair_disabled(domain):
        return {"status": "blocked", "reason": "automation_disabled"}

    if is_ssl_in_cooldown(domain):
        return {"status": "blocked", "reason": "cooldown_active"}

    try:
        await run_certbot_renew(domain)

        inspection = inspect_ssl(domain)

        update_ssl_observation(
            domain,
            inspection["expiry_date"],
            inspection["status"],
        )

        if inspection["status"] == "valid" and inspection["days_remaining"] > 10:
            update_ssl_repair_attempt(
                domain,
                status="success",
                reason=reason,
                expiry_date=inspection["expiry_date"],
                days_remaining=inspection["days_remaining"],
            )

            reset_ssl_failures(domain)

            return {
                "status": "success",
                "domain": domain,
                "days_remaining": inspection["days_remaining"],
            }

        raise Exception("Post-repair verification failed")

    except Exception as e:
        update_ssl_failure(domain, str(e))

        update_ssl_repair_attempt(
            domain,
            status="failed",
            reason=reason,
            error=str(e),
        )

        return {
            "status": "failed",
            "domain": domain,
            "error": str(e),
        }


# -----------------------------
# API Endpoints
# -----------------------------

@router.get("/state")
def ssl_state(domain: str = Query(...)):
    return get_ssl_state(domain)


@router.post("/enable-assisted")
def enable_assisted(domain: str = Query(...)):
    return set_renewal_mode(domain, "assisted")


@router.post("/repair")
async def repair_ssl(domain: str = Query(...)):
    return await execute_ssl_repair(domain, reason="manual_trigger")
