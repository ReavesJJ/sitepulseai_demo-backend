# ssl_automation.py
import asyncio
from fastapi import APIRouter, Query
from ssl_state import (
    get_ssl_state,
    set_renewal_mode,
    mark_assisted_renewal,
    update_ssl_observation,
    record_repair_attempt
)
from ssl_utils import normalize_domain, inspect_ssl

router = APIRouter(prefix="/ssl", tags=["SSL Automation"])

# -----------------------
# State Endpoints
# -----------------------

@router.get("/state")
def ssl_state_endpoint(domain: str = Query(...)):
    return get_ssl_state(domain)

@router.post("/enable-assisted")
def enable_assisted_endpoint(domain: str):
    return set_renewal_mode(domain, "assisted")

@router.post("/assisted-renew")
def assisted_renew_endpoint(domain: str):
    return mark_assisted_renewal(domain)

# -----------------------
# Core Autonomous Repair
# -----------------------

async def repair_ssl(domain: str):
    """Attempt SSL repair with retries, backoff, and post-verification."""
    domain = normalize_domain(domain)
    state = get_ssl_state(domain)

    if state.get("repair_disabled"):
        return {"success": False, "message": "Repair disabled due to repeated failures."}

    for attempt in range(3):  # max 3 retries
        try:
            status, expiry = inspect_ssl(domain)
            update_ssl_observation(domain, status, expiry)
            if status == "valid":
                record_repair_attempt(domain, True)
                return {"success": True, "status": status, "expiry_date": expiry}
            
            # simulate repair action (placeholder for real certbot)
            await asyncio.sleep(2)  # async repair delay
            repair_success = True  # simulate success

            record_repair_attempt(domain, repair_success)
            if repair_success:
                status, expiry = inspect_ssl(domain)
                update_ssl_observation(domain, status, expiry)
                return {"success": True, "status": status, "expiry_date": expiry}

        except Exception as e:
            record_repair_attempt(domain, False)
            await asyncio.sleep(2 ** attempt)  # exponential backoff

    return {"success": False, "message": "Repair attempts failed."}

@router.post("/repair")
async def repair_endpoint(domain: str):
    """API entry point for autonomous repair."""
    result = await repair_ssl(domain)
    return result
