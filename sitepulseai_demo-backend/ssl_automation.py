# ssl_automation.py
from fastapi import APIRouter, Query
from datetime import datetime
import asyncio
import subprocess
from typing import Dict

from ssl_utils import normalize_domain, inspect_ssl
from ssl_state import (
    get_ssl_state,
    update_ssl_observation,
    record_repair_attempt,
    record_escalation,
)
from ssl_policy import evaluate_ssl_repair_policy

router = APIRouter(prefix="/ssl", tags=["SSL Automation"])

# -----------------------------
# Internal helpers
# -----------------------------

async def _run_certbot(domain: str) -> Dict:
    """Run certbot renew for a specific domain."""
    try:
        process = await asyncio.create_subprocess_exec(
            "certbot",
            "certonly",
            "--standalone",
            "-d",
            domain,
            "--non-interactive",
            "--agree-tos",
            "-m",
            "admin@sitepulseai.local",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await process.communicate()

        if process.returncode == 0:
            return {"success": True, "output": stdout.decode()}

        return {"success": False, "error": stderr.decode()}

    except Exception as e:
        return {"success": False, "error": str(e)}


async def _post_repair_verification(domain: str) -> Dict:
    """Verify SSL state after repair attempt."""
    try:
        result = inspect_ssl(domain)
        status = result.get("status")
        expiry_date = result.get("expiry_date")

        update_ssl_observation(domain, status)

        return {
            "verified": status == "valid",
            "status": status,
            "expiry_date": expiry_date,
        }
    except Exception as e:
        return {"verified": False, "error": str(e)}


async def _execute_autonomous_repair(domain: str) -> Dict:
    """Full autonomous SSL repair flow with policy + verification."""

    domain = normalize_domain(domain)

    # 1) Evaluate policy
    policy = evaluate_ssl_repair_policy(domain, severity="CRITICAL")

    if not policy.get("allowed"):
        return {
            "success": False,
            "blocked": True,
            "reason": policy.get("reason"),
            "mode": policy.get("mode"),
        }

    # 2) Record attempt
    record_repair_attempt(domain)

    # 3) Run certbot
    repair_result = await _run_certbot(domain)

    if not repair_result.get("success"):
        record_escalation(domain, reason="certbot_failed")
        return {
            "success": False,
            "stage": "repair",
            "error": repair_result.get("error"),
        }

    # 4) Post-repair verification
    verification = await _post_repair_verification(domain)

    if not verification.get("verified"):
        record_escalation(domain, reason="post_verification_failed")
        return {
            "success": False,
            "stage": "verification",
            "verification": verification,
        }

    return {
        "success": True,
        "domain": domain,
        "policy": policy,
        "verification": verification,
    }


# -----------------------------
# API endpoints
# -----------------------------



@router.get("/state")
def ssl_state(domain: str = Query(...)):
    domain = normalize_domain(domain)
    return get_ssl_state(domain)


@router.post("/observe")
def observe_ssl(domain: str = Query(...)):
    domain = normalize_domain(domain)
    result = inspect_ssl(domain)

    status = result.get("status")
    update_ssl_observation(domain, status)

    return {
        "domain": domain,
        "observation": result,
    }


@router.post("/repair")
async def repair_ssl(domain: str = Query(...)):
    return await _execute_autonomous_repair(domain)


@router.post("/verify")
async def verify_ssl(domain: str = Query(...)):
    domain = normalize_domain(domain)
    return await _post_repair_verification(domain)


