from fastapi import APIRouter
from typing import Dict, Any

from ssl_utils import normalize_domain, inspect_ssl
from ssl_state import (
    get_ssl_state,
    set_renewal_mode,
    mark_assisted_renewal,
    update_ssl_observation,
    can_attempt_repair,
    mark_repair_attempt,
    mark_repair_success,
    mark_repair_failure,
)

router = APIRouter(prefix="/ssl", tags=["SSL Automation"])


# -----------------------------
# Core Autonomous SSL Engine
# -----------------------------

def evaluate_and_repair_ssl(domain: str) -> Dict[str, Any]:
    """
    Deterministic SSL inspection + autonomous repair decision engine.
    Safe to call repeatedly. Enforces retry + cooldown + escalation rules.
    """

    domain = normalize_domain(domain)
    state = get_ssl_state(domain)

    # 1) Inspect live SSL state
    ssl_info = inspect_ssl(domain)

    expiry_date = ssl_info.get("expiry_date")
    status = ssl_info.get("status")  # healthy | expiring | expired

    # 2) Update observation in state store
    update_ssl_observation(domain, expiry_date, status)

    # 3) If healthy → nothing to do
    if status == "healthy":
        return {
            "domain": domain,
            "action": "none",
            "status": "healthy",
            "state": state,
        }

    # 4) Expiring / Expired → attempt autonomous repair if allowed
    if status in ("expiring", "expired"):

        if not can_attempt_repair(domain):
            mark_assisted_renewal(
                domain,
                reason="Autonomous repair disabled, cooldown active, or retry limit reached",
            )

            return {
                "domain": domain,
                "action": "assisted_required",
                "status": status,
                "state": get_ssl_state(domain),
            }

        # 5) Mark repair attempt (idempotent-safe)
        mark_repair_attempt(domain)

        try:
            # --------------------------------------------------
            # PLACEHOLDER: real ACME / certbot logic goes here
            # --------------------------------------------------
            # Example later:
            # success = run_certbot_renewal(domain)
            success = False  # intentionally False for Phase 2A

            if success:
                mark_repair_success(domain)

                return {
                    "domain": domain,
                    "action": "repaired",
                    "status": "healthy",
                    "state": get_ssl_state(domain),
                }

            raise RuntimeError("Autonomous renewal command failed")

        except Exception as e:
            mark_repair_failure(domain, str(e))

            return {
                "domain": domain,
                "action": "repair_failed",
                "status": status,
                "error": str(e),
                "state": get_ssl_state(domain),
            }

    # 6) Fallback safety net (should never be hit)
    return {
        "domain": domain,
        "action": "noop",
        "status": status,
        "state": state,
        "warning": "Unhandled SSL status path",
    }


# -----------------------------
# FastAPI Endpoints
# -----------------------------

@router.get("/status/{domain}")
def ssl_status(domain: str) -> Dict[str, Any]:
    """
    Read-only: returns current SSL state machine snapshot.
    """
    domain = normalize_domain(domain)
    state = get_ssl_state(domain)

    return {
        "domain": domain,
        "state": state,
    }


@router.post("/evaluate/{domain}")
def ssl_evaluate(domain: str) -> Dict[str, Any]:
    """
    Triggers inspection + autonomous repair logic once.
    Safe to call from UI, cron, or agent loop.
    """
    domain = normalize_domain(domain)
    result = evaluate_and_repair_ssl(domain)
    return result


@router.post("/mode/{domain}/{mode}")
def set_mode(domain: str, mode: str) -> Dict[str, Any]:
    """
    Manually override renewal mode: autonomous | assisted | frozen
    """
    domain = normalize_domain(domain)
    set_renewal_mode(domain, mode)

    return {
        "domain": domain,
        "renewal_mode": mode,
        "state": get_ssl_state(domain),
    }
