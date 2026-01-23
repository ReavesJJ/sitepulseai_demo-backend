# ssl_automation.py
from datetime import datetime, timedelta
from fastapi import APIRouter, Query, HTTPException
from ssl_state import get_ssl_state, update_ssl_state
from ssl_utils import normalize_domain, inspect_ssl
from ssl_state import (
    get_ssl_state,
    set_renewal_mode,
    mark_assisted_renewal,
    update_ssl_observation
)

router = APIRouter(
    prefix="/ssl",
    tags=["SSL Automation"]
)

# -----------------------------
# Configuration (Phase 2A Stub)
# -----------------------------
EXPIRY_WARNING_DAYS = 14
AUTO_RENEW_THRESHOLD_DAYS = 5


# -----------------------------
# Core Observation Logic
# -----------------------------
def observe_ssl(domain: str) -> dict:
    """
    Pull live SSL data, persist observation into agent memory,
    and return the merged state.
    """
    clean_domain = normalize_domain(domain)

    try:
        ssl_data = inspect_ssl(clean_domain)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SSL निरीक्षण failed: {str(e)}")

    expires_at = ssl_data.get("expires_at")
    days_remaining = ssl_data.get("days_remaining")
    issuer = ssl_data.get("issuer")
    ssl_valid = ssl_data.get("valid", False)

    update_ssl_observation(
        domain=clean_domain,
        ssl_valid=ssl_valid,
        issuer=issuer,
        expires_at=expires_at,
        days_remaining=days_remaining
    )

    state = get_ssl_state(clean_domain)

    # Policy signals
    state["warning"] = (
        days_remaining is not None and days_remaining <= EXPIRY_WARNING_DAYS
    )

    state["auto_renew_due"] = (
        days_remaining is not None and days_remaining <= AUTO_RENEW_THRESHOLD_DAYS
    )

    return state


# -----------------------------
# Stub Autonomous Renewal
# -----------------------------
def stub_auto_renew(domain: str) -> dict:
    """
    Phase 2A stub: simulate SSL renewal without certbot.
    """
    clean_domain = normalize_domain(domain)

    # Simulate a successful renewal event
    now = datetime.utcnow()
    fake_expiry = now + timedelta(days=90)

    update_ssl_observation(
        domain=clean_domain,
        ssl_valid=True,
        issuer="Stub-CA",
        expires_at=fake_expiry.isoformat(),
        days_remaining=90
    )

    state = get_ssl_state(clean_domain)
    state["last_auto_renewed_at"] = now.isoformat()
    state["renewal_note"] = "Stub auto-renew executed (Phase 2A)"

    return state


# -----------------------------
# API Endpoints
# -----------------------------
@router.get("/observe")
def observe_endpoint(domain: str = Query(...)):
    """
    Observe SSL state, persist it, and return agent view.
    """
    return observe_ssl(domain)


@router.get("/state")
def get_state_endpoint(domain: str = Query(...)):
    """
    Return current SSL agent memory for a domain.
    """
    clean_domain = normalize_domain(domain)
    return get_ssl_state(clean_domain)


@router.post("/enable-assisted")
def enable_assisted_endpoint(domain: str = Query(...)):
    """
    Switch domain into assisted renewal mode.
    """
    clean_domain = normalize_domain(domain)
    return set_renewal_mode(clean_domain, "assisted")


@router.post("/assisted-renew")
def assisted_renew_endpoint(domain: str = Query(...)):
    """
    Simulate a human-approved renewal.
    """
    clean_domain = normalize_domain(domain)
    mark_assisted_renewal(clean_domain)
    return stub_auto_renew(clean_domain)


@router.post("/auto-renew-stub")
def auto_renew_stub_endpoint(domain: str = Query(...)):
    """
    Phase 2A autonomous renewal stub endpoint.
    """
    clean_domain = normalize_domain(domain)

    state = get_ssl_state(clean_domain)
    mode = state.get("renewal_mode", "monitor_only")

    if mode != "autonomous":
        raise HTTPException(
            status_code=403,
            detail="Autonomous renewal not enabled for this domain."
        )

    return stub_auto_renew(clean_domain)
