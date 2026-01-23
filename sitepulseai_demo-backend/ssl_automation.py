# ssl_automation.py
import subprocess
from fastapi import APIRouter, Query
from ssl_utils import normalize_domain, inspect_ssl
from ssl_state import (
    get_ssl_state,
    update_ssl_observation,
    set_renewal_mode,
    mark_assisted_renewal
)

router = APIRouter(
    prefix="/ssl",
    tags=["SSL Automation"]
)

# -----------------------------
# Get SSL state for a domain
# -----------------------------
@router.get("/state")
def ssl_state_endpoint(domain: str = Query(...)):
    """
    Returns the current SSL state for a domain.
    """
    return get_ssl_state(domain)

# -----------------------------
# Enable assisted SSL mode
# -----------------------------
@router.post("/enable-assisted")
def enable_assisted_endpoint(domain: str = Query(...)):
    """
    Enable assisted SSL renewal mode for a domain.
    """
    return set_renewal_mode(domain, mode="assisted")

# -----------------------------
# Simulate assisted renewal approval
# -----------------------------
@router.post("/assisted-renew")
def assisted_renew_endpoint(domain: str = Query(...)):
    """
    Simulate approval of SSL renewal by user.
    Marks assisted renewal in the SSL state.
    """
    return mark_assisted_renewal(domain)

# -----------------------------
# Dry-run renewal endpoint
# -----------------------------
@router.post("/dry-run")
def ssl_dry_run_endpoint(domain: str = Query(...)):
    """
    Simulates SSL renewal without making any changes.
    Returns a message indicating success/failure.
    """
    domain = normalize_domain(domain)
    try:
        # Inspect SSL locally
        ssl_status, expiry_date = inspect_ssl(domain)
        # Update the observation in ssl_state
        update_ssl_observation(domain, ssl_status=ssl_status, expiry_date=expiry_date)
        return {
            "domain": domain,
            "ssl_status": ssl_status,
            "expiry_date": expiry_date,
            "message": f"Dry-run complete. SSL status: {ssl_status}, expires: {expiry_date}"
        }
    except Exception as e:
        return {
            "domain": domain,
            "ssl_status": "unknown",
            "expiry_date": None,
            "message": f"Dry-run failed: {str(e)}"
        }

# -----------------------------
# Actual renewal endpoint
# -----------------------------
@router.post("/renew")
def renew_ssl_endpoint(domain: str = Query(...)):
    """
    Performs real SSL renewal using Certbot.
    Updates SSL state after completion.
    """
    domain = normalize_domain(domain)
    try:
        process = subprocess.run(
            ["certbot", "renew", "--cert-name", domain, "--quiet"],
            capture_output=True,
            text=True
        )

        if process.returncode == 0:
            ssl_status, expiry_date = inspect_ssl(domain)
            update_ssl_observation(domain, ssl_status=ssl_status, expiry_date=expiry_date)
            return {
                "domain": domain,
                "ssl_status": ssl_status,
                "expiry_date": expiry_date,
                "message": "Renewal successful."
            }

        else:
            return {
                "domain": domain,
                "ssl_status": "unknown",
                "expiry_date": None,
                "message": f"Renewal failed: {process.stderr}"
            }

    except Exception as e:
        return {
            "domain": domain,
            "ssl_status": "unknown",
            "expiry_date": None,
            "message": f"Renewal exception: {str(e)}"
        }
