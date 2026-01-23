# ssl_automation.py
# ssl_automation.py
from fastapi import APIRouter
from ssl_utils import normalize_domain, inspect_ssl

from ssl_state import update_ssl_state

router = APIRouter(prefix="/ssl", tags=["SSL Automation"])

@router.get("/state")
def get_ssl_state(domain: str):
    clean_domain = normalize_domain(domain)
    ssl_info = inspect_ssl(domain)


    update_ssl_state(
        domain=clean_domain,
        ssl_valid=ssl_info["valid"],
        issuer=ssl_info.get("issuer"),
        expires_at=ssl_info.get("expires_at"),
        days_remaining=ssl_info.get("days_remaining")
    )

    return ssl_info

@router.post("/enable-assisted")
def enable_assisted_ssl(domain: str):
    clean_domain = normalize_domain(domain)
    return {"status": "assisted SSL mode enabled", "domain": clean_domain}

@router.post("/assisted-renew")
def assisted_renew(domain: str):
    clean_domain = normalize_domain(domain)
    update_ssl_state(
        domain=clean_domain,
        ssl_valid=True,
        issuer="Stub CA",
        expires_at=None,
        days_remaining=90
    )
    return {"status": "SSL renewed (stub)", "domain": clean_domain}

@router.post("/dry-run")
def dry_run_renewal(domain: str):
    clean_domain = normalize_domain(domain)
    return {"message": f"Dry-run successful for {clean_domain} (stub)"}
