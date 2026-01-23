# ssl_automation.py
# ssl_automation.py
from fastapi import APIRouter
from ssl_utils import normalize_domain, inspect_ssl
from ssl_state import (
    get_ssl_state,
    set_renewal_mode,
    mark_assisted_renewal,
    update_ssl_observation
)



router = APIRouter(prefix="/ssl", tags=["SSL Automation"])



@router.get("/state")
def get_ssl_state(domain: str):
    clean_domain = normalize_domain(domain)
    ssl_info = inspect_ssl(domain)


    update_ssl_observation(
    domain=domain,
    ssl_valid=True,
    issuer=None,
    expires_at=None,
    days_remaining=None
)


    

@router.post("/enable-assisted")
def enable_assisted_ssl(domain: str):
    clean_domain = normalize_domain(domain)
    return {"status": "assisted SSL mode enabled", "domain": clean_domain}



@router.post("/assisted-renew")
def assisted_renew(domain: str):
    clean_domain = normalize_domain(domain)





@router.post("/dry-run")
def dry_run_renewal(domain: str):
    clean_domain = normalize_domain(domain)
    return {"message": f"Dry-run successful for {clean_domain} (stub)"}
