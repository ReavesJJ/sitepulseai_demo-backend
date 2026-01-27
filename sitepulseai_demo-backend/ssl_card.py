from fastapi import APIRouter
from ssl_utils import get_ssl_certificate, evaluate_ssl_policy

ssl_router = APIRouter(prefix="/ssl", tags=["ssl"])

@ssl_router.get("/{domain}")
def ssl_card(domain: str):
    cert = get_ssl_certificate(domain)
    policy = evaluate_ssl_policy(domain)
    return {
        "domain": domain,
        "valid": cert.get("valid", False),
        "issuer": cert.get("issuer"),
        "subject": cert.get("subject"),
        "expires_in_days": cert.get("expires_in_days"),
        "managed": policy.get("managed", False),
    }
