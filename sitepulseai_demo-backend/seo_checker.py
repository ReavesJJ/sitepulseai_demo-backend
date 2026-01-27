from fastapi import APIRouter
from seo_checker import scan_seo

seo_router = APIRouter(prefix="/seo", tags=["seo"])

@seo_router.get("/{domain}")
def seo_card(domain: str):
    seo_data = scan_seo(domain)
    return {
        "score": seo_data.get("score"),
        "status": seo_data.get("status")
    }

