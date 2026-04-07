# sitepulseai_demo-backend/vulnerabilities_checkers.py
from fastapi import APIRouter
from vulnerabilities import scan_domain
import asyncio


router = APIRouter(
    prefix="/vulnerabilities",
    tags=["Vulnerabilities"]
)

async def async_scan_domain(domain: str) -> dict:
    """
    Async wrapper for scan_domain to return safe fallback on failure.
    """
    try:
        result = await asyncio.to_thread(scan_domain, domain)
    except Exception:
        result = None


    # Fallback to prevent frontend errors
    if not result or "findings" not in result or "counts" not in result:
        return {
    "domain": domain,
    "findings": [],
    "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
    "risk_score": 0,
    "status": "degraded"
}
    
    # Calculate a simple real-time risk score based on severity counts
    counts = result.get("counts", {})
    risk_score = (
        counts.get("critical", 0) * 5 +
        counts.get("high", 0) * 3 +
        counts.get("medium", 0) * 2 +
        counts.get("low", 0) * 1
    )
    result["risk_score"] = risk_score
    result["domain"] = domain
    return result
    

def classify_risk(score):
    if score >= 15:
        return "CRITICAL"
    elif score >= 8:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    return "LOW"




@router.get("/{domain}")
async def vuln_card(domain: str):
    result = await async_scan_domain(domain)

    return {
        "status": "ok",
        "service": "vulnerability",
        "data": result
    }