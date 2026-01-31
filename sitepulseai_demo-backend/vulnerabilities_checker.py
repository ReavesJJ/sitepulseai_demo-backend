# sitepulseai_demo-backend/vulnerabilities_checkers.py

from fastapi import APIRouter, Query
from vulnerabilities import scan_domain

router = APIRouter()

@router.get("/vulnerabilities/{domain}")
def vuln_card(domain: str = Query(...)):
    """
    Vulnerability card endpoint.
    Delegates to authoritative scanners.
    """
    result = scan_domain(domain)
    # Safe fallback
    if not result or "findings" not in result or "counts" not in result:
        return {"findings": [], "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}}
    return result
