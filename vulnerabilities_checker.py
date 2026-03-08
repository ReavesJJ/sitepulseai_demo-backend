# sitepulseai_demo-backend/vulnerabilities_checkers.py
# sitepulseai_demo-backend/vulnerabilities_checkers.py

from fastapi import APIRouter
from vulnerabilities import scan_domain

router = APIRouter(
    prefix="/vulnerabilities",
    tags=["Vulnerabilities"]
)

@router.get("/{domain}")
def vuln_card(domain: str):
    """
    Unified vulnerability endpoint for the dashboard.
    - Returns SSL/TLS + header findings
    - Includes severity counts
    - Safe fallback if scan fails
    """
    result = scan_domain(domain)

    # Fallback to prevent frontend errors
    if not result or "findings" not in result or "counts" not in result:
        return {
            "findings": [],
            "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}
        }

    return result
