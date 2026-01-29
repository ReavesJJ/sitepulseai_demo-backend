# autofix_router.py

from fastapi import APIRouter, Query
from typing import List
from autofix_engine import execute_remediation
from remediation_store import get_pending_remediations, clear_remediations

router = APIRouter(prefix="/autofix", tags=["autofix"])

@router.post("/run")
async def run_autofix(sites: List[str] = Query(..., description="List of website URLs to autofix")):
    """
    Execute Auto-Fix for all provided sites.
    Returns a list of executed remediation results.
    """
    results = []

    # Generate pending remediation tasks for demonstration purposes
    # In production, you could dynamically generate these based on scan results
    for site in sites:
        # Example tasks: SSL expired, weak protocols, missing headers
        pending_tasks = [
            {"remediation_id": f"{site}-ssl-expired", "vuln_id": "ssl_expired", "site": site},
            {"remediation_id": f"{site}-ssl-weak", "vuln_id": "ssl_weak_protocols", "site": site},
            {"remediation_id": f"{site}-headers", "vuln_id": "missing_security_headers", "site": site},
        ]
        for task in pending_tasks:
            result = execute_remediation(task)
            results.append(result)

    # Optional: clear store after execution to avoid duplicates
    clear_remediations()

    return {"executed_fixes": results, "count": len(results)}
