from fastapi import APIRouter, Path
from vulnerabilities_checker import scan_headers

vuln_router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])

@vuln_router.get("/{domain}")
def vulnerabilities_card(domain: str):
    findings = scan_headers(domain)
    return {"findings": findings or []}
