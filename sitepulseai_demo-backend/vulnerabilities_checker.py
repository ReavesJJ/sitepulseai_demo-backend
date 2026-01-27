from fastapi import APIRouter, Path


vuln_router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])

def scan_headers(domain):
    # your implementation
    pass


@vuln_router.get("/{domain}")
def vulnerabilities_card(domain: str):
    findings = scan_headers(domain)
    return {"findings": findings or []}
