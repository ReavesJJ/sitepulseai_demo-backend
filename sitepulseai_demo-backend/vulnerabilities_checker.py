from fastapi import APIRouter, Path
from vulnerabilities import scan_headers   # <--- correct import

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])

@router.get("/{domain}")
def vuln_card(domain: str = Path(..., description="Domain to scan for vulnerabilities")):
    return scan_headers(domain)
