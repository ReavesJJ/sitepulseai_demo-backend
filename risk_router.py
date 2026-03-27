from fastapi import APIRouter
from risk_engine import build_risk

router = APIRouter(prefix="/risk", tags=["Risk"])

@router.get("/{domain}")
def get_risk(domain: str):
    return build_risk(domain)