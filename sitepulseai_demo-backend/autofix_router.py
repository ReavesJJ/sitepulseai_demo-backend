# autofix_router.py
from fastapi import APIRouter
from autofix_engine import execute_remediation
from datetime import datetime

router = APIRouter(
    prefix="/autofix",
    tags=["AutoFix"]
)

@router.post("/execute")
def run_autofix(payload: dict):
    """
    Executes remediation actions sent from the dashboard.
    """
    try:
        result = execute_remediation(payload)
        return {
            "status": "executed",
            "result": result,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "status": "failed",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }
