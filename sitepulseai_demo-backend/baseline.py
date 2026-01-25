from fastapi import APIRouter, HTTPException
from scanners import run_full_scan
from persistence import save_baseline

router = APIRouter()

@router.post("/baselines/{domain}")
async def create_baseline(domain: str):
    try:
        baseline = run_full_scan(domain)
        save_baseline(domain, baseline)

        return {
            "status": "baseline_created",
            "domain": domain
        }

    except Exception as e:
        print("BASELINE ERROR:", e)
        raise HTTPException(status_code=500, detail=str(e))
