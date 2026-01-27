# uptime.py

from fastapi import APIRouter, Path
import time
import requests

router = APIRouter()

@router.get("/uptime/{domain}")
def get_uptime(domain: str):
    start = time.time()
    try:
        resp = requests.get(f"https://{domain}", timeout=10)
        elapsed = int((time.time() - start) * 1000)

        return {
            "domain": domain,
            "status": "Online" if resp.status_code < 500 else "Degraded",
            "response_time_ms": elapsed,
            "status_code": resp.status_code
        }

    except Exception as e:
        return {
            "domain": domain,
            "status": "Offline",
            "response_time_ms": None,
            "error": str(e)
        }
