# latency.py
from fastapi import APIRouter, Query
import httpx
import time

router = APIRouter(prefix="/latency", tags=["latency"])

@router.get("/{domain}")
async def latency_card(domain: str = Query(..., description="Website domain")):
    url = f"https://{domain}"
    try:
        start = time.perf_counter()
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(url)
        end = time.perf_counter()
        latency_ms = round((end - start) * 1000, 2)
        return {"domain": domain, "response_time_ms": latency_ms, "status": "Online" if resp.status_code == 200 else "Offline"}
    except Exception as e:
        return {"domain": domain, "response_time_ms": None, "status": "Offline", "error": str(e)}
