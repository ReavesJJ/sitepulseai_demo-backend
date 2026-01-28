# latency.py
from fastapi import APIRouter, Path
import httpx
import time

router = APIRouter(prefix="/latency", tags=["latency"])

@router.get("/{domain}")
async def latency_card(domain: str = Path(..., description="Website domain")):
    url = f"https://{domain}"

    try:
        start = time.perf_counter()

        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True
        ) as client:
            resp = await client.get(url)

        end = time.perf_counter()
        latency_ms = round((end - start) * 1000, 2)

        return {
            "status": "ok",
            "scanner": "latency",
            "domain": domain,
            "data": {
                "response_time_ms": latency_ms,
                "online": resp.status_code == 200
            }
        }

    except Exception as e:
        return {
            "status": "error",
            "scanner": "latency",
            "domain": domain,
            "data": {
                "response_time_ms": None,
                "online": False
            },
            "error": str(e)
        }
