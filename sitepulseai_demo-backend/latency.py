# latency.py
from fastapi import APIRouter, Path
import httpx
import time
import asyncio

router = APIRouter(prefix="/latency", tags=["latency"])

@router.get("/{domain}")
async def latency_card(domain: str = Path(..., description="Website domain")):
    url = f"https://{domain}"

    try:
        start = time.perf_counter()

        async with httpx.AsyncClient(
            timeout=5.0,
            follow_redirects=True
        ) as client:
            resp = await asyncio.wait_for(
                client.get(url),
                timeout=6.0
            )

        latency_ms = round((time.perf_counter() - start) * 1000, 2)

        return {
            "status": "ok",
            "scanner": "latency",
            "domain": domain,
            "data": {
                "response_time_ms": latency_ms,
                "online": resp.status_code == 200
            }
        }

    except asyncio.TimeoutError:
        return {
            "status": "error",
            "scanner": "latency",
            "domain": domain,
            "data": {
                "response_time_ms": None,
                "online": False
            },
            "error": "Latency check timed out"
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
