# latency_checker.py
from fastapi import APIRouter, Path
import httpx
import time

# -------------------------------
# Router setup
# -------------------------------
router = APIRouter(
    prefix="/latency",
    tags=["Latency"]
)

# -------------------------------
# Endpoint: GET /latency/{domain}
# -------------------------------
@router.get("/{domain}")
async def latency_card(domain: str = Path(..., description="Website domain")):
    """
    Returns the response time (latency) for a given domain in milliseconds.
    Returns status Online/Offline and handles network errors gracefully.
    """
    url = f"https://{domain}"

    try:
        start_time = time.perf_counter()
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            response = await client.get(url)
        end_time = time.perf_counter()

        latency_ms = round((end_time - start_time) * 1000, 2)
        status = "Online" if response.status_code == 200 else "Offline"

        return {
            "domain": domain,
            "response_time_ms": latency_ms,
            "status": status
        }

    except httpx.RequestError as e:
        # Network or connection errors
        return {
            "domain": domain,
            "response_time_ms": None,
            "status": "Offline",
            "error": str(e)
        }
    except Exception as e:
        # Catch any other unexpected error
        return {
            "domain": domain,
            "response_time_ms": None,
            "status": "Offline",
            "error": f"Unexpected error: {str(e)}"
        }
