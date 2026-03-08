from fastapi import APIRouter
import requests
import time

router = APIRouter()

@router.get("/uptime/{domain}")
def uptime_card(domain: str):
    url = f"https://{domain}"
    try:
        start = time.time()
        r = requests.get(url, timeout=5)
        latency_ms = int((time.time() - start) * 1000)
        status = "Online" if r.status_code < 400 else "Offline"
        return {"status": status, "response_time_ms": latency_ms}
    except requests.RequestException:
        return {"status": "Offline", "response_time_ms": None}
