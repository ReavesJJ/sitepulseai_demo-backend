# latency.py
from fastapi import APIRouter
import time
import requests

router = APIRouter()

@router.get("/latency/{domain}")
def latency_card(domain: str):
    url = domain if domain.startswith("http") else f"https://{domain}"

    start = time.time()
    try:
        r = requests.get(url, timeout=10)
        latency_ms = int((time.time() - start) * 1000)

        return {
            "status": "ok",
            "latency_ms": latency_ms
        }

    except Exception as e:
        return {
            "status": "error",
            "latency_ms": None,
            "error": str(e)
        }
