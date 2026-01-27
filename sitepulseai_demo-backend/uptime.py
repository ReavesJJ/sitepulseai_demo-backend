# uptime.py
from fastapi import APIRouter
import requests
import time

uptime_router = APIRouter(prefix="/uptime", tags=["uptime"])
latency_router = APIRouter(prefix="/latency", tags=["latency"])

@uptime_router.get("/{domain}")
def uptime_card(domain: str):
    url = f"https://{domain}"
    try:
        start = time.time()
        response = requests.get(url, timeout=10)
        response_time = round((time.time() - start) * 1000, 2)
        return {
            "status": "Online" if response.status_code < 500 else "Offline",
            "response_time_ms": response_time
        }
    except requests.exceptions.RequestException as e:
        return {
            "status": "Offline",
            "response_time_ms": None,
            "error": str(e)
        }

@latency_router.get("/{domain}")
def latency_card(domain: str):
    url = f"https://{domain}"
    try:
        start = time.time()
        requests.get(url, timeout=10)
        response_time = round((time.time() - start) * 1000, 2)
        return {"response_time_ms": response_time}
    except:
        return {"response_time_ms": None}
