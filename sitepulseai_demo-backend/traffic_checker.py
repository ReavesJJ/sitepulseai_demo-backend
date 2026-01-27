from fastapi import APIRouter, Path
from traffic_checker import get_traffic

traffic_router = APIRouter(prefix="/traffic", tags=["traffic"])

@traffic_router.get("/{domain}")
def traffic_card(domain: str):
    traffic = get_traffic(domain)
    return {
        "visitors_30d": traffic.get("visitors_30d"),
        "status": traffic.get("status")
    }
