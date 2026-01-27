from fastapi import APIRouter

router = APIRouter()

@router.get("/traffic/{domain}")
def traffic_card(domain: str):
    return {"visitors_30d": None, "status": "Beta"}
