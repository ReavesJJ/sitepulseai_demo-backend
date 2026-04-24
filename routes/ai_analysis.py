from fastapi import APIRouter, Header, HTTPException
from typing import Optional

from services.ai_engine import generate_analysis

router = APIRouter(prefix="/ai", tags=["AI Analysis"])


@router.post("/analyze")
def analyze(
    payload: dict,
    x_ai_provider: Optional[str] = Header("openai"),
    x_ai_key: Optional[str] = Header(None)
):

    if not x_ai_key:
        raise HTTPException(status_code=403, detail="AI API key required")

    try:
        result = generate_analysis(payload, x_ai_provider, x_ai_key)

        return {
            "provider": x_ai_provider,
            "analysis": result
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))