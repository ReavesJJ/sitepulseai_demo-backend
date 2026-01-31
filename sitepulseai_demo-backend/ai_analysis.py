from fastapi import APIRouter, Header, HTTPException
from typing import Optional
import openai
import os

router = APIRouter(prefix="/ai", tags=["AI Analysis"])

@router.post("/analyze")
def analyze(payload: dict, x_openai_key: Optional[str] = Header(None)):
    api_key = x_openai_key or os.getenv("OPENAI_API_KEY")

    if not api_key:
        raise HTTPException(status_code=403, detail="AI disabled")

    openai.api_key = api_key

    prompt = f"""
You are a security and SEO auditor.

Domain: {payload['domain']}

SSL:
{payload['ssl']}

Vulnerabilities:
{payload['vulnerabilities']}

SEO:
{payload['seo']}

Headers:
{payload['headers']}

Provide:
1) Executive summary (plain English)
2) Prioritized recommendations
"""

    response = openai.ChatCompletion.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3
    )

    content = response.choices[0].message.content

    # Simple split for UI
    parts = content.split("Recommendations:")

    return {
        "summary": parts[0].strip(),
        "recommendations": parts[1].strip().split("\n") if len(parts) > 1 else []
    }
