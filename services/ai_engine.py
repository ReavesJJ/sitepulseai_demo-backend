from fastapi import APIRouter, Header, HTTPException
from typing import Optional
import os
from openai import OpenAI

router = APIRouter(prefix="/ai", tags=["AI Analysis"])

client = OpenAI()

SYSTEM_PROMPT = """
You are an infrastructure monitoring interpretation layer for SitePulseAI.

Your role is to interpret structured telemetry and present it in clear, professional, non-technical language.

RULES:
- Do NOT invent data
- Do NOT exaggerate severity
- Do NOT use alarmist language
- Do NOT issue commands (no "fix", "patch", "must")
- Use calm, observational tone
- Translate technical findings into plain English
- Focus on clarity for non-technical stakeholders

OUTPUT FORMAT:

Current Status:
(1-2 sentence summary)

Key Observations:
- Bullet points

Why It Matters:
(Explain impact in simple terms)

Suggested Considerations:
(Soft guidance only, no commands)

Confidence Note:
(Short statement about telemetry-based interpretation)
"""

@router.post("/analyze")
def analyze(payload: dict, x_openai_key: Optional[str] = Header(None)):

    api_key = x_openai_key or os.getenv("OPENAI_API_KEY")

    if not api_key:
        raise HTTPException(status_code=403, detail="AI disabled")

    # Build structured input (IMPORTANT)
    user_input = f"""
Domain: {payload.get('domain')}

SSL Status: {payload.get('ssl')}

Vulnerabilities Detected: {payload.get('vulnerabilities')}

SEO Signals: {payload.get('seo')}

Security Headers: {payload.get('headers')}
"""

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        temperature=0.2,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_input}
        ]
    )

    content = response.choices[0].message.content

    return {
        "analysis": content
    }