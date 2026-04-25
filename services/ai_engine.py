from openai import OpenAI
import requests
import json

SYSTEM_PROMPT = """
You are an infrastructure monitoring interpretation layer for SitePulseAI.

RULES:
- No commands
- No alarmism
- No opinions beyond telemetry
- Output MUST be valid JSON only

OUTPUT FORMAT:
{
  "observations": [],
  "risks": [],
  "neutral": []
}
"""


# ---------------------------
# OPENAI
# ---------------------------
def call_openai(prompt, api_key):
    client = OpenAI(api_key=api_key)

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        temperature=0.2,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]
    )

    return response.choices[0].message.content


# ---------------------------
# CLAUDE
# ---------------------------
def call_claude(prompt, api_key):
    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        },
        json={
            "model": "claude-3-haiku-20240307",
            "max_tokens": 800,
            "temperature": 0.2,
            "messages": [
                {
                    "role": "user",
                    "content": SYSTEM_PROMPT + "\n\n" + prompt
                }
            ]
        },
        timeout=10
    )

    data = response.json()
    return data["content"][0]["text"]


# ---------------------------
# LOCAL (placeholder)
# ---------------------------
def call_local(prompt, api_key=None):
    # Replace with Ollama / local LLM later
    return json.dumps({
        "observations": [],
        "risks": ["Local model not configured"],
        "neutral": []
    })


# ---------------------------
# MAIN UNIFIED INTERFACE
# ---------------------------
def call_ai_model(prompt, provider="openai", api_key=None):

    try:
        if provider == "openai":
            return call_openai(prompt, api_key)

        elif provider == "anthropic":
            return call_claude(prompt, api_key)

        elif provider == "local":
            return call_local(prompt, api_key)

        else:
            return json.dumps({
                "observations": [],
                "risks": ["Unsupported provider"],
                "neutral": []
            })

    except Exception as e:
        return json.dumps({
            "observations": [],
            "risks": [f"AI error: {str(e)}"],
            "neutral": []
        })