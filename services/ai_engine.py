from openai import OpenAI
import requests


SYSTEM_PROMPT = """
You are an infrastructure monitoring interpretation layer for SitePulseAI.

- No alarmist language
- No commands
- Non-technical clarity
- Interpret only given telemetry
"""


def generate_analysis(payload: dict, provider: str, api_key: str):

    user_input = f"""
Domain: {payload.get('domain')}
SSL: {payload.get('ssl')}
Vulnerabilities: {payload.get('vulnerabilities')}
SEO: {payload.get('seo')}
Headers: {payload.get('headers')}
"""

    # 🔷 OpenAI
    if provider == "openai":
        client = OpenAI(api_key=api_key)

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            temperature=0.2,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_input}
            ]
        )

        return response.choices[0].message.content

    # 🔷 Claude (Anthropic)
    elif provider == "claude":
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            },
            json={
                "model": "claude-3-haiku-20240307",
                "max_tokens": 500,
                "temperature": 0.2,
                "messages": [
                    {
                        "role": "user",
                        "content": SYSTEM_PROMPT + "\n\n" + user_input
                    }
                ]
            }
        )

        data = response.json()

        return data["content"][0]["text"]

    else:
        return "Unsupported AI provider"