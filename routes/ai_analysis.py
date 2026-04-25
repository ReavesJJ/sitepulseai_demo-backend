# ---------------------------
# SitePulseAI - AI Analysis Layer
# Multi-Model Interpretation Engine (Production)
# ---------------------------

from fastapi import APIRouter, Request
import json
import logging
import time
import concurrent.futures

from services.ai_engine import call_ai_model

router = APIRouter()

# ---------------------------
# CONFIG
# ---------------------------
MODEL_PRIORITY = ["openai", "anthropic", "local"]
MODEL_TIMEOUT = 8  # total timeout for all providers

# ---------------------------
# PROMPT BUILDER
# ---------------------------
def build_interpretation_prompt(domains_data):
    return f"""
You are an infrastructure monitoring interpretation layer.

CRITICAL RULES:
- You DO NOT give commands or recommendations
- You DO NOT act as an authority
- You ONLY describe observed signals and potential risks
- You MUST return valid JSON only (no markdown, no explanations)

OUTPUT FORMAT (STRICT):
{{
  "observations": [string],
  "risks": [string],
  "neutral": [string]
}}

CLASSIFICATION RULES:
- Observations = confirmed healthy or stable signals
- Risks = anything degraded, invalid, vulnerable, expiring, or anomalous
- Neutral = unclear, informational, or inconclusive signals

INPUT DATA:
{domains_data}

RETURN JSON ONLY.
"""


# ---------------------------
# VALIDATION (ZERO TRUST)
# ---------------------------
def validate_ai_output(raw_text):
    try:
        data = json.loads(raw_text)

        if not isinstance(data, dict):
            raise ValueError("Not a JSON object")

        for key in ["observations", "risks", "neutral"]:
            if key not in data or not isinstance(data[key], list):
                raise ValueError(f"Invalid key: {key}")

            # Clean values
            data[key] = [
                str(item).strip()
                for item in data[key]
                if str(item).strip()
            ]

        return data

    except Exception as e:
        logging.warning(f"AI output invalid: {e}")
        return None


# ---------------------------
# FALLBACK (SYSTEM SAFE)
# ---------------------------
def fallback_response(reason="AI unavailable"):
    return {
        "observations": [],
        "risks": [reason],
        "neutral": [],
        "_meta": {
            "provider": "none",
            "latency": None
        }
    }


# ---------------------------
# PROVIDER RUNNER
# ---------------------------
def try_provider(provider, prompt, api_keys):
    try:
        api_key = api_keys.get(provider)

        # Local models may not require a key
        if provider != "local" and not api_key:
            return None

        start = time.time()

        raw = call_ai_model(
            prompt=prompt,
            provider=provider,
            api_key=api_key
        )

        latency = round(time.time() - start, 2)

        if not raw:
            return None

        validated = validate_ai_output(raw)

        if validated:
            return {
                "data": validated,
                "provider": provider,
                "latency": latency
            }

    except Exception as e:
        logging.warning(f"{provider} error: {e}")

    return None


# ---------------------------
# MULTI-MODEL RACE (FASTEST VALID WINS)
# ---------------------------
def run_with_failover(prompt, api_keys):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [
            executor.submit(try_provider, provider, prompt, api_keys)
            for provider in MODEL_PRIORITY
        ]

        try:
            for future in concurrent.futures.as_completed(futures, timeout=MODEL_TIMEOUT):
                result = future.result()

                if result:
                    logging.info(
                        f"{result['provider']} succeeded in {result['latency']}s"
                    )

                    return {
                        **result["data"],
                        "_meta": {
                            "provider": result["provider"],
                            "latency": result["latency"]
                        }
                    }

        except concurrent.futures.TimeoutError:
            logging.warning("All providers timed out")

    return fallback_response("All AI providers failed")


# ---------------------------
# ENDPOINT
# ---------------------------
@router.post("/ai/analyze")
async def analyze(request: Request):
    try:
        body = await request.json()

        domains = body.get("domains", [])
        mode = body.get("mode", "interpretation_not_authority")

        # 🔒 Enforce interpretation-only mode
        if mode != "interpretation_not_authority":
            return fallback_response("Invalid mode")

        # ---------------------------
        # API KEYS (PER PROVIDER)
        # ---------------------------
        api_keys = {
            "openai": request.headers.get("x-openai-key"),
            "anthropic": request.headers.get("x-anthropic-key"),
            "local": None
        }

        # Require at least one usable provider
        if not any(api_keys.values()):
            return fallback_response("No AI providers configured")

        # ---------------------------
        # BUILD PROMPT
        # ---------------------------
        prompt = build_interpretation_prompt(domains)

        # ---------------------------
        # EXECUTE MULTI-MODEL RACE
        # ---------------------------
        result = run_with_failover(prompt, api_keys)

        return result

    except Exception as e:
        logging.error(f"AI analysis failure: {e}")
        return fallback_response("System error")