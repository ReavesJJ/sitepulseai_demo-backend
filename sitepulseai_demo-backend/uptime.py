import requests


def check_uptime(domain: str):
    try:
        r = requests.get(f"https://{domain}", timeout=10)
        return {
            "status": "up" if r.status_code == 200 else "down",
            "response_time_ms": int(r.elapsed.total_seconds() * 1000),
            "status_code": r.status_code,
        }

    except Exception as e:
        return {
            "status": "down",
            "error": str(e),
            "response_time_ms": None,
            "status_code": None,
        }
