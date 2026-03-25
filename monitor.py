import time
import httpx
from bs4 import BeautifulSoup

# ---------------------------
# Single website check
# ---------------------------
def check_website(url: str):
    result = {
        "url": url,
        "timestamp": time.time(),
        "status_code": None,
        "load_time": None,
        "title": None,
        "meta_description": None,
        "alerts": [],
    }

    try:
        start = time.time()
        response = httpx.get(url, timeout=10)
        duration = time.time() - start

        result["status_code"] = response.status_code
        result["load_time"] = round(duration, 2)

        if response.status_code != 200:
            result["alerts"].append(f"Non-200 status: {response.status_code}")

        soup = BeautifulSoup(response.text, "html.parser")
        result["title"] = soup.title.string if soup.title else None

        meta_desc = soup.find("meta", attrs={"name": "description"})
        if meta_desc and meta_desc.get("content"):
            result["meta_description"] = meta_desc["content"]
        else:
            result["alerts"].append("Missing meta description")

    except Exception as e:
        result["alerts"].append(f"Error: {str(e)}")

    return result

# ---------------------------
# Full check for a domain
# ---------------------------
def run_full_check(domain):
    """
    Runs all monitoring checks for a single domain.
    Returns a dictionary of results.
    """
    results = {}

    # 1️⃣ Core website check
    website_metrics = check_website(f"https://{domain}")
    results["website"] = website_metrics

    # 2️⃣ Placeholder for other metrics (SSL, uptime, vulnerabilities, etc.)
    # These can be filled with actual functions later
    # Example:
    # results["ssl"] = check_ssl(domain)
    # results["uptime"] = check_uptime(domain)
    # results["seo"] = check_seo(domain)

    return results





