# main.py
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import requests, time
from urllib.parse import urlparse

from ssl_utils import inspect_ssl, normalize_domain
from ssl_state import get_ssl_state, update_ssl_observation
from ssl_automation import router as ssl_router

app = FastAPI(title="SitePulseAI Demo Backend")

# -----------------------------
# CORS
# -----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"]
)

# -----------------------------
# Root / Health
# -----------------------------
@app.get("/")
def root():
    return {"status": "SitePulseAI backend running"}

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "sitepulseai_demo_backend"
    }

# -----------------------------
# In-memory traffic log
# -----------------------------
traffic_log = {}

class SiteRequest(BaseModel):
    url: str

# -----------------------------
# Utility functions
# -----------------------------

def check_uptime(url: str) -> str:
    try:
        res = requests.get(url, timeout=6)
        return "Online" if res.status_code == 200 else "Offline"
    except:
        return "Offline"


def get_response_time(url: str) -> str:
    try:
        start = time.time()
        requests.get(url, timeout=6)
        return f"{int((time.time() - start) * 1000)}ms"
    except:
        return "N/A"


def check_seo_tags(url: str) -> str:
    try:
        html = requests.get(url, timeout=6).text.lower()
        missing = []
        if '<meta name="description"' not in html:
            missing.append("description")
        if '<meta name="keywords"' not in html:
            missing.append("keywords")
        if '<title>' not in html:
            missing.append("title")
        return "All tags present" if not missing else "Missing: " + ", ".join(missing)
    except:
        return "SEO check failed"


def detect_common_vulnerabilities(url: str):
    try:
        response = requests.get(url, timeout=6)
        headers = response.headers
        html = response.text.lower()
        issues = []

        if "x-content-type-options" not in headers:
            issues.append("Missing X-Content-Type-Options header")
        if "x-frame-options" not in headers:
            issues.append("Missing X-Frame-Options header")
        if "content-security-policy" not in headers:
            issues.append("Missing Content-Security-Policy header")
        if "strict-transport-security" not in headers:
            issues.append("Missing Strict-Transport-Security header")
        if "/admin" in html or "wp-admin" in html:
            issues.append("Exposed admin interface detected")
        if "jquery" in html:
            if any(ver in html for ver in ["1.12", "1.7", "1.8"]):
                issues.append("Outdated jQuery version detected")

        return issues if issues else ["No major vulnerabilities found"]
    except Exception as e:
        return [f"Error during scan: {str(e)}"]

# -----------------------------
# Summary endpoint
# -----------------------------
@app.get("/summary")
def get_site_summary(url: str = Query(..., description="URL of site to monitor")):
    domain = normalize_domain(url)

    try:
        uptime = check_uptime(url)
        response_time = get_response_time(url)
        seo_status = check_seo_tags(url)
        vulnerabilities = detect_common_vulnerabilities(url)
        visits = traffic_log.get(domain, 0)

        # Canonical SSL inspection
        ssl_result = inspect_ssl(domain)

        update_ssl_observation(
            domain=domain,
            ssl_valid=ssl_result.get("ssl_valid"),
            issuer=ssl_result.get("issuer"),
            expires_at=ssl_result.get("expires_at"),
            days_remaining=ssl_result.get("days_remaining")
        )

        ssl_status = ssl_result.get("status")

        summary_text = (
            f"Your site is {uptime}. SSL: {ssl_status}. "
            f"Response time: {response_time}. SEO: {seo_status}. "
            f"Detected vulnerabilities: {'; '.join(vulnerabilities)}"
        )

        return {
            "url": url,
            "domain": domain,
            "summary": summary_text,
            "uptime": uptime,
            "response_time": response_time,
            "ssl_status": ssl_status,
            "seo_status": seo_status,
            "vulnerabilities": vulnerabilities,
            "visits": visits,
        }

    except Exception as e:
        return {"error": str(e)}

# -----------------------------
# Track site traffic
# -----------------------------
@app.post("/track-visit")
def track_visit(site: SiteRequest):
    domain = normalize_domain(site.url)
    traffic_log[domain] = traffic_log.get(domain, 0) + 1
    return {"status": "tracked", "visits": traffic_log[domain]}


@app.get("/traffic")
def get_traffic(url: str):
    domain = normalize_domain(url)
    return {"total_visits": traffic_log.get(domain, 0)}

# -----------------------------
# SSL Automation router
# -----------------------------
app.include_router(ssl_router)
