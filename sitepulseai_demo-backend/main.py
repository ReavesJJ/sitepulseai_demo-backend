# main.py
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import time
import requests
import socket
import ssl
import os
from urllib.parse import urlparse

# -----------------------------
# SSL / Automation Routers
# -----------------------------
from ssl_automation import router as ssl_router
from ssl_utils import normalize_domain, inspect_ssl
from ssl_state import get_ssl_state, update_ssl_observation

# -----------------------------
# Load environment variables
# -----------------------------
from dotenv import load_dotenv
import openai

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

# -----------------------------
# FastAPI App Setup
# -----------------------------
app = FastAPI(title="SitePulseAI Demo Backend")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change to specific domains in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include SSL router
app.include_router(ssl_router)

# -----------------------------
# In-memory traffic log
# -----------------------------
traffic_log = {}

# -----------------------------
# Pydantic Models
# -----------------------------
class SiteRequest(BaseModel):
    url: str

# -----------------------------
# Utility Functions
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

def check_ssl_validity(domain: str) -> str:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
        return "valid"
    except:
        return "invalid"

def check_seo_tags(url: str) -> str:
    try:
        html = requests.get(url, timeout=6).text.lower()
        missing = []
        if "<meta name=\"description\"" not in html: missing.append("description")
        if "<meta name=\"keywords\"" not in html: missing.append("keywords")
        if "<title>" not in html: missing.append("title")
        return "All tags present" if not missing else "Missing: " + ", ".join(missing)
    except:
        return "SEO check failed"

def detect_common_vulnerabilities(url: str) -> list:
    try:
        response = requests.get(url, timeout=6)
        headers = response.headers
        html = response.text.lower()
        issues = []
        if "x-content-type-options" not in headers: issues.append("Missing X-Content-Type-Options header")
        if "x-frame-options" not in headers: issues.append("Missing X-Frame-Options header")
        if "content-security-policy" not in headers: issues.append("Missing Content-Security-Policy header")
        if "strict-transport-security" not in headers: issues.append("Missing Strict-Transport-Security header")
        if "/admin" in html or "wp-admin" in html: issues.append("Exposed admin interface detected")
        if "jquery" in html:
            if any(ver in html for ver in ["1.12","1.7","1.8"]): issues.append("Outdated jQuery version detected")
        return issues if issues else ["No major vulnerabilities found"]
    except Exception as e:
        return [f"Error during scan: {str(e)}"]

# -----------------------------
# Root / Health Endpoints
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
# Summary Endpoint
# -----------------------------
@app.get("/summary")
def get_site_summary(url: str = Query(..., description="URL of site to monitor")):
    domain = normalize_domain(url)
    try:
        uptime = check_uptime(url)
        response_time = get_response_time(url)
        ssl_status = check_ssl_validity(domain)
        seo_status = check_seo_tags(url)
        vulnerabilities = detect_common_vulnerabilities(url)
        visits = traffic_log.get(domain, 0)

        summary_text = (
            f"Your site is {uptime}. SSL: {ssl_status}. "
            f"Response time: {response_time}. SEO: {seo_status}. "
            f"Detected vulnerabilities: {'; '.join(vulnerabilities)}"
        )

        # Update SSL observation using new utility
        ssl_info = inspect_ssl(domain)
        update_ssl_observation(domain, ssl_info)

        return {
            "url": url,
            "domain": domain,
            "summary": summary_text,
            "uptime": uptime,
            "response_time": response_time,
            "ssl_status": ssl_status,
            "seo_status": seo_status,
            "vulnerabilities": vulnerabilities,
            "visits": visits
        }

    except Exception as e:
        return {"error": str(e)}

# -----------------------------
# Traffic Endpoints
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
