# main.py
from fastapi import FastAPI, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import requests, ssl, socket, time, os
from dotenv import load_dotenv
# SSL automation router
from ssl_state import set_ssl_state
import openai
from urllib.parse import urlparse
from ssl_automation import router as ssl_router
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="SitePulseAI Demo Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def root():
    return {"status": "SitePulseAI backend running"}

@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "sitepulseai_demo_backend"
    }


app.include_router(ssl_router)





def normalize_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname or url





# Load OpenAI API key
load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")


# -----------------------------
# FastAPI app
# -----------------------------








# -----------------------------
# In-memory traffic log
# -----------------------------
traffic_log = {}

# -----------------------------
# Vulnerability scan model
# -----------------------------
class VulnerabilityRequest(BaseModel):
    url: str

# -----------------------------
# Root / Health endpoint
# -----------------------------
@app.get("/")
def root():
    return {"message": "SitePulseAI Backend is live."}

# -----------------------------
# Website Summary endpoint
# -----------------------------
@app.get("/summary")
async def get_site_summary(
    url: str = Query(..., description="URL of site to monitor")
):
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

        # Persist SSL state (DOMAIN ONLY)
        set_ssl_state(
            domain=domain,
            ssl_valid=ssl_status == "valid",
            issuer=None,
            expires_at=None,
            days_remaining=None
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
class SiteRequest(BaseModel):
    url: str

@app.post("/track-visit")
def track_visit(site: SiteRequest):
    url = site.url
    traffic_log[url] = traffic_log.get(url, 0) + 1
    return {"status": "tracked", "visits": traffic_log[url]}

@app.get("/traffic")
def get_traffic(url: str):
    return {"total_visits": traffic_log.get(url, 0)}

# -----------------------------
# Utility functions
# -----------------------------
def check_uptime(url):
    try:
        res = requests.get(url, timeout=6)
        return "Online" if res.status_code == 200 else "Offline"
    except:
        return "Offline"

def get_response_time(url):
    try:
        start = time.time()
        requests.get(url, timeout=6)
        return f"{int((time.time() - start) * 1000)}ms"
    except:
        return "N/A"

def check_ssl_validity(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or url
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
        return "valid"
    except:
        return "invalid"

def check_seo_tags(url):
    try:
        html = requests.get(url, timeout=6).text.lower()
        missing = []
        if "<meta name=\"description\"" not in html: missing.append("description")
        if "<meta name=\"keywords\"" not in html: missing.append("keywords")
        if "<title>" not in html: missing.append("title")
        return "All tags present" if not missing else "Missing: " + ", ".join(missing)
    except:
        return "SEO check failed"

def detect_common_vulnerabilities(url):
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
