# main.py

from fastapi import FastAPI, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import requests, ssl, socket, time, os
from dotenv import load_dotenv
from urllib.parse import urlparse

from ssl_state import set_ssl_state
from ssl_automation import router as ssl_router

# -----------------------------
# App init (ONE instance only)
# -----------------------------
app = FastAPI(title="SitePulseAI Demo Backend")

# -----------------------------
# CORS (nuclear-safe for demo)
# -----------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          
    allow_credentials=False,      
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------
# Routers
# -----------------------------
app.include_router(ssl_router)

# -----------------------------
# Env
# -----------------------------
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# -----------------------------
# In-memory traffic log
# -----------------------------
traffic_log = {}

# -----------------------------
# Models
# -----------------------------
class SiteRequest(BaseModel):
    url: str

# -----------------------------
# Helpers
# -----------------------------
def normalize_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname or url

# -----------------------------
# Root / Health
# -----------------------------
@app.get("/")
def root():
    return {"status": "SitePulseAI backend running"}

@app.get("/health")
def health():
    return {"status": "ok", "service": "sitepulseai_demo_backend"}

# -----------------------------
# Summary
# -----------------------------
@app.get("/summary")
async def get_site_summary(url: str = Query(...)):
    domain = normalize_domain(url)

    uptime = check_uptime(url)
    response_time = get_response_time(url)
    ssl_status = check_ssl_validity(url)
    seo_status = check_seo_tags(url)
    vulnerabilities = detect_common_vulnerabilities(url)

    visits = traffic_log.get(domain, 0)

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
        "uptime": uptime,
        "response_time": response_time,
        "ssl_status": ssl_status,
        "seo_status": seo_status,
        "vulnerabilities": vulnerabilities,
        "visits": visits,
    }

# -----------------------------
# Track visits
# -----------------------------
@app.post("/track-visit")
def track_visit(site: SiteRequest):
    domain = normalize_domain(site.url)
    traffic_log[domain] = traffic_log.get(domain, 0) + 1

    return {
        "status": "tracked",
        "domain": domain,
        "visits": traffic_log[domain],
    }

# -----------------------------
# SSL direct endpoint (dashboard-safe)
# -----------------------------
@app.get("/ssl/state")
def ssl_state(domain: str):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        return {
            "domain": domain,
            "ssl_status": "Valid",
            "expires": cert.get("notAfter"),
        }

    except Exception as e:
        return {
            "domain": domain,
            "ssl_status": "Invalid",
            "error": str(e),
        }

# -----------------------------
# Utilities
# -----------------------------
def check_uptime(url):
    try:
        r = requests.get(url, timeout=6)
        return "Online" if r.status_code == 200 else "Offline"
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
        hostname = normalize_domain(url)
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
        if '<meta name="description"' not in html: missing.append("description")
        if '<meta name="keywords"' not in html: missing.append("keywords")
        if "<title>" not in html: missing.append("title")
        return "All tags present" if not missing else "Missing: " + ", ".join(missing)
    except:
        return "SEO check failed"

def detect_common_vulnerabilities(url):
    try:
        r = requests.get(url, timeout=6)
        headers = r.headers
        html = r.text.lower()
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
            if any(v in html for v in ["1.12", "1.7", "1.8"]):
                issues.append("Outdated jQuery version detected")

        return issues if issues else ["No major vulnerabilities found"]

    except Exception as e:
        return [f"Error during scan: {str(e)}"]
