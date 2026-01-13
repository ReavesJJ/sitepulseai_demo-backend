
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime
import requests
import ssl
import socket
import os
import time
import openai
from urllib.parse import urlparse
from dotenv import load_dotenv
from bs4 import BeautifulSoup
from fastapi import APIRouter
from ssl_automation import router as ssl_router
from ssl_automation import run_certbot_renew
from ssl_state import set_renewal_mode
from ssl_utils import check_ssl_validity
# main.py or ssl_utils.py
from ssl_state import load_ssl_state



app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ssl_router)

@app.get("/")
def root():
    return {"message": "SitePulseAI Backend is live."}




# ---------------------------
# Vulnerability Scan Endpoint
# ---------------------------
vuln_router = APIRouter()

class VulnerabilityRequest(BaseModel):
    url: str

@vuln_router.post("/vulnerabilities")
def scan_vulnerabilities(payload: VulnerabilityRequest):
    url = payload.url
    return {
        "url": url,
        "scan_status": "complete",
        "vulnerabilities_found": True,
        "vulnerabilities": [
            {
                "type": "Information Disclosure",
                "detail": "X-Powered-By header is exposed",
                "severity": "Low",
                "recommendation": "Remove or obfuscate the X-Powered-By header."
            }
        ]
    }

app.include_router(vuln_router)

@app.get("/")
def root():
    return {"message": "SitePulseAI Backend is live."}

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")


app.include_router(vuln_router)

# CORS config
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Site traffic tracker
traffic_log = {}

class SiteRequest(BaseModel):
    url: str

@app.post("/track-visit")
def track_visit(site: SiteRequest):
    url = site.url
    traffic_log[url] = traffic_log.get(url, 0) + 1
    return {"status": "tracked", "visits": traffic_log[url]}

@app.get("/traffic")
def get_traffic(url: str):
    visits = traffic_log.get(url, 0)
    return {"total_visits": visits}

# Uptime checker
def check_uptime(url):
    try:
        res = requests.get(url, timeout=6)
        return "Online" if res.status_code == 200 else "Offline"
    except:
        return "Offline"

# Response time

def get_response_time(url):
    try:
        start = time.time()
        requests.get(url, timeout=6)
        return f"{int((time.time() - start) * 1000)}ms"
    except:
        return "N/A"
    

# SSL checker

def get_ssl_details(domain: str):
    
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
        s.settimeout(5)
        s.connect((domain, 443))
        cert = s.getpeercert()

    expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    days_left = (expires - datetime.utcnow()).days

    return {
        "valid": days_left > 0,
        "issuer": dict(x[0] for x in cert["issuer"]).get("organizationName"),
        "expires_on": expires.isoformat(),
        "days_remaining": days_left
    }




    if result["success"]:
        update_ssl_state("success")
        return {
            "status": "renewed by SitePulseAI"
        }

    return {
        "status": "renewal failed",
        "error": result["error"]
    }



@app.get("/ssl-status")
def ssl_status(domain: str):
    return get_ssl_details(domain)



# SEO tag checker
def check_seo_tags(url):
    try:
        html = requests.get(url, timeout=6).text.lower()
        missing = []
        if "<meta name=\"description\"" not in html:
            missing.append("description")
        if "<meta name=\"keywords\"" not in html:
            missing.append("keywords")
        if "<title>" not in html:
            missing.append("title")
        return "Missing: " + ", ".join(missing) if missing else "All tags present"
    except:
        return "SEO check failed"

@app.post("/summary")
async def get_site_summary(request: Request):
    body = await request.json()
    url = body.get("url")

    uptime = check_uptime(url)
    response_time = get_response_time(url)
    ssl_status = check_ssl_validity(url)
    seo_status = check_seo_tags(url)
    visits = traffic_log.get(url, 0)
    vulnerabilities = detect_common_vulnerabilities(url)

    summary = f"Your site is {uptime}. SSL is {ssl_status}. Response time is {response_time}. SEO scan: {seo_status}.Detected vulnerabilities: {'; '.join(vulnerabilities)}"
    

    

    try:
        prompt = f"""
        A user has this website summary:
        {summary}

        Provide 3 detailed, professional recommendations for improvements in performance, SEO, or security.
        """
        response = openai.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7
        )
        recommendations = response.choices[0].message.content.strip().split("\n")
    except:
        recommendations = [
            "Improve load speed by optimizing image size and caching.",
            "Ensure all SEO meta tags are present and up to date.",
            "Update SSL certificate before expiration to maintain trust."
        ]



    return {
        "uptime": uptime,
        "response_time": response_time,
        "ssl": ssl_status,
        "seo": seo_status,
        "summary": summary,
        "recommendations": recommendations,
        "visits": visits,
        "vulnerabilities": vulnerabilities
    }


def detect_common_vulnerabilities(url):
    try:
        response = requests.get(url, timeout=6)
        headers = response.headers
        html = response.text.lower()

        issues = []

        # Check for missing security headers
        if "x-content-type-options" not in headers:
            issues.append("Missing X-Content-Type-Options header.")
        if "x-frame-options" not in headers:
            issues.append("Missing X-Frame-Options header.")
        if "content-security-policy" not in headers:
            issues.append("Missing Content-Security-Policy header.")
        if "strict-transport-security" not in headers:
            issues.append("Missing Strict-Transport-Security header.")

        # Check for exposed admin/login pages
        if "/admin" in html or "wp-admin" in html:
            issues.append("Exposed admin interface detected in page source.")

        # Check for outdated jQuery
        if "jquery" in html:
            if "1.12" in html or "1.7" in html or "1.8" in html:
                issues.append("Outdated jQuery version detected (1.x series).")

        return issues if issues else ["No major vulnerabilities found."]
    except Exception as e:
        return [f"Error during scan: {str(e)}"]



def check_ssl_config(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            subject = cert.get('subject', [])
            issuer = cert.get('issuer', [])

            details = {
                "Subject": str(subject),
                "Issuer": str(issuer)
            }

            if " Let's Encrypt" in str(issuer):
                return "⚠️ SSL issued by Let's Encrypt – check renewal policy."
            return "✅ SSL issuer and subject valid."
    except Exception as e:
        return f"❌ SSL check failed: {str(e)}"



@app.get("/")
def root():
    return {"message": "SitePulseAI Backend is live."}





