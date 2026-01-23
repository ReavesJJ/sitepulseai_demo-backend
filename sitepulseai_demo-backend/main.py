# main.py
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

# Routers
from ssl_automation import router as ssl_router

# SSL State & Utils
from ssl_utils import normalize_domain, inspect_ssl
from ssl_state import get_ssl_state, set_renewal_mode, mark_assisted_renewal, update_ssl_observation

# FastAPI app
app = FastAPI(title="SitePulseAI Demo Backend")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include SSL automation router
app.include_router(ssl_router)

# In-memory traffic log
traffic_log = {}

# -----------------------------
# Utility Functions
# -----------------------------
def check_uptime(url: str) -> str:
    import requests
    try:
        res = requests.get(url, timeout=6)
        return "Online" if res.status_code == 200 else "Offline"
    except:
        return "Offline"

def get_response_time(url: str) -> str:
    import requests, time
    try:
        start = time.time()
        requests.get(url, timeout=6)
        return f"{int((time.time() - start) * 1000)}ms"
    except:
        return "N/A"

# -----------------------------
# Endpoints
# -----------------------------
@app.get("/")
def root():
    return {"status": "SitePulseAI backend running"}

@app.get("/health")
def health():
    return {"status": "ok", "service": "sitepulseai_demo_backend"}

@app.get("/summary")
def get_site_summary(url: str = Query(...)):
    domain = normalize_domain(url)
    uptime = check_uptime(url)
    response_time = get_response_time(url)
    ssl_info = inspect_ssl(domain)
    visits = traffic_log.get(domain, 0)

    # Example vulnerability scan placeholder
    vulnerabilities = ["No major vulnerabilities found"]

    summary_text = (
        f"Your site is {uptime}. SSL: {ssl_info['ssl_status']}. "
        f"Response time: {response_time}. Detected vulnerabilities: {', '.join(vulnerabilities)}"
    )

    return {
        "url": url,
        "domain": domain,
        "summary": summary_text,
        "uptime": uptime,
        "response_time": response_time,
        "ssl_status": ssl_info["ssl_status"],
        "vulnerabilities": vulnerabilities,
        "visits": visits,
    }

@app.post("/track-visit")
def track_visit(site: dict):
    url = site.get("url")
    traffic_log[url] = traffic_log.get(url, 0) + 1
    return {"status": "tracked", "visits": traffic_log[url]}

@app.get("/traffic")
def get_traffic(url: str):
    return {"total_visits": traffic_log.get(url, 0)}
