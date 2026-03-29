# ============================================================
# SitePulseAI Backend
# Licensed Monitoring Infrastructure
# ============================================================

import os
import json
from datetime import datetime
import threading
import time
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests


# -----------------------
# Existing monitoring engine
# -----------------------
from monitoring_engine import add_domain_to_monitoring


# -----------------------
# Routers for each card
# -----------------------
from ssl_automation import router as ssl_router
from uptime import router as uptime_router
from vulnerabilities_checker import router as vulnerabilities_router
from seo_checker import router as seo_router
from traffic_checker import router as traffic_router
from latency_checker import router as latency_router
from autofix_route import router as autofix_router  # Auto-fix routes
from risk_router import router as risk_router


# -----------------------
# Engines / persistence
# -----------------------
import autofix_engine
import remediation_engine
import remediation_store
import persistence

# -----------------------
# Immutable log & attestation
# -----------------------
from immutable_audit_log import write_audit_log
from telemetry_attestation import generate_telemetry_attestation



# -----------------------
# License enforcement
# -----------------------
from license_enforcer import (
    create_license,
    get_license,
    validate_domain,
    check_feature_access
)

# -----------------------
# FastAPI app initialization
# -----------------------
app = FastAPI(
    title="SitePulseAI Backend",
    description="Autonomous website operations agent backend.",
    version="2.3.0"
)

app = FastAPI()



# -----------------------
# Middleware
# -----------------------

# --- CORS ---
origins = ["http://127.0.0.1:5500", "http://localhost:5500"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



# -----------------------
# Include routers
# -----------------------
app.include_router(ssl_router)
app.include_router(uptime_router)
app.include_router(vulnerabilities_router)
app.include_router(seo_router)
app.include_router(traffic_router)
app.include_router(latency_router)
app.include_router(autofix_router)
app.include_router(risk_router)


# -----------------------
# Telemetry Event storage path
# -----------------------
TELEMETRY_DIR = "telemetry_events"
TELEMETRY_FILE = os.path.join(TELEMETRY_DIR, "telemetry_event_log.json")
os.makedirs(TELEMETRY_DIR, exist_ok=True)


# ============================================================
# Existing /monitor endpoint
# ============================================================
@app.post("/monitor")
def monitor(client_id: str = Query(...), domain: str = Query(...)):

    # 1️⃣ Validate license
    license_data = get_license(client_id)

    # 2️⃣ Domain enforcement
    validate_domain(client_id, domain)

    # 3️⃣ Prepare results dict
    results = {"domain": domain, "timestamp": datetime.utcnow().isoformat()}
    features = license_data["features"]



    # -----------------------
    # Tier / feature enforcement
    # -----------------------
    if "ssl" in features:
        check_feature_access(client_id, "ssl")
        results["ssl"] = ssl_router.check_ssl(domain)

    if "uptime" in features:
        check_feature_access(client_id, "uptime")
        results["uptime"] = uptime_router.check_uptime(domain)

    if "seo" in features:
        check_feature_access(client_id, "seo")
        results["seo"] = seo_router.check_seo(domain)

    if "latency" in features:
        check_feature_access(client_id, "latency")
        results["latency"] = latency_router.check_latency(domain)

    if "traffic" in features:
        check_feature_access(client_id, "traffic")
        results["traffic"] = traffic_router.check_traffic(domain)

    if "vulnerabilities" in features:
        check_feature_access(client_id, "vulnerabilities")
        results["vulnerabilities"] = vulnerabilities_router.check_vulnerabilities(domain)


    # -----------------------
    # Immutable audit log
    # -----------------------
    write_audit_log({
        "event": "monitor_run",
        "client_id": client_id,
        "domain": domain,
        "tier": license_data["tier"]
    })



    # -----------------------
    # Telemetry Event Record
    # -----------------------
    try:
        if os.path.exists(TELEMETRY_FILE):
            with open(TELEMETRY_FILE, "r") as f:
                telemetry_events = json.load(f)
        else:
            telemetry_events = []

        previous_hash = telemetry_events[-1]["event_hash"] if telemetry_events else "GENESIS"

        event_record = {
            "event_type": "monitoring_event",
            "event_id": f"SP-{os.urandom(4).hex().upper()}",
            "timestamp": datetime.utcnow().isoformat(),
            "client_id": client_id,
            "domain": domain,
            "monitoring_agent": "SitePulseAI Node",
            "previous_event_hash": previous_hash,
            "results_snapshot": results
        }

        import hashlib
        event_string = json.dumps(event_record, sort_keys=True, default=str)
        event_hash = hashlib.sha256(event_string.encode()).hexdigest()
        event_record["event_hash"] = event_hash

        telemetry_events.append(event_record)
        with open(TELEMETRY_FILE, "w") as f:
            json.dump(telemetry_events, f, indent=2, default=str)

        results["telemetry_event_record"] = event_record

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Telemetry Event failed: {e}")



    # -----------------------
    # Telemetry attestation certificate
    # -----------------------
    certificate = generate_telemetry_attestation(client_id, domain, results)
    results["telemetry_certificate"] = certificate

    return results



# -----------------------
# Endpoint to get latest telemetry event
# -----------------------
@app.get("/telemetry/latest")
def latest_telemetry():
    if not os.path.exists(TELEMETRY_FILE):
        raise HTTPException(status_code=404, detail="No telemetry events found")
    with open(TELEMETRY_FILE, "r") as f:
        telemetry_events = json.load(f)
    return {
        "status": "ok",
        "latest_telemetry_event": telemetry_events[-1]
    }



# -----------------------
# License generation endpoint
# -----------------------
@app.post("/generate_license")
def generate_license(tier: str = Query(...), domains: str = Query(...), expiration_date: str = Query(...)):
    domains_list = [d.strip() for d in domains.split(",")]
    client_id = create_license(tier, domains_list, expiration_date)
    return {"client_id": client_id, "tier": tier, "domains": domains_list, "expiration_date": expiration_date}



# ============================================================
# AUTONOMOUS MONITORING INTEGRATION
# ============================================================

# Persistent domain storage
DOMAINS_FILE = "monitored_domains.json"
MONITOR_INTERVAL = 300  # seconds (5 min)
try:
    with open(DOMAINS_FILE, "r") as f:
        monitored_domains = json.load(f)
except FileNotFoundError:
    monitored_domains = []

# Domain model for /add_url
class DomainRequest(BaseModel):
    domain: str



# Add URL endpoint
GLOBAL_SEGMENTS = {"default": []}

@app.post("/add_url")
def add_url(payload: dict):
    domain = payload.get("domain")
    segment = payload.get("segment", "default")

    if segment not in GLOBAL_SEGMENTS:
        GLOBAL_SEGMENTS[segment] = []

    if domain not in GLOBAL_SEGMENTS[segment]:
        GLOBAL_SEGMENTS[segment].append(domain)

    return {"status": "added", "segments": GLOBAL_SEGMENTS}


@app.get("/segments")
def get_segments():
    return {"segments": GLOBAL_SEGMENTS}


# Internal monitoring trigger
def run_monitor(domain):
    from monitoring_engine import run_full_check
    try:
        results = run_full_check(domain)  # ✅ capture result

        if results:
            print(f"[Monitor OK] {domain}")
        else:
            print(f"[Monitor Warning] {domain} returned no results")

        return results  # ✅ return it

    except Exception as e:
        print(f"[Monitor Exception] {domain}: {e}")
        return None



# Background autonomous monitoring loop
def monitoring_loop():
    while True:
        for domain in monitored_domains:
            run_monitor(domain)
        time.sleep(MONITOR_INTERVAL)


# Start background loop in daemon thread
threading.Thread(target=monitoring_loop, daemon=True).start()


# ============================================================
# ROOT / HEALTH ENDPOINTS
# ============================================================
@app.get("/health")
def health_check():
    return {"status": "OK", "monitored_domains_count": len(monitored_domains)}

@app.get("/")
async def root():
    return {
        "status": "ok",
        "message": "SitePulseAI Backend running",
        "version": "2.3.0"
    }


@app.get("/segments")
def get_segments():
    try:
        with open("domains.json", "r") as f:
            data = json.load(f)
            return data
    except:
        return {"segments": {"default": []}}



@app.get("/vulnerabilities/{domain}")
def check_vulnerabilities(domain: str):
    issues = []

    try:
        url = f"https://{domain}"
        response = requests.get(url, timeout=5)

        headers = response.headers

        # Security headers check
        if "X-Frame-Options" not in headers:
            issues.append("missing_x_frame_options")

        if "Content-Security-Policy" not in headers:
            issues.append("missing_csp")

        if "Strict-Transport-Security" not in headers:
            issues.append("missing_hsts")

        if "X-Content-Type-Options" not in headers:
            issues.append("missing_x_content_type")

        return {
            "count": len(issues),
            "issues": issues
        }

    except:
        return {
            "count": 0,
            "issues": []
        }





# ============================================================
# FASTAPI STARTUP / SHUTDOWN
# ============================================================
@app.on_event("startup")
async def startup_event():
    print("🔥 SitePulseAI Backend startup complete.")
    print("🔐 SSL Automation router loaded.")
    print("⚡ Uptime & Latency router loaded.")
    print("🛡️ Vulnerabilities scanner loaded.")
    print("📈 SEO scanner loaded.")
    print("📊 Traffic scanner loaded.")
    print("🛠️ Remediation Engine ready.")
    print("📦 Persistence layer ready.")
    print("🤖 Auto-Fix engine ready (skeleton).")
    os.makedirs("licenses", exist_ok=True)
    os.makedirs(TELEMETRY_DIR, exist_ok=True)

@app.on_event("shutdown")
async def shutdown_event():
    print("🛑 SitePulseAI Backend shutting down.")