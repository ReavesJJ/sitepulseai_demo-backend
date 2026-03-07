# ============================================================
# SitePulseAI Backend
# Licensed Monitoring Infrastructure
# ============================================================

import os
import uuid
import json
import hashlib
from datetime import datetime
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

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

# ============================================================
# Licensed Monitoring Infrastructure Telemetry Layer
# Telemetry Event Record System (Hash-Chained Infrastructure Telemetry)
# ============================================================

def get_last_event_hash(log_file):
    """
    Retrieves the hash of the last telemetry event for chain integrity.
    """

    if not os.path.exists(log_file):
        return "GENESIS"

    try:
        with open(log_file, "r") as f:
            lines = f.readlines()
            if not lines:
                return "GENESIS"

            last_event = json.loads(lines[-1])
            return last_event.get("event_hash", "GENESIS")

    except Exception:
        return "GENESIS"


def generate_telemetry_event_record(client_id, domain, results):
    """
    Generates a hash-chained Telemetry Event Record.
    """

    os.makedirs("telemetry_events", exist_ok=True)
    log_file = os.path.join("telemetry_events", "telemetry_event_log.json")

    event_id = f"SP-{uuid.uuid4().hex[:10].upper()}"
    timestamp = datetime.utcnow().isoformat()

    previous_hash = get_last_event_hash(log_file)

    event_record = {
        "event_type": "monitoring_event",
        "event_id": event_id,
        "timestamp": timestamp,
        "client_id": client_id,
        "domain": domain,
        "monitoring_agent": "SitePulseAI Node",
        "previous_event_hash": previous_hash,
        "results_snapshot": results
    }

    # Create new hash including previous hash
    event_string = json.dumps(event_record, sort_keys=True)
    event_hash = hashlib.sha256(event_string.encode()).hexdigest()

    event_record["event_hash"] = event_hash

    return event_record


def write_telemetry_event_record(event_record):
    """
    Append Telemetry Event Record to chained telemetry log.
    """

    os.makedirs("telemetry_events", exist_ok=True)
    log_file = os.path.join("telemetry_events", "telemetry_event_log.json")

    with open(log_file, "a") as f:
        f.write(json.dumps(event_record) + "\n")

# -----------------------
# FastAPI app initialization
# -----------------------
app = FastAPI(
    title="SitePulseAI Backend",
    description="Autonomous website operations agent backend.",
    version="2.3.0"
)

# -----------------------
# Middleware
# -----------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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

# -----------------------
# Root / health endpoints
# -----------------------
@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/")
async def root():
    return {
        "status": "ok",
        "message": "SitePulseAI Backend running",
        "version": "2.3.0"
    }

# -----------------------
# Monitoring endpoint example
# -----------------------
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

    # ============================================================
    # Telemetry Event Record (Infrastructure Telemetry Layer)
    # ============================================================

    telemetry_event = generate_telemetry_event_record(
        client_id,
        domain,
        results
    )

    write_telemetry_event_record(telemetry_event)

    results["telemetry_event_record"] = telemetry_event

    # -----------------------
    # Telemetry attestation certificate
    # -----------------------
    certificate = generate_telemetry_attestation(client_id, domain, results)
    results["telemetry_certificate"] = certificate

    return results

# -----------------------
# License generation endpoint (POST)
# -----------------------
@app.post("/generate_license")
def generate_license(tier: str = Query(...), domains: str = Query(...), expiration_date: str = Query(...)):
    """
    Example: /generate_license?tier=tier_1&domains=sitepulseai.com&expiration_date=2027-12-31
    """
    domains_list = [d.strip() for d in domains.split(",")]
    client_id = create_license(tier, domains_list, expiration_date)
    return {"client_id": client_id, "tier": tier, "domains": domains_list, "expiration_date": expiration_date}

# -----------------------
# Startup / shutdown events
# -----------------------
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
    os.makedirs("telemetry_events", exist_ok=True)

@app.on_event("shutdown")
async def shutdown_event():
    print("🛑 SitePulseAI Backend shutting down.")