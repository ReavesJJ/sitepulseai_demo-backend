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
from telemetry_attestation import generate_telemetry_attestation
from telemetry_event_store import create_telemetry_event
import requests






# -----------------------
# Existing monitoring engine
# -----------------------
from monitoring_engine import (
    add_domain_to_monitoring,
    run_full_check,
    start_monitoring
)


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
    get_license,
    validate_domain,
    check_feature_access,
    tier_features
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
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # later restrict to your domain
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
def monitor(
    client_id: str = Query(...),
    domain: str = Query(...)
):
    # --------------------------------------------------------
    # 1. LICENSE + DOMAIN ENFORCEMENT
    # --------------------------------------------------------

    license_data = get_license(client_id)
    validate_domain(client_id, domain)

    features = tier_features(license_data["tier"])

    for feature in features:
        check_feature_access(client_id, feature)

    # --------------------------------------------------------
    # 2. RUN EXISTING MONITORING ENGINE
    #
    # Do NOT call ssl_router.check_ssl(), etc.
    # Those variables are FastAPI APIRouter objects.
    # --------------------------------------------------------

    try:
        monitoring_results = run_full_check(domain)

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Monitoring failed: {e}"
        )

    if not monitoring_results:
        raise HTTPException(
            status_code=500,
            detail="Monitoring returned no results."
        )

    # --------------------------------------------------------
    # 3. BUILD MONITORING RESULT
    # --------------------------------------------------------

    results = {
        "domain": domain,
        "timestamp": datetime.utcnow().isoformat(),
        "monitoring": monitoring_results
    }

    # Preserve individual metrics at the top level when
    # run_full_check returns those keys.
    if isinstance(monitoring_results, dict):
        for feature in features:
            if feature in monitoring_results:
                results[feature] = monitoring_results[feature]

    # --------------------------------------------------------
    # 4. IMMUTABLE AUDIT LOG
    # --------------------------------------------------------

    write_audit_log({
        "event": "monitor_run",
        "client_id": client_id,
        "domain": domain,
        "tier": license_data["tier"]
    })

        # --------------------------------------------------------
    # 5. TELEMETRY EVENT
    #
    # Shared telemetry evidence layer.
    # Used by both manual and autonomous monitoring.
    # --------------------------------------------------------

    try:
        event_record = create_telemetry_event(
            client_id=client_id,
            domain=domain,
            results=results
        )

        # Return only the telemetry event metadata here.
        #
        # Do NOT attach the full event_record to results because
        # event_record contains results_snapshot -> results.
        # Attaching the full record would create a circular
        # reference during certificate generation.
        results["telemetry_event_record"] = {
            "event_type": event_record["event_type"],
            "event_id": event_record["event_id"],
            "timestamp": event_record["timestamp"],
            "client_id": event_record["client_id"],
            "domain": event_record["domain"],
            "monitoring_agent": event_record["monitoring_agent"],
            "previous_event_hash": event_record["previous_event_hash"],
            "event_hash": event_record["event_hash"]
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Telemetry Event failed: {e}"
        )
    # --------------------------------------------------------
    # 6. TELEMETRY ATTESTATION
    # --------------------------------------------------------

    try:
        certificate = generate_telemetry_attestation(
            client_id,
            domain,
            results
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Telemetry certificate failed: {e}"
        )

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



@app.post("/delete_url")
def delete_url(data: dict):
    domain = data.get("domain")

    removed = False

    for segment in GLOBAL_SEGMENTS:
        if domain in GLOBAL_SEGMENTS[segment]:
            GLOBAL_SEGMENTS[segment].remove(domain)
            removed = True

    return {
        "status": "deleted" if removed else "not_found",
        "domain": domain
    }




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
# threading.Thread(target=monitoring_loop, daemon=True).start()


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



def get_ssl_expiry(domain: str):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        expiry_str = cert.get('notAfter')
        expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")

        days_remaining = (expiry_date - datetime.utcnow()).days

        if days_remaining < 7:
            status = "Critical"
        elif days_remaining < 30:
            status = "Warning"
        else:
            status = "Healthy"

        return {
            "ssl_expiry": expiry_date.strftime("%Y-%m-%d"),
            "days_remaining": days_remaining,
            "ssl_status": status
        }

    except Exception:
        return {
            "ssl_expiry": None,
            "days_remaining": None,
            "ssl_status": "Unknown"
        }



import requests
import socket
import ssl
from datetime import datetime


def get_ssl_expiry(domain: str):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        expiry_str = cert.get('notAfter')
        expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")

        days_remaining = (expiry_date - datetime.utcnow()).days

        if days_remaining < 7:
            status = "Critical"
        elif days_remaining < 30:
            status = "Warning"
        else:
            status = "Healthy"

        return {
            "ssl_expiry": expiry_date.strftime("%Y-%m-%d"),
            "days_remaining": days_remaining,
            "ssl_status": status
        }

    except Exception:
        return {
            "ssl_expiry": None,
            "days_remaining": None,
            "ssl_status": "Unknown"
        }


@app.get("/vulnerabilities/{domain}")
def check_vulnerabilities(domain: str):
    issues = []

    try:
        url = f"https://{domain}"

        response = requests.get(
            url,
            timeout=5,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        headers = response.headers

        # 🔐 Security header checks
        if "X-Frame-Options" not in headers:
            issues.append({"type": "missing_x_frame_options", "severity": "Medium"})

        if "Content-Security-Policy" not in headers:
            issues.append({"type": "missing_csp", "severity": "High"})

        if "Strict-Transport-Security" not in headers:
            issues.append({"type": "missing_hsts", "severity": "High"})

        if "X-Content-Type-Options" not in headers:
            issues.append({"type": "missing_x_content_type", "severity": "Low"})

    except Exception:
        # fail gracefully
        issues = []

    # 🔢 Count severities
    counts = {
        "critical": sum(1 for i in issues if i["severity"] == "Critical"),
        "high": sum(1 for i in issues if i["severity"] == "High"),
        "medium": sum(1 for i in issues if i["severity"] == "Medium"),
        "low": sum(1 for i in issues if i["severity"] == "Low"),
    }

    # 🔥 Risk score calculation
    risk_score = (
        counts["critical"] * 10 +
        counts["high"] * 7 +
        counts["medium"] * 4 +
        counts["low"] * 1
    )

    # 🔐 SSL DATA (restored)
    ssl_info = get_ssl_expiry(domain)
    

    # ✅ FINAL RESPONSE (matches frontend expectations)
    return {
        "domain": domain,

        "vulnerabilities": {
            "total": len(issues),
            "risk_score": risk_score,
            "issues": issues,
            "counts": counts
        },

        # 🔥 THIS FIXES YOUR SSL CARD
        "ssl_expiry": ssl_info["ssl_expiry"],
        "days_remaining": ssl_info["days_remaining"],
        "ssl_status": ssl_info["ssl_status"]
    }

@app.post("/generate_telemetry_certificate")
def generate_telemetry_certificate(payload: dict):

    domain = payload.get("domain")

    # Temporary default for current SitePulseAI deployment.
    # Later this should come from authenticated client context.
    client_id = payload.get(
        "client_id",
        "SPA-TIER_1-5CF062E6"
    )

    # ---------------------------------------
    # VALIDATE REQUEST
    # ---------------------------------------

    if not domain:
        raise HTTPException(
            status_code=400,
            detail="Domain is required."
        )

    # Verify license and licensed domain
    get_license(client_id)
    validate_domain(client_id, domain)

    # ---------------------------------------
    # LOAD EXISTING TELEMETRY
    # ---------------------------------------

    if not os.path.exists(TELEMETRY_FILE):
        raise HTTPException(
            status_code=404,
            detail="No telemetry events found."
        )

    try:
        with open(
            TELEMETRY_FILE,
            "r",
            encoding="utf-8"
        ) as f:
            telemetry_events = json.load(f)

    except (OSError, json.JSONDecodeError) as e:
        raise HTTPException(
            status_code=500,
            detail=f"Unable to read telemetry events: {e}"
        )

    if not isinstance(telemetry_events, list) or not telemetry_events:
        raise HTTPException(
            status_code=404,
            detail="No telemetry events available."
        )

    # ---------------------------------------
    # FIND LATEST EVENT FOR THIS
    # CLIENT + DOMAIN
    # ---------------------------------------

    requested_domain = (
        domain
        .lower()
        .replace("www.", "")
        .strip()
    )

    latest_event = None

    for event in reversed(telemetry_events):

        event_domain = (
            str(event.get("domain", ""))
            .lower()
            .replace("www.", "")
            .strip()
        )

        if (
            event.get("client_id") == client_id
            and event_domain == requested_domain
        ):
            latest_event = event
            break

    if latest_event is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "No telemetry event found "
                "for this licensed domain."
            )
        )

    # ---------------------------------------
    # BUILD CERTIFICATE RESULTS
    # ---------------------------------------

    results = {
        "domain": domain,
        "telemetry": latest_event
    }

    # ---------------------------------------
    # GENERATE TELEMETRY ATTESTATION
    # ---------------------------------------
    try:
        certificate = generate_telemetry_attestation(
            client_id=client_id,
            domain=domain,
            results=results
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Certificate generation failed: {e}"
        )

    # ---------------------------------------
    # HUMAN-READABLE CERTIFICATE ID
    # ---------------------------------------

    certificate_id = f"SPTC-{certificate[:12].upper()}"

    # ---------------------------------------
    # RETURN TO CONSOLE
    # ---------------------------------------

    return {
        "status": "success",
        "domain": domain,
        "client_id": client_id,
        "certificate_id": certificate_id,
        "certificate": certificate,
        "telemetry_event_id": latest_event.get("event_id"),
        "telemetry_event_hash": latest_event.get("event_hash"),
        "timestamp": datetime.utcnow().isoformat()
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


    start_monitoring()


@app.on_event("shutdown")
async def shutdown_event():
    print("🛑 SitePulseAI Backend shutting down.")


    