# ============================================================
# SitePulseAI Backend
# Licensed Monitoring Infrastructure
# ============================================================

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from urllib.parse import urlparse
from typing import List
from datetime import datetime
from license_enforcer import validate_license
from telemetry_attestation import generate_attestation
from immutable_audit_log import write_audit_log
import uuid
import hashlib
import json
import os





# ============================================================
# ------------------ Persistence & License ------------------
# ============================================================

LICENSE_FILE = "licenses.json"
EVENT_LOG_FILE = "events.log"
SECRET_KEY = "CHANGE_THIS_TO_LONG_RANDOM_SECRET"

def _load_licenses():
    if not os.path.exists(LICENSE_FILE):
        return {}
    with open(LICENSE_FILE, "r") as f:
        return json.load(f)

def _save_licenses(data):
    with open(LICENSE_FILE, "w") as f:
        json.dump(data, f, indent=4)

def _generate_signature(client_id, tier, domains, expiration):
    payload = f"{client_id}{tier}{domains}{expiration}{SECRET_KEY}"
    return hashlib.sha256(payload.encode()).hexdigest()

def generate_client_id(tier: str) -> str:
    random_part = uuid.uuid4().hex[:8].upper()
    return f"SPA-{tier.upper()}-{random_part}"

def create_license(tier: str, domains: List[str], expiration_date: str):
    licenses = _load_licenses()
    client_id = generate_client_id(tier)
    signature = _generate_signature(client_id, tier, domains, expiration_date)
    licenses[client_id] = {
        "active": True,
        "tier": tier.lower(),
        "domains": domains,
        "expiration_date": expiration_date,
        "signature": signature,
        "created_at": datetime.utcnow().isoformat()
    }
    _save_licenses(licenses)
    return client_id

def get_license(client_id: str):
    licenses = _load_licenses()
    license_data = licenses.get(client_id)
    if not license_data:
        return None
    # Expiration enforcement
    exp = datetime.strptime(license_data["expiration_date"], "%Y-%m-%d")
    if datetime.utcnow() > exp:
        license_data["active"] = False
    # Signature verification
    expected_signature = _generate_signature(
        client_id,
        license_data["tier"],
        license_data["domains"],
        license_data["expiration_date"]
    )
    if expected_signature != license_data.get("signature"):
        return None
    return license_data

def log_event(event_data: dict):
    event_data["timestamp"] = datetime.utcnow().isoformat()
    with open(EVENT_LOG_FILE, "a") as f:
        f.write(json.dumps(event_data) + "\n")

# ============================================================
# ------------------ Domain Enforcement ---------------------
# ============================================================

def normalize_domain(raw_url: str) -> str:
    parsed = urlparse(raw_url if "://" in raw_url else f"https://{raw_url}")
    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid domain format")
    return hostname.lower().rstrip(".")

def is_valid_domain(requested: str, allowed: str) -> bool:
    if requested == allowed:
        return True
    if requested.endswith("." + allowed):
        return True
    return False

def validate_license(client_id: str):
    license_data = get_license(client_id)
    if not license_data:
        raise HTTPException(status_code=403, detail="Invalid or tampered license")
    if not license_data.get("active"):
        raise HTTPException(status_code=403, detail="License inactive or expired")
    return license_data

def validate_domain_access(client_id: str, site: str):
    license_data = validate_license(client_id)
    allowed_domains = license_data.get("domains", [])
    normalized = normalize_domain(site)
    for allowed in allowed_domains:
        allowed_normalized = normalize_domain(allowed)
        if is_valid_domain(normalized, allowed_normalized):
            return normalized
    raise HTTPException(status_code=403, detail="Unauthorized domain")

def enforce_tier(license_data: dict, feature: str):
    tier_permissions = {
        "tier_1": [
            "ssl",
            "uptime",
            "seo",
            "latency",
            "traffic",
            "vulnerabilities"
        ],
        "tier_2": [
            "ssl",
            "uptime",
            "seo",
            "latency",
            "traffic",
            "vulnerabilities"
        ],
        "tier_3": [
            "ssl",
            "uptime",
            "seo",
            "latency",
            "traffic",
            "vulnerabilities",
            "autofix"
        ]
    }
    tier = license_data.get("tier")
    if feature not in tier_permissions.get(tier, []):
        raise HTTPException(
            status_code=403,
            detail=f"{feature} not allowed for this license tier"
        )

# ============================================================
# ------------------ Routers / Engines ----------------------
# ============================================================

# Replace with your actual imports
from ssl_automation import router as ssl_router
from uptime import router as uptime_router
from vulnerabilities_checker import router as vulnerabilities_router
from seo_checker import router as seo_router
from traffic_checker import router as traffic_router
from latency_checker import router as latency_router
from autofix_route import router as autofix_router
from autofix_engine import execute_remediation
from remediation_store import get_pending_remediations



# ============================================================
# ------------------ App Initialization --------------------
# ============================================================

app = FastAPI(
    title="SitePulseAI Backend",
    description="Licensed Monitoring Infrastructure Backend",
    version="3.2.0"
)

@app.get("/attestation")
def get_attestation(domain: str):
    
    license_data = validate_license(domain)

    if not license_data:
        raise HTTPException(status_code=403, detail="License validation failed")

    attestation = generate_attestation(domain)

    write_audit_log({
        "event": "attestation_generated",
        "domain": domain,
        "client_id": license_data["client_id"]
    })

    return attestation


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with your dashboard domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# ------------------ License Generator Endpoint -------------
# ============================================================

@app.post("/generate_license")
async def generate_license_endpoint(
    tier: str = Query(..., description="tier_1 / tier_2 / tier_3"),
    domains: str = Query(..., description="comma-separated domains"),
    expiration_date: str = Query(..., description="YYYY-MM-DD")
):
    domains_list = [d.strip() for d in domains.split(",")]
    client_id = create_license(tier, domains_list, expiration_date)
    return {"client_id": client_id, "tier": tier, "domains": domains_list, "expiration_date": expiration_date}

# ============================================================
# ------------------ Hardened AutoFix Endpoint -------------
# ============================================================

@app.post("/autofix/all")
async def auto_fix_all(
    site: str = Query(..., description="Website URL"),
    client_id: str = Query(..., description="Licensed client ID")
):
    license_data = validate_license(client_id)
    enforce_tier(license_data, "autofix")
    normalized_site = validate_domain_access(client_id, site)
    log_event({
        "client_id": client_id,
        "action": "autofix",
        "site": normalized_site
    })
    pending = get_pending_remediations(normalized_site)
    if not pending:
        pending = [
            {"vuln_id": "ssl_expired", "site": normalized_site, "remediation_id": f"{normalized_site}-ssl-expired"}
        ]
    results = [execute_remediation(remediation) for remediation in pending]
    return {"site": normalized_site, "results": results}

# ============================================================
# ------------------ Include Routers ------------------------
# ============================================================

app.include_router(ssl_router)
app.include_router(uptime_router)
app.include_router(vulnerabilities_router)
app.include_router(seo_router)
app.include_router(traffic_router)
app.include_router(latency_router)
app.include_router(autofix_router)

# ============================================================
# ------------------ Health & Root --------------------------
# ============================================================

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/")
async def root():
    return {"status": "ok", "message": "SitePulseAI Backend running", "version": "3.2.0"}

# ============================================================
# ------------------ Startup / Shutdown --------------------
# ============================================================

@app.on_event("startup")
async def startup_event():
    print("🔥 SitePulseAI Backend startup complete.")
    print("🔒 Domain enforcement active.")
    print("🎟️ License validation active.")
    print("📊 Tier enforcement active.")
    print("🛡️ Vulnerability observation enabled in Tier 1.")
    print("🤖 AutoFix restricted to Tier 3.")
    print("🎫 License generator endpoint active.")

@app.on_event("shutdown")
async def shutdown_event():
    print("🛑 SitePulseAI Backend shutting down.")