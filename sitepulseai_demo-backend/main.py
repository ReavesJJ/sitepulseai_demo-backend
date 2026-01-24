# main.py
from fastapi import FastAPI, Body
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime

# -------------------------------
# Local Routers / Engines
# -------------------------------

# Existing SSL automation router
from ssl_automation import router as ssl_router

# Phase 3 — Remediation Engine
from remediation_engine import generate_remediation


# -------------------------------
# Initialize FastAPI app
# -------------------------------
app = FastAPI(
    title="SitePulseAI Backend",
    description="Autonomous website operations agent backend. SSL automation, monitoring, vulnerability detection, and remediation.",
    version="3.1.0"
)


# -------------------------------
# Middleware (CORS)
# -------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Lock down later for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -------------------------------
# Include Routers
# -------------------------------
app.include_router(ssl_router)


# -------------------------------
# Root + Health Endpoints
# -------------------------------
@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "SitePulseAI Backend",
        "version": "3.1.0",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "uptime": "running",
        "timestamp": datetime.utcnow().isoformat()
    }


# -------------------------------
# Phase 3 — Step 1: Remediation Engine
# -------------------------------
@app.post("/remediation/generate")
def remediation_generate(payload: dict = Body(...)):
    vuln_id = payload.get("vuln_id")
    site_url = payload.get("site_url")
    evidence = payload.get("evidence", {})

    if not vuln_id or not site_url:
        return {
            "error": "vuln_id and site_url are required",
            "timestamp": datetime.utcnow().isoformat()
        }

    remediation = generate_remediation(
        vuln_id=vuln_id,
        site_url=site_url,
        evidence=evidence
    )

    return remediation


# -------------------------------
# Phase 3 — Step 2 Placeholder (Auto-Fix)
# -------------------------------
@app.post("/remediation/execute")
def remediation_execute(payload: dict = Body(...)):
    remediation_id = payload.get("remediation_id")

    if not remediation_id:
        return {
            "error": "remediation_id is required",
            "timestamp": datetime.utcnow().isoformat()
        }

    # Placeholder for Phase 3.2
    return {
        "remediation_id": remediation_id,
        "status": "queued",
        "message": "Remediation execution engine not yet enabled",
        "timestamp": datetime.utcnow().isoformat()
    }


# -------------------------------
# Startup / Shutdown Hooks
# -------------------------------
@app.on_event("startup")
async def startup_event():
    print("🔥 SitePulseAI Backend startup complete.")
    print("🔐 SSL Automation router loaded.")
    print("🛠️  Remediation Engine ready.")


@app.on_event("shutdown")
async def shutdown_event():
    print("🛑 SitePulseAI Backend shutting down.")
