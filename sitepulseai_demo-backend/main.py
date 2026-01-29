from fastapi import FastAPI
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
from autofix_ssl import fix_expired_ssl
from autofix_router import router as autofix_router  # adjust file name
from remediation_store import get_pending_remediations, add_remediation, clear_remediations




# -----------------------
# Other engines / persistence
# -----------------------
import remediation_engine
import remediation_store
import autofix_engine
import persistence


from fastapi import APIRouter, HTTPException, Query
from autofix_engine import execute_remediation
from remediation_store import get_pending_remediations  # optional: get pending issues per site
from typing import List

router = APIRouter(prefix="/autofix", tags=["autofix"])

@router.post("/all")
async def auto_fix_all(site: str = Query(..., description="Website URL to auto-fix")):
    """
    Automatically run all supported auto-fixes for a given site.
    Returns the results of each fix.
    """

    # Step 1: Get pending remediations for the site
    # If you want to automatically generate fixes from vulnerabilities, etc.,
    # you can replace this with real checks
    pending = get_pending_remediations(site)

    if not pending:
        # fallback: create at least SSL fix check to ensure one fix runs
        pending = [
            {"vuln_id": "ssl_expired", "site": site, "remediation_id": f"{site}-ssl-expired"}
        ]

    # Step 2: Execute auto-fix for each pending remediation
    results = []
    for remediation in pending:
        fix_result = execute_remediation(remediation)
        results.append(fix_result)

    return {"site": site, "results": results}






# -----------------------
# App initialization
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
# Include routers (clean and sequential)
# -----------------------
app.include_router(ssl_router)
app.include_router(uptime_router)
app.include_router(vulnerabilities_router)
app.include_router(seo_router)
app.include_router(traffic_router)
app.include_router(latency_router)
app.include_router(autofix_router)


# -----------------------
# Root endpoint
# -----------------------
@app.get("/")
async def root():
    return {
        "status": "ok",
        "message": "SitePulseAI Backend running",
        "version": "2.3.0"
    }

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
    print("🛠️  Remediation Engine ready.")
    print("📦 Persistence layer ready.")
    print("🤖 Auto-Fix engine ready (skeleton).")

@app.on_event("shutdown")
async def shutdown_event():
    print("🛑 SitePulseAI Backend shutting down.")
