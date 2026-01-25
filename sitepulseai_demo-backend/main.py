from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ssl_automation import router as ssl_router
from baseline import router as baseline_router

import remediation_engine
import remediation_store
import autofix_engine
import persistence

app = FastAPI(
    title="SitePulseAI Backend",
    description="Autonomous website operations agent backend.",
    version="2.3.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ssl_router)
app.include_router(baseline_router)

@app.get("/")
async def root():
    return {
        "status": "ok",
        "message": "SitePulseAI Backend running",
        "version": "2.3.0"
    }

@app.on_event("startup")
async def startup_event():
    print("🔥 SitePulseAI Backend startup complete.")
    print("🔐 SSL Automation router loaded.")
    print("🛠️  Remediation Engine ready.")
    print("📦 Remediation persistence layer ready.")
    print("🤖 Auto-Fix orchestration engine ready (skeleton).")

@app.on_event("shutdown")
async def shutdown_event():
    print("🛑 SitePulseAI Backend shutting down.")
