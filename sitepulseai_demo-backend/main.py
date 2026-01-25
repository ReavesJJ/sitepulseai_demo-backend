from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Routers
from ssl_automation import router as ssl_router
from baseline import router as baseline_router

# Side-effect imports (ensure these modules initialize cleanly)
import remediation_engine
import persistence

app = FastAPI(
    title="SitePulseAI Backend",
    description="Autonomous website operations agent backend. SSL repair, monitoring, and state management.",
    version="2.1.0"
)

# -------------------------------
# Middleware
# -------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten later for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------
# Include routers
# -------------------------------
app.include_router(ssl_router)
app.include_router(baseline_router)

# -------------------------------
# Health check
# -------------------------------
@app.get("/")
async def root():
    return {
        "status": "ok",
        "message": "SitePulseAI Backend running",
        "version": "2.1.0"
    }

# -------------------------------
# Startup / Shutdown hooks
# -------------------------------
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
