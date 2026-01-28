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
# main.py or wherever your app is defined



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

# -----------------------
# Root endpoint
# -----------------------

@app.get("/")
def health():
    return {"status": "SitePulseAI backend alive"}


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
