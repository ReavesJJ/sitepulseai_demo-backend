
from latency import router as latency_router
from seo_checker import router as seo_router
from vulnerabilities_checker import router as vulnerabilities_router


from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from ssl_automation import router as ssl_router
from uptime import router as uptime_router

from baseline import router as baseline_router

app = FastAPI(
    title="SitePulseAI Backend",
    description="Autonomous website operations agent backend.",
    version="2.3.0"
)

app.include_router(latency_router)
app.include_router(vulnerabilities_router)
app.include_router(seo_router)



app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Core monitoring routers ----
app.include_router(ssl_router)
app.include_router(uptime_router)
app.include_router(latency_router)
app.include_router(vulnerabilities_router)
app.include_router(seo_router)
app.include_router(baseline_router)

# ---- Health check ----
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
    print("🔐 SSL router loaded.")
    print("⏱️  Uptime router loaded.")
    print("📡 Latency router loaded.")
    print("🛡️  Vulnerabilities router loaded.")
    print("📈 SEO router loaded.")
    print("📊 Baseline router loaded.")

@app.on_event("shutdown")
async def shutdown_event():
    print("🛑 SitePulseAI Backend shutting down.")
