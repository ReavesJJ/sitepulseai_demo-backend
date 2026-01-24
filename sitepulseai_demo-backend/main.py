# main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import the SSL automation router
from ssl_automation import router as ssl_router

# Initialize FastAPI app
app = FastAPI(
    title="SitePulseAI Backend",
    description="Autonomous website operations agent backend. SSL repair, monitoring, and state management.",
    version="2.0.0"
)

# -------------------------------
# Middleware (optional, but recommended)
# -------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust for production domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------
# Include routers
# -------------------------------
app.include_router(ssl_router)

# -------------------------------
# Health check endpoint
# -------------------------------
@app.get("/")
async def root():
    return {
        "status": "ok",
        "message": "SitePulseAI Backend running",
        "version": "2.0.0"
    }

# -------------------------------
# Startup / Shutdown hooks (optional)
# -------------------------------
@app.on_event("startup")
async def startup_event():
    print("🔥 SitePulseAI Backend startup complete. SSL Automation ready.")

@app.on_event("shutdown")
async def shutdown_event():
    print("🛑 SitePulseAI Backend shutting down.")
