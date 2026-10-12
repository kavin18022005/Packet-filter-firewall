import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.database import Base, engine, SessionLocal
from app.seed_data import seed_database
from app.services.simulator import simulator
from app.services.pcap_service import PcapService
from app.routers import (
    rules,
    packets,
    alerts,
    dashboard,
    simulator as sim_router,
    pcap,
    settings as settings_router
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: ensure tables exist and seed default rules and system settings
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_database(db)
    finally:
        db.close()

    # Pre-generate sample PCAP file for offline testing if it does not exist yet
    sample_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "sample_captures", "sample_traffic.pcap")
    if not os.path.exists(sample_path):
        try:
            PcapService.generate_sample_pcap(sample_path)
        except Exception as e:
            print(f"[PCAP Warning] Could not generate sample PCAP: {e}")

    yield

    # Shutdown: cleanly stop simulator if running
    await simulator.stop()

app = FastAPI(
    title="Data-Driven Packet Filtering Firewall API",
    description="High-performance, modular packet inspection and firewall engine with Scapy analysis and anomaly alerts.",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for local Vite development & cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register Routers
app.include_router(dashboard.router)
app.include_router(rules.router)
app.include_router(packets.router)
app.include_router(alerts.router)
app.include_router(sim_router.router)
app.include_router(pcap.router)
app.include_router(settings_router.router)

@app.get("/api/health", tags=["Health"])
def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "default_policy": simulator.firewall_engine.default_policy,
        "simulator_active": simulator.is_running
    }

@app.get("/", tags=["Root"])
def root():
    return {
        "message": "Data-Driven Packet Filtering Firewall Backend Running",
        "docs_url": "/docs",
        "health_check": "/api/health"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
