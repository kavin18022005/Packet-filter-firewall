from fastapi import APIRouter, Query
from typing import Dict, Any
from app.services.simulator import simulator
from app.schemas import SimulatorStatus, SimulatorConfig

router = APIRouter(prefix="/api/simulator", tags=["Traffic Simulator"])

@router.get("/status", response_model=SimulatorStatus)
def get_simulator_status():
    return simulator.get_status()

@router.post("/start")
async def start_simulator():
    await simulator.start()
    return {"status": "started", "message": "Synthetic packet generator is now active"}

@router.post("/stop")
async def stop_simulator():
    await simulator.stop()
    return {"status": "stopped", "message": "Synthetic packet generator has been paused"}

@router.post("/config")
def update_simulator_config(config: SimulatorConfig):
    simulator.set_config(rate_ms=config.rate_ms, batch_size=config.batch_size)
    return {"status": "updated", "config": simulator.get_status()}

@router.post("/generate")
def generate_packets_batch(count: int = Query(5, ge=1, le=50)):
    logs = simulator.generate_batch(count=count)
    return {
        "status": "success",
        "generated_count": len(logs),
        "packets": logs
    }
