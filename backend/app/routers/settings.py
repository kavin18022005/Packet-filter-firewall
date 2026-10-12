from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from app.database import get_db
from app.models import SystemSetting, FirewallRule, PacketLog, SecurityAlert
from app.schemas import SystemSettingResponse, SystemSettingUpdate
from app.services.simulator import simulator

router = APIRouter(prefix="/api/settings", tags=["Settings"])

@router.get("", response_model=List[SystemSettingResponse])
def get_all_settings(db: Session = Depends(get_db)):
    return db.query(SystemSetting).all()

@router.put("/{key}", response_model=SystemSettingResponse)
def update_setting(
    key: str,
    update: SystemSettingUpdate,
    db: Session = Depends(get_db)
):
    clean_key = key.upper()
    setting = db.query(SystemSetting).filter(SystemSetting.key == clean_key).first()
    if not setting:
        setting = SystemSetting(key=clean_key, value=update.value)
        db.add(setting)
    else:
        setting.value = update.value

    # Update active engine policy if changing DEFAULT_POLICY
    if clean_key == "DEFAULT_POLICY":
        if update.value.upper() not in ("ALLOW", "BLOCK"):
            raise HTTPException(status_code=400, detail="DEFAULT_POLICY must be either 'ALLOW' or 'BLOCK'")
        setting.value = update.value.upper()
        simulator.firewall_engine.set_default_policy(setting.value)

    # Update anomaly detector thresholds if changing port scan threshold
    if clean_key == "PORT_SCAN_THRESHOLD":
        try:
            val = int(update.value)
            simulator.anomaly_detector.port_scan_threshold = val
        except ValueError:
            raise HTTPException(status_code=400, detail="PORT_SCAN_THRESHOLD must be an integer")

    db.commit()
    db.refresh(setting)
    return setting

@router.post("/reset-to-defaults")
def reset_to_defaults(db: Session = Depends(get_db)):
    """Restores default firewall rules and baseline configuration."""
    from app.seed_data import seed_database
    seed_database(db, reset_all=False)
    return {"status": "success", "message": "Baseline rules and settings initialized"}
