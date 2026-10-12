from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import List, Optional
import math
from app.database import get_db
from app.models import SecurityAlert, FirewallRule
from app.schemas import SecurityAlertResponse, SecurityAlertStatusUpdate, FirewallRuleResponse

router = APIRouter(prefix="/api/alerts", tags=["Security Alerts"])

@router.get("", response_model=List[SecurityAlertResponse])
def get_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db)
):
    query = db.query(SecurityAlert)
    if severity:
        query = query.filter(SecurityAlert.severity == severity.upper())
    if status:
        query = query.filter(SecurityAlert.status == status.upper())
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                SecurityAlert.src_ip.like(search_term),
                SecurityAlert.description.like(search_term),
                SecurityAlert.alert_type.like(search_term)
            )
        )
    return query.order_by(SecurityAlert.timestamp.desc(), SecurityAlert.id.desc()).limit(limit).all()

@router.patch("/{alert_id}/status", response_model=SecurityAlertResponse)
def update_alert_status(
    alert_id: int,
    status_update: SecurityAlertStatusUpdate,
    db: Session = Depends(get_db)
):
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = status_update.status
    db.commit()
    db.refresh(alert)
    return alert

@router.post("/{alert_id}/block-ip", response_model=FirewallRuleResponse)
def block_offending_ip(alert_id: int, db: Session = Depends(get_db)):
    """One-click mitigation: instantly creates an urgent priority 10 BLOCK rule for the alert's source IP."""
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    existing_rule = db.query(FirewallRule).filter(
        FirewallRule.src_ip == alert.src_ip,
        FirewallRule.action == "BLOCK"
    ).first()

    if existing_rule:
        existing_rule.enabled = True
        db.commit()
        db.refresh(existing_rule)
        rule = existing_rule
    else:
        rule = FirewallRule(
            name=f"Auto-Block {alert.src_ip} ({alert.alert_type})",
            priority=10, # High priority block
            action="BLOCK",
            protocol="ANY",
            src_ip=alert.src_ip,
            dst_ip="ANY",
            src_port="ANY",
            dst_port="ANY",
            enabled=True,
            description=f"Auto-generated from alert #{alert.id}: {alert.description}"
        )
        db.add(rule)
        db.commit()
        db.refresh(rule)

    alert.status = "ACKNOWLEDGED"
    db.commit()
    return rule

@router.delete("/clear")
def clear_alerts(db: Session = Depends(get_db)):
    count = db.query(SecurityAlert).delete()
    db.commit()
    return {"status": "success", "deleted_count": count}
