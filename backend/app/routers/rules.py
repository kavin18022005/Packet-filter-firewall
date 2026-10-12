from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.models import FirewallRule
from app.schemas import FirewallRuleCreate, FirewallRuleUpdate, FirewallRuleResponse
from app.engine.rule_matcher import RuleMatcher

router = APIRouter(prefix="/api/rules", tags=["Firewall Rules"])

@router.get("", response_model=List[FirewallRuleResponse])
def get_rules(
    enabled_only: bool = False,
    db: Session = Depends(get_db)
):
    query = db.query(FirewallRule)
    if enabled_only:
        query = query.filter(FirewallRule.enabled == True)
    return query.order_by(FirewallRule.priority.asc(), FirewallRule.id.asc()).all()

@router.post("", response_model=FirewallRuleResponse, status_code=201)
def create_rule(
    rule_in: FirewallRuleCreate,
    db: Session = Depends(get_db)
):
    # Validate IP specifications
    valid, err = RuleMatcher.validate_ip_spec(rule_in.src_ip)
    if not valid:
        raise HTTPException(status_code=400, detail=f"Source IP error: {err}")
    valid, err = RuleMatcher.validate_ip_spec(rule_in.dst_ip)
    if not valid:
        raise HTTPException(status_code=400, detail=f"Destination IP error: {err}")

    # Validate Port specifications
    valid, err = RuleMatcher.validate_port_spec(rule_in.src_port)
    if not valid:
        raise HTTPException(status_code=400, detail=f"Source Port error: {err}")
    valid, err = RuleMatcher.validate_port_spec(rule_in.dst_port)
    if not valid:
        raise HTTPException(status_code=400, detail=f"Destination Port error: {err}")

    rule = FirewallRule(
        name=rule_in.name,
        priority=rule_in.priority,
        action=rule_in.action.upper(),
        protocol=rule_in.protocol.upper(),
        src_ip=rule_in.src_ip.strip(),
        dst_ip=rule_in.dst_ip.strip(),
        src_port=rule_in.src_port.strip(),
        dst_port=rule_in.dst_port.strip(),
        enabled=rule_in.enabled,
        description=rule_in.description
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule

@router.get("/{rule_id}", response_model=FirewallRuleResponse)
def get_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Firewall rule not found")
    return rule

@router.put("/{rule_id}", response_model=FirewallRuleResponse)
def update_rule(
    rule_id: int,
    rule_in: FirewallRuleUpdate,
    db: Session = Depends(get_db)
):
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Firewall rule not found")

    if rule_in.src_ip is not None:
        valid, err = RuleMatcher.validate_ip_spec(rule_in.src_ip)
        if not valid:
            raise HTTPException(status_code=400, detail=f"Source IP error: {err}")
        rule.src_ip = rule_in.src_ip.strip()

    if rule_in.dst_ip is not None:
        valid, err = RuleMatcher.validate_ip_spec(rule_in.dst_ip)
        if not valid:
            raise HTTPException(status_code=400, detail=f"Destination IP error: {err}")
        rule.dst_ip = rule_in.dst_ip.strip()

    if rule_in.src_port is not None:
        valid, err = RuleMatcher.validate_port_spec(rule_in.src_port)
        if not valid:
            raise HTTPException(status_code=400, detail=f"Source Port error: {err}")
        rule.src_port = rule_in.src_port.strip()

    if rule_in.dst_port is not None:
        valid, err = RuleMatcher.validate_port_spec(rule_in.dst_port)
        if not valid:
            raise HTTPException(status_code=400, detail=f"Destination Port error: {err}")
        rule.dst_port = rule_in.dst_port.strip()

    if rule_in.name is not None:
        rule.name = rule_in.name
    if rule_in.priority is not None:
        rule.priority = rule_in.priority
    if rule_in.action is not None:
        rule.action = rule_in.action.upper()
    if rule_in.protocol is not None:
        rule.protocol = rule_in.protocol.upper()
    if rule_in.enabled is not None:
        rule.enabled = rule_in.enabled
    if rule_in.description is not None:
        rule.description = rule_in.description

    db.commit()
    db.refresh(rule)
    return rule

@router.patch("/{rule_id}/toggle", response_model=FirewallRuleResponse)
def toggle_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Firewall rule not found")
    rule.enabled = not rule.enabled
    db.commit()
    db.refresh(rule)
    return rule

@router.patch("/{rule_id}/priority", response_model=FirewallRuleResponse)
def update_rule_priority(
    rule_id: int,
    priority: int = Query(..., ge=1, le=10000),
    db: Session = Depends(get_db)
):
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Firewall rule not found")
    rule.priority = priority
    db.commit()
    db.refresh(rule)
    return rule

@router.delete("/{rule_id}")
def delete_rule(rule_id: int, db: Session = Depends(get_db)):
    rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Firewall rule not found")
    db.delete(rule)
    db.commit()
    return {"status": "success", "message": f"Rule #{rule_id} deleted"}
