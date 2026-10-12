from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import Dict, Any, List
import datetime
from app.database import get_db
from app.models import PacketLog, SecurityAlert, FirewallRule
from app.schemas import DashboardStats

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

@router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db)):
    total_packets = db.query(PacketLog).count()
    allowed_packets = db.query(PacketLog).filter(PacketLog.action == "ALLOW").count()
    blocked_packets = db.query(PacketLog).filter(PacketLog.action == "BLOCK").count()
    block_rate = round((blocked_packets / total_packets * 100), 1) if total_packets > 0 else 0.0

    total_alerts = db.query(SecurityAlert).count()
    active_alerts = db.query(SecurityAlert).filter(SecurityAlert.status == "NEW").count()
    active_rules_count = db.query(FirewallRule).filter(FirewallRule.enabled == True).count()

    # Protocol breakdown
    proto_counts = db.query(
        PacketLog.protocol, func.count(PacketLog.id)
    ).group_by(PacketLog.protocol).all()
    protocol_distribution = {proto: count for proto, count in proto_counts}

    # Action breakdown
    action_distribution = {
        "ALLOW": allowed_packets,
        "BLOCK": blocked_packets
    }

    # Recent 10 logs
    recent_logs = db.query(PacketLog).order_by(PacketLog.timestamp.desc(), PacketLog.id.desc()).limit(10).all()
    recent_activity = [
        {
            "id": log.id,
            "timestamp": log.timestamp.strftime("%H:%M:%S"),
            "src_ip": log.src_ip,
            "dst_ip": log.dst_ip,
            "protocol": log.protocol,
            "action": log.action,
            "decision_reason": log.decision_reason
        }
        for log in recent_logs
    ]

    return DashboardStats(
        total_packets=total_packets,
        allowed_packets=allowed_packets,
        blocked_packets=blocked_packets,
        block_rate_percent=block_rate,
        total_alerts=total_alerts,
        active_alerts=active_alerts,
        active_rules_count=active_rules_count,
        protocol_distribution=protocol_distribution,
        action_distribution=action_distribution,
        recent_activity=recent_activity
    )

@router.get("/timeline")
def get_traffic_timeline(db: Session = Depends(get_db)):
    """Provides time-series data for the dashboard charts."""
    # Fetch last 30 packets ordered ascending by time for sparkline/area chart
    logs = db.query(PacketLog).order_by(PacketLog.timestamp.desc(), PacketLog.id.desc()).limit(50).all()
    logs.reverse()

    points = []
    for log in logs:
        points.append({
            "time": log.timestamp.strftime("%H:%M:%S"),
            "allowed": 1 if log.action == "ALLOW" else 0,
            "blocked": 1 if log.action == "BLOCK" else 0,
            "size": log.packet_size
        })
    return points
