import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from app.database import Base

def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)

class FirewallRule(Base):
    __tablename__ = "firewall_rules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    priority = Column(Integer, default=100, index=True)
    action = Column(String(10), nullable=False)  # "ALLOW" or "BLOCK"
    protocol = Column(String(10), default="ANY") # "TCP", "UDP", "ICMP", "ANY"
    src_ip = Column(String(50), default="ANY")   # "ANY", "192.168.1.1", "192.168.1.0/24"
    dst_ip = Column(String(50), default="ANY")
    src_port = Column(String(50), default="ANY") # "ANY", "80", "1024-65535", "80,443"
    dst_port = Column(String(50), default="ANY")
    enabled = Column(Boolean, default=True, index=True)
    description = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=utc_now)
    updated_at = Column(DateTime, default=utc_now, onupdate=utc_now)


class PacketLog(Base):
    __tablename__ = "packet_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utc_now, index=True)
    src_ip = Column(String(50), nullable=False, index=True)
    dst_ip = Column(String(50), nullable=False, index=True)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=False, index=True) # "TCP", "UDP", "ICMP"
    packet_size = Column(Integer, default=0)
    tcp_flags = Column(String(20), nullable=True) # e.g. "SYN", "ACK", "SYN-ACK", "FIN", "RST"
    action = Column(String(10), nullable=False, index=True) # "ALLOW" or "BLOCK"
    matched_rule_id = Column(Integer, nullable=True)
    matched_rule_name = Column(String(100), nullable=True)
    decision_reason = Column(String(255), nullable=False)
    is_simulated = Column(Boolean, default=True)
    raw_summary = Column(Text, nullable=True)


class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=utc_now, index=True)
    alert_type = Column(String(50), nullable=False) # "PORT_SCAN", "SYN_FLOOD", "SENSITIVE_PORT_PROBE", "PING_FLOOD"
    severity = Column(String(20), nullable=False, index=True) # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    src_ip = Column(String(50), nullable=False, index=True)
    dst_ip = Column(String(50), nullable=True)
    description = Column(String(255), nullable=False)
    packet_count = Column(Integer, default=1)
    status = Column(String(20), default="NEW", index=True) # "NEW", "ACKNOWLEDGED", "RESOLVED"


class SystemSetting(Base):
    __tablename__ = "system_settings"

    key = Column(String(50), primary_key=True)
    value = Column(String(255), nullable=False)
    description = Column(String(255), nullable=True)
