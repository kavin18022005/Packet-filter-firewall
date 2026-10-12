from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime

# --- Firewall Rule Schemas ---
class FirewallRuleBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    priority: int = Field(100, ge=1, le=10000, description="Lower number = higher priority")
    action: str = Field(..., pattern="^(ALLOW|BLOCK)$")
    protocol: str = Field("ANY", pattern="^(TCP|UDP|ICMP|ANY)$")
    src_ip: str = Field("ANY", max_length=50)
    dst_ip: str = Field("ANY", max_length=50)
    src_port: str = Field("ANY", max_length=50)
    dst_port: str = Field("ANY", max_length=50)
    enabled: bool = True
    description: Optional[str] = Field(None, max_length=255)

class FirewallRuleCreate(FirewallRuleBase):
    pass

class FirewallRuleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    priority: Optional[int] = Field(None, ge=1, le=10000)
    action: Optional[str] = Field(None, pattern="^(ALLOW|BLOCK)$")
    protocol: Optional[str] = Field(None, pattern="^(TCP|UDP|ICMP|ANY)$")
    src_ip: Optional[str] = Field(None, max_length=50)
    dst_ip: Optional[str] = Field(None, max_length=50)
    src_port: Optional[str] = Field(None, max_length=50)
    dst_port: Optional[str] = Field(None, max_length=50)
    enabled: Optional[bool] = None
    description: Optional[str] = None

class FirewallRuleResponse(FirewallRuleBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

# --- Packet Log Schemas ---
class PacketLogBase(BaseModel):
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    packet_size: int = 0
    tcp_flags: Optional[str] = None
    action: str
    matched_rule_id: Optional[int] = None
    matched_rule_name: Optional[str] = None
    decision_reason: str
    is_simulated: bool = True
    raw_summary: Optional[str] = None

class PacketLogResponse(PacketLogBase):
    model_config = ConfigDict(from_attributes=True)

    id: int

class PaginatedPacketLogs(BaseModel):
    total: int
    page: int
    page_size: int
    total_pages: int
    items: List[PacketLogResponse]

# --- Security Alert Schemas ---
class SecurityAlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    alert_type: str
    severity: str
    src_ip: str
    dst_ip: Optional[str] = None
    description: str
    packet_count: int
    status: str

class SecurityAlertStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(NEW|ACKNOWLEDGED|RESOLVED)$")

# --- System Settings Schemas ---
class SystemSettingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    key: str
    value: str
    description: Optional[str] = None

class SystemSettingUpdate(BaseModel):
    value: str

# --- Dashboard & Simulator Schemas ---
class DashboardStats(BaseModel):
    total_packets: int
    allowed_packets: int
    blocked_packets: int
    block_rate_percent: float
    total_alerts: int
    active_alerts: int
    active_rules_count: int
    protocol_distribution: Dict[str, int]
    action_distribution: Dict[str, int]
    recent_activity: List[Dict[str, Any]]

class SimulatorStatus(BaseModel):
    is_running: bool
    packets_generated: int
    rate_ms: int
    batch_size: int

class SimulatorConfig(BaseModel):
    rate_ms: Optional[int] = Field(None, ge=100, le=10000)
    batch_size: Optional[int] = Field(None, ge=1, le=50)

# --- Raw Packet Ingestion Schema ---
class PacketIngestRequest(BaseModel):
    src_ip: str
    dst_ip: str
    protocol: str = "TCP"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    packet_size: int = 64
    tcp_flags: Optional[str] = None
    is_simulated: bool = True
