import asyncio
import random
import time
import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import FirewallRule, PacketLog, SecurityAlert, SystemSetting
from app.engine.firewall import FirewallEngine
from app.engine.anomaly_detector import AnomalyDetector
from app.config import settings

class TrafficSimulator:
    """
    Simulates enterprise and adversary network traffic streams without needing root/admin privileges.
    Evaluates every simulated packet against live firewall rules and anomaly detection triggers.
    """

    BENIGN_SOURCES = [
        "192.168.1.10", "192.168.1.15", "192.168.1.25", "192.168.1.50",
        "10.0.0.12", "10.0.0.45", "172.16.0.8"
    ]
    
    DESTINATIONS = [
        "93.184.216.34",   # example.com
        "142.250.190.46",  # google.com
        "151.101.1.140",   # cdn / cloud
        "8.8.8.8",         # Google DNS
        "1.1.1.1",         # Cloudflare DNS
        "192.168.1.1",     # Default Gateway
        "192.168.1.100"    # Internal App Server
    ]

    ATTACK_SOURCES = [
        "198.51.100.23",   # Adversary IP
        "203.0.113.88",    # Scanner Bot
        "45.33.32.156",    # External Recon IP
        "185.220.101.5"    # Suspicious IP
    ]

    def __init__(self):
        self.is_running: bool = False
        self.packets_generated: int = 0
        self.rate_ms: int = settings.SIMULATOR_RATE_MS
        self.batch_size: int = settings.SIMULATOR_BATCH_SIZE
        self.anomaly_detector = AnomalyDetector()
        self.firewall_engine = FirewallEngine(default_policy=settings.DEFAULT_POLICY)
        self._task: Optional[asyncio.Task] = None
        self._scan_counter = 0

    def get_status(self) -> Dict[str, Any]:
        return {
            "is_running": self.is_running,
            "packets_generated": self.packets_generated,
            "rate_ms": self.rate_ms,
            "batch_size": self.batch_size
        }

    def set_config(self, rate_ms: Optional[int] = None, batch_size: Optional[int] = None):
        if rate_ms is not None:
            self.rate_ms = rate_ms
        if batch_size is not None:
            self.batch_size = batch_size

    async def start(self):
        if self.is_running:
            return
        self.is_running = True
        self._task = asyncio.create_task(self._simulation_loop())

    async def stop(self):
        self.is_running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def _simulation_loop(self):
        while self.is_running:
            try:
                self.generate_batch(self.batch_size)
                await asyncio.sleep(self.rate_ms / 1000.0)
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[Simulator Error] {e}")
                await asyncio.sleep(1.0)

    def generate_packet_profile(self) -> Dict[str, Any]:
        """Generates realistic packet attributes based on weighted enterprise & threat profiles."""
        roll = random.random()

        # 10% Chance: Malicious Reconnaissance / Port Scan
        if roll < 0.10:
            attacker = random.choice(self.ATTACK_SOURCES)
            target = random.choice(self.DESTINATIONS)
            common_scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
            port = common_scan_ports[self._scan_counter % len(common_scan_ports)]
            self._scan_counter += 1
            return {
                "src_ip": attacker,
                "dst_ip": target,
                "protocol": "TCP",
                "src_port": random.randint(40000, 65000),
                "dst_port": port,
                "packet_size": random.randint(40, 60),
                "tcp_flags": "SYN",
                "raw_summary": f"TCP {attacker} -> {target}:{port} [SYN]"
            }

        # 5% Chance: Probing Sensitive Port (Telnet / SMB / RDP)
        elif roll < 0.15:
            attacker = random.choice(self.ATTACK_SOURCES)
            target = random.choice(["192.168.1.100", "192.168.1.1"])
            sensitive_port = random.choice([23, 445, 3389, 5555])
            return {
                "src_ip": attacker,
                "dst_ip": target,
                "protocol": "TCP",
                "src_port": random.randint(40000, 65000),
                "dst_port": sensitive_port,
                "packet_size": random.randint(52, 120),
                "tcp_flags": "SYN",
                "raw_summary": f"TCP {attacker} -> {target}:{sensitive_port} [SYN] Probe"
            }

        # 10% Chance: ICMP Ping
        elif roll < 0.25:
            src = random.choice(self.BENIGN_SOURCES + self.ATTACK_SOURCES)
            dst = random.choice(self.DESTINATIONS)
            return {
                "src_ip": src,
                "dst_ip": dst,
                "protocol": "ICMP",
                "src_port": None,
                "dst_port": None,
                "packet_size": random.randint(64, 84),
                "tcp_flags": None,
                "raw_summary": f"ICMP echo request from {src} to {dst}"
            }

        # 15% Chance: DNS Query
        elif roll < 0.40:
            src = random.choice(self.BENIGN_SOURCES)
            dst = random.choice(["8.8.8.8", "1.1.1.1"])
            return {
                "src_ip": src,
                "dst_ip": dst,
                "protocol": "UDP",
                "src_port": random.randint(49152, 65535),
                "dst_port": 53,
                "packet_size": random.randint(60, 140),
                "tcp_flags": None,
                "raw_summary": f"UDP {src} -> {dst}:53 DNS query"
            }

        # 50% Chance: Standard HTTPS / HTTP Web Traffic
        elif roll < 0.90:
            src = random.choice(self.BENIGN_SOURCES)
            dst = random.choice(["93.184.216.34", "142.250.190.46", "151.101.1.140"])
            port = 443 if random.random() > 0.25 else 80
            flags = random.choice(["SYN", "ACK", "PSH-ACK"])
            return {
                "src_ip": src,
                "dst_ip": dst,
                "protocol": "TCP",
                "src_port": random.randint(30000, 60000),
                "dst_port": port,
                "packet_size": random.randint(128, 1460),
                "tcp_flags": flags,
                "raw_summary": f"TCP {src} -> {dst}:{port} [{flags}]"
            }

        # 10% Chance: SSH Administration
        else:
            src = random.choice(self.BENIGN_SOURCES + self.ATTACK_SOURCES)
            dst = "192.168.1.100"
            return {
                "src_ip": src,
                "dst_ip": dst,
                "protocol": "TCP",
                "src_port": random.randint(40000, 60000),
                "dst_port": 22,
                "packet_size": random.randint(70, 200),
                "tcp_flags": "SYN",
                "raw_summary": f"TCP {src} -> {dst}:22 [SYN] SSH connection attempt"
            }

    def process_packet_data(self, pkt_data: Dict[str, Any], db: Session) -> PacketLog:
        """Evaluates packet data, logs to database, and triggers alerts if suspicious."""
        # Refresh default policy from db settings if present
        policy_setting = db.query(SystemSetting).filter(SystemSetting.key == "DEFAULT_POLICY").first()
        if policy_setting:
            self.firewall_engine.set_default_policy(policy_setting.value)

        # Retrieve active rules
        rules = db.query(FirewallRule).all()

        # Evaluate through firewall engine
        decision = self.firewall_engine.evaluate_packet(
            rules=rules,
            src_ip=pkt_data["src_ip"],
            dst_ip=pkt_data["dst_ip"],
            protocol=pkt_data["protocol"],
            src_port=pkt_data.get("src_port"),
            dst_port=pkt_data.get("dst_port")
        )

        # Run through anomaly detector
        alerts = self.anomaly_detector.inspect_packet(
            src_ip=pkt_data["src_ip"],
            dst_ip=pkt_data["dst_ip"],
            protocol=pkt_data["protocol"],
            src_port=pkt_data.get("src_port"),
            dst_port=pkt_data.get("dst_port"),
            tcp_flags=pkt_data.get("tcp_flags")
        )

        # Record alerts in DB
        for alert_dict in alerts:
            alert = SecurityAlert(
                timestamp=datetime.datetime.now(datetime.timezone.utc),
                alert_type=alert_dict["alert_type"],
                severity=alert_dict["severity"],
                src_ip=alert_dict["src_ip"],
                dst_ip=alert_dict.get("dst_ip"),
                description=alert_dict["description"],
                packet_count=alert_dict.get("packet_count", 1),
                status="NEW"
            )
            db.add(alert)

        # Record packet log
        packet_log = PacketLog(
            timestamp=datetime.datetime.now(datetime.timezone.utc),
            src_ip=pkt_data["src_ip"],
            dst_ip=pkt_data["dst_ip"],
            src_port=pkt_data.get("src_port"),
            dst_port=pkt_data.get("dst_port"),
            protocol=pkt_data["protocol"],
            packet_size=pkt_data.get("packet_size", 64),
            tcp_flags=pkt_data.get("tcp_flags"),
            action=decision.action,
            matched_rule_id=decision.matched_rule_id,
            matched_rule_name=decision.matched_rule_name,
            decision_reason=decision.reason,
            is_simulated=pkt_data.get("is_simulated", True),
            raw_summary=pkt_data.get("raw_summary")
        )
        db.add(packet_log)
        db.commit()
        db.refresh(packet_log)
        self.packets_generated += 1
        return packet_log

    def generate_batch(self, count: int = 1, external_db: Optional[Session] = None) -> List[Dict[str, Any]]:
        """Generates a synchronous batch of simulated packets and returns structured summary dicts."""
        results = []
        db = external_db or SessionLocal()
        try:
            for _ in range(count):
                pkt_data = self.generate_packet_profile()
                log = self.process_packet_data(pkt_data, db)
                results.append({
                    "id": log.id,
                    "src_ip": log.src_ip,
                    "dst_ip": log.dst_ip,
                    "protocol": log.protocol,
                    "action": log.action,
                    "decision_reason": log.decision_reason
                })
            return results
        finally:
            if not external_db:
                db.close()

# Singleton simulator instance
simulator = TrafficSimulator()
