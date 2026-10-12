import os
import time
import datetime
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from scapy.all import rdpcap, wrpcap, Ether, IP, TCP, UDP, ICMP, Raw
from app.models import FirewallRule, PacketLog, SecurityAlert, SystemSetting
from app.engine.firewall import FirewallEngine
from app.engine.anomaly_detector import AnomalyDetector
from app.services.packet_analyzer import PacketAnalyzer
from app.config import settings

class PcapService:
    """
    Handles offline PCAP packet ingestion, Scapy packet dissection, rule matching,
    and sample PCAP capture generation.
    """

    @staticmethod
    def process_pcap_file(filepath: str, db: Session) -> Dict[str, Any]:
        """
        Parses a PCAP file using Scapy, applies firewall rules and anomaly detection,
        records logs with is_simulated=False, and returns summary metrics.
        """
        start_time = time.time()
        
        # Read PCAP packets using Scapy
        try:
            packets = rdpcap(filepath)
        except Exception as e:
            raise ValueError(f"Failed to read PCAP file with Scapy: {str(e)}")

        firewall_engine = FirewallEngine(default_policy=settings.DEFAULT_POLICY)
        policy_setting = db.query(SystemSetting).filter(SystemSetting.key == "DEFAULT_POLICY").first()
        if policy_setting:
            firewall_engine.set_default_policy(policy_setting.value)

        rules = db.query(FirewallRule).all()
        anomaly_detector = AnomalyDetector()

        total = 0
        allowed = 0
        blocked = 0
        protocols_count = {}
        alerts_created = []

        for pkt in packets:
            metadata = PacketAnalyzer.analyze_scapy_packet(pkt)
            if not metadata or metadata.protocol == "NON-IP":
                continue

            total += 1
            protocols_count[metadata.protocol] = protocols_count.get(metadata.protocol, 0) + 1

            # Firewall rule evaluation
            decision = firewall_engine.evaluate_packet(
                rules=rules,
                src_ip=metadata.src_ip,
                dst_ip=metadata.dst_ip,
                protocol=metadata.protocol,
                src_port=metadata.src_port,
                dst_port=metadata.dst_port
            )

            if decision.action == "ALLOW":
                allowed += 1
            else:
                blocked += 1

            # Anomaly detection
            detected_alerts = anomaly_detector.inspect_packet(
                src_ip=metadata.src_ip,
                dst_ip=metadata.dst_ip,
                protocol=metadata.protocol,
                src_port=metadata.src_port,
                dst_port=metadata.dst_port,
                tcp_flags=metadata.tcp_flags
            )

            for alert_dict in detected_alerts:
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
                alerts_created.append(alert_dict["description"])

            # Save packet log (is_simulated = False because this is a PCAP file)
            packet_log = PacketLog(
                timestamp=datetime.datetime.now(datetime.timezone.utc),
                src_ip=metadata.src_ip,
                dst_ip=metadata.dst_ip,
                src_port=metadata.src_port,
                dst_port=metadata.dst_port,
                protocol=metadata.protocol,
                packet_size=metadata.packet_size,
                tcp_flags=metadata.tcp_flags,
                action=decision.action,
                matched_rule_id=decision.matched_rule_id,
                matched_rule_name=decision.matched_rule_name,
                decision_reason=decision.reason,
                is_simulated=False,
                raw_summary=metadata.raw_summary
            )
            db.add(packet_log)

        db.commit()

        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        return {
            "total_packets": total,
            "allowed_packets": allowed,
            "blocked_packets": blocked,
            "protocol_breakdown": protocols_count,
            "alerts_generated": len(alerts_created),
            "alert_samples": alerts_created[:5],
            "processing_time_ms": elapsed_ms
        }

    @staticmethod
    def generate_sample_pcap(output_path: str):
        """Generates a realistic sample PCAP file with 25 test packets for demonstration and testing."""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        packets = []

        # 1. DNS Query & Response
        packets.append(IP(src="192.168.1.15", dst="8.8.8.8") / UDP(sport=53214, dport=53) / Raw(b"DNS query example.com"))
        packets.append(IP(src="8.8.8.8", dst="192.168.1.15") / UDP(sport=53, dport=53214) / Raw(b"DNS answer 93.184.216.34"))

        # 2. HTTP Web Request & Response
        packets.append(IP(src="192.168.1.15", dst="93.184.216.34") / TCP(sport=49160, dport=80, flags="S"))
        packets.append(IP(src="93.184.216.34", dst="192.168.1.15") / TCP(sport=80, dport=49160, flags="SA"))
        packets.append(IP(src="192.168.1.15", dst="93.184.216.34") / TCP(sport=49160, dport=80, flags="PA") / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))

        # 3. HTTPS TLS Client Hello
        packets.append(IP(src="192.168.1.20", dst="142.250.190.46") / TCP(sport=51200, dport=443, flags="S"))
        packets.append(IP(src="142.250.190.46", dst="192.168.1.20") / TCP(sport=443, dport=51200, flags="SA"))

        # 4. ICMP Ping echo request
        packets.append(IP(src="192.168.1.10", dst="1.1.1.1") / ICMP(type=8))
        packets.append(IP(src="1.1.1.1", dst="192.168.1.10") / ICMP(type=0))

        # 5. External Adversary Port Scan on ports 21, 22, 23, 80, 443, 8080
        attacker = "198.51.100.99"
        victim = "192.168.1.100"
        for p in [21, 22, 23, 80, 443, 3389, 8080]:
            packets.append(IP(src=attacker, dst=victim) / TCP(sport=random_port(p), dport=p, flags="S"))

        # 6. SMB exploit attempt on port 445
        packets.append(IP(src="203.0.113.45", dst="192.168.1.1") / TCP(sport=44120, dport=445, flags="S"))

        # 7. Allowed SSH session
        packets.append(IP(src="192.168.1.50", dst="192.168.1.100") / TCP(sport=38200, dport=22, flags="S"))

        wrpcap(output_path, packets)
        return output_path

def random_port(seed: int) -> int:
    return 40000 + (seed * 137) % 20000
