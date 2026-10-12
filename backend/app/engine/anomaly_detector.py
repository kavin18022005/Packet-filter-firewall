import time
from collections import defaultdict, deque
from typing import Optional, List, Dict, Any, Tuple
from app.config import settings

class AnomalyDetector:
    """
    Stateful anomaly detection engine tracking connection patterns over sliding time windows.
    Detects:
    1. Port scanning (many ports targeted on destination hosts)
    2. SYN flood / connection bursts
    3. Probing known sensitive/vulnerable ports (e.g. 23, 445, 3389)
    4. ICMP ping flood attacks
    """

    SENSITIVE_PORTS = {
        23: "Telnet (Unencrypted Remote Access)",
        445: "SMB/Microsoft-DS (WannaCry/EternalBlue vector)",
        3389: "RDP (Remote Desktop Protocol)",
        1433: "MSSQL Server",
        3306: "MySQL Database Direct Access",
        2323: "Mirai Botnet Telnet Alternate",
        5555: "Android Debug Bridge (ADB)",
        4444: "Metasploit Default Handler Port",
        6379: "Redis Unauthenticated Exposure"
    }

    def __init__(
        self,
        port_scan_threshold: int = settings.PORT_SCAN_THRESHOLD,
        port_scan_window_sec: int = settings.PORT_SCAN_WINDOW_SECONDS,
        syn_flood_threshold: int = settings.SYN_FLOOD_THRESHOLD,
        syn_flood_window_sec: int = 15
    ):
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window_sec = port_scan_window_sec
        self.syn_flood_threshold = syn_flood_threshold
        self.syn_flood_window_sec = syn_flood_window_sec

        # IP -> deque of (timestamp, dst_port)
        self.ip_port_history: Dict[str, deque] = defaultdict(deque)
        # IP -> deque of timestamp for SYN packets
        self.ip_syn_history: Dict[str, deque] = defaultdict(deque)
        # IP -> deque of timestamp for ICMP packets
        self.ip_icmp_history: Dict[str, deque] = defaultdict(deque)
        # Cooldown trackers to prevent spamming duplicate alerts (key: (src_ip, alert_type) -> last_alert_time)
        self.alert_cooldowns: Dict[Tuple[str, str], float] = {}

    def inspect_packet(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        tcp_flags: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Inspects packet metadata and returns a list of detected alerts (if any).
        """
        now = time.time()
        detected_alerts = []

        # 1. Check Sensitive Port Probe
        if dst_port in self.SENSITIVE_PORTS:
            service_desc = self.SENSITIVE_PORTS[dst_port]
            cooldown_key = (src_ip, f"SENSITIVE_PORT_{dst_port}")
            if now - self.alert_cooldowns.get(cooldown_key, 0) > 20:
                self.alert_cooldowns[cooldown_key] = now
                detected_alerts.append({
                    "alert_type": "SENSITIVE_PORT_PROBE",
                    "severity": "HIGH",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "description": f"Probing sensitive service on port {dst_port} ({service_desc})",
                    "packet_count": 1
                })

        # 2. Check Port Scan
        if dst_port is not None:
            history = self.ip_port_history[src_ip]
            history.append((now, dst_port))

            # Prune entries older than port_scan_window_sec
            while history and now - history[0][0] > self.port_scan_window_sec:
                history.popleft()

            # Calculate unique destination ports scanned in window
            unique_ports = {p for _, p in history}
            if len(unique_ports) >= self.port_scan_threshold:
                cooldown_key = (src_ip, "PORT_SCAN")
                if now - self.alert_cooldowns.get(cooldown_key, 0) > 25:
                    self.alert_cooldowns[cooldown_key] = now
                    detected_alerts.append({
                        "alert_type": "PORT_SCAN",
                        "severity": "CRITICAL",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "description": f"Port scan detected: {len(unique_ports)} distinct ports probed in {self.port_scan_window_sec}s",
                        "packet_count": len(history)
                    })

        # 3. Check SYN Flood / Burst
        if protocol.upper() == "TCP" and tcp_flags and "SYN" in tcp_flags.upper():
            syn_history = self.ip_syn_history[src_ip]
            syn_history.append(now)

            while syn_history and now - syn_history[0] > self.syn_flood_window_sec:
                syn_history.popleft()

            if len(syn_history) >= self.syn_flood_threshold:
                cooldown_key = (src_ip, "SYN_FLOOD")
                if now - self.alert_cooldowns.get(cooldown_key, 0) > 20:
                    self.alert_cooldowns[cooldown_key] = now
                    detected_alerts.append({
                        "alert_type": "SYN_FLOOD",
                        "severity": "HIGH",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "description": f"SYN flood pattern: {len(syn_history)} connection requests in {self.syn_flood_window_sec}s",
                        "packet_count": len(syn_history)
                    })

        # 4. Check ICMP Ping Flood
        if protocol.upper() == "ICMP":
            icmp_history = self.ip_icmp_history[src_ip]
            icmp_history.append(now)

            while icmp_history and now - icmp_history[0] > 10:
                icmp_history.popleft()

            if len(icmp_history) >= 10:
                cooldown_key = (src_ip, "PING_FLOOD")
                if now - self.alert_cooldowns.get(cooldown_key, 0) > 15:
                    self.alert_cooldowns[cooldown_key] = now
                    detected_alerts.append({
                        "alert_type": "PING_FLOOD",
                        "severity": "MEDIUM",
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "description": f"ICMP ping burst: {len(icmp_history)} echo requests in 10s",
                        "packet_count": len(icmp_history)
                    })

        return detected_alerts
