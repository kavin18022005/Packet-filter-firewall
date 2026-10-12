from typing import Optional, Dict, Any
from scapy.all import Packet, IP, IPv6, TCP, UDP, ICMP, Raw

class PacketMetadata:
    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        packet_size: int = 0,
        tcp_flags: Optional[str] = None,
        raw_summary: Optional[str] = None
    ):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.src_port = src_port
        self.dst_port = dst_port
        self.packet_size = packet_size
        self.tcp_flags = tcp_flags
        self.raw_summary = raw_summary

    def to_dict(self) -> Dict[str, Any]:
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "packet_size": self.packet_size,
            "tcp_flags": self.tcp_flags,
            "raw_summary": self.raw_summary
        }


class PacketAnalyzer:
    """
    Extracts structured Layer 3 and Layer 4 metadata from raw Scapy packets or network buffers.
    Handles TCP, UDP, ICMP, and non-IP packets safely.
    """

    @staticmethod
    def parse_tcp_flags(flags) -> str:
        """Parses Scapy TCP flags into a human-readable string (e.g. 'SYN-ACK', 'SYN', 'ACK', 'FIN', 'RST')."""
        if not flags:
            return ""
        flag_names = []
        flag_str = str(flags)
        if "F" in flag_str:
            flag_names.append("FIN")
        if "S" in flag_str:
            flag_names.append("SYN")
        if "R" in flag_str:
            flag_names.append("RST")
        if "P" in flag_str:
            flag_names.append("PSH")
        if "A" in flag_str:
            flag_names.append("ACK")
        if "U" in flag_str:
            flag_names.append("URG")
        return "-".join(flag_names) if flag_names else str(flags)

    @classmethod
    def analyze_scapy_packet(cls, packet: Packet) -> Optional[PacketMetadata]:
        """Dissects a Scapy packet object and returns structured PacketMetadata."""
        try:
            packet_size = len(packet) if packet else 0
            src_ip = ""
            dst_ip = ""
            protocol = "OTHER"
            src_port = None
            dst_port = None
            tcp_flags = None

            # Layer 3 - IP
            if packet.haslayer(IP):
                ip_layer = packet.getlayer(IP)
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
            elif packet.haslayer(IPv6):
                ipv6_layer = packet.getlayer(IPv6)
                src_ip = ipv6_layer.src
                dst_ip = ipv6_layer.dst
            else:
                # Non-IP packet (e.g., ARP, STP)
                return PacketMetadata(
                    src_ip="0.0.0.0",
                    dst_ip="255.255.255.255",
                    protocol="NON-IP",
                    packet_size=packet_size,
                    raw_summary=packet.summary() if hasattr(packet, "summary") else "Non-IP frame"
                )

            # Layer 4 - TCP / UDP / ICMP
            if packet.haslayer(TCP):
                tcp_layer = packet.getlayer(TCP)
                protocol = "TCP"
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                tcp_flags = cls.parse_tcp_flags(tcp_layer.flags)
            elif packet.haslayer(UDP):
                udp_layer = packet.getlayer(UDP)
                protocol = "UDP"
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
                src_port = None
                dst_port = None

            summary = packet.summary() if hasattr(packet, "summary") else f"{protocol} {src_ip} -> {dst_ip}"

            return PacketMetadata(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                src_port=src_port,
                dst_port=dst_port,
                packet_size=packet_size,
                tcp_flags=tcp_flags,
                raw_summary=summary
            )
        except Exception as e:
            # Fallback error recovery
            return PacketMetadata(
                src_ip="0.0.0.0",
                dst_ip="0.0.0.0",
                protocol="MALFORMED",
                packet_size=len(packet) if packet else 0,
                raw_summary=f"Malformed packet parse error: {str(e)}"
            )
