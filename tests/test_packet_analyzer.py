import pytest
from scapy.all import IP, TCP, UDP, ICMP, Ether, Raw
from app.services.packet_analyzer import PacketAnalyzer

def test_analyze_tcp_packet():
    scapy_pkt = IP(src="192.168.1.15", dst="93.184.216.34") / TCP(sport=51234, dport=443, flags="SA")
    meta = PacketAnalyzer.analyze_scapy_packet(scapy_pkt)

    assert meta is not None
    assert meta.src_ip == "192.168.1.15"
    assert meta.dst_ip == "93.184.216.34"
    assert meta.protocol == "TCP"
    assert meta.src_port == 51234
    assert meta.dst_port == 443
    assert "SYN" in meta.tcp_flags
    assert "ACK" in meta.tcp_flags
    assert meta.packet_size > 0

def test_analyze_udp_packet():
    scapy_pkt = IP(src="10.0.0.5", dst="8.8.8.8") / UDP(sport=61000, dport=53) / Raw(b"DNS query")
    meta = PacketAnalyzer.analyze_scapy_packet(scapy_pkt)

    assert meta is not None
    assert meta.src_ip == "10.0.0.5"
    assert meta.dst_ip == "8.8.8.8"
    assert meta.protocol == "UDP"
    assert meta.src_port == 61000
    assert meta.dst_port == 53
    assert meta.tcp_flags is None

def test_analyze_icmp_packet_missing_ports():
    scapy_pkt = IP(src="192.168.1.50", dst="1.1.1.1") / ICMP(type=8)
    meta = PacketAnalyzer.analyze_scapy_packet(scapy_pkt)

    assert meta is not None
    assert meta.src_ip == "192.168.1.50"
    assert meta.dst_ip == "1.1.1.1"
    assert meta.protocol == "ICMP"
    assert meta.src_port is None
    assert meta.dst_port is None

def test_analyze_non_ip_packet():
    scapy_pkt = Ether() / Raw(b"Raw Ethernet Frame")
    meta = PacketAnalyzer.analyze_scapy_packet(scapy_pkt)

    assert meta is not None
    assert meta.protocol == "NON-IP"

def test_parse_tcp_flags():
    assert PacketAnalyzer.parse_tcp_flags("S") == "SYN"
    assert PacketAnalyzer.parse_tcp_flags("A") == "ACK"
    assert PacketAnalyzer.parse_tcp_flags("SA") == "SYN-ACK"
    assert PacketAnalyzer.parse_tcp_flags("FA") == "FIN-ACK"
    assert PacketAnalyzer.parse_tcp_flags("R") == "RST"
    assert PacketAnalyzer.parse_tcp_flags("") == ""
