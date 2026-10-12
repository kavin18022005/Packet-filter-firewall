import pytest
from app.engine.anomaly_detector import AnomalyDetector

def test_sensitive_port_probe_alert():
    detector = AnomalyDetector()
    alerts = detector.inspect_packet(
        src_ip="198.51.100.99",
        dst_ip="192.168.1.1",
        protocol="TCP",
        src_port=54000,
        dst_port=23,
        tcp_flags="SYN"
    )
    assert len(alerts) >= 1
    assert any(a["alert_type"] == "SENSITIVE_PORT_PROBE" and a["severity"] == "HIGH" for a in alerts)

def test_port_scan_detection_threshold():
    detector = AnomalyDetector(port_scan_threshold=5, port_scan_window_sec=30)
    attacker_ip = "198.51.100.22"

    # Send 4 distinct port probes (below threshold of 5)
    for p in [21, 22, 80, 443]:
        alerts = detector.inspect_packet(
            src_ip=attacker_ip,
            dst_ip="192.168.1.10",
            protocol="TCP",
            src_port=40000 + p,
            dst_port=p,
            tcp_flags="SYN"
        )
        assert not any(a["alert_type"] == "PORT_SCAN" for a in alerts)

    # 5th distinct port probe reaches threshold -> PORT_SCAN alert
    alerts = detector.inspect_packet(
        src_ip=attacker_ip,
        dst_ip="192.168.1.10",
        protocol="TCP",
        src_port=40000 + 8080,
        dst_port=8080,
        tcp_flags="SYN"
    )
    port_scan_alerts = [a for a in alerts if a["alert_type"] == "PORT_SCAN"]
    assert len(port_scan_alerts) == 1
    assert port_scan_alerts[0]["severity"] == "CRITICAL"
    assert "5 distinct ports" in port_scan_alerts[0]["description"]

def test_syn_flood_alert_threshold():
    detector = AnomalyDetector(syn_flood_threshold=10, syn_flood_window_sec=10)
    attacker_ip = "203.0.113.50"

    # Send 9 SYN packets (below threshold of 10)
    for _ in range(9):
        alerts = detector.inspect_packet(
            src_ip=attacker_ip,
            dst_ip="192.168.1.100",
            protocol="TCP",
            src_port=50000,
            dst_port=80,
            tcp_flags="SYN"
        )
        assert not any(a["alert_type"] == "SYN_FLOOD" for a in alerts)

    # 10th SYN packet triggers SYN_FLOOD alert
    alerts = detector.inspect_packet(
        src_ip=attacker_ip,
        dst_ip="192.168.1.100",
        protocol="TCP",
        src_port=50001,
        dst_port=80,
        tcp_flags="SYN"
    )
    syn_flood_alerts = [a for a in alerts if a["alert_type"] == "SYN_FLOOD"]
    assert len(syn_flood_alerts) == 1
    assert syn_flood_alerts[0]["severity"] == "HIGH"
