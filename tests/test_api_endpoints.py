import pytest

def test_health_check(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "default_policy" in data

def test_rules_crud_and_validation(client):
    # 1. Reject invalid IP
    bad_ip_payload = {
        "name": "Bad IP Rule",
        "priority": 100,
        "action": "ALLOW",
        "protocol": "TCP",
        "src_ip": "invalid-ip-string",
        "dst_ip": "ANY",
        "src_port": "ANY",
        "dst_port": "80"
    }
    res = client.post("/api/rules", json=bad_ip_payload)
    assert res.status_code == 400
    assert "Source IP error" in res.json()["detail"]

    # 2. Reject invalid Port
    bad_port_payload = {
        "name": "Bad Port Rule",
        "priority": 100,
        "action": "ALLOW",
        "protocol": "TCP",
        "src_ip": "ANY",
        "dst_ip": "ANY",
        "src_port": "ANY",
        "dst_port": "99999"
    }
    res = client.post("/api/rules", json=bad_port_payload)
    assert res.status_code == 400
    assert "Destination Port error" in res.json()["detail"]

    # 3. Create valid rule with CIDR and port range
    valid_payload = {
        "name": "Allow Web Subnet",
        "priority": 50,
        "action": "ALLOW",
        "protocol": "TCP",
        "src_ip": "192.168.1.0/24",
        "dst_ip": "ANY",
        "src_port": "ANY",
        "dst_port": "80,443",
        "enabled": True,
        "description": "Internal web access"
    }
    res = client.post("/api/rules", json=valid_payload)
    assert res.status_code == 201
    created_rule = res.json()
    assert created_rule["id"] > 0
    assert created_rule["name"] == "Allow Web Subnet"
    rule_id = created_rule["id"]

    # 4. Get rules list
    res = client.get("/api/rules")
    assert res.status_code == 200
    rules = res.json()
    assert any(r["id"] == rule_id for r in rules)

    # 5. Toggle enabled
    res = client.patch(f"/api/rules/{rule_id}/toggle")
    assert res.status_code == 200
    assert res.json()["enabled"] is False

    # 6. Update priority
    res = client.patch(f"/api/rules/{rule_id}/priority?priority=15")
    assert res.status_code == 200
    assert res.json()["priority"] == 15

    # 7. Delete rule
    res = client.delete(f"/api/rules/{rule_id}")
    assert res.status_code == 200
    assert res.json()["status"] == "success"

def test_packet_ingestion_and_pagination(client):
    # Ingest a packet
    packet_payload = {
        "src_ip": "10.0.0.15",
        "dst_ip": "142.250.190.46",
        "protocol": "TCP",
        "src_port": 50000,
        "dst_port": 443,
        "packet_size": 128,
        "tcp_flags": "SYN",
        "is_simulated": True
    }
    res = client.post("/api/packets/ingest", json=packet_payload)
    assert res.status_code == 201
    log = res.json()
    assert log["src_ip"] == "10.0.0.15"
    assert log["action"] in ("ALLOW", "BLOCK")

    # Fetch paginated logs
    res = client.get("/api/packets?page=1&page_size=10")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 1
    assert len(data["items"]) >= 1

    # Search filter
    res = client.get("/api/packets?search=10.0.0.15")
    assert res.status_code == 200
    search_data = res.json()
    assert search_data["total"] >= 1

def test_security_alerts_and_auto_mitigation(client):
    # Ingest suspicious port 23 packet to trigger sensitive port alert
    client.post("/api/packets/ingest", json={
        "src_ip": "198.51.100.99",
        "dst_ip": "192.168.1.1",
        "protocol": "TCP",
        "src_port": 45000,
        "dst_port": 23,
        "tcp_flags": "SYN"
    })

    # Retrieve alerts
    res = client.get("/api/alerts")
    assert res.status_code == 200
    alerts = res.json()
    assert len(alerts) >= 1
    alert_id = alerts[0]["id"]

    # Update alert status
    res = client.patch(f"/api/alerts/{alert_id}/status", json={"status": "ACKNOWLEDGED"})
    assert res.status_code == 200
    assert res.json()["status"] == "ACKNOWLEDGED"

    # One-click block IP mitigation
    res = client.post(f"/api/alerts/{alert_id}/block-ip")
    assert res.status_code == 200
    blocked_rule = res.json()
    assert blocked_rule["action"] == "BLOCK"
    assert blocked_rule["src_ip"] == "198.51.100.99"

def test_dashboard_stats(client):
    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    stats = res.json()
    assert "total_packets" in stats
    assert "allowed_packets" in stats
    assert "blocked_packets" in stats
    assert "protocol_distribution" in stats

def test_simulator_and_settings(client):
    # Check simulator status
    res = client.get("/api/simulator/status")
    assert res.status_code == 200
    assert "is_running" in res.json()

    # Generate immediate batch
    res = client.post("/api/simulator/generate?count=3")
    assert res.status_code == 200
    assert res.json()["generated_count"] == 3

    # Update default policy in settings
    res = client.put("/api/settings/DEFAULT_POLICY", json={"value": "ALLOW"})
    assert res.status_code == 200
    assert res.json()["value"] == "ALLOW"

    # Reset back to BLOCK
    res = client.put("/api/settings/DEFAULT_POLICY", json={"value": "BLOCK"})
    assert res.status_code == 200
    assert res.json()["value"] == "BLOCK"
