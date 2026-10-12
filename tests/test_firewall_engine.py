import pytest
from app.engine.firewall import FirewallEngine
from app.models import FirewallRule

def make_rule(id, name, priority, action, protocol="ANY", src_ip="ANY", dst_ip="ANY", src_port="ANY", dst_port="ANY", enabled=True):
    return FirewallRule(
        id=id,
        name=name,
        priority=priority,
        action=action,
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        enabled=enabled
    )

def test_default_deny_behavior():
    engine = FirewallEngine(default_policy="BLOCK")
    # Empty rules list
    decision = engine.evaluate_packet(
        rules=[],
        src_ip="192.168.1.100",
        dst_ip="93.184.216.34",
        protocol="TCP",
        src_port=50000,
        dst_port=80
    )
    assert decision.action == "BLOCK"
    assert decision.matched_rule_id is None
    assert "Default-block policy applied" in decision.reason

def test_default_allow_behavior():
    engine = FirewallEngine(default_policy="ALLOW")
    decision = engine.evaluate_packet(
        rules=[],
        src_ip="192.168.1.100",
        dst_ip="93.184.216.34",
        protocol="TCP",
        src_port=50000,
        dst_port=80
    )
    assert decision.action == "ALLOW"
    assert decision.matched_rule_id is None
    assert "Default-allow policy applied" in decision.reason

def test_allowed_packet_match():
    engine = FirewallEngine(default_policy="BLOCK")
    rules = [
        make_rule(1, "Allow HTTP", priority=50, action="ALLOW", protocol="TCP", dst_port="80")
    ]
    decision = engine.evaluate_packet(
        rules=rules,
        src_ip="192.168.1.50",
        dst_ip="93.184.216.34",
        protocol="TCP",
        src_port=40120,
        dst_port=80
    )
    assert decision.action == "ALLOW"
    assert decision.matched_rule_id == 1
    assert "Matched Rule #1 'Allow HTTP'" in decision.reason

def test_blocked_packet_match():
    engine = FirewallEngine(default_policy="ALLOW")
    rules = [
        make_rule(2, "Block Telnet", priority=20, action="BLOCK", protocol="TCP", dst_port="23")
    ]
    decision = engine.evaluate_packet(
        rules=rules,
        src_ip="192.168.1.50",
        dst_ip="192.168.1.1",
        protocol="TCP",
        src_port=40120,
        dst_port=23
    )
    assert decision.action == "BLOCK"
    assert decision.matched_rule_id == 2
    assert "Matched Rule #2 'Block Telnet'" in decision.reason

def test_rule_priority_resolution():
    engine = FirewallEngine(default_policy="BLOCK")
    # Rule A: Priority 10 -> BLOCK subnet 198.51.100.0/24 on port 80
    # Rule B: Priority 20 -> ALLOW all TCP on port 80
    rules = [
        make_rule(10, "Allow All Web", priority=20, action="ALLOW", protocol="TCP", dst_port="80"),
        make_rule(20, "Block Malicious Host", priority=10, action="BLOCK", protocol="TCP", src_ip="198.51.100.0/24", dst_port="80")
    ]

    # Host from malicious subnet should be blocked because priority 10 < priority 20
    decision1 = engine.evaluate_packet(
        rules=rules,
        src_ip="198.51.100.44",
        dst_ip="192.168.1.1",
        protocol="TCP",
        src_port=52000,
        dst_port=80
    )
    assert decision1.action == "BLOCK"
    assert decision1.matched_rule_id == 20

    # Benign host should be allowed by rule 10
    decision2 = engine.evaluate_packet(
        rules=rules,
        src_ip="192.168.1.25",
        dst_ip="192.168.1.1",
        protocol="TCP",
        src_port=52000,
        dst_port=80
    )
    assert decision2.action == "ALLOW"
    assert decision2.matched_rule_id == 10

def test_disabled_rules_are_skipped():
    engine = FirewallEngine(default_policy="BLOCK")
    rules = [
        make_rule(1, "Disabled Allow Rule", priority=10, action="ALLOW", protocol="TCP", dst_port="80", enabled=False)
    ]
    decision = engine.evaluate_packet(
        rules=rules,
        src_ip="192.168.1.50",
        dst_ip="93.184.216.34",
        protocol="TCP",
        src_port=40120,
        dst_port=80
    )
    # Since the only rule is disabled, default policy applies
    assert decision.action == "BLOCK"
    assert decision.matched_rule_id is None
