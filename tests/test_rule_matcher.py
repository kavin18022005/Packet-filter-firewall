import pytest
from app.engine.rule_matcher import RuleMatcher

def test_ip_exact_and_cidr_matching():
    # Exact IP
    assert RuleMatcher.match_ip("192.168.1.10", "192.168.1.10") is True
    assert RuleMatcher.match_ip("192.168.1.10", "192.168.1.11") is False

    # CIDR Subnet /24
    assert RuleMatcher.match_ip("192.168.1.0/24", "192.168.1.55") is True
    assert RuleMatcher.match_ip("192.168.1.0/24", "192.168.2.1") is False

    # CIDR Subnet /16
    assert RuleMatcher.match_ip("10.0.0.0/16", "10.0.254.1") is True
    assert RuleMatcher.match_ip("10.0.0.0/16", "10.1.0.1") is False

    # Wildcards & ANY
    assert RuleMatcher.match_ip("ANY", "203.0.113.5") is True
    assert RuleMatcher.match_ip("*", "8.8.8.8") is True
    assert RuleMatcher.match_ip("", "127.0.0.1") is True

def test_invalid_ip_spec_validation():
    valid, err = RuleMatcher.validate_ip_spec("192.168.1.1")
    assert valid is True
    assert err is None

    valid, err = RuleMatcher.validate_ip_spec("10.0.0.0/8")
    assert valid is True
    assert err is None

    valid, err = RuleMatcher.validate_ip_spec("999.999.999.999")
    assert valid is False
    assert "Invalid IP" in err

    valid, err = RuleMatcher.validate_ip_spec("not-an-ip")
    assert valid is False

def test_port_matching():
    # Single port
    assert RuleMatcher.match_port("80", 80) is True
    assert RuleMatcher.match_port("80", 443) is False

    # Comma-separated list
    assert RuleMatcher.match_port("80,443,8080", 443) is True
    assert RuleMatcher.match_port("80,443,8080", 8080) is True
    assert RuleMatcher.match_port("80,443,8080", 22) is False

    # Port range
    assert RuleMatcher.match_port("8000-8088", 8050) is True
    assert RuleMatcher.match_port("8000-8088", 8000) is True
    assert RuleMatcher.match_port("8000-8088", 8088) is True
    assert RuleMatcher.match_port("8000-8088", 8089) is False

    # ANY matches anything and None
    assert RuleMatcher.match_port("ANY", 80) is True
    assert RuleMatcher.match_port("ANY", None) is True
    assert RuleMatcher.match_port("*", 53) is True

    # Missing port (None) with specific rule port
    assert RuleMatcher.match_port("80", None) is False

def test_invalid_port_spec_validation():
    valid, err = RuleMatcher.validate_port_spec("80,443")
    assert valid is True

    valid, err = RuleMatcher.validate_port_spec("1024-65535")
    assert valid is True

    # Out of range
    valid, err = RuleMatcher.validate_port_spec("70000")
    assert valid is False
    assert "outside valid range" in err

    # Inverted range
    valid, err = RuleMatcher.validate_port_spec("5000-4000")
    assert valid is False
    assert "start port greater than end port" in err

    # Non-integer
    valid, err = RuleMatcher.validate_port_spec("http")
    assert valid is False

def test_protocol_matching():
    # Standard matches (case-insensitive)
    assert RuleMatcher.match_protocol("TCP", "tcp") is True
    assert RuleMatcher.match_protocol("UDP", "UDP") is True
    assert RuleMatcher.match_protocol("ICMP", "icmp") is True
    assert RuleMatcher.match_protocol("ANY", "TCP") is True
    assert RuleMatcher.match_protocol("*", "UDP") is True

    # Mismatches
    assert RuleMatcher.match_protocol("TCP", "UDP") is False
    assert RuleMatcher.match_protocol("TCP", "ICMP") is False

    # Unsupported / unknown protocol
    assert RuleMatcher.match_protocol("TCP", "SCTP") is False
