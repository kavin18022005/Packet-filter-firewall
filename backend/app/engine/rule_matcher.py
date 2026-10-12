import ipaddress
from typing import Optional, Tuple, List

class RuleMatcher:
    """
    Evaluates packet attributes against firewall rule criteria:
    - IP addresses and CIDR subnets (IPv4 and IPv6)
    - TCP/UDP Ports (single, lists, ranges, ANY)
    - Network Protocols (TCP, UDP, ICMP, ANY)
    """

    @staticmethod
    def validate_ip_spec(ip_spec: str) -> Tuple[bool, Optional[str]]:
        """Validates an IP or CIDR specification."""
        clean = ip_spec.strip().upper()
        if clean in ("ANY", "*", ""):
            return True, None
        try:
            # Allows single IP or CIDR (strict=False permits e.g. 192.168.1.5/24)
            ipaddress.ip_network(clean, strict=False)
            return True, None
        except ValueError as e:
            return False, f"Invalid IP or CIDR '{ip_spec}': {str(e)}"

    @staticmethod
    def validate_port_spec(port_spec: str) -> Tuple[bool, Optional[str]]:
        """Validates a port specification: ANY, single (80), list (80,443), range (8000-8080)."""
        clean = port_spec.strip().upper()
        if clean in ("ANY", "*", ""):
            return True, None

        # Split comma-separated items
        parts = clean.split(",")
        for part in parts:
            part = part.strip()
            if "-" in part:
                range_tokens = part.split("-")
                if len(range_tokens) != 2:
                    return False, f"Invalid port range '{part}'. Format must be START-END (e.g. 8000-8080)."
                try:
                    p1 = int(range_tokens[0])
                    p2 = int(range_tokens[1])
                    if not (1 <= p1 <= 65535 and 1 <= p2 <= 65535):
                        return False, f"Port range '{part}' contains values outside 1-65535."
                    if p1 > p2:
                        return False, f"Port range '{part}' has start port greater than end port."
                except ValueError:
                    return False, f"Port range '{part}' contains non-integer values."
            else:
                try:
                    p = int(part)
                    if not (1 <= p <= 65535):
                        return False, f"Port '{part}' is outside valid range (1-65535)."
                except ValueError:
                    return False, f"Port '{part}' is not a valid integer."

        return True, None

    @staticmethod
    def match_ip(rule_ip: str, packet_ip: str) -> bool:
        """
        Returns True if packet_ip matches rule_ip.
        rule_ip can be 'ANY', '*', single IP ('192.168.1.10'), or CIDR ('10.0.0.0/8').
        """
        clean_rule = rule_ip.strip().upper() if rule_ip else "ANY"
        if clean_rule in ("ANY", "*", ""):
            return True

        if not packet_ip:
            return False

        try:
            pkt_addr = ipaddress.ip_address(packet_ip.strip())
            rule_net = ipaddress.ip_network(clean_rule, strict=False)
            return pkt_addr in rule_net
        except ValueError:
            # Fallback string comparison if address parsing fails
            return clean_rule == packet_ip.strip().upper()

    @staticmethod
    def match_port(rule_port: str, packet_port: Optional[int]) -> bool:
        """
        Returns True if packet_port matches rule_port.
        rule_port can be 'ANY', '*', single port, comma list, or range.
        If rule_port is 'ANY', it matches even if packet_port is None (e.g. ICMP).
        If rule_port is specific and packet_port is None, returns False.
        """
        clean_rule = rule_port.strip().upper() if rule_port else "ANY"
        if clean_rule in ("ANY", "*", ""):
            return True

        if packet_port is None:
            return False

        parts = clean_rule.split(",")
        for part in parts:
            part = part.strip()
            if "-" in part:
                try:
                    p1, p2 = map(int, part.split("-"))
                    if p1 <= packet_port <= p2:
                        return True
                except ValueError:
                    continue
            else:
                try:
                    if int(part) == packet_port:
                        return True
                except ValueError:
                    continue

        return False

    @staticmethod
    def match_protocol(rule_proto: str, packet_proto: str) -> bool:
        """
        Returns True if packet_proto matches rule_proto.
        'ANY' matches any protocol.
        """
        clean_rule = rule_proto.strip().upper() if rule_proto else "ANY"
        if clean_rule in ("ANY", "*", ""):
            return True

        clean_pkt = packet_proto.strip().upper() if packet_proto else ""
        return clean_rule == clean_pkt
