from typing import List, Optional, Dict, Any
from app.models import FirewallRule
from app.engine.rule_matcher import RuleMatcher

class FirewallDecision:
    def __init__(
        self,
        action: str,
        matched_rule_id: Optional[int],
        matched_rule_name: Optional[str],
        reason: str
    ):
        self.action = action.upper()
        self.matched_rule_id = matched_rule_id
        self.matched_rule_name = matched_rule_name
        self.reason = reason

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "matched_rule_id": self.matched_rule_id,
            "matched_rule_name": self.matched_rule_name,
            "reason": self.reason
        }


class FirewallEngine:
    """
    Core Firewall Engine implementing rule ordering, evaluation, and default policy fallback.
    """

    def __init__(self, default_policy: str = "BLOCK"):
        self.default_policy = default_policy.upper()

    def set_default_policy(self, policy: str):
        if policy.upper() in ("ALLOW", "BLOCK"):
            self.default_policy = policy.upper()

    def evaluate_packet(
        self,
        rules: List[FirewallRule],
        src_ip: str,
        dst_ip: str,
        protocol: str,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None
    ) -> FirewallDecision:
        """
        Evaluates an incoming packet against active rules in priority order.
        Rules with lower priority integer are evaluated first.
        First matching enabled rule determines the decision.
        If no rules match, the default policy (BLOCK/ALLOW) is applied.
        """
        # Sort rules by priority ascending, then id ascending
        sorted_rules = sorted(
            [r for r in rules if r.enabled],
            key=lambda r: (r.priority, r.id)
        )

        for rule in sorted_rules:
            # Check protocol
            if not RuleMatcher.match_protocol(rule.protocol, protocol):
                continue

            # Check source IP
            if not RuleMatcher.match_ip(rule.src_ip, src_ip):
                continue

            # Check destination IP
            if not RuleMatcher.match_ip(rule.dst_ip, dst_ip):
                continue

            # Check source port
            if not RuleMatcher.match_port(rule.src_port, src_port):
                continue

            # Check destination port
            if not RuleMatcher.match_port(rule.dst_port, dst_port):
                continue

            # If all criteria match, this rule dictates the decision
            return FirewallDecision(
                action=rule.action,
                matched_rule_id=rule.id,
                matched_rule_name=rule.name,
                reason=f"Matched Rule #{rule.id} '{rule.name}' (Priority {rule.priority})"
            )

        # Default-deny / fallback policy
        return FirewallDecision(
            action=self.default_policy,
            matched_rule_id=None,
            matched_rule_name=None,
            reason=f"Default-{self.default_policy.lower()} policy applied (No matching rule)"
        )
