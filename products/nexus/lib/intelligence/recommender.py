"""
Nexus Action Recommender

Generates prioritized defense recommendations based on
threat analysis, correlation results, and MITRE ATT&CK mapping.
"""

import logging
import uuid
from typing import Any, Dict, List, Optional

from shared.mssp.types import ActionPriority, ActionType, RecommendedAction

from .correlator import CorrelationResult

logger = logging.getLogger(__name__)

# MITRE ATT&CK technique → recommended actions
MITRE_ACTION_MAP = {
    # Reconnaissance
    "T1595": [("monitor", ActionPriority.LOW)],  # Active Scanning
    "T1046": [("rate_limit", ActionPriority.MEDIUM)],  # Network Service Discovery

    # Initial Access
    "T1190": [("block_ip", ActionPriority.HIGH)],  # Exploit Public-Facing Application
    "T1566": [("alert", ActionPriority.MEDIUM)],  # Phishing

    # Execution
    "T1059": [("quarantine", ActionPriority.HIGH)],  # Command and Scripting
    "T1203": [("block_ip", ActionPriority.CRITICAL)],  # Exploitation for Client Execution

    # Command and Control
    "T1071": [("block_domain", ActionPriority.HIGH)],  # Application Layer Protocol
    "T1568": [("dns_sinkhole", ActionPriority.HIGH)],  # Dynamic Resolution (DGA)
    "T1572": [("block_ip", ActionPriority.HIGH)],  # Protocol Tunneling

    # Exfiltration
    "T1048": [("block_ip", ActionPriority.CRITICAL)],  # Exfiltration Over Alternative Protocol
    "T1041": [("terminate_session", ActionPriority.CRITICAL)],  # Exfiltration Over C2

    # Impact
    "T1498": [("rate_limit", ActionPriority.CRITICAL)],  # Network Denial of Service
    "T1499": [("block_ip", ActionPriority.CRITICAL)],  # Endpoint Denial of Service
}

# Severity → default action map
SEVERITY_ACTION_MAP = {
    "CRITICAL": ("block_ip", ActionPriority.CRITICAL),
    "HIGH": ("block_ip", ActionPriority.HIGH),
    "MEDIUM": ("rate_limit", ActionPriority.MEDIUM),
    "LOW": ("monitor", ActionPriority.LOW),
    "INFO": ("alert", ActionPriority.INFO),
}


class ActionRecommender:
    """Generates defense recommendations from analysis results.

    Uses MITRE ATT&CK mapping, correlation data, and confidence
    scoring to produce prioritized RecommendedAction objects.
    """

    def __init__(self, nexus_node_id: str = ""):
        self._nexus_node_id = nexus_node_id
        self._recommendations_generated = 0

    def recommend(
        self,
        finding: Dict[str, Any],
        correlation: Optional[CorrelationResult] = None,
        mitre_id: str = "",
    ) -> List[RecommendedAction]:
        """Generate recommendations for a finding.

        Args:
            finding: The threat finding dict.
            correlation: Cross-device correlation result.
            mitre_id: MITRE ATT&CK technique ID.

        Returns:
            List of RecommendedAction objects, sorted by priority.
        """
        recommendations = []
        severity = finding.get("severity", "LOW")
        ioc_value = finding.get("ioc_value", "")
        finding_id = finding.get("finding_id", "")

        # Get base action from MITRE mapping or severity
        if mitre_id and mitre_id in MITRE_ACTION_MAP:
            for action_type, priority in MITRE_ACTION_MAP[mitre_id]:
                rec = self._build_recommendation(
                    finding_id=finding_id,
                    action_type=action_type,
                    target=ioc_value,
                    priority=priority,
                    confidence=0.85,
                    reasoning=f"MITRE ATT&CK {mitre_id} detected. "
                              f"Recommended action: {action_type}.",
                    mitre_id=mitre_id,
                )
                recommendations.append(rec)
        else:
            action_type, priority = SEVERITY_ACTION_MAP.get(
                severity, ("alert", ActionPriority.INFO),
            )
            rec = self._build_recommendation(
                finding_id=finding_id,
                action_type=action_type,
                target=ioc_value,
                priority=priority,
                confidence=0.7,
                reasoning=f"Severity {severity} threat detected. "
                          f"Recommended action: {action_type}.",
            )
            recommendations.append(rec)

        # Boost priority if campaign detected
        if correlation and correlation.is_campaign:
            for rec in recommendations:
                rec.priority = max(1, rec.priority - 1)  # Increase priority
                rec.confidence = min(1.0, rec.confidence + 0.1)
                rec.mesh_propagate = True
                rec.reasoning += (
                    f" CAMPAIGN: Same IOC seen on {len(correlation.source_nodes)} nodes."
                )

        # Set mesh propagation for HIGH+ priority
        for rec in recommendations:
            if rec.priority <= ActionPriority.HIGH.value:
                rec.mesh_propagate = True

        # Sort by priority (lower = higher)
        recommendations.sort(key=lambda r: r.priority)

        self._recommendations_generated += len(recommendations)
        return recommendations

    def get_stats(self) -> Dict:
        return {"recommendations_generated": self._recommendations_generated}

    def _build_recommendation(
        self,
        finding_id: str,
        action_type: str,
        target: str,
        priority: int,
        confidence: float,
        reasoning: str,
        mitre_id: str = "",
    ) -> RecommendedAction:
        """Build a RecommendedAction with standard fields."""
        # Map action type string to ActionType enum value
        action_type_value = action_type
        for at in ActionType:
            if at.value == action_type:
                action_type_value = at.value
                break

        # TTL based on priority
        ttl_map = {1: 86400, 2: 14400, 3: 3600, 4: 1800, 5: 900}
        ttl = ttl_map.get(priority, 3600)

        return RecommendedAction(
            finding_id=finding_id,
            action_type=action_type_value,
            target=target,
            confidence=confidence,
            reasoning=reasoning,
            ttl_seconds=ttl,
            priority=priority,
            mitre_attack_id=mitre_id,
            nexus_analysis={
                "nexus_node": self._nexus_node_id,
                "analysis_version": "1.0.0",
            },
        )
