"""
Nexus Analysis Engine

Deep threat analysis orchestrator. Takes findings from the MSSP queue,
enriches them with cross-device correlation, classifies using AEGIS-Deep,
and generates actionable recommendations.

Pipeline:
    1. Enrich — cross-reference with correlation DB
    2. Correlate — check same IOC across other nodes
    3. Classify — map to MITRE ATT&CK
    4. Recommend — generate prioritized actions
    5. Validate — confidence scoring
"""

import logging
import time
from typing import Any, Dict, List, Optional

from shared.mssp.types import IntelligenceReport, RecommendedAction, ThreatFinding

from .correlator import ThreatCorrelator
from .recommender import ActionRecommender

logger = logging.getLogger(__name__)

# MITRE ATT&CK classification heuristics
THREAT_MITRE_MAP = {
    "ids_alert": "T1190",           # Exploit Public-Facing Application
    "port_scan": "T1046",           # Network Service Discovery
    "brute_force": "T1110",         # Brute Force
    "dns_suspicious": "T1568",      # Dynamic Resolution
    "dns_tunnel": "T1572",          # Protocol Tunneling
    "malware_c2": "T1071",          # Application Layer Protocol
    "ddos": "T1498",                # Network DoS
    "exfiltration": "T1048",        # Exfil Over Alternative Protocol
    "lateral_movement": "T1021",    # Remote Services
    "privilege_escalation": "T1068",# Exploitation for Privilege Escalation
}


class AnalysisResult:
    """Result of deep analysis on a finding."""

    def __init__(self, finding: ThreatFinding):
        self.finding = finding
        self.mitre_techniques: List[str] = []
        self.cross_device_hits = 0
        self.is_campaign = False
        self.threat_assessment = "possible"  # confirmed/likely/possible/false_positive
        self.confidence = 0.0
        self.recommendations: List[RecommendedAction] = []
        self.analysis_duration_ms = 0
        self.summary = ""


class NexusAnalysisEngine:
    """Deep threat analysis engine for Nexus nodes.

    Orchestrates the full analysis pipeline:
    enrichment → correlation → classification → recommendation.
    """

    def __init__(self, nexus_node_id: str = ""):
        self._nexus_node_id = nexus_node_id
        self.correlator = ThreatCorrelator()
        self.recommender = ActionRecommender(nexus_node_id)

        # Statistics
        self._stats = {
            "findings_analyzed": 0,
            "campaigns_detected": 0,
            "recommendations_generated": 0,
            "avg_analysis_ms": 0.0,
        }

    def analyze(self, finding: ThreatFinding) -> AnalysisResult:
        """Run the full analysis pipeline on a finding.

        Args:
            finding: The ThreatFinding to analyze.

        Returns:
            AnalysisResult with recommendations.
        """
        start = time.time()
        result = AnalysisResult(finding)

        # Step 1: Enrich with correlation
        correlation = self.correlator.ingest(
            ioc_value=finding.ioc_value,
            ioc_type=finding.ioc_type,
            source_node=finding.source_node_id,
            severity=finding.severity,
        )

        result.cross_device_hits = correlation.hit_count
        result.is_campaign = correlation.is_campaign

        # Step 2: Classify MITRE ATT&CK
        mitre_id = self._classify_mitre(finding)
        if mitre_id:
            result.mitre_techniques.append(mitre_id)

        # Step 3: Assess threat level
        result.threat_assessment = self._assess_threat(finding, correlation)
        result.confidence = self._compute_confidence(finding, correlation)

        # Step 4: Generate recommendations
        if result.threat_assessment != "false_positive":
            finding_dict = finding.to_dict()
            recommendations = self.recommender.recommend(
                finding=finding_dict,
                correlation=correlation,
                mitre_id=mitre_id,
            )
            result.recommendations = recommendations

        # Step 5: Generate summary
        result.summary = self._generate_summary(result)
        result.analysis_duration_ms = int((time.time() - start) * 1000)

        # Update stats
        self._stats["findings_analyzed"] += 1
        self._stats["recommendations_generated"] += len(result.recommendations)
        if result.is_campaign:
            self._stats["campaigns_detected"] += 1

        # Running average
        n = self._stats["findings_analyzed"]
        self._stats["avg_analysis_ms"] = (
            (self._stats["avg_analysis_ms"] * (n - 1) + result.analysis_duration_ms) / n
        )

        logger.info(
            "Analysis complete: %s → %s (confidence=%.2f, %dms, %d recommendations)",
            finding.finding_id[:8],
            result.threat_assessment,
            result.confidence,
            result.analysis_duration_ms,
            len(result.recommendations),
        )

        return result

    def to_intelligence_report(self, result: AnalysisResult) -> IntelligenceReport:
        """Convert analysis result to MSSP IntelligenceReport."""
        return IntelligenceReport(
            finding_id=result.finding.finding_id,
            analyzed_by=self._nexus_node_id,
            analysis_duration_ms=result.analysis_duration_ms,
            threat_assessment=result.threat_assessment,
            cross_device_hits=result.cross_device_hits,
            mitre_techniques=result.mitre_techniques,
            recommendations=result.recommendations,
            summary=result.summary,
        )

    def get_stats(self) -> Dict:
        return {
            **self._stats,
            "correlator": self.correlator.get_stats(),
            "recommender": self.recommender.get_stats(),
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _classify_mitre(self, finding: ThreatFinding) -> str:
        """Map threat to MITRE ATT&CK technique ID."""
        # Direct mapping from threat type
        mitre_id = THREAT_MITRE_MAP.get(finding.threat_type, "")
        if mitre_id:
            return mitre_id

        # Check raw evidence for more clues
        evidence = finding.raw_evidence
        if evidence.get("signature", ""):
            sig = evidence["signature"].lower()
            if "scan" in sig:
                return "T1046"
            if "brute" in sig:
                return "T1110"
            if "exfil" in sig:
                return "T1048"

        return ""

    def _assess_threat(
        self, finding: ThreatFinding, correlation
    ) -> str:
        """Assess overall threat level."""
        # Campaign = likely real
        if correlation.is_campaign:
            return "confirmed"

        # High confidence + high severity = likely
        if finding.confidence >= 0.8 and finding.severity in ("CRITICAL", "HIGH"):
            return "likely"

        # Multiple sources = likely
        if correlation.hit_count >= 2:
            return "likely"

        # Single observation
        if finding.confidence >= 0.5:
            return "possible"

        return "possible"

    def _compute_confidence(
        self, finding: ThreatFinding, correlation
    ) -> float:
        """Compute overall confidence score."""
        base = finding.confidence

        # Boost for multi-source corroboration
        if correlation.hit_count >= 3:
            base = min(1.0, base + 0.2)
        elif correlation.hit_count >= 2:
            base = min(1.0, base + 0.1)

        # Boost for campaign
        if correlation.is_campaign:
            base = min(1.0, base + 0.15)

        return round(base, 3)

    def _generate_summary(self, result: AnalysisResult) -> str:
        """Generate plain-English summary."""
        f = result.finding
        parts = [
            f"Analyzed {f.threat_type} from {f.source_tier} node {f.source_node_id[:12]}.",
            f"IOC: {f.ioc_type} = {f.ioc_value}.",
            f"Assessment: {result.threat_assessment} (confidence: {result.confidence:.0%}).",
        ]

        if result.is_campaign:
            parts.append(
                f"CAMPAIGN: Same IOC seen on {result.cross_device_hits} nodes."
            )

        if result.mitre_techniques:
            parts.append(f"MITRE ATT&CK: {', '.join(result.mitre_techniques)}.")

        if result.recommendations:
            actions = [r.action_type for r in result.recommendations]
            parts.append(f"Recommended: {', '.join(actions)}.")

        return " ".join(parts)
