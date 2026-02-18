"""
Defense Feedback — Vulnerability Report to QSecBit Signature Pipeline.

When the shadow pentester finds a vulnerability that QSecBit did not
detect, this module:
1. Extracts the attack signature (indicators, parameters, patterns)
2. Maps the attack to an OSI layer and severity
3. Generates a candidate QSecBit detection rule
4. Validates the rule against the attack execution evidence
5. Queues the rule for deployment via the signature updater

Integration points:
    core/qsecbit/signatures/updater.py — SignatureUpdater.record_detection()
    core/qsecbit/signatures/database.py — SignatureDatabase, ThreatSignature

Author: Andrei Toma
License: Proprietary
Version: 1.0.0
"""

import hashlib
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from .attack_library import AttackExecution, ExpectedDetection

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Layer & Severity Mappings
# ------------------------------------------------------------------

# Map attack_library ExpectedDetection → QSecBit OSILayer value
_DETECTION_TO_OSI_LAYER = {
    ExpectedDetection.L2_DATA_LINK: 2,
    ExpectedDetection.L3_NETWORK: 3,
    ExpectedDetection.L4_TRANSPORT: 4,
    ExpectedDetection.L5_SESSION: 5,
    ExpectedDetection.L7_APPLICATION: 7,
    ExpectedDetection.BEHAVIORAL: 7,   # Behavioral maps to application
    ExpectedDetection.NONE: 7,         # Default for evasion tests
}

# Map severity string → QSecBit Severity value (int)
_SEVERITY_MAP = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


# ------------------------------------------------------------------
# Data Types
# ------------------------------------------------------------------

@dataclass
class SignatureCandidate:
    """A candidate QSecBit signature generated from a pentest finding."""
    sig_id: str
    name: str
    description: str
    osi_layer: int                     # OSILayer enum value (2-7)
    severity: int                      # Severity enum value (0-4)
    attack_category: str
    mitre_id: str = ""
    indicators: List[str] = field(default_factory=list)
    feature_patterns: List[Dict[str, Any]] = field(default_factory=list)
    source_finding_id: str = ""
    confidence: float = 0.5
    validated: bool = False
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sig_id": self.sig_id,
            "name": self.name,
            "description": self.description,
            "osi_layer": self.osi_layer,
            "severity": self.severity,
            "attack_category": self.attack_category,
            "mitre_id": self.mitre_id,
            "indicators": self.indicators,
            "feature_patterns": self.feature_patterns,
            "source_finding_id": self.source_finding_id,
            "confidence": self.confidence,
            "validated": self.validated,
            "timestamp": self.timestamp,
        }


@dataclass
class FeedbackStats:
    """Statistics for the defense feedback loop."""
    findings_received: int = 0
    signatures_generated: int = 0
    signatures_deployed: int = 0
    signatures_rejected: int = 0
    last_finding_time: float = 0.0


# ------------------------------------------------------------------
# Defense Feedback
# ------------------------------------------------------------------

class DefenseFeedback:
    """Converts shadow pentester findings into QSecBit signatures.

    The pipeline:
    1. Receive VulnerabilityFinding from ShadowPentester
    2. Extract attack indicators and parameters
    3. Generate signature candidate with feature patterns
    4. Validate candidate (basic checks)
    5. Queue for deployment via signature_updater

    Thread-safe. Multiple pentest cycles can report concurrently.
    """

    MAX_PENDING = 100          # Max pending signatures before backpressure
    MIN_CONFIDENCE = 0.3       # Minimum confidence to generate signature

    def __init__(
        self,
        signature_updater: Optional[Any] = None,
        on_signature_generated: Optional[Callable] = None,
    ):
        """Initialize defense feedback.

        Args:
            signature_updater: QSecBit SignatureUpdater instance.
            on_signature_generated: Callback when a new signature is generated.
        """
        self._updater = signature_updater
        self._on_generated = on_signature_generated

        self._lock = threading.Lock()
        self._pending: List[SignatureCandidate] = []
        self._deployed: List[SignatureCandidate] = []
        self._stats = FeedbackStats()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process_finding(self, finding: Any) -> Optional[SignatureCandidate]:
        """Process a vulnerability finding from the shadow pentester.

        Args:
            finding: VulnerabilityFinding from shadow_pentester.

        Returns:
            SignatureCandidate if generated, None if rejected.
        """
        self._stats.findings_received += 1
        self._stats.last_finding_time = time.time()

        # Extract attack details from the finding
        evidence = getattr(finding, "evidence", {}) or {}
        attack_template = getattr(finding, "attack_template", "unknown")
        mitre_id = getattr(finding, "mitre_id", "")
        detection_gap = getattr(finding, "detection_gap", "")
        severity_str = getattr(finding, "severity", None)

        # Determine OSI layer from detection gap
        osi_layer = self._infer_osi_layer(detection_gap, evidence)

        # Determine severity
        severity = self._infer_severity(severity_str, evidence)

        # Extract indicators
        indicators = self._extract_indicators(evidence)

        # Generate feature patterns
        patterns = self._generate_feature_patterns(evidence, indicators)

        # Build signature candidate
        sig_id = self._make_sig_id(attack_template, mitre_id)
        candidate = SignatureCandidate(
            sig_id=sig_id,
            name=f"shadow-{attack_template}",
            description=(
                f"Auto-generated from shadow pentester finding: "
                f"{getattr(finding, 'title', attack_template)}"
            ),
            osi_layer=osi_layer,
            severity=severity,
            attack_category=evidence.get("category", "unknown"),
            mitre_id=mitre_id,
            indicators=indicators,
            feature_patterns=patterns,
            source_finding_id=getattr(finding, "finding_id", ""),
            confidence=self._calculate_confidence(evidence, indicators, patterns),
        )

        # Validate
        if candidate.confidence < self.MIN_CONFIDENCE:
            logger.debug(
                "Signature %s rejected: confidence %.2f < %.2f",
                sig_id, candidate.confidence, self.MIN_CONFIDENCE,
            )
            self._stats.signatures_rejected += 1
            return None

        candidate.validated = True
        self._stats.signatures_generated += 1

        # Queue for deployment
        with self._lock:
            if len(self._pending) >= self.MAX_PENDING:
                self._pending.pop(0)  # Drop oldest
            self._pending.append(candidate)

        # Deploy to updater if available
        self._deploy_signature(candidate)

        # Notify callback
        if self._on_generated:
            try:
                self._on_generated(candidate)
            except Exception as e:
                logger.warning("Signature callback error: %s", e)

        logger.info(
            "Generated signature %s from finding %s (confidence=%.2f)",
            sig_id,
            getattr(finding, "finding_id", "?"),
            candidate.confidence,
        )
        return candidate

    def get_pending(self) -> List[Dict[str, Any]]:
        """Get pending signature candidates."""
        with self._lock:
            return [s.to_dict() for s in self._pending]

    def get_deployed(self) -> List[Dict[str, Any]]:
        """Get deployed signatures."""
        with self._lock:
            return [s.to_dict() for s in self._deployed]

    def stats(self) -> Dict[str, Any]:
        """Get feedback statistics."""
        return {
            "findings_received": self._stats.findings_received,
            "signatures_generated": self._stats.signatures_generated,
            "signatures_deployed": self._stats.signatures_deployed,
            "signatures_rejected": self._stats.signatures_rejected,
            "pending_count": len(self._pending),
            "deployed_count": len(self._deployed),
            "last_finding_time": self._stats.last_finding_time,
        }

    # ------------------------------------------------------------------
    # Internal: Signature Generation
    # ------------------------------------------------------------------

    def _infer_osi_layer(
        self,
        detection_gap: str,
        evidence: Dict[str, Any],
    ) -> int:
        """Infer OSI layer from detection gap description."""
        gap_lower = detection_gap.lower()
        for detection, layer in _DETECTION_TO_OSI_LAYER.items():
            if detection.value.lower() in gap_lower:
                return layer

        # Fallback: look at evidence for clues
        category = evidence.get("category", "")
        if category in ("reconnaissance", "initial_access"):
            return 3  # Network layer
        if category in ("exfiltration", "c2"):
            return 7  # Application layer
        if category == "impact":
            return 4  # Transport layer

        return 7  # Default to application

    def _infer_severity(
        self,
        finding_severity: Any,
        evidence: Dict[str, Any],
    ) -> int:
        """Infer QSecBit severity from finding."""
        # Try finding severity directly
        if finding_severity is not None:
            sev_str = str(finding_severity).upper()
            if hasattr(finding_severity, "value"):
                sev_str = finding_severity.value.upper()
            if sev_str in _SEVERITY_MAP:
                return _SEVERITY_MAP[sev_str]

        # Try evidence severity
        ev_severity = evidence.get("severity_assigned", "")
        if ev_severity in _SEVERITY_MAP:
            return _SEVERITY_MAP[ev_severity]

        return 2  # Default MEDIUM

    def _extract_indicators(self, evidence: Dict[str, Any]) -> List[str]:
        """Extract attack indicators from execution evidence."""
        indicators = []

        # Template name is always an indicator
        template = evidence.get("template_name", "")
        if template:
            indicators.append(f"attack_type:{template}")

        # Category
        category = evidence.get("category", "")
        if category:
            indicators.append(f"category:{category}")

        # Parameters contain specific IOCs
        params = evidence.get("parameters", {})
        for key, value in params.items():
            if key in ("target_ip", "victim_ip", "attacker_ip"):
                continue  # IPs are context, not signatures
            if key in ("c2_domain",):
                indicators.append(f"domain:{value}")
            elif key in ("encoding",):
                indicators.append(f"encoding:{value}")
            elif key in ("scan_rate", "rate_pps") and isinstance(value, (int, float)):
                indicators.append(f"rate_threshold:{value}")

        return indicators

    def _generate_feature_patterns(
        self,
        evidence: Dict[str, Any],
        indicators: List[str],
    ) -> List[Dict[str, Any]]:
        """Generate QSecBit feature patterns from evidence."""
        patterns = []
        params = evidence.get("parameters", {})
        template_name = evidence.get("template_name", "")

        # Rate-based patterns
        for key in ("scan_rate", "rate_pps"):
            if key in params and isinstance(params[key], (int, float)):
                patterns.append({
                    "feature_name": "packet_rate",
                    "operator": "gt",
                    "value": params[key] * 0.5,  # 50% of attack rate
                    "weight": 1.5,
                })

        # DNS-based patterns
        if template_name in ("dns_tunnel", "dns_enumeration", "dga_c2"):
            patterns.append({
                "feature_name": "dns_query_rate",
                "operator": "gt",
                "value": 10,  # queries per second
                "weight": 1.5,
            })
            if template_name == "dns_tunnel":
                patterns.append({
                    "feature_name": "dns_query_length",
                    "operator": "gt",
                    "value": 60,
                    "weight": 2.0,
                })
            if template_name == "dga_c2":
                patterns.append({
                    "feature_name": "dns_nxdomain_rate",
                    "operator": "gt",
                    "value": 5,
                    "weight": 2.0,
                })

        # Port-scan patterns
        if template_name in ("port_scan", "slow_scan"):
            patterns.append({
                "feature_name": "unique_dest_ports",
                "operator": "gt",
                "value": 20,
                "weight": 1.5,
            })

        # ARP patterns
        if template_name in ("arp_spoof", "arp_scan"):
            patterns.append({
                "feature_name": "arp_rate",
                "operator": "gt",
                "value": 5,
                "weight": 1.5,
            })

        # Flood patterns
        if template_name in ("syn_flood", "udp_flood"):
            patterns.append({
                "feature_name": "half_open_connections",
                "operator": "gt",
                "value": 100,
                "weight": 2.0,
            })

        return patterns

    def _calculate_confidence(
        self,
        evidence: Dict[str, Any],
        indicators: List[str],
        patterns: List[Dict[str, Any]],
    ) -> float:
        """Calculate confidence score for the generated signature."""
        score = 0.3  # Base confidence

        # More indicators = higher confidence
        score += min(0.2, len(indicators) * 0.05)

        # Feature patterns increase confidence
        score += min(0.3, len(patterns) * 0.1)

        # Attack success increases confidence
        if evidence.get("success", False):
            score += 0.1

        # MITRE ID increases confidence (well-known technique)
        if evidence.get("template_id", ""):
            score += 0.1

        return min(1.0, score)

    # ------------------------------------------------------------------
    # Internal: Deployment
    # ------------------------------------------------------------------

    def _deploy_signature(self, candidate: SignatureCandidate) -> None:
        """Deploy a validated signature to QSecBit via the updater."""
        if self._updater is None:
            return

        try:
            # Use record_detection to feed the learning system
            features = {}
            for pattern in candidate.feature_patterns:
                features[pattern["feature_name"]] = pattern["value"]

            # Map layer int to OSILayer enum name
            layer_names = {
                2: "L2_DATA_LINK",
                3: "L3_NETWORK",
                4: "L4_TRANSPORT",
                5: "L5_SESSION",
                6: "L6_PRESENTATION",
                7: "L7_APPLICATION",
            }
            severity_names = {
                0: "INFO",
                1: "LOW",
                2: "MEDIUM",
                3: "HIGH",
                4: "CRITICAL",
            }

            # Import enums at call-time to avoid circular imports
            try:
                from core.qsecbit.signatures.database import OSILayer, Severity
                layer_enum = OSILayer[layer_names.get(candidate.osi_layer, "L7_APPLICATION")]
                severity_enum = Severity[severity_names.get(candidate.severity, "MEDIUM")]
            except (ImportError, KeyError):
                logger.debug("Could not import QSecBit enums — skipping deploy")
                return

            self._updater.record_detection(
                features=features,
                layer=layer_enum,
                severity=severity_enum,
                matched_sig_id=None,  # New signature, not matching existing
            )

            self._stats.signatures_deployed += 1
            with self._lock:
                self._deployed.append(candidate)
                if len(self._deployed) > 200:
                    self._deployed = self._deployed[-200:]

            logger.info("Deployed signature %s to QSecBit updater", candidate.sig_id)

        except Exception as e:
            logger.error("Failed to deploy signature %s: %s", candidate.sig_id, e)

    # ------------------------------------------------------------------
    # Internal: Helpers
    # ------------------------------------------------------------------

    def _make_sig_id(self, template_name: str, mitre_id: str) -> str:
        """Generate a unique signature ID."""
        data = f"shadow-sig-{template_name}-{mitre_id}-{time.time()}"
        return f"SHADOW-{hashlib.sha256(data.encode()).hexdigest()[:12].upper()}"
