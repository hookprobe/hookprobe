"""
Hybrid Attack Classifier - ML + Signature Fusion

Combines machine learning classification with signature-based detection
for optimal accuracy and performance.

Strategy:
1. Signature check first (fast, deterministic)
2. ML classification second (probabilistic, catches novel attacks)
3. Confidence fusion for final decision

Performance:
- <1ms total classification time
- ~300KB memory footprint
- Minimal CPU overhead

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import time
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Tuple, Any
from collections import defaultdict

from .classifier import AttackClassifier, FeatureExtractor, NetworkFeatures
from ..signatures import SignatureDatabase, SignatureMatcher, MatchResult
from ..signatures.database import OSILayer, Severity, AttackCategory
from ..threat_types import AttackType, ThreatSeverity


@dataclass
class HybridClassification:
    """
    Result of hybrid classification (signature + ML).
    """
    # Overall result
    is_attack: bool
    confidence: float                      # Combined confidence (0.0-1.0)
    attack_type: Optional[str] = None      # Attack type name
    severity: Optional[str] = None         # Severity level

    # Signature results
    signature_matched: bool = False
    signature_id: Optional[str] = None
    signature_confidence: float = 0.0
    signature_patterns: List[str] = field(default_factory=list)

    # ML results
    ml_attack_probability: float = 0.0
    ml_classifications: List[Tuple[str, float]] = field(default_factory=list)

    # Metadata
    layer: Optional[str] = None
    mitre_technique: Optional[str] = None
    recommended_action: str = "Monitor"
    auto_block: bool = False
    classification_time_us: int = 0

    def to_dict(self) -> dict:
        return {
            'is_attack': self.is_attack,
            'confidence': self.confidence,
            'attack_type': self.attack_type,
            'severity': self.severity,
            'signature_matched': self.signature_matched,
            'signature_id': self.signature_id,
            'signature_confidence': self.signature_confidence,
            'signature_patterns': self.signature_patterns,
            'ml_attack_probability': self.ml_attack_probability,
            'ml_classifications': self.ml_classifications,
            'layer': self.layer,
            'mitre_technique': self.mitre_technique,
            'recommended_action': self.recommended_action,
            'auto_block': self.auto_block,
            'classification_time_us': self.classification_time_us,
        }


class HybridClassifier:
    """
    Hybrid Attack Classifier combining signatures and ML.

    This is the recommended classifier for production use as it:
    - Provides fast, deterministic detection via signatures
    - Catches novel attacks via ML classification
    - Minimizes false positives through confidence fusion
    - Works efficiently on resource-constrained devices
    """

    # Confidence weights for fusion
    SIGNATURE_WEIGHT = 0.7    # Signatures are more reliable when matched
    ML_WEIGHT = 0.3           # ML provides coverage for unknowns

    # Thresholds
    ATTACK_THRESHOLD = 0.5    # Combined confidence to classify as attack
    HIGH_CONFIDENCE = 0.8     # High confidence threshold

    def __init__(
        self,
        signature_db: Optional[SignatureDatabase] = None,
        ml_classifier: Optional[AttackClassifier] = None,
        feature_extractor: Optional[FeatureExtractor] = None,
        enable_ml: bool = True,
        enable_signatures: bool = True
    ):
        """
        Initialize hybrid classifier.

        Args:
            signature_db: Signature database (creates default if None)
            ml_classifier: ML classifier (creates default if None)
            feature_extractor: Feature extractor (creates default if None)
            enable_ml: Enable ML classification
            enable_signatures: Enable signature matching
        """
        # Components
        self.enable_ml = enable_ml
        self.enable_signatures = enable_signatures

        # Signature system
        if enable_signatures:
            self.signature_db = signature_db or SignatureDatabase()
            self.signature_matcher = SignatureMatcher(self.signature_db)
        else:
            self.signature_db = None
            self.signature_matcher = None

        # ML system
        if enable_ml:
            self.ml_classifier = ml_classifier or AttackClassifier()
            self.feature_extractor = feature_extractor or FeatureExtractor()
        else:
            self.ml_classifier = None
            self.feature_extractor = None

        # Statistics
        self.stats = {
            'classifications': 0,
            'attacks_detected': 0,
            'signature_detections': 0,
            'ml_detections': 0,
            'hybrid_detections': 0,
            'avg_time_us': 0.0,
            'by_layer': defaultdict(int),
            'by_severity': defaultdict(int),
        }

    def classify(
        self,
        features: Dict[str, Any],
        layer: Optional[OSILayer] = None,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
        source_ip: Optional[str] = None
    ) -> HybridClassification:
        """
        Perform hybrid classification on traffic features.

        Args:
            features: Dictionary of network features
            layer: OSI layer hint (improves signature matching)
            protocol: Protocol hint (tcp, udp, icmp)
            port: Port number hint
            source_ip: Source IP for context

        Returns:
            HybridClassification with combined results
        """
        start_time = time.perf_counter_ns()
        self.stats['classifications'] += 1

        # Initialize result
        result = HybridClassification(
            is_attack=False,
            confidence=0.0
        )

        # 1. Signature matching (fast path)
        sig_confidence = 0.0
        if self.enable_signatures and self.signature_matcher:
            sig_results = self.signature_matcher.match_features(
                features=features,
                layer=layer,
                protocol=protocol,
                port=port,
                source_ip=source_ip
            )

            if sig_results:
                best_match = max(sig_results, key=lambda r: r.confidence)
                if best_match.matched and best_match.signature:
                    sig = best_match.signature
                    sig_confidence = best_match.confidence

                    result.signature_matched = True
                    result.signature_id = sig.sig_id
                    result.signature_confidence = sig_confidence
                    result.signature_patterns = best_match.matched_patterns
                    result.attack_type = sig.name
                    result.severity = sig.severity.name
                    result.layer = sig.layer.name
                    result.mitre_technique = sig.mitre_technique
                    result.recommended_action = sig.recommended_action
                    result.auto_block = sig.auto_block

                    self.stats['signature_detections'] += 1
                    self.stats['by_layer'][sig.layer.name] += 1
                    self.stats['by_severity'][sig.severity.name] += 1

        # 2. ML classification (covers unknowns)
        ml_confidence = 0.0
        if self.enable_ml and self.ml_classifier:
            # Convert dict to NetworkFeatures if needed
            if isinstance(features, dict):
                net_features = self._dict_to_network_features(features)
            else:
                net_features = features

            ml_confidence = self.ml_classifier.get_attack_probability(net_features)
            ml_classifications = self.ml_classifier.classify(net_features)

            result.ml_attack_probability = ml_confidence
            result.ml_classifications = [
                (at.name, conf) for at, conf in ml_classifications[:3]
            ]

            if ml_confidence > self.ATTACK_THRESHOLD:
                self.stats['ml_detections'] += 1

        # 3. Confidence fusion
        if result.signature_matched:
            # Signature match - use weighted combination
            result.confidence = (
                self.SIGNATURE_WEIGHT * sig_confidence +
                self.ML_WEIGHT * ml_confidence
            )
        else:
            # No signature - rely on ML
            result.confidence = ml_confidence

        # 4. Final decision
        result.is_attack = result.confidence >= self.ATTACK_THRESHOLD

        if result.is_attack:
            self.stats['attacks_detected'] += 1

            # If detected by both, it's a hybrid detection
            if result.signature_matched and ml_confidence > self.ATTACK_THRESHOLD:
                self.stats['hybrid_detections'] += 1

            # Set defaults if not from signature
            if not result.attack_type and result.ml_classifications:
                result.attack_type = result.ml_classifications[0][0]
            if not result.severity:
                result.severity = self._confidence_to_severity(result.confidence)
            if not result.recommended_action:
                result.recommended_action = "Alert" if result.confidence < self.HIGH_CONFIDENCE else "Block"

        # Calculate timing
        result.classification_time_us = (time.perf_counter_ns() - start_time) // 1000

        # Update average time
        total = self.stats['classifications']
        self.stats['avg_time_us'] = (
            (self.stats['avg_time_us'] * (total - 1) + result.classification_time_us) / total
        )

        return result

    def classify_packet(
        self,
        packet_info: Dict[str, Any]
    ) -> HybridClassification:
        """
        Convenience method to classify a packet from raw info.

        Expected packet_info keys:
        - src_ip, dst_ip, src_port, dst_port
        - protocol (tcp/udp/icmp)
        - size, flags
        - any extracted features
        """
        # Determine layer from protocol
        protocol = packet_info.get('protocol', '').lower()
        if protocol == 'icmp':
            layer = OSILayer.L3_NETWORK
        elif protocol in ['tcp', 'udp']:
            layer = OSILayer.L4_TRANSPORT
        else:
            layer = None

        return self.classify(
            features=packet_info,
            layer=layer,
            protocol=protocol,
            port=packet_info.get('dst_port'),
            source_ip=packet_info.get('src_ip')
        )

    def _dict_to_network_features(self, d: Dict[str, Any]) -> NetworkFeatures:
        """Convert feature dictionary to NetworkFeatures object."""
        nf = NetworkFeatures()
        for key, value in d.items():
            if hasattr(nf, key):
                setattr(nf, key, value)
        return nf

    def _confidence_to_severity(self, confidence: float) -> str:
        """Map confidence to severity level."""
        if confidence >= 0.9:
            return "CRITICAL"
        elif confidence >= 0.7:
            return "HIGH"
        elif confidence >= 0.5:
            return "MEDIUM"
        else:
            return "LOW"

    def get_stats(self) -> Dict[str, Any]:
        """Get classifier statistics."""
        sig_stats = self.signature_matcher.get_stats() if self.signature_matcher else {}

        return {
            **self.stats,
            'signature_stats': sig_stats,
            'signature_count': len(self.signature_db.signatures) if self.signature_db else 0,
            'ml_enabled': self.enable_ml,
            'signatures_enabled': self.enable_signatures,
        }

    def reset_stats(self):
        """Reset statistics."""
        self.stats = {
            'classifications': 0,
            'attacks_detected': 0,
            'signature_detections': 0,
            'ml_detections': 0,
            'hybrid_detections': 0,
            'avg_time_us': 0.0,
            'by_layer': defaultdict(int),
            'by_severity': defaultdict(int),
        }

        if self.signature_matcher:
            self.signature_matcher.reset_stats()


class RealtimeClassifier:
    """
    Ultra-lightweight classifier for real-time packet inspection.

    Designed for high-throughput scenarios (>10,000 packets/sec).
    Only performs signature matching against critical signatures.
    """

    def __init__(self, signature_db: Optional[SignatureDatabase] = None):
        self.signature_db = signature_db or SignatureDatabase()

        # Only keep auto-block signatures for speed
        self.critical_signatures: Dict[OSILayer, List[Tuple[str, Any]]] = {
            layer: [] for layer in OSILayer
        }

        for sig in self.signature_db.get_all():
            if sig.auto_block and sig.enabled:
                # Pre-compile quick checks
                quick_check = self._compile_quick_check(sig)
                self.critical_signatures[sig.layer].append((sig.sig_id, quick_check))

        self.stats = {
            'packets_checked': 0,
            'attacks_blocked': 0,
        }

    def _compile_quick_check(self, sig) -> Dict[str, Tuple[str, Any]]:
        """Compile signature to quick check dict."""
        checks = {}
        for pattern in sig.patterns[:2]:  # Only first 2 patterns
            checks[pattern.feature_name] = (pattern.operator, pattern.value)
        return checks

    def check_packet(
        self,
        layer: OSILayer,
        features: Dict[str, Any]
    ) -> Optional[str]:
        """
        Quick check for blocking decision.

        Returns signature ID if should block, None otherwise.
        """
        self.stats['packets_checked'] += 1

        for sig_id, checks in self.critical_signatures.get(layer, []):
            if self._matches_checks(features, checks):
                self.stats['attacks_blocked'] += 1
                return sig_id

        return None

    def _matches_checks(
        self,
        features: Dict[str, Any],
        checks: Dict[str, Tuple[str, Any]]
    ) -> bool:
        """Check if features match quick checks."""
        matches = 0
        for name, (op, value) in checks.items():
            actual = features.get(name)
            if actual is None:
                continue

            try:
                if op == 'ge' and actual >= value:
                    matches += 1
                elif op == 'le' and actual <= value:
                    matches += 1
                elif op == 'eq' and actual == value:
                    matches += 1
                elif op == 'gt' and actual > value:
                    matches += 1
                elif op == 'lt' and actual < value:
                    matches += 1
            except (TypeError, ValueError):
                continue

        return matches >= len(checks) * 0.5 if checks else False

    def get_stats(self) -> Dict[str, Any]:
        return self.stats
