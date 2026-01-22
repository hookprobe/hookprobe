"""
Qsecbit Unified - Unified Threat Engine

The Single Source of Truth for cybersecurity threat detection.
Integrates all layer detectors, ML classification, energy monitoring,
and response orchestration into a unified scoring engine.

Author: HookProbe Team
License: Proprietary
Version: 5.0.0
"""

import os
import socket
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any
from enum import Enum

import numpy as np

from .threat_types import (
    ThreatEvent, AttackType, ThreatSeverity, OSILayer,
    LayerScore, QsecbitUnifiedScore, ResponseAction
)
from .detectors import (
    L2DataLinkDetector,
    L3NetworkDetector,
    L4TransportDetector,
    L5SessionDetector,
    L7ApplicationDetector
)
from .ml import AttackClassifier, FeatureExtractor
from .response import ResponseOrchestrator
from .xdp_manager import XDPManager
from .energy_monitor import EnergyMonitor


class DeploymentType(Enum):
    """Deployment type affects weight configuration."""
    GUARDIAN = "guardian"     # Travel/portable (WiFi focus)
    FORTRESS = "fortress"     # Edge router (network focus)
    NEXUS = "nexus"           # ML/AI compute


@dataclass
class UnifiedEngineConfig:
    """
    Configuration for the Unified Threat Engine.
    """
    # Deployment type (affects default weights)
    deployment_type: DeploymentType = DeploymentType.GUARDIAN

    # Layer weights (defaults vary by deployment)
    # Set to None to use deployment-specific defaults
    l2_weight: Optional[float] = None
    l3_weight: Optional[float] = None
    l4_weight: Optional[float] = None
    l5_weight: Optional[float] = None
    l7_weight: Optional[float] = None
    energy_weight: Optional[float] = None
    behavioral_weight: Optional[float] = None
    correlation_weight: Optional[float] = None

    # RAG thresholds
    amber_threshold: float = 0.45
    red_threshold: float = 0.70

    # Detection settings
    enable_xdp: bool = True
    enable_energy_monitoring: bool = True
    enable_ml_classifier: bool = True
    enable_response_orchestration: bool = True

    # Data directory
    data_dir: str = "/opt/hookprobe/data"

    # Detection intervals
    detection_interval_seconds: int = 5

    def get_weights(self) -> Dict[str, float]:
        """
        Get layer weights based on deployment type.

        Returns weight dict normalized to sum to 1.0.
        """
        # Default weights by deployment type
        defaults = {
            DeploymentType.GUARDIAN: {
                'l2': 0.25, 'l3': 0.10, 'l4': 0.10,
                'l5': 0.25, 'l7': 0.10, 'energy': 0.10,
                'behavioral': 0.05, 'correlation': 0.05
            },
            DeploymentType.FORTRESS: {
                'l2': 0.15, 'l3': 0.20, 'l4': 0.25,
                'l5': 0.10, 'l7': 0.15, 'energy': 0.05,
                'behavioral': 0.05, 'correlation': 0.05
            },
            DeploymentType.NEXUS: {
                'l2': 0.10, 'l3': 0.15, 'l4': 0.15,
                'l5': 0.15, 'l7': 0.20, 'energy': 0.10,
                'behavioral': 0.10, 'correlation': 0.05
            },
        }

        weights = defaults.get(self.deployment_type, defaults[DeploymentType.GUARDIAN]).copy()

        # Override with custom weights if provided
        if self.l2_weight is not None:
            weights['l2'] = self.l2_weight
        if self.l3_weight is not None:
            weights['l3'] = self.l3_weight
        if self.l4_weight is not None:
            weights['l4'] = self.l4_weight
        if self.l5_weight is not None:
            weights['l5'] = self.l5_weight
        if self.l7_weight is not None:
            weights['l7'] = self.l7_weight
        if self.energy_weight is not None:
            weights['energy'] = self.energy_weight
        if self.behavioral_weight is not None:
            weights['behavioral'] = self.behavioral_weight
        if self.correlation_weight is not None:
            weights['correlation'] = self.correlation_weight

        # Normalize to sum to 1.0
        total = sum(weights.values())
        return {k: v / total for k, v in weights.items()}


class UnifiedThreatEngine:
    """
    Qsecbit Unified - Unified Threat Engine

    The Single Source of Truth for cybersecurity threat detection and response.

    Integrates:
    - Layer-specific detectors (L2, L3, L4, L5, L7)
    - ML-based attack classification
    - Energy consumption monitoring
    - Attack chain correlation
    - Automated response orchestration

    Produces a single unified Qsecbit score that represents the
    complete security posture of the system.
    """

    def __init__(self, config: Optional[UnifiedEngineConfig] = None):
        """
        Initialize the Unified Threat Engine.

        Args:
            config: Engine configuration (uses defaults if None)
        """
        self.config = config or UnifiedEngineConfig()

        # System metadata
        self.hostname = socket.gethostname()
        self.deployment_type = self.config.deployment_type

        # Initialize layer detectors
        self.detectors = {
            OSILayer.L2_DATA_LINK: L2DataLinkDetector(data_dir=self.config.data_dir),
            OSILayer.L3_NETWORK: L3NetworkDetector(data_dir=self.config.data_dir),
            OSILayer.L4_TRANSPORT: L4TransportDetector(data_dir=self.config.data_dir),
            OSILayer.L5_SESSION: L5SessionDetector(data_dir=self.config.data_dir),
            OSILayer.L7_APPLICATION: L7ApplicationDetector(data_dir=self.config.data_dir),
        }

        # XDP manager for kernel-level filtering
        self.xdp_manager: Optional[XDPManager] = None
        if self.config.enable_xdp:
            try:
                self.xdp_manager = XDPManager(auto_detect=True)
                if self.xdp_manager.interface:
                    self.xdp_manager.load_program()
                    print("✓ XDP/eBPF DDoS mitigation enabled")
            except Exception as e:
                print(f"Warning: XDP initialization failed: {e}")

        # Energy monitor
        self.energy_monitor: Optional[EnergyMonitor] = None
        if self.config.enable_energy_monitoring:
            try:
                self.energy_monitor = EnergyMonitor()
                print("✓ Energy monitoring enabled")
            except Exception as e:
                print(f"Warning: Energy monitoring failed: {e}")

        # ML classifier
        self.classifier: Optional[AttackClassifier] = None
        self.feature_extractor: Optional[FeatureExtractor] = None
        if self.config.enable_ml_classifier:
            self.classifier = AttackClassifier()
            self.feature_extractor = FeatureExtractor()
            print("✓ ML attack classifier enabled")

        # Response orchestrator
        self.response_orchestrator: Optional[ResponseOrchestrator] = None
        if self.config.enable_response_orchestration:
            self.response_orchestrator = ResponseOrchestrator(
                xdp_manager=self.xdp_manager,
                data_dir=self.config.data_dir
            )
            print("✓ Response orchestration enabled")

        # Scoring history
        self.score_history: List[QsecbitUnifiedScore] = []
        self.threat_history: List[ThreatEvent] = []

        # Attack chain tracking
        self.active_chains: Dict[str, List[ThreatEvent]] = {}  # chain_id -> [events]

        # Get weights
        self.weights = self.config.get_weights()

        print(f"✓ Unified Threat Engine initialized ({self.deployment_type.value})")
        print(f"  Weights: {self.weights}")

    def detect(self) -> QsecbitUnifiedScore:
        """
        Run comprehensive threat detection across all layers.

        This is the main entry point - call this periodically (e.g., every 5 seconds)
        to get an updated Qsecbit score.

        Returns:
            QsecbitUnifiedScore with complete security posture
        """
        all_threats: List[ThreatEvent] = []
        layer_scores: Dict[OSILayer, LayerScore] = {}

        # Run all layer detectors
        for layer, detector in self.detectors.items():
            try:
                threats = detector.detect()
                all_threats.extend(threats)

                # Calculate layer score
                layer_score = LayerScore(layer=layer)
                for threat in threats:
                    layer_score.threat_count += 1
                    if threat.severity == ThreatSeverity.CRITICAL:
                        layer_score.critical_count += 1
                    elif threat.severity == ThreatSeverity.HIGH:
                        layer_score.high_count += 1
                    elif threat.severity == ThreatSeverity.MEDIUM:
                        layer_score.medium_count += 1
                    elif threat.severity == ThreatSeverity.LOW:
                        layer_score.low_count += 1

                    if threat.attack_type not in layer_score.top_threats:
                        layer_score.top_threats.append(threat.attack_type)

                layer_score.calculate_score()
                layer_scores[layer] = layer_score

            except Exception as e:
                print(f"Warning: {layer.name} detection failed: {e}")
                layer_scores[layer] = LayerScore(layer=layer)

        # Energy anomaly score
        energy_score = 0.0
        if self.energy_monitor:
            try:
                snapshot = self.energy_monitor.capture_snapshot()
                if snapshot:
                    anomalies = self.energy_monitor.detect_anomalies(snapshot)
                    energy_score = anomalies.get('anomaly_score', 0.0)
            except Exception:
                pass

        # ML behavioral score
        behavioral_score = 0.0
        if self.classifier and self.feature_extractor:
            try:
                features = self.feature_extractor.extract_features()
                behavioral_score = self.classifier.get_attack_probability(features)
            except Exception:
                pass

        # Attack chain correlation score
        correlation_score = self._calculate_correlation_score(all_threats)

        # Calculate unified Qsecbit score
        score = self._calculate_unified_score(
            layer_scores=layer_scores,
            energy_score=energy_score,
            behavioral_score=behavioral_score,
            correlation_score=correlation_score
        )

        # Determine RAG status
        if score >= self.config.red_threshold:
            rag_status = "RED"
        elif score >= self.config.amber_threshold:
            rag_status = "AMBER"
        else:
            rag_status = "GREEN"

        # Create unified score object
        unified_score = QsecbitUnifiedScore(
            timestamp=datetime.now(),
            score=score,
            rag_status=rag_status,
            layer_scores=layer_scores,
            l2_score=layer_scores.get(OSILayer.L2_DATA_LINK, LayerScore(layer=OSILayer.L2_DATA_LINK)).score,
            l3_score=layer_scores.get(OSILayer.L3_NETWORK, LayerScore(layer=OSILayer.L3_NETWORK)).score,
            l4_score=layer_scores.get(OSILayer.L4_TRANSPORT, LayerScore(layer=OSILayer.L4_TRANSPORT)).score,
            l5_score=layer_scores.get(OSILayer.L5_SESSION, LayerScore(layer=OSILayer.L5_SESSION)).score,
            l7_score=layer_scores.get(OSILayer.L7_APPLICATION, LayerScore(layer=OSILayer.L7_APPLICATION)).score,
            energy_score=energy_score,
            behavioral_score=behavioral_score,
            correlation_score=correlation_score,
            weights=self.weights,
            active_threats=len(all_threats),
            critical_threats=sum(1 for t in all_threats if t.severity == ThreatSeverity.CRITICAL),
            blocked_threats=sum(1 for t in all_threats if t.blocked),
            trend=self._calculate_trend(),
            convergence_rate=self._calculate_convergence_rate(),
            deployment_type=self.deployment_type.value,
            hostname=self.hostname
        )

        # Store history
        self.score_history.append(unified_score)
        if len(self.score_history) > 1000:
            self.score_history = self.score_history[-1000:]

        self.threat_history.extend(all_threats)
        if len(self.threat_history) > 10000:
            self.threat_history = self.threat_history[-10000:]

        # Execute responses
        if self.response_orchestrator:
            for threat in all_threats:
                self.response_orchestrator.respond(threat)

        return unified_score

    def _calculate_unified_score(
        self,
        layer_scores: Dict[OSILayer, LayerScore],
        energy_score: float,
        behavioral_score: float,
        correlation_score: float
    ) -> float:
        """
        Calculate the unified Qsecbit score.

        Formula:
        Q = Σ(ωᵢ × Lᵢ) + β×E + γ×B + δ×C

        Where:
        - Lᵢ = Layer-specific threat scores
        - E = Energy anomaly score
        - B = Behavioral (ML) score
        - C = Correlation score
        """
        score = 0.0

        # Layer contributions
        l2_score = layer_scores.get(OSILayer.L2_DATA_LINK, LayerScore(layer=OSILayer.L2_DATA_LINK)).score
        l3_score = layer_scores.get(OSILayer.L3_NETWORK, LayerScore(layer=OSILayer.L3_NETWORK)).score
        l4_score = layer_scores.get(OSILayer.L4_TRANSPORT, LayerScore(layer=OSILayer.L4_TRANSPORT)).score
        l5_score = layer_scores.get(OSILayer.L5_SESSION, LayerScore(layer=OSILayer.L5_SESSION)).score
        l7_score = layer_scores.get(OSILayer.L7_APPLICATION, LayerScore(layer=OSILayer.L7_APPLICATION)).score

        score += self.weights['l2'] * l2_score
        score += self.weights['l3'] * l3_score
        score += self.weights['l4'] * l4_score
        score += self.weights['l5'] * l5_score
        score += self.weights['l7'] * l7_score
        score += self.weights['energy'] * energy_score
        score += self.weights['behavioral'] * behavioral_score
        score += self.weights['correlation'] * correlation_score

        return min(1.0, score)

    def _calculate_correlation_score(self, threats: List[ThreatEvent]) -> float:
        """
        Calculate attack chain correlation score.

        Detects multi-stage attacks by correlating threats from
        the same source across different layers.
        """
        if not threats:
            return 0.0

        # Group threats by source
        by_source: Dict[str, List[ThreatEvent]] = {}
        for threat in threats:
            key = threat.source_ip or threat.source_mac or "unknown"
            if key not in by_source:
                by_source[key] = []
            by_source[key].append(threat)

        # Score based on multi-layer attacks from same source
        max_layers = 0
        for source, source_threats in by_source.items():
            layers = set(t.layer for t in source_threats)
            if len(layers) > max_layers:
                max_layers = len(layers)

        # Multi-layer attack = high correlation score
        # 1 layer = 0.0, 5 layers = 1.0
        return min(1.0, (max_layers - 1) / 4.0) if max_layers > 1 else 0.0

    def _calculate_trend(self) -> str:
        """Calculate trend in recent scores."""
        if len(self.score_history) < 10:
            return "STABLE"

        recent = [s.score for s in self.score_history[-10:]]
        x = np.arange(len(recent))
        slope, _ = np.polyfit(x, recent, 1)

        if slope < -0.01:
            return "IMPROVING"
        elif slope > 0.01:
            return "DEGRADING"
        return "STABLE"

    def _calculate_convergence_rate(self) -> Optional[float]:
        """Calculate how quickly system returns to GREEN after alert."""
        if len(self.score_history) < 20:
            return None

        recent = self.score_history[-20:]
        convergence_times = []
        in_alert = False
        alert_start = None

        for i, score in enumerate(recent):
            if score.rag_status in ['RED', 'AMBER'] and not in_alert:
                in_alert = True
                alert_start = i
            elif score.rag_status == 'GREEN' and in_alert:
                if alert_start is not None:
                    convergence_times.append(i - alert_start)
                in_alert = False

        return float(np.mean(convergence_times)) if convergence_times else None

    def get_threat_report(self) -> Dict[str, Any]:
        """Generate comprehensive threat report."""
        recent_threats = self.threat_history[-100:]

        # Count by type
        type_counts: Dict[str, int] = {}
        for threat in recent_threats:
            type_name = threat.attack_type.name
            type_counts[type_name] = type_counts.get(type_name, 0) + 1

        # Count by layer
        layer_counts: Dict[str, int] = {}
        for threat in recent_threats:
            layer_name = threat.layer.name
            layer_counts[layer_name] = layer_counts.get(layer_name, 0) + 1

        # Count by severity
        severity_counts = {
            'CRITICAL': sum(1 for t in recent_threats if t.severity == ThreatSeverity.CRITICAL),
            'HIGH': sum(1 for t in recent_threats if t.severity == ThreatSeverity.HIGH),
            'MEDIUM': sum(1 for t in recent_threats if t.severity == ThreatSeverity.MEDIUM),
            'LOW': sum(1 for t in recent_threats if t.severity == ThreatSeverity.LOW),
        }

        # Get latest score
        latest_score = self.score_history[-1] if self.score_history else None

        return {
            'timestamp': datetime.now().isoformat(),
            'deployment_type': self.deployment_type.value,
            'hostname': self.hostname,
            'current_score': latest_score.score if latest_score else 0.0,
            'rag_status': latest_score.rag_status if latest_score else 'GREEN',
            'trend': latest_score.trend if latest_score else 'STABLE',
            'recent_threats': len(recent_threats),
            'threats_by_type': type_counts,
            'threats_by_layer': layer_counts,
            'threats_by_severity': severity_counts,
            'blocked_count': sum(1 for t in recent_threats if t.blocked),
            'response_stats': self.response_orchestrator.get_statistics() if self.response_orchestrator else {},
            'detector_stats': {
                layer.name: detector.get_statistics()
                for layer, detector in self.detectors.items()
            },
        }

    def get_recent_threats(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent threat events as dictionaries."""
        return [t.to_dict() for t in self.threat_history[-limit:]]

    def block_ip(self, ip: str) -> bool:
        """Manually block an IP address."""
        if self.xdp_manager:
            return self.xdp_manager.block_ip(ip)
        return False

    def unblock_ip(self, ip: str) -> bool:
        """Manually unblock an IP address."""
        if self.xdp_manager:
            return self.xdp_manager.unblock_ip(ip)
        return False


# Convenience function for quick initialization
def create_unified_engine(
    deployment_type: str = "guardian",
    **kwargs
) -> UnifiedThreatEngine:
    """
    Create a Unified Threat Engine with the specified deployment type.

    Args:
        deployment_type: One of "guardian", "fortress", "nexus"
        **kwargs: Additional config options

    Returns:
        Configured UnifiedThreatEngine instance
    """
    deployment = DeploymentType[deployment_type.upper()]
    config = UnifiedEngineConfig(deployment_type=deployment, **kwargs)
    return UnifiedThreatEngine(config)
