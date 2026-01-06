#!/usr/bin/env python3
"""
Purple Team Orchestrator - AI vs AI Simulation Engine

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2025 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

The main orchestrator for HookProbe's Red/Purple teaming capabilities.
Nexus acts as the Red Team (attacker) while Fortress acts as Blue Team (defender).

Architecture:
┌─────────────────────────────────────────────────────────────────────────────┐
│                       PURPLE TEAMING ORCHESTRATOR                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
│  │ DIGITAL TWIN│───▶│  RED TEAM   │───▶│  BLUE TEAM  │───▶│  VALIDATION │  │
│  │  CREATION   │    │   ATTACK    │    │   DEFENSE   │    │   WEBHOOK   │  │
│  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  │
│   Shadow OVS         9 Attack          SDN Autopilot     n8n Feedback      │
│   + Bubbles          Vectors           + QSECBIT         + ClickHouse      │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                        META-REGRESSIVE LEARNING                         ││
│  │  Collect Effect Sizes → Analyze β Coefficients → Update Autopilot      ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘

The 9 Attack Vectors for SDN Bubbles:
1. TER Replay - Replay old mDNS handshakes to trick bubble assignment
2. Entropy Poisoning - Inject noise to disrupt NEURO protocol affinity
3. Timing Attacks - Mimic temporal patterns of family members
4. Weight Prediction - Guess neural weights to bypass QSECBIT scoring
5. MAC Impersonation - Clone device MAC to infiltrate bubble
6. mDNS Spoofing - Fake mDNS responses to manipulate discovery
7. Temporal Mimicry - Copy wake/sleep patterns of target bubble
8. DHCP Fingerprint Spoof - Forge DHCP Option 55 for OS detection evasion
9. D2D Affinity Injection - Inject fake D2D flows to boost affinity scores
"""

import hashlib
import json
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Configuration paths
NEXUS_CONFIG = Path('/etc/hookprobe/nexus.conf')
SIMULATION_DATA = Path('/var/lib/hookprobe/nexus/simulations')


class SimulationState(Enum):
    """State machine for purple team simulation."""
    IDLE = "idle"
    TWIN_CREATION = "creating_twin"
    RED_ATTACK = "red_attack_phase"
    BLUE_DEFENSE = "blue_defense_phase"
    VALIDATION = "validation_phase"
    LEARNING = "meta_learning_phase"
    COMPLETED = "completed"
    FAILED = "failed"


class AttackPhase(Enum):
    """Phases of the Red Team attack."""
    RECONNAISSANCE = "reconnaissance"
    STAGING = "staging"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"


class DetectionPhase(Enum):
    """Phases of the Blue Team detection."""
    MONITORING = "monitoring"
    ALERTING = "alerting"
    MITIGATION = "mitigation"
    RECOVERY = "recovery"


class ValidationPhase(Enum):
    """Phases of the Purple Team validation."""
    VERIFICATION = "verification"
    SCORING = "scoring"
    FEEDBACK = "feedback"
    OPTIMIZATION = "optimization"


@dataclass
class PurpleTeamConfig:
    """Configuration for purple team simulation."""
    # Simulation parameters
    simulation_id: str = ""
    target_fortress_ip: str = "127.0.0.1"
    target_fortress_port: int = 8443

    # Digital twin
    twin_enabled: bool = True
    twin_sync_interval: int = 60  # seconds

    # Attack configuration
    enabled_attacks: List[str] = field(default_factory=lambda: [
        "ter_replay",
        "entropy_poisoning",
        "timing_attack",
        "weight_prediction",
        "mac_impersonation",
        "mdns_spoofing",
        "temporal_mimicry",
        "dhcp_fingerprint_spoof",
        "d2d_affinity_injection",
    ])
    max_attack_duration: int = 300  # seconds per attack
    attack_intensity: float = 0.5  # 0.0-1.0 scale

    # Detection thresholds
    qsecbit_red_threshold: float = 0.30
    qsecbit_amber_threshold: float = 0.55

    # Validation webhook
    n8n_webhook_url: Optional[str] = None
    n8n_auth_token: Optional[str] = None
    validation_timeout: int = 30  # seconds

    # Meta-regression
    meta_learning_enabled: bool = True
    min_samples_for_regression: int = 10

    # Output
    report_dir: str = "/var/lib/hookprobe/nexus/reports"
    clickhouse_enabled: bool = True

    def __post_init__(self):
        if not self.simulation_id:
            self.simulation_id = f"SIM-{datetime.now().strftime('%Y%m%d-%H%M%S')}"


@dataclass
class AttackResult:
    """Result of a single attack simulation."""
    attack_name: str
    attack_type: str
    success: bool
    partial_success: bool = False
    confidence: float = 0.0
    execution_time_ms: float = 0.0
    exploitability: float = 0.0  # 0-10 CVSS scale
    impact: float = 0.0  # 0-10 CVSS scale
    evidence: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    # SDN-specific results
    bubble_penetrated: bool = False
    target_bubble: str = ""
    devices_affected: List[str] = field(default_factory=list)
    qsecbit_score_before: float = 0.0
    qsecbit_score_after: float = 0.0
    neuro_resonance_disrupted: bool = False

    @property
    def cvss_score(self) -> float:
        return (self.exploitability + self.impact) / 2

    def to_dict(self) -> Dict:
        return {
            'attack_name': self.attack_name,
            'attack_type': self.attack_type,
            'success': self.success,
            'partial_success': self.partial_success,
            'confidence': self.confidence,
            'execution_time_ms': self.execution_time_ms,
            'cvss_score': self.cvss_score,
            'exploitability': self.exploitability,
            'impact': self.impact,
            'evidence': self.evidence,
            'bubble_penetrated': self.bubble_penetrated,
            'target_bubble': self.target_bubble,
            'devices_affected': self.devices_affected,
            'qsecbit_delta': self.qsecbit_score_after - self.qsecbit_score_before,
            'neuro_disrupted': self.neuro_resonance_disrupted,
        }


@dataclass
class DetectionResult:
    """Result of Blue Team detection."""
    detected: bool
    detection_time_ms: float
    detection_method: str
    threat_type: str
    severity: str  # critical, high, medium, low
    qsecbit_score: float
    rag_status: str  # RED, AMBER, GREEN
    response_actions: List[str] = field(default_factory=list)
    blocked: bool = False
    quarantined: bool = False

    def to_dict(self) -> Dict:
        return {
            'detected': self.detected,
            'detection_time_ms': self.detection_time_ms,
            'detection_method': self.detection_method,
            'threat_type': self.threat_type,
            'severity': self.severity,
            'qsecbit_score': self.qsecbit_score,
            'rag_status': self.rag_status,
            'response_actions': self.response_actions,
            'blocked': self.blocked,
            'quarantined': self.quarantined,
        }


@dataclass
class ValidationResult:
    """Result of Purple Team validation."""
    simulation_id: str
    timestamp: datetime
    attack_results: List[AttackResult]
    detection_results: List[DetectionResult]

    # Aggregate metrics
    attacks_total: int = 0
    attacks_successful: int = 0
    attacks_detected: int = 0
    attacks_blocked: int = 0

    # CVSS metrics
    max_cvss: float = 0.0
    avg_cvss: float = 0.0

    # Bubble metrics
    bubbles_penetrated: int = 0
    devices_compromised: int = 0

    # Detection efficacy
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0

    # Overall score
    defense_score: float = 0.0  # 0-100
    overall_risk: str = "UNKNOWN"

    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    auto_mitigations: List[Dict] = field(default_factory=list)

    def calculate_metrics(self):
        """Calculate aggregate metrics from results."""
        if not self.attack_results:
            return

        self.attacks_total = len(self.attack_results)
        self.attacks_successful = sum(1 for a in self.attack_results if a.success)

        cvss_scores = [a.cvss_score for a in self.attack_results if a.success]
        if cvss_scores:
            self.max_cvss = max(cvss_scores)
            self.avg_cvss = sum(cvss_scores) / len(cvss_scores)

        self.bubbles_penetrated = sum(1 for a in self.attack_results if a.bubble_penetrated)
        all_devices = set()
        for a in self.attack_results:
            all_devices.update(a.devices_affected)
        self.devices_compromised = len(all_devices)

        # Detection metrics
        if self.detection_results:
            self.attacks_detected = sum(1 for d in self.detection_results if d.detected)
            self.attacks_blocked = sum(1 for d in self.detection_results if d.blocked)

            # Confusion matrix
            for i, attack in enumerate(self.attack_results):
                if i < len(self.detection_results):
                    detection = self.detection_results[i]
                    if attack.success and detection.detected:
                        self.true_positives += 1
                    elif not attack.success and not detection.detected:
                        self.true_negatives += 1
                    elif attack.success and not detection.detected:
                        self.false_negatives += 1
                    elif not attack.success and detection.detected:
                        self.false_positives += 1

        # Defense score calculation
        if self.attacks_total > 0:
            detection_rate = self.attacks_detected / self.attacks_total
            blocking_rate = self.attacks_blocked / self.attacks_total
            penetration_rate = self.bubbles_penetrated / self.attacks_total

            # Defense score: weighted combination
            self.defense_score = (
                (detection_rate * 40) +
                (blocking_rate * 40) +
                ((1 - penetration_rate) * 20)
            )

        # Risk classification
        if self.max_cvss >= 9.0 or self.defense_score < 40:
            self.overall_risk = "CRITICAL"
        elif self.max_cvss >= 7.0 or self.defense_score < 60:
            self.overall_risk = "HIGH"
        elif self.max_cvss >= 4.0 or self.defense_score < 80:
            self.overall_risk = "MEDIUM"
        else:
            self.overall_risk = "LOW"

    def to_dict(self) -> Dict:
        return {
            'simulation_id': self.simulation_id,
            'timestamp': self.timestamp.isoformat(),
            'summary': {
                'attacks_total': self.attacks_total,
                'attacks_successful': self.attacks_successful,
                'attacks_detected': self.attacks_detected,
                'attacks_blocked': self.attacks_blocked,
            },
            'cvss': {
                'max': self.max_cvss,
                'avg': self.avg_cvss,
            },
            'bubble_metrics': {
                'penetrated': self.bubbles_penetrated,
                'devices_compromised': self.devices_compromised,
            },
            'detection': {
                'true_positives': self.true_positives,
                'false_positives': self.false_positives,
                'true_negatives': self.true_negatives,
                'false_negatives': self.false_negatives,
            },
            'defense_score': self.defense_score,
            'overall_risk': self.overall_risk,
            'recommendations': self.recommendations,
            'auto_mitigations': self.auto_mitigations,
            'attack_details': [a.to_dict() for a in self.attack_results],
            'detection_details': [d.to_dict() for d in self.detection_results],
        }


@dataclass
class SimulationResult:
    """Complete result of a purple team simulation."""
    simulation_id: str
    start_time: datetime
    end_time: datetime
    duration_seconds: float
    state: SimulationState
    config: PurpleTeamConfig
    validation: ValidationResult

    # Learning results
    effect_sizes: Dict[str, float] = field(default_factory=dict)
    beta_coefficients: Dict[str, float] = field(default_factory=dict)
    optimization_applied: bool = False

    def to_dict(self) -> Dict:
        return {
            'simulation_id': self.simulation_id,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'duration_seconds': self.duration_seconds,
            'state': self.state.value,
            'validation': self.validation.to_dict(),
            'learning': {
                'effect_sizes': self.effect_sizes,
                'beta_coefficients': self.beta_coefficients,
                'optimization_applied': self.optimization_applied,
            },
        }


class PurpleTeamOrchestrator:
    """
    Main orchestrator for Purple Team AI vs AI simulations.

    Coordinates:
    1. Digital Twin creation (shadow of Fortress OVS)
    2. Red Team attacks (9 attack vectors)
    3. Blue Team defense (SDN Autopilot + QSECBIT)
    4. Purple Team validation (n8n webhook feedback)
    5. Meta-regressive learning (bubble accuracy optimization)

    Usage:
        orchestrator = PurpleTeamOrchestrator(config)
        result = orchestrator.run_simulation()
        print(result.validation.defense_score)
    """

    def __init__(self, config: PurpleTeamConfig = None):
        self.config = config or PurpleTeamConfig()
        self.state = SimulationState.IDLE
        self._lock = threading.Lock()

        # Component placeholders (initialized on first use)
        self._digital_twin = None
        self._attack_engine = None
        self._meta_regressor = None
        self._n8n_client = None

        # History
        self._simulation_history: List[SimulationResult] = []
        self._learning_samples: List[Dict] = []

        # Callbacks
        self._state_callbacks: List[Callable[[SimulationState], None]] = []
        self._progress_callbacks: List[Callable[[str, float], None]] = []

        # Ensure directories exist
        SIMULATION_DATA.mkdir(parents=True, exist_ok=True)
        Path(self.config.report_dir).mkdir(parents=True, exist_ok=True)

        logger.info(f"PurpleTeamOrchestrator initialized: {self.config.simulation_id}")

    def _set_state(self, new_state: SimulationState):
        """Update state and notify callbacks."""
        with self._lock:
            old_state = self.state
            self.state = new_state
            logger.info(f"State: {old_state.value} → {new_state.value}")

            for callback in self._state_callbacks:
                try:
                    callback(new_state)
                except Exception as e:
                    logger.debug(f"State callback error: {e}")

    def _report_progress(self, phase: str, progress: float):
        """Report progress to callbacks."""
        for callback in self._progress_callbacks:
            try:
                callback(phase, progress)
            except Exception as e:
                logger.debug(f"Progress callback error: {e}")

    def register_state_callback(self, callback: Callable[[SimulationState], None]):
        """Register callback for state changes."""
        self._state_callbacks.append(callback)

    def register_progress_callback(self, callback: Callable[[str, float], None]):
        """Register callback for progress updates."""
        self._progress_callbacks.append(callback)

    def run_simulation(self) -> SimulationResult:
        """
        Run a complete purple team simulation.

        Flow:
        1. Create digital twin of Fortress
        2. Execute red team attacks
        3. Monitor blue team defenses
        4. Validate with purple team
        5. Apply meta-regression learning

        Returns:
            SimulationResult with all findings
        """
        start_time = datetime.now()

        try:
            # Phase 1: Digital Twin Creation
            self._set_state(SimulationState.TWIN_CREATION)
            self._report_progress("twin_creation", 0.0)
            twin_state = self._create_digital_twin()
            self._report_progress("twin_creation", 1.0)

            # Phase 2: Red Team Attack
            self._set_state(SimulationState.RED_ATTACK)
            self._report_progress("red_attack", 0.0)
            attack_results = self._execute_red_attacks(twin_state)
            self._report_progress("red_attack", 1.0)

            # Phase 3: Blue Team Defense
            self._set_state(SimulationState.BLUE_DEFENSE)
            self._report_progress("blue_defense", 0.0)
            detection_results = self._monitor_blue_defense(attack_results)
            self._report_progress("blue_defense", 1.0)

            # Phase 4: Purple Team Validation
            self._set_state(SimulationState.VALIDATION)
            self._report_progress("validation", 0.0)
            validation = self._validate_results(attack_results, detection_results)
            self._report_progress("validation", 1.0)

            # Phase 5: Meta-Regression Learning
            effect_sizes = {}
            beta_coefficients = {}
            optimization_applied = False

            if self.config.meta_learning_enabled:
                self._set_state(SimulationState.LEARNING)
                self._report_progress("learning", 0.0)
                effect_sizes, beta_coefficients, optimization_applied = \
                    self._apply_meta_learning(validation)
                self._report_progress("learning", 1.0)

            # Build result
            self._set_state(SimulationState.COMPLETED)
            end_time = datetime.now()

            result = SimulationResult(
                simulation_id=self.config.simulation_id,
                start_time=start_time,
                end_time=end_time,
                duration_seconds=(end_time - start_time).total_seconds(),
                state=SimulationState.COMPLETED,
                config=self.config,
                validation=validation,
                effect_sizes=effect_sizes,
                beta_coefficients=beta_coefficients,
                optimization_applied=optimization_applied,
            )

            # Save result
            self._save_result(result)
            self._simulation_history.append(result)

            logger.info(
                f"Simulation {self.config.simulation_id} completed: "
                f"Defense Score={validation.defense_score:.1f}, "
                f"Risk={validation.overall_risk}"
            )

            return result

        except Exception as e:
            self._set_state(SimulationState.FAILED)
            logger.error(f"Simulation failed: {e}")
            raise

    def _create_digital_twin(self) -> Dict:
        """
        Create a digital twin of the Fortress OVS environment.

        The twin includes:
        - Virtual OVS bridge configuration
        - Virtual device MACs and IPs
        - Bubble assignments
        - QSECBIT scores
        """
        # Import here to avoid circular imports
        try:
            from .digital_twin import DigitalTwinSimulator, TwinConfig
            twin_config = TwinConfig(
                fortress_ip=self.config.target_fortress_ip,
                sync_interval=self.config.twin_sync_interval,
            )
            self._digital_twin = DigitalTwinSimulator(twin_config)
            return self._digital_twin.create_snapshot()
        except ImportError:
            # Fallback: create mock twin state
            logger.warning("DigitalTwinSimulator not available, using mock state")
            return self._create_mock_twin_state()

    def _create_mock_twin_state(self) -> Dict:
        """Create mock digital twin state for testing."""
        return {
            'ovs_bridge': 'FTS',
            'devices': [
                {'mac': 'AA:BB:CC:DD:EE:01', 'ip': '10.200.0.10', 'bubble': 'family-dad'},
                {'mac': 'AA:BB:CC:DD:EE:02', 'ip': '10.200.0.11', 'bubble': 'family-dad'},
                {'mac': 'AA:BB:CC:DD:EE:03', 'ip': '10.200.0.20', 'bubble': 'family-mom'},
                {'mac': 'AA:BB:CC:DD:EE:04', 'ip': '10.200.0.30', 'bubble': 'guests'},
            ],
            'bubbles': {
                'family-dad': {'vlan': 110, 'devices': 2, 'type': 'FAMILY'},
                'family-mom': {'vlan': 110, 'devices': 1, 'type': 'FAMILY'},
                'guests': {'vlan': 150, 'devices': 1, 'type': 'GUEST'},
            },
            'qsecbit_scores': {
                'AA:BB:CC:DD:EE:01': 0.85,
                'AA:BB:CC:DD:EE:02': 0.90,
                'AA:BB:CC:DD:EE:03': 0.80,
                'AA:BB:CC:DD:EE:04': 0.65,
            },
            'timestamp': datetime.now().isoformat(),
        }

    def _execute_red_attacks(self, twin_state: Dict) -> List[AttackResult]:
        """
        Execute Red Team attacks against the digital twin.

        Runs 9 attack vectors specific to SDN bubbles:
        1. TER Replay
        2. Entropy Poisoning
        3. Timing Attack
        4. Weight Prediction
        5. MAC Impersonation
        6. mDNS Spoofing
        7. Temporal Mimicry
        8. DHCP Fingerprint Spoof
        9. D2D Affinity Injection
        """
        results = []
        attack_count = len(self.config.enabled_attacks)

        for i, attack_name in enumerate(self.config.enabled_attacks):
            try:
                progress = i / attack_count
                self._report_progress("red_attack", progress)

                logger.info(f"Executing attack: {attack_name}")
                result = self._run_attack(attack_name, twin_state)
                results.append(result)

            except Exception as e:
                logger.error(f"Attack {attack_name} failed: {e}")
                results.append(AttackResult(
                    attack_name=attack_name,
                    attack_type="error",
                    success=False,
                    evidence=[f"Execution error: {str(e)}"],
                ))

        return results

    def _run_attack(self, attack_name: str, twin_state: Dict) -> AttackResult:
        """Run a single attack against the digital twin."""
        try:
            from .bubble_attacks import get_attack_class

            attack_class = get_attack_class(attack_name)
            if attack_class:
                attack = attack_class()
                return attack.execute(twin_state, intensity=self.config.attack_intensity)
        except ImportError:
            pass

        # Fallback: simulate attack result
        return self._simulate_attack(attack_name, twin_state)

    def _simulate_attack(self, attack_name: str, twin_state: Dict) -> AttackResult:
        """Simulate attack result for testing."""
        import random

        # Randomize results for simulation
        success = random.random() < self.config.attack_intensity
        partial = random.random() < 0.3 if not success else False

        target_device = random.choice(twin_state.get('devices', [{}]))
        target_bubble = target_device.get('bubble', 'unknown')

        return AttackResult(
            attack_name=attack_name,
            attack_type=attack_name.replace('_', ' ').title(),
            success=success,
            partial_success=partial,
            confidence=random.uniform(0.6, 0.95),
            execution_time_ms=random.uniform(50, 500),
            exploitability=random.uniform(3.0, 8.0) if success else random.uniform(1.0, 4.0),
            impact=random.uniform(4.0, 9.0) if success else random.uniform(1.0, 3.0),
            evidence=[
                f"Attack {attack_name} executed against {target_bubble}",
                f"Target MAC: {target_device.get('mac', 'unknown')}",
            ],
            details={'simulated': True},
            bubble_penetrated=success,
            target_bubble=target_bubble,
            devices_affected=[target_device.get('mac')] if success else [],
            qsecbit_score_before=twin_state.get('qsecbit_scores', {}).get(
                target_device.get('mac'), 0.7
            ),
            qsecbit_score_after=random.uniform(0.2, 0.5) if success else random.uniform(0.6, 0.9),
            neuro_resonance_disrupted=success and random.random() < 0.4,
        )

    def _monitor_blue_defense(self, attack_results: List[AttackResult]) -> List[DetectionResult]:
        """
        Monitor Blue Team (Fortress SDN Autopilot) defense responses.

        Queries Fortress for:
        - QSECBIT scores
        - RAG status changes
        - XDP/iptables blocks
        - Quarantine actions
        """
        detection_results = []

        for attack in attack_results:
            try:
                # Query Fortress for detection status
                detection = self._query_fortress_detection(attack)
                detection_results.append(detection)

            except Exception as e:
                logger.debug(f"Detection query failed: {e}")
                # Simulate detection
                detection_results.append(self._simulate_detection(attack))

        return detection_results

    def _query_fortress_detection(self, attack: AttackResult) -> DetectionResult:
        """Query Fortress API for detection status."""
        # TODO: Implement actual Fortress API query
        return self._simulate_detection(attack)

    def _simulate_detection(self, attack: AttackResult) -> DetectionResult:
        """Simulate detection result for testing."""
        import random

        # Detection probability based on attack success
        detection_prob = 0.7 if attack.success else 0.3
        detected = random.random() < detection_prob

        # Stronger attacks are more likely to be detected
        if attack.cvss_score > 7.0:
            detection_prob += 0.2
            detected = random.random() < detection_prob

        # RAG status based on simulated QSECBIT
        qsecbit = random.uniform(0.3, 0.9)
        if attack.success and not detected:
            qsecbit = random.uniform(0.2, 0.4)

        if qsecbit < self.config.qsecbit_red_threshold:
            rag = "RED"
        elif qsecbit < self.config.qsecbit_amber_threshold:
            rag = "AMBER"
        else:
            rag = "GREEN"

        blocked = detected and random.random() < 0.8

        return DetectionResult(
            detected=detected,
            detection_time_ms=random.uniform(10, 200) if detected else 0,
            detection_method="qsecbit_anomaly" if detected else "",
            threat_type=attack.attack_type,
            severity="high" if attack.cvss_score > 7 else "medium",
            qsecbit_score=qsecbit,
            rag_status=rag,
            response_actions=["ALERT", "BLOCK_IP"] if blocked else [],
            blocked=blocked,
            quarantined=blocked and random.random() < 0.3,
        )

    def _validate_results(
        self,
        attack_results: List[AttackResult],
        detection_results: List[DetectionResult]
    ) -> ValidationResult:
        """
        Validate simulation results and generate recommendations.

        Creates ValidationResult with:
        - Aggregate metrics
        - Confusion matrix
        - Defense score
        - Risk classification
        - Recommendations
        """
        validation = ValidationResult(
            simulation_id=self.config.simulation_id,
            timestamp=datetime.now(),
            attack_results=attack_results,
            detection_results=detection_results,
        )

        validation.calculate_metrics()

        # Generate recommendations based on results
        validation.recommendations = self._generate_recommendations(validation)

        # Generate auto-mitigations
        validation.auto_mitigations = self._generate_auto_mitigations(
            attack_results, detection_results
        )

        # Send to n8n webhook if configured
        if self.config.n8n_webhook_url:
            self._send_validation_webhook(validation)

        return validation

    def _generate_recommendations(self, validation: ValidationResult) -> List[str]:
        """Generate security recommendations based on validation results."""
        recommendations = []

        # Check for undetected attacks
        if validation.false_negatives > 0:
            recommendations.append(
                f"CRITICAL: {validation.false_negatives} attacks went undetected. "
                "Review QSECBIT sensitivity thresholds."
            )

        # Check for bubble penetration
        if validation.bubbles_penetrated > 0:
            recommendations.append(
                f"HIGH: {validation.bubbles_penetrated} bubbles were penetrated. "
                "Strengthen NSE heartbeat verification."
            )

        # Check for low defense score
        if validation.defense_score < 60:
            recommendations.append(
                f"HIGH: Defense score ({validation.defense_score:.1f}) below threshold. "
                "Consider enabling additional XDP rules."
            )

        # Check for high CVSS
        if validation.max_cvss >= 7.0:
            recommendations.append(
                f"HIGH: Maximum CVSS score of {validation.max_cvss:.1f} detected. "
                "Review attack vector: {attack_results[0].attack_name}"
            )

        # General recommendations
        if validation.true_positives > 0 and validation.false_positives == 0:
            recommendations.append(
                "GOOD: Zero false positives with good detection rate. "
                "Current QSECBIT configuration is effective."
            )

        return recommendations

    def _generate_auto_mitigations(
        self,
        attack_results: List[AttackResult],
        detection_results: List[DetectionResult]
    ) -> List[Dict]:
        """Generate automated mitigation suggestions for Fortress."""
        mitigations = []

        for i, attack in enumerate(attack_results):
            if i >= len(detection_results):
                continue

            detection = detection_results[i]

            # Only generate mitigations for undetected successful attacks
            if attack.success and not detection.detected:
                mitigation = self._create_mitigation(attack)
                if mitigation:
                    mitigations.append(mitigation)

        return mitigations

    def _create_mitigation(self, attack: AttackResult) -> Optional[Dict]:
        """Create a mitigation rule for a specific attack."""
        mitigation_map = {
            'ter_replay': {
                'type': 'ovs_flow',
                'rule': 'Add replay detection with sequence number validation',
                'priority': 100,
                'action': 'track_ter_sequence',
            },
            'entropy_poisoning': {
                'type': 'neuro',
                'rule': 'Increase entropy threshold for resonance',
                'priority': 90,
                'action': 'raise_entropy_threshold',
            },
            'timing_attack': {
                'type': 'qsecbit',
                'rule': 'Add jitter to temporal correlation analysis',
                'priority': 80,
                'action': 'add_timing_jitter',
            },
            'mac_impersonation': {
                'type': 'xdp',
                'rule': 'Enable MAC binding per VLAN',
                'priority': 95,
                'action': 'bind_mac_vlan',
            },
            'mdns_spoofing': {
                'type': 'ovs_flow',
                'rule': 'Validate mDNS source against known devices',
                'priority': 85,
                'action': 'validate_mdns_source',
            },
        }

        attack_type = attack.attack_name.replace(' ', '_').lower()
        if attack_type in mitigation_map:
            mitigation = mitigation_map[attack_type].copy()
            mitigation['attack_name'] = attack.attack_name
            mitigation['target_bubble'] = attack.target_bubble
            mitigation['generated_at'] = datetime.now().isoformat()
            return mitigation

        return None

    def _send_validation_webhook(self, validation: ValidationResult):
        """Send validation results to n8n webhook."""
        if not self.config.n8n_webhook_url:
            return

        try:
            import urllib.request
            import urllib.error

            payload = json.dumps({
                'event_type': 'purple_team_validation',
                'timestamp': datetime.now().isoformat(),
                'data': validation.to_dict(),
            }).encode('utf-8')

            request = urllib.request.Request(
                self.config.n8n_webhook_url,
                data=payload,
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'HookProbe-Nexus/1.0',
                }
            )

            if self.config.n8n_auth_token:
                request.add_header('Authorization', f'Bearer {self.config.n8n_auth_token}')

            with urllib.request.urlopen(request, timeout=self.config.validation_timeout) as response:
                if response.status == 200:
                    logger.info("Validation webhook sent successfully")
                else:
                    logger.warning(f"Webhook returned {response.status}")

        except Exception as e:
            logger.warning(f"Failed to send validation webhook: {e}")

    def _apply_meta_learning(
        self,
        validation: ValidationResult
    ) -> Tuple[Dict[str, float], Dict[str, float], bool]:
        """
        Apply meta-regressive learning to optimize bubble accuracy.

        Uses effect sizes from simulations to adjust:
        - QSECBIT weights
        - Temporal correlation parameters
        - D2D affinity thresholds
        """
        # Collect sample for regression
        sample = {
            'defense_score': validation.defense_score,
            'detection_rate': validation.attacks_detected / max(validation.attacks_total, 1),
            'blocking_rate': validation.attacks_blocked / max(validation.attacks_total, 1),
            'false_positive_rate': validation.false_positives / max(
                validation.true_positives + validation.false_positives, 1
            ),
            'bubble_penetration_rate': validation.bubbles_penetrated / max(
                validation.attacks_total, 1
            ),
        }
        self._learning_samples.append(sample)

        # Check if we have enough samples for regression
        if len(self._learning_samples) < self.config.min_samples_for_regression:
            logger.info(
                f"Not enough samples for meta-learning: "
                f"{len(self._learning_samples)}/{self.config.min_samples_for_regression}"
            )
            return {}, {}, False

        # Calculate effect sizes
        effect_sizes = self._calculate_effect_sizes()

        # Run regression to get beta coefficients
        beta_coefficients = self._run_meta_regression()

        # Apply optimization if significant
        optimization_applied = self._apply_optimization(beta_coefficients)

        return effect_sizes, beta_coefficients, optimization_applied

    def _calculate_effect_sizes(self) -> Dict[str, float]:
        """Calculate effect sizes from learning samples."""
        if len(self._learning_samples) < 2:
            return {}

        # Simple effect size calculation (Cohen's d-like)
        effect_sizes = {}
        metrics = ['detection_rate', 'blocking_rate', 'false_positive_rate', 'bubble_penetration_rate']

        for metric in metrics:
            values = [s.get(metric, 0) for s in self._learning_samples]
            if len(values) >= 2:
                mean = sum(values) / len(values)
                variance = sum((v - mean) ** 2 for v in values) / len(values)
                std = variance ** 0.5 if variance > 0 else 1

                # Effect size: how much the last value differs from mean
                last_value = values[-1]
                effect_sizes[metric] = (last_value - mean) / std if std > 0 else 0

        return effect_sizes

    def _run_meta_regression(self) -> Dict[str, float]:
        """
        Run meta-regression to find optimal parameters.

        Model: E = β0 + β1(Temporal_Sync) + β2(D2D_Affinity) + β3(NSE_Resonance) + ε

        Returns beta coefficients for each factor.
        """
        # Simplified regression using correlation analysis
        beta_coefficients = {
            'temporal_sync': 0.0,
            'd2d_affinity': 0.0,
            'nse_resonance': 0.0,
            'detection_sensitivity': 0.0,
        }

        if len(self._learning_samples) < 5:
            return beta_coefficients

        # Calculate correlations with defense score
        defense_scores = [s.get('defense_score', 0) for s in self._learning_samples]
        detection_rates = [s.get('detection_rate', 0) for s in self._learning_samples]
        blocking_rates = [s.get('blocking_rate', 0) for s in self._learning_samples]
        penetration_rates = [s.get('bubble_penetration_rate', 0) for s in self._learning_samples]

        # Simple correlation coefficients as beta proxies
        beta_coefficients['temporal_sync'] = self._correlation(defense_scores, detection_rates)
        beta_coefficients['d2d_affinity'] = self._correlation(defense_scores, blocking_rates)
        beta_coefficients['nse_resonance'] = -self._correlation(defense_scores, penetration_rates)
        beta_coefficients['detection_sensitivity'] = self._correlation(detection_rates, blocking_rates)

        return beta_coefficients

    def _correlation(self, x: List[float], y: List[float]) -> float:
        """Calculate Pearson correlation coefficient."""
        if len(x) != len(y) or len(x) < 2:
            return 0.0

        n = len(x)
        mean_x = sum(x) / n
        mean_y = sum(y) / n

        numerator = sum((x[i] - mean_x) * (y[i] - mean_y) for i in range(n))
        denom_x = sum((x[i] - mean_x) ** 2 for i in range(n)) ** 0.5
        denom_y = sum((y[i] - mean_y) ** 2 for i in range(n)) ** 0.5

        if denom_x * denom_y == 0:
            return 0.0

        return numerator / (denom_x * denom_y)

    def _apply_optimization(self, beta_coefficients: Dict[str, float]) -> bool:
        """
        Apply optimization based on meta-regression results.

        Sends recommendations to Fortress SDN Autopilot.
        """
        # Check if any coefficient is significant (|β| > 0.3)
        significant = any(abs(b) > 0.3 for b in beta_coefficients.values())

        if not significant:
            logger.info("No significant beta coefficients, skipping optimization")
            return False

        # Generate optimization recommendations
        optimizations = []

        if abs(beta_coefficients.get('temporal_sync', 0)) > 0.3:
            if beta_coefficients['temporal_sync'] > 0:
                optimizations.append({
                    'parameter': 'temporal_sync_weight',
                    'action': 'increase',
                    'reason': 'Temporal sync strongly correlates with defense score',
                })
            else:
                optimizations.append({
                    'parameter': 'temporal_sync_weight',
                    'action': 'decrease',
                    'reason': 'Temporal sync negatively affects defense score',
                })

        if abs(beta_coefficients.get('d2d_affinity', 0)) > 0.3:
            optimizations.append({
                'parameter': 'd2d_affinity_threshold',
                'action': 'adjust',
                'value': beta_coefficients['d2d_affinity'],
                'reason': 'D2D affinity impacts blocking effectiveness',
            })

        if optimizations:
            # Send to Fortress via webhook
            self._send_optimization_webhook(optimizations)
            return True

        return False

    def _send_optimization_webhook(self, optimizations: List[Dict]):
        """Send optimization recommendations to Fortress."""
        if not self.config.n8n_webhook_url:
            logger.info(f"Optimization recommendations: {optimizations}")
            return

        try:
            import urllib.request

            payload = json.dumps({
                'event_type': 'purple_team_optimization',
                'timestamp': datetime.now().isoformat(),
                'data': {
                    'simulation_id': self.config.simulation_id,
                    'optimizations': optimizations,
                },
            }).encode('utf-8')

            request = urllib.request.Request(
                self.config.n8n_webhook_url,
                data=payload,
                headers={
                    'Content-Type': 'application/json',
                    'User-Agent': 'HookProbe-Nexus/1.0',
                }
            )

            if self.config.n8n_auth_token:
                request.add_header('Authorization', f'Bearer {self.config.n8n_auth_token}')

            with urllib.request.urlopen(request, timeout=self.config.validation_timeout):
                logger.info("Optimization recommendations sent to Fortress")

        except Exception as e:
            logger.warning(f"Failed to send optimization webhook: {e}")

    def _save_result(self, result: SimulationResult):
        """Save simulation result to disk and ClickHouse."""
        # Save JSON report
        report_path = Path(self.config.report_dir) / f"{result.simulation_id}.json"
        with open(report_path, 'w') as f:
            json.dump(result.to_dict(), f, indent=2, default=str)
        logger.info(f"Report saved: {report_path}")

        # Save to ClickHouse if enabled
        if self.config.clickhouse_enabled:
            self._save_to_clickhouse(result)

    def _save_to_clickhouse(self, result: SimulationResult):
        """Save simulation result to ClickHouse for analytics."""
        try:
            # TODO: Implement ClickHouse insertion
            logger.debug("ClickHouse save not yet implemented")
        except Exception as e:
            logger.debug(f"ClickHouse save failed: {e}")

    def get_simulation_history(self) -> List[SimulationResult]:
        """Get history of all simulations."""
        return self._simulation_history.copy()

    def get_learning_samples(self) -> List[Dict]:
        """Get all learning samples collected."""
        return self._learning_samples.copy()

    def compare_simulations(self, sim_id_1: str, sim_id_2: str) -> Dict:
        """Compare two simulations to see improvement."""
        sim_1 = next((s for s in self._simulation_history if s.simulation_id == sim_id_1), None)
        sim_2 = next((s for s in self._simulation_history if s.simulation_id == sim_id_2), None)

        if not sim_1 or not sim_2:
            return {'error': 'Simulation not found'}

        return {
            'comparison': f"{sim_id_1} vs {sim_id_2}",
            'defense_score_change': sim_2.validation.defense_score - sim_1.validation.defense_score,
            'risk_change': f"{sim_1.validation.overall_risk} → {sim_2.validation.overall_risk}",
            'detection_improvement': (
                sim_2.validation.attacks_detected - sim_1.validation.attacks_detected
            ),
            'improved': sim_2.validation.defense_score > sim_1.validation.defense_score,
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_purple_team_orchestrator(
    target_fortress_ip: str = "127.0.0.1",
    n8n_webhook_url: str = None,
    attack_intensity: float = 0.5,
) -> PurpleTeamOrchestrator:
    """Create a purple team orchestrator with common defaults."""
    config = PurpleTeamConfig(
        target_fortress_ip=target_fortress_ip,
        n8n_webhook_url=n8n_webhook_url,
        attack_intensity=attack_intensity,
    )
    return PurpleTeamOrchestrator(config)


def run_quick_simulation(
    target_fortress_ip: str = "127.0.0.1",
) -> SimulationResult:
    """Run a quick purple team simulation with defaults."""
    orchestrator = create_purple_team_orchestrator(
        target_fortress_ip=target_fortress_ip,
        attack_intensity=0.3,  # Lower intensity for quick test
    )
    return orchestrator.run_simulation()


# =============================================================================
# CLI INTERFACE
# =============================================================================

if __name__ == '__main__':
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    parser = argparse.ArgumentParser(description='Purple Team Orchestrator')
    parser.add_argument('command', choices=['run', 'status', 'history', 'compare'])
    parser.add_argument('--target', default='127.0.0.1', help='Fortress IP')
    parser.add_argument('--webhook', help='n8n webhook URL')
    parser.add_argument('--intensity', type=float, default=0.5, help='Attack intensity')
    parser.add_argument('--sim1', help='First simulation ID for comparison')
    parser.add_argument('--sim2', help='Second simulation ID for comparison')
    args = parser.parse_args()

    orchestrator = create_purple_team_orchestrator(
        target_fortress_ip=args.target,
        n8n_webhook_url=args.webhook,
        attack_intensity=args.intensity,
    )

    if args.command == 'run':
        print(f"Starting Purple Team simulation against {args.target}...")
        result = orchestrator.run_simulation()
        print("\n" + "=" * 60)
        print("SIMULATION COMPLETE")
        print("=" * 60)
        print(f"Simulation ID: {result.simulation_id}")
        print(f"Duration: {result.duration_seconds:.1f}s")
        print(f"Defense Score: {result.validation.defense_score:.1f}/100")
        print(f"Overall Risk: {result.validation.overall_risk}")
        print(f"Attacks: {result.validation.attacks_total} total, "
              f"{result.validation.attacks_successful} successful")
        print(f"Detection: {result.validation.attacks_detected} detected, "
              f"{result.validation.attacks_blocked} blocked")
        print(f"Bubbles Penetrated: {result.validation.bubbles_penetrated}")
        if result.validation.recommendations:
            print("\nRecommendations:")
            for rec in result.validation.recommendations:
                print(f"  - {rec}")

    elif args.command == 'status':
        print(f"Orchestrator State: {orchestrator.state.value}")
        print(f"Target: {orchestrator.config.target_fortress_ip}")
        print(f"Enabled Attacks: {len(orchestrator.config.enabled_attacks)}")

    elif args.command == 'history':
        history = orchestrator.get_simulation_history()
        print(f"Simulation History: {len(history)} simulations")
        for sim in history:
            print(f"  - {sim.simulation_id}: Score={sim.validation.defense_score:.1f}")

    elif args.command == 'compare':
        if not args.sim1 or not args.sim2:
            print("Error: --sim1 and --sim2 required for comparison")
        else:
            comparison = orchestrator.compare_simulations(args.sim1, args.sim2)
            print(f"Comparison: {comparison}")
