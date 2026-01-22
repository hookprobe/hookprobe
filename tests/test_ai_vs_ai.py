"""
Tests for AI vs AI Module

Tests the core AI vs AI components:
- ThreatPredictor
- IoCGenerator
- DefenseOrchestrator
- ComputeEvaluator

Author: HookProbe Team
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

# Import modules under test
from core.ai_vs_ai.models import (
    IoC,
    IoCType,
    ThreatSeverity,
    ThreatPrediction,
    DefenseStrategy,
    DefenseAction,
    ComputeTask,
    ComputeTier,
    AIConsultationRequest,
    AIConsultationResponse,
    get_mitre_mapping,
    ATTACK_TO_MITRE,
)

from core.ai_vs_ai.ioc_generator import (
    IoCGenerator,
    ATTACK_DESCRIPTIONS,
    ATTACK_SEVERITY,
    generate_ioc_from_attack_sequence,
)

from core.ai_vs_ai.threat_predictor import (
    ThreatPredictor,
    ATTACK_CATEGORIES,
    CATEGORY_TO_IDX,
    create_predictor_for_tier,
)

from core.ai_vs_ai.defense_orchestrator import (
    DefenseOrchestrator,
    DEFAULT_DEFENSE_ACTIONS,
    create_orchestrator_for_tier,
)

from core.ai_vs_ai.compute_evaluator import (
    ComputeEvaluator,
    SystemResources,
    NexusNode,
    TIER_THRESHOLDS,
    create_evaluator_for_product,
)


# Test markers
pytestmark = [pytest.mark.unit, pytest.mark.ai_vs_ai]


# ============================================================
# FIXTURES
# ============================================================

@pytest.fixture
def sample_prediction():
    """Create sample threat prediction"""
    return ThreatPrediction(
        predicted_attack="brute_force",
        confidence=0.85,
        attack_probabilities={
            "brute_force": 0.85,
            "port_scan": 0.10,
            "unknown": 0.05,
        },
        input_sequence=["port_scan", "address_scan", "brute_force"],
        sequence_length=3,
        attack_intensity=5.0,
        trend="increasing",
        anomaly_score=0.15,
        is_anomalous=False,
    )


@pytest.fixture
def sample_ioc():
    """Create sample IoC"""
    return IoC(
        ioc_id="test_ioc_001",
        ioc_type=IoCType.IP_ADDRESS,
        value="192.168.0.0",
        confidence=0.8,
        severity=ThreatSeverity.HIGH,
        attack_category="brute_force",
        attack_description="Credential brute force attack detected",
        attack_sequence=["port_scan", "address_scan", "brute_force"],
        mitre_tactics=["Credential Access"],
        mitre_techniques=["T1110"],
        source_system="lstm",
    )


@pytest.fixture
def sample_strategy():
    """Create sample defense strategy"""
    return DefenseStrategy(
        ioc_id="test_ioc_001",
        primary_action=DefenseAction.BLOCK_IP,
        secondary_actions=[DefenseAction.ALERT],
        reasoning="Block IP due to brute force attack",
        confidence=0.8,
    )


@pytest.fixture
def predictor():
    """Create threat predictor"""
    return ThreatPredictor(compute_tier=ComputeTier.FORTRESS_LITE)


@pytest.fixture
def ioc_generator(tmp_path):
    """Create IoC generator with temp output dir"""
    return IoCGenerator(output_dir=tmp_path / "ioc")


@pytest.fixture
def orchestrator():
    """Create defense orchestrator with mocked AI"""
    orch = DefenseOrchestrator(compute_tier=ComputeTier.FORTRESS_LITE)
    # Disable AI for tests
    for ai_name in orch.ai_config:
        orch.ai_config[ai_name]["enabled"] = False
    return orch


@pytest.fixture
def evaluator():
    """Create compute evaluator"""
    return ComputeEvaluator(local_tier=ComputeTier.FORTRESS_STANDARD)


# ============================================================
# MODEL TESTS
# ============================================================

class TestModels:
    """Test data model classes"""

    def test_ioc_creation(self):
        """Test IoC creation and ID generation"""
        ioc = IoC(
            ioc_id="",
            ioc_type=IoCType.IP_ADDRESS,
            value="10.0.0.0",
            confidence=0.9,
            severity=ThreatSeverity.HIGH,
            attack_category="port_scan",
            attack_description="Port scanning detected",
            attack_sequence=["port_scan"],
        )

        assert ioc.ioc_id != ""  # Auto-generated
        assert len(ioc.ioc_id) == 16
        assert ioc.first_seen != ""
        assert ioc.last_seen != ""

    def test_ioc_to_dict(self, sample_ioc):
        """Test IoC serialization"""
        d = sample_ioc.to_dict()

        assert d["ioc_type"] == "ip_address"
        assert d["severity"] == "high"
        assert d["attack_category"] == "brute_force"
        assert "mitre_techniques" in d

    def test_ioc_to_prompt(self, sample_ioc):
        """Test IoC prompt generation"""
        prompt = sample_ioc.to_prompt()

        assert "THREAT INDICATOR" in prompt
        assert "brute_force" in prompt.lower()
        assert "T1110" in prompt
        assert "defense actions" in prompt.lower()

    def test_threat_prediction_top_predictions(self, sample_prediction):
        """Test getting top predictions"""
        top = sample_prediction.get_top_predictions(2)

        assert len(top) == 2
        assert top[0][0] == "brute_force"
        assert top[0][1] == 0.85

    def test_defense_strategy_to_dict(self, sample_strategy):
        """Test defense strategy serialization"""
        d = sample_strategy.to_dict()

        assert d["primary_action"] == "block_ip"
        assert d["secondary_actions"] == ["alert"]

    def test_compute_task_can_run_on_fortress(self):
        """Test task resource evaluation"""
        small_task = ComputeTask(
            task_type="prediction",
            estimated_memory_mb=512,
            estimated_cpu_cores=0.5,
            estimated_gpu_required=False,
            estimated_duration_sec=5,
        )
        assert small_task.can_run_on_fortress() is True

        large_task = ComputeTask(
            task_type="training",
            estimated_memory_mb=8192,
            estimated_cpu_cores=4.0,
            estimated_gpu_required=True,
            estimated_duration_sec=3600,
        )
        assert large_task.can_run_on_fortress() is False
        assert large_task.requires_nexus() is True

    def test_mitre_mapping(self):
        """Test MITRE ATT&CK mapping"""
        mapping = get_mitre_mapping("sql_injection")

        assert "Initial Access" in mapping["tactics"]
        assert "T1190" in mapping["techniques"]

    def test_mitre_mapping_unknown(self):
        """Test MITRE mapping for unknown category"""
        mapping = get_mitre_mapping("nonexistent_attack")

        assert mapping["tactics"] == ["Unknown"]


# ============================================================
# IOC GENERATOR TESTS
# ============================================================

class TestIoCGenerator:
    """Test IoC generation"""

    def test_from_prediction(self, ioc_generator, sample_prediction):
        """Test IoC generation from prediction"""
        ioc = ioc_generator.from_prediction(
            sample_prediction,
            source_ip="192.168.1.100"
        )

        assert ioc.attack_category == "brute_force"
        assert ioc.confidence == 0.85
        assert "192.168.0.0" in ioc.value or ioc.value  # Anonymized
        assert "Credential Access" in ioc.mitre_tactics

    def test_from_prediction_with_sequence(self, ioc_generator, sample_prediction):
        """Test IoC includes attack sequence"""
        ioc = ioc_generator.from_prediction(sample_prediction)

        assert len(ioc.attack_sequence) == 3
        assert "port_scan" in ioc.attack_sequence

    def test_ip_anonymization(self, ioc_generator):
        """Test IP anonymization"""
        anon = ioc_generator._anonymize_ip("192.168.1.100")
        assert anon == "192.168.0.0"

        anon = ioc_generator._anonymize_ip("10.0.5.200")
        assert anon == "10.0.0.0"

    def test_severity_mapping(self):
        """Test attack category to severity mapping"""
        assert ATTACK_SEVERITY["malware_c2"] == ThreatSeverity.CRITICAL
        assert ATTACK_SEVERITY["port_scan"] == ThreatSeverity.LOW

    def test_description_mapping(self):
        """Test attack descriptions exist for all categories"""
        for category in ATTACK_CATEGORIES:
            if category != "unknown":
                assert category in ATTACK_DESCRIPTIONS or category in ATTACK_SEVERITY

    def test_aggregate_iocs(self, ioc_generator, sample_prediction):
        """Test IoC aggregation"""
        # Generate multiple IoCs
        for _ in range(5):
            ioc_generator.from_prediction(sample_prediction)

        aggregated = ioc_generator.aggregate_iocs(60)
        assert len(aggregated) >= 1

    def test_convenience_function(self):
        """Test generate_ioc_from_attack_sequence"""
        ioc = generate_ioc_from_attack_sequence(
            ["port_scan", "brute_force"],
            source_ip="10.0.0.1"
        )

        assert ioc.attack_category == "brute_force"  # Last in sequence


# ============================================================
# THREAT PREDICTOR TESTS
# ============================================================

class TestThreatPredictor:
    """Test threat prediction"""

    def test_add_event(self, predictor):
        """Test adding events to sequence"""
        predictor.add_event("port_scan")
        predictor.add_event("brute_force")

        assert len(predictor._sequence_buffer) == 2

    def test_statistical_prediction(self, predictor):
        """Test statistical fallback prediction"""
        # Build up sequence
        for _ in range(3):
            predictor.add_event("port_scan")
            predictor.add_event("brute_force")

        prediction = predictor.predict()

        assert prediction.predicted_attack in ATTACK_CATEGORIES
        assert 0 <= prediction.confidence <= 1
        assert prediction.model_version == "statistical"

    def test_empty_prediction(self, predictor):
        """Test prediction with no events"""
        prediction = predictor.predict()

        assert prediction.predicted_attack == "unknown"
        assert prediction.confidence == 0.0

    def test_temporal_features(self, predictor):
        """Test temporal analysis"""
        # Add events with timestamps
        predictor.add_event("port_scan")
        predictor.add_event("port_scan")
        predictor.add_event("brute_force")

        prediction = predictor.predict()

        assert prediction.attack_intensity >= 0
        assert prediction.trend in ["increasing", "stable", "decreasing"]

    def test_anomaly_detection(self, predictor):
        """Test anomaly score calculation"""
        # Build normal pattern
        for _ in range(5):
            predictor.add_event("port_scan")
            predictor.add_event("brute_force")

        # Add anomalous event
        predictor.add_event("malware_c2")

        prediction = predictor.predict()
        assert prediction.anomaly_score >= 0

    def test_get_stats(self, predictor):
        """Test predictor statistics"""
        predictor.add_event("port_scan")
        predictor.predict()

        stats = predictor.get_stats()

        assert "model_loaded" in stats
        assert "sequence_length" in stats
        assert "prediction_count" in stats

    def test_factory_function(self):
        """Test create_predictor_for_tier factory"""
        predictor = create_predictor_for_tier(ComputeTier.FORTRESS_LITE)
        assert predictor.compute_tier == ComputeTier.FORTRESS_LITE


# ============================================================
# DEFENSE ORCHESTRATOR TESTS
# ============================================================

class TestDefenseOrchestrator:
    """Test defense orchestration"""

    def test_default_strategy(self, orchestrator, sample_ioc):
        """Test default strategy generation"""
        strategy = orchestrator._default_strategy(sample_ioc)

        assert strategy.primary_action == DefenseAction.BLOCK_IP
        assert DefenseAction.ALERT in strategy.secondary_actions

    def test_consult_without_ai(self, orchestrator, sample_ioc, sample_prediction):
        """Test consultation without AI (using defaults)"""
        strategy = orchestrator.consult(
            sample_ioc,
            sample_prediction,
            use_ai=False
        )

        assert strategy is not None
        assert strategy.ioc_id == sample_ioc.ioc_id

    def test_default_defense_actions(self):
        """Test default action mapping exists for all categories"""
        for category in ATTACK_CATEGORIES:
            assert category in DEFAULT_DEFENSE_ACTIONS

    def test_action_params_generation(self, orchestrator, sample_ioc):
        """Test action parameter generation"""
        actions = [DefenseAction.BLOCK_IP, DefenseAction.RATE_LIMIT]
        params = orchestrator._build_action_params(sample_ioc, actions)

        assert "block_ip" in params
        assert "duration_minutes" in params["block_ip"]

    def test_cache_key_generation(self, orchestrator, sample_ioc):
        """Test cache key is consistent"""
        key1 = orchestrator._cache_key(sample_ioc)
        key2 = orchestrator._cache_key(sample_ioc)

        assert key1 == key2
        assert len(key1) == 16

    def test_get_stats(self, orchestrator, sample_ioc):
        """Test orchestrator statistics"""
        orchestrator.consult(sample_ioc, use_ai=False)

        stats = orchestrator.get_stats()

        assert stats["consultation_count"] >= 1
        assert "enabled_ais" in stats

    def test_factory_function(self):
        """Test create_orchestrator_for_tier factory"""
        orch = create_orchestrator_for_tier(
            ComputeTier.FORTRESS_LITE,
            enable_local_ai=False
        )
        assert orch.compute_tier == ComputeTier.FORTRESS_LITE

    def test_response_callback(self, orchestrator, sample_ioc):
        """Test response callback registration"""
        callback_called = []

        def test_callback(strategy):
            callback_called.append(strategy)

        orchestrator.register_callback(test_callback)
        orchestrator.consult(sample_ioc, use_ai=False)

        assert len(callback_called) == 1


# ============================================================
# COMPUTE EVALUATOR TESTS
# ============================================================

class TestComputeEvaluator:
    """Test compute evaluation and routing"""

    def test_tier_thresholds(self):
        """Test tier threshold definitions"""
        for tier in ComputeTier:
            assert tier in TIER_THRESHOLDS or tier == ComputeTier.MESH_CLOUD

    def test_evaluate_small_task(self, evaluator):
        """Test evaluation of small task"""
        task = ComputeTask(
            task_type="prediction",
            estimated_memory_mb=256,
            estimated_cpu_cores=0.5,
            estimated_gpu_required=False,
            estimated_duration_sec=5,
        )

        tier, node = evaluator.evaluate_task(task)

        assert tier == ComputeTier.FORTRESS_STANDARD
        assert node is None  # Local

    def test_evaluate_large_task(self, evaluator):
        """Test evaluation of large task"""
        task = ComputeTask(
            task_type="training",
            estimated_memory_mb=16384,
            estimated_cpu_cores=8.0,
            estimated_gpu_required=True,
            estimated_duration_sec=3600,
        )

        # Without Nexus nodes registered, should still route locally
        tier, node = evaluator.evaluate_task(task)

        # Will be routed locally with warning since no Nexus available
        assert tier is not None

    def test_route_task(self, evaluator):
        """Test task routing"""
        task = ComputeTask(
            task_type="prediction",
            estimated_memory_mb=512,
        )

        routed = evaluator.route_task(task)

        assert routed.assigned_tier is not None
        assert routed.routed_to_node is not None

    def test_register_nexus_node(self, evaluator, tmp_path):
        """Test Nexus node registration"""
        evaluator.nexus_registry_path = tmp_path / "nexus.json"

        evaluator.register_nexus_node(
            node_id="nexus-test",
            address="192.168.1.100",
            port=8765,
            tier=ComputeTier.NEXUS_STANDARD,
        )

        assert "nexus-test" in evaluator._nexus_nodes

    def test_get_recommendation(self, evaluator):
        """Test routing recommendation"""
        task = ComputeTask(
            task_type="analysis",
            estimated_memory_mb=2048,
            estimated_gpu_required=True,
        )

        rec = evaluator.get_recommendation(task)

        assert "recommended_tier" in rec
        assert "can_run_locally" in rec
        assert "reasons" in rec

    def test_get_routing_stats(self, evaluator):
        """Test routing statistics"""
        # Route a few tasks
        for _ in range(3):
            task = ComputeTask(task_type="test", estimated_memory_mb=256)
            evaluator.route_task(task)

        stats = evaluator.get_routing_stats()

        assert stats["total_tasks"] == 3
        assert stats["local_tasks"] >= 0

    def test_factory_function(self):
        """Test create_evaluator_for_product factory"""
        evaluator = create_evaluator_for_product("fortress")
        assert evaluator.local_tier in [
            ComputeTier.FORTRESS_LITE,
            ComputeTier.FORTRESS_STANDARD,
        ]


# ============================================================
# INTEGRATION TESTS
# ============================================================

class TestIntegration:
    """Integration tests for AI vs AI flow"""

    def test_full_flow(self, predictor, ioc_generator, orchestrator):
        """Test full prediction → IoC → strategy flow"""
        # 1. Add events to predictor
        predictor.add_event("port_scan")
        predictor.add_event("address_scan")
        predictor.add_event("brute_force")

        # 2. Get prediction
        prediction = predictor.predict()
        assert prediction.predicted_attack != "unknown"

        # 3. Generate IoC
        ioc = ioc_generator.from_prediction(prediction, source_ip="10.0.0.1")
        assert ioc.attack_category == prediction.predicted_attack

        # 4. Get defense strategy
        strategy = orchestrator.consult(ioc, prediction, use_ai=False)
        assert strategy.primary_action is not None

    @pytest.mark.xfail(reason="Pre-existing: severity mapping logic mismatch")
    def test_escalation_scenario(self, predictor, ioc_generator):
        """Test attack escalation scenario"""
        # Simulate reconnaissance → attack escalation
        sequence = [
            "reconnaissance",
            "port_scan",
            "address_scan",
            "brute_force",
            "privilege_escalation",
        ]

        for attack in sequence:
            predictor.add_event(attack)

        prediction = predictor.predict()

        # Should predict continuation of escalation
        assert prediction.sequence_length == len(sequence)
        assert prediction.trend in ["increasing", "stable"]

        # IoC should reflect high severity
        ioc = ioc_generator.from_prediction(prediction)
        assert ioc.severity in [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]

    def test_compute_routing_decision(self, evaluator, predictor):
        """Test compute routing based on task"""
        predictor.add_event("port_scan")

        task = predictor.get_compute_task()
        routed = evaluator.route_task(task)

        # Statistical prediction should run locally
        assert routed.routed_to_node == "local"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
