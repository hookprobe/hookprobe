"""
SLA AI Test Suite

Tests for the SLA AI components:
    - CostTracker
    - FailbackIntelligence
    - LSTMPredictor
    - DNSIntelligence
    - SLAEngine
"""

import pytest
import asyncio
import tempfile
import os
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock

# Import SLA AI components
from shared.slaai.cost_tracker import CostTracker, UsageBudget, UsageStatus
from shared.slaai.failback import (
    FailbackIntelligence,
    FailbackPolicy,
    FailbackDecision,
    FailbackState,
    HealthCheck,
)
from shared.slaai.predictor import (
    LSTMPredictor,
    Prediction,
    FeatureExtractor,
    LightweightLSTM,
)
from shared.slaai.dns_intelligence import (
    DNSIntelligence,
    DNSProvider,
    DNSHealth,
    DNSStatus,
)
from shared.slaai.metrics_collector import WANMetrics
from shared.slaai.config import SLAAIConfig, InterfaceConfig, load_config


class TestCostTracker:
    """Tests for CostTracker."""

    def test_set_budget(self):
        """Test setting a budget for an interface."""
        tracker = CostTracker()
        tracker.set_budget(
            "wwan0",
            daily_mb=500,
            monthly_mb=10000,
            cost_per_gb=0.50,
        )

        assert tracker.is_metered("wwan0")
        assert not tracker.is_metered("eth0")

    def test_record_usage(self):
        """Test recording usage."""
        tracker = CostTracker()
        tracker.set_budget("wwan0", daily_mb=500, monthly_mb=10000)

        tracker.record_usage("wwan0", bytes_sent=1000, bytes_received=2000)
        tracker.record_usage("wwan0", bytes_sent=500, bytes_received=500)

        # Session tracking
        assert tracker._session_usage["wwan0"]["sent"] == 1500
        assert tracker._session_usage["wwan0"]["received"] == 2500

    def test_get_status_no_budget(self):
        """Test status for non-metered interface."""
        tracker = CostTracker()
        status = tracker.get_status("eth0")

        assert status.interface == "eth0"
        assert status.daily_limit_bytes == 0
        assert status.urgency_score == 0.0

    def test_urgency_score_calculation(self):
        """Test urgency score increases with usage."""
        tracker = CostTracker()
        tracker.set_budget("wwan0", daily_mb=100, monthly_mb=1000)

        # Simulate 50% daily usage in session
        tracker._session_usage["wwan0"] = {
            "sent": 25 * 1024 * 1024,
            "received": 25 * 1024 * 1024,
        }

        status = tracker.get_status("wwan0")
        assert status.daily_pct == pytest.approx(50.0, rel=0.1)
        assert status.urgency_score > 0.0

    def test_failback_urgency_multiplier(self):
        """Test failback urgency multiplier."""
        tracker = CostTracker()
        tracker.set_budget("wwan0", daily_mb=100, monthly_mb=1000)

        # No usage - multiplier should be 1.0
        multiplier = tracker.get_failback_urgency_multiplier("wwan0")
        assert multiplier >= 1.0

        # High usage - multiplier should increase
        tracker._session_usage["wwan0"] = {
            "sent": 90 * 1024 * 1024,
            "received": 90 * 1024 * 1024,
        }

        multiplier = tracker.get_failback_urgency_multiplier("wwan0")
        assert multiplier > 1.5

    def test_should_warn_usage(self):
        """Test usage warnings."""
        tracker = CostTracker()
        tracker.set_budget("wwan0", daily_mb=100, monthly_mb=1000)

        # No warning at low usage
        warning = tracker.should_warn_usage("wwan0")
        assert warning is None

        # Warning at 85% daily
        tracker._session_usage["wwan0"] = {
            "sent": 42 * 1024 * 1024,
            "received": 43 * 1024 * 1024,
        }

        warning = tracker.should_warn_usage("wwan0")
        assert warning is not None
        assert "85%" in warning or "daily" in warning.lower()


class TestFailbackIntelligence:
    """Tests for FailbackIntelligence."""

    def test_policy_defaults(self):
        """Test default policy values."""
        policy = FailbackPolicy()

        assert policy.min_backup_duration_s == 120
        assert policy.primary_stable_duration_s == 60
        assert policy.health_checks_required == 5
        assert policy.metered_failback_urgency == 1.5

    def test_record_failover(self):
        """Test recording a failover event."""
        failback = FailbackIntelligence()
        failback.set_interfaces("eth0", "wwan0")

        failback.record_failover("eth0", "wwan0")

        assert failback._failover_timestamp is not None
        assert failback._switch_count_hour == 1

    def test_flap_prevention(self):
        """Test flap prevention logic."""
        policy = FailbackPolicy(max_switches_per_hour=3)
        failback = FailbackIntelligence(policy=policy)
        failback.set_interfaces("eth0", "wwan0")

        # Record multiple failovers
        for _ in range(4):
            failback.record_failover("eth0", "wwan0")

        # Should be blocked now
        assert not failback._check_flap_prevention()

    def test_evaluate_not_on_backup(self):
        """Test evaluation when not on backup."""
        failback = FailbackIntelligence()

        decision = failback.evaluate(current_on_backup=False)

        assert not decision.should_failback
        assert decision.state == FailbackState.NOT_READY
        assert "primary" in decision.reason.lower()

    def test_evaluate_min_duration_not_met(self):
        """Test evaluation before minimum backup duration."""
        failback = FailbackIntelligence()
        failback.set_interfaces("eth0", "wwan0")
        failback.record_failover("eth0", "wwan0")

        decision = failback.evaluate(current_on_backup=True)

        assert not decision.should_failback
        assert decision.state == FailbackState.NOT_READY
        assert "duration" in decision.reason.lower()

    def test_health_check_recording(self):
        """Test recording health checks."""
        failback = FailbackIntelligence()
        failback.set_interfaces("eth0", "wwan0")

        check = HealthCheck(
            timestamp=datetime.now(),
            interface="eth0",
            rtt_ms=50.0,
            packet_loss_pct=0.0,
            is_healthy=True,
        )

        failback.record_health_check(check)

        assert "eth0" in failback._health_checks
        assert len(failback._health_checks["eth0"]) == 1


class TestFeatureExtractor:
    """Tests for FeatureExtractor."""

    def test_extract_empty_window(self):
        """Test feature extraction with empty window."""
        features = FeatureExtractor.extract([])

        assert len(features) == 24
        assert all(f == 0.0 for f in features)

    def test_normalize(self):
        """Test normalization."""
        assert FeatureExtractor._normalize(50, 0, 100) == 0.5
        assert FeatureExtractor._normalize(0, 0, 100) == 0.0
        assert FeatureExtractor._normalize(100, 0, 100) == 1.0
        assert FeatureExtractor._normalize(150, 0, 100) == 1.0  # Clamped

    def test_std_calculation(self):
        """Test standard deviation calculation."""
        assert FeatureExtractor._std([]) == 0.0
        assert FeatureExtractor._std([5]) == 0.0
        assert FeatureExtractor._std([1, 2, 3, 4, 5]) == pytest.approx(1.414, rel=0.01)

    def test_trend_calculation(self):
        """Test trend calculation."""
        # Increasing trend
        assert FeatureExtractor._trend([1, 2, 3, 4, 5]) > 0

        # Decreasing trend
        assert FeatureExtractor._trend([5, 4, 3, 2, 1]) < 0

        # Flat trend
        assert FeatureExtractor._trend([5, 5, 5, 5, 5]) == pytest.approx(0.0, abs=0.01)


class TestLightweightLSTM:
    """Tests for LightweightLSTM."""

    def test_initialization(self):
        """Test LSTM initialization."""
        lstm = LightweightLSTM(input_size=24, hidden_size=32, output_size=3)

        assert len(lstm.Wi) == 24
        assert len(lstm.Wh) == 32
        assert len(lstm.b) == 128  # 32 * 4 gates
        assert len(lstm.b2) == 3

    def test_forward_pass(self):
        """Test forward pass produces valid probabilities."""
        lstm = LightweightLSTM()

        # Create dummy sequence
        sequence = [[0.5] * 24 for _ in range(12)]

        output = lstm.forward(sequence)

        assert len(output) == 3
        assert sum(output) == pytest.approx(1.0, rel=0.001)  # Softmax sums to 1
        assert all(0 <= p <= 1 for p in output)

    def test_weight_serialization(self):
        """Test weight serialization/deserialization."""
        lstm1 = LightweightLSTM()
        lstm2 = LightweightLSTM()

        # Get weights from lstm1
        weights = lstm1.get_weights()

        # Set weights on lstm2
        lstm2.set_weights(weights)

        # They should produce same output
        sequence = [[0.3] * 24 for _ in range(12)]

        out1 = lstm1.forward(sequence)
        out2 = lstm2.forward(sequence)

        for p1, p2 in zip(out1, out2):
            assert p1 == pytest.approx(p2, rel=0.001)


class TestLSTMPredictor:
    """Tests for LSTMPredictor."""

    def test_predict_insufficient_data(self):
        """Test prediction with insufficient data."""
        predictor = LSTMPredictor()

        prediction = predictor.predict("eth0")

        assert prediction.state == "healthy"
        assert prediction.confidence == 0.3
        assert prediction.features_used < 3

    def test_update_features(self):
        """Test feature buffer update."""
        predictor = LSTMPredictor(window_size=12)

        metrics = WANMetrics(
            timestamp=datetime.now(),
            interface="eth0",
            rtt_ms=50.0,
            jitter_ms=5.0,
            packet_loss_pct=0.0,
        )

        predictor.update_features("eth0", metrics)

        assert "eth0" in predictor._feature_buffers
        assert len(predictor._feature_buffers["eth0"]) == 1


class TestDNSIntelligence:
    """Tests for DNSIntelligence."""

    def test_default_providers(self):
        """Test default DNS providers."""
        dns = DNSIntelligence()

        assert len(dns.providers) == 4
        assert dns.providers[0].name == "cloudflare"
        assert dns._current_primary == "1.1.1.1"

    def test_add_provider(self):
        """Test adding a DNS provider."""
        dns = DNSIntelligence()

        provider = DNSProvider(
            name="custom",
            primary="9.9.9.9",
            secondary="9.9.9.10",
            priority=5,
        )

        dns.add_provider(provider)

        assert len(dns.providers) == 5
        assert dns.providers[-1].name == "custom"

    def test_remove_provider(self):
        """Test removing a DNS provider."""
        dns = DNSIntelligence()

        dns.remove_provider("opendns")

        assert len(dns.providers) == 3
        assert all(p.name != "opendns" for p in dns.providers)

    def test_score_calculation(self):
        """Test DNS score calculation."""
        dns = DNSIntelligence()

        # Add some response times
        dns._response_times["1.1.1.1"] = [20, 25, 30, 22, 28]

        score = dns._calculate_score("1.1.1.1", priority=1)

        # Should have high score for fast DNS with priority 1
        assert score > 80

    def test_get_status(self):
        """Test DNS status determination."""
        dns = DNSIntelligence()

        # Unknown status for unseen IP
        assert dns.get_status("unknown.ip") == DNSStatus.UNKNOWN

        # Healthy status for fast responses
        dns._response_times["1.1.1.1"] = [20, 25, 30]
        assert dns.get_status("1.1.1.1") == DNSStatus.HEALTHY

    def test_get_best_dns(self):
        """Test best DNS selection."""
        dns = DNSIntelligence()

        # Add response times
        dns._response_times["1.1.1.1"] = [20, 25, 30]
        dns._response_times["8.8.8.8"] = [50, 60, 70]

        primary, secondary = dns.get_best_dns()

        # Cloudflare should be best (faster and higher priority)
        assert primary == "1.1.1.1"


class TestConfig:
    """Tests for configuration."""

    def test_load_config_defaults(self):
        """Test loading config with defaults."""
        config = load_config()

        assert config.enabled is True
        assert config.check_interval_s == 5
        assert config.prediction_interval_s == 30

    def test_load_config_from_file(self):
        """Test loading config from file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("""
enabled: true
check_interval_s: 10
primary:
  name: eth0
  type: ethernet
backup:
  name: wwan0
  type: lte
  metered: true
  daily_budget_mb: 500
""")
            config_path = f.name

        try:
            config = load_config(config_path)

            assert config.check_interval_s == 10
            assert config.primary.name == "eth0"
            assert config.backup.name == "wwan0"
            assert config.backup.metered is True
            assert config.backup.daily_budget_mb == 500
        finally:
            os.unlink(config_path)


class TestIntegration:
    """Integration tests for SLA AI components."""

    @pytest.mark.asyncio
    async def test_metrics_to_prediction_flow(self):
        """Test flow from metrics to prediction."""
        predictor = LSTMPredictor(window_size=5)

        # Simulate healthy metrics
        for i in range(10):
            metrics = WANMetrics(
                timestamp=datetime.now(),
                interface="eth0",
                rtt_ms=50 + i,
                jitter_ms=5,
                packet_loss_pct=0.0,
            )
            predictor.update_features("eth0", metrics)

        prediction = predictor.predict("eth0")

        assert prediction.features_used == 5  # Window size
        assert prediction.state in ["healthy", "degraded", "failure"]
        assert 0 <= prediction.confidence <= 1

    @pytest.mark.asyncio
    async def test_failback_with_cost_tracker(self):
        """Test failback decision with cost awareness."""
        cost_tracker = CostTracker()
        cost_tracker.set_budget("wwan0", daily_mb=100, monthly_mb=1000)

        failback = FailbackIntelligence(cost_tracker=cost_tracker)
        failback.set_interfaces("eth0", "wwan0")

        # Simulate high usage on backup
        cost_tracker._session_usage["wwan0"] = {
            "sent": 80 * 1024 * 1024,
            "received": 80 * 1024 * 1024,
        }

        # The urgency multiplier should be high
        multiplier = cost_tracker.get_failback_urgency_multiplier("wwan0")
        assert multiplier > 1.5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
