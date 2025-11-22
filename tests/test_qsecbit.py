"""
Unit tests for Qsecbit algorithm

Tests the core Qsecbit threat analysis functionality.
"""

import sys
import os
import numpy as np
import pytest
from datetime import datetime

# Add Scripts/autonomous to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'Scripts', 'autonomous'))

try:
    from qsecbit import Qsecbit, QsecbitConfig, QsecbitSample
except ImportError:
    pytest.skip("qsecbit.py not available", allow_module_level=True)


class TestQsecbitConfig:
    """Test QsecbitConfig dataclass"""

    def test_default_config(self):
        """Test default configuration values"""
        config = QsecbitConfig()

        assert config.amber_threshold == 0.45
        assert config.red_threshold == 0.70
        assert config.alpha == 0.30
        assert config.beta == 0.30
        assert config.gamma == 0.20
        assert config.delta == 0.20

    def test_weights_sum_to_one(self):
        """Test that component weights sum to 1.0"""
        config = QsecbitConfig()
        weight_sum = config.alpha + config.beta + config.gamma + config.delta
        assert np.isclose(weight_sum, 1.0, atol=0.01)

    def test_invalid_weights_raise_error(self):
        """Test that invalid weights raise ValueError"""
        with pytest.raises(ValueError, match="Weights must sum to 1.0"):
            QsecbitConfig(alpha=0.5, beta=0.5, gamma=0.5, delta=0.5)

    def test_invalid_thresholds_raise_error(self):
        """Test that invalid thresholds raise ValueError"""
        with pytest.raises(ValueError, match="Thresholds must satisfy"):
            QsecbitConfig(amber_threshold=0.8, red_threshold=0.5)

    def test_custom_config(self):
        """Test custom configuration"""
        config = QsecbitConfig(
            amber_threshold=0.40,
            red_threshold=0.65,
            alpha=0.35,
            beta=0.35,
            gamma=0.15,
            delta=0.15
        )

        assert config.amber_threshold == 0.40
        assert config.red_threshold == 0.65
        weight_sum = config.alpha + config.beta + config.gamma + config.delta
        assert np.isclose(weight_sum, 1.0, atol=0.01)


class TestQsecbitSample:
    """Test QsecbitSample dataclass"""

    def test_sample_creation(self):
        """Test creating a QsecbitSample"""
        sample = QsecbitSample(
            timestamp=datetime.now(),
            score=0.65,
            components={'drift': 0.5, 'attack': 0.8},
            rag_status='AMBER',
            system_state=np.array([1.0, 2.0, 3.0])
        )

        assert sample.score == 0.65
        assert sample.rag_status == 'AMBER'
        assert len(sample.system_state) == 3

    def test_sample_to_dict(self):
        """Test serialization to dictionary"""
        timestamp = datetime(2025, 1, 1, 12, 0, 0)
        sample = QsecbitSample(
            timestamp=timestamp,
            score=0.65,
            components={'drift': 0.5},
            rag_status='AMBER',
            system_state=np.array([1.0, 2.0])
        )

        result = sample.to_dict()

        assert 'timestamp' in result
        assert result['score'] == 0.65
        assert result['rag_status'] == 'AMBER'
        assert isinstance(result['system_state'], list)


class TestQsecbit:
    """Test Qsecbit calculator"""

    @pytest.fixture
    def baseline_system(self):
        """Create baseline system state"""
        mu = np.array([0.0, 0.0, 0.0])
        cov = np.eye(3)
        q_anchor = 1.0
        return mu, cov, q_anchor

    @pytest.fixture
    def qsecbit_instance(self, baseline_system):
        """Create Qsecbit instance"""
        mu, cov, q_anchor = baseline_system
        return Qsecbit(mu, cov, q_anchor)

    def test_qsecbit_initialization(self, qsecbit_instance):
        """Test Qsecbit initialization"""
        assert qsecbit_instance is not None
        assert qsecbit_instance.config is not None
        assert hasattr(qsecbit_instance, 'mu')
        assert hasattr(qsecbit_instance, 'inv_cov')

    def test_drift_calculation_baseline(self, qsecbit_instance):
        """Test drift calculation at baseline"""
        x_t = np.array([0.0, 0.0, 0.0])  # At baseline
        drift = qsecbit_instance._drift(x_t)

        # At baseline, drift should be low
        assert 0.0 <= drift <= 1.0
        assert drift < 0.5

    def test_drift_calculation_anomaly(self, qsecbit_instance):
        """Test drift calculation with anomaly"""
        x_t = np.array([5.0, 5.0, 5.0])  # Far from baseline
        drift = qsecbit_instance._drift(x_t)

        # Far from baseline, drift should be high
        assert 0.0 <= drift <= 1.0
        assert drift > 0.5

    def test_drift_returns_float(self, qsecbit_instance):
        """Test that drift returns a float"""
        x_t = np.array([1.0, 1.0, 1.0])
        drift = qsecbit_instance._drift(x_t)

        assert isinstance(drift, float)

    def test_classifier_decay_first_call(self, qsecbit_instance):
        """Test classifier decay on first call"""
        c_t = np.array([0.5, 0.3, 0.2])
        decay = qsecbit_instance._classifier_decay(c_t, dt=1.0)

        # First call should return 0.0
        assert decay == 0.0

    def test_classifier_decay_subsequent_call(self, qsecbit_instance):
        """Test classifier decay on subsequent calls"""
        c_t1 = np.array([0.5, 0.3, 0.2])
        c_t2 = np.array([0.6, 0.25, 0.15])

        # First call
        qsecbit_instance._classifier_decay(c_t1, dt=1.0)

        # Second call should calculate decay
        decay = qsecbit_instance._classifier_decay(c_t2, dt=1.0)

        assert 0.0 <= decay <= 1.0
        assert isinstance(decay, float)

    def test_custom_config(self, baseline_system):
        """Test Qsecbit with custom configuration"""
        mu, cov, q_anchor = baseline_system
        config = QsecbitConfig(
            amber_threshold=0.40,
            red_threshold=0.60
        )

        qsecbit = Qsecbit(mu, cov, q_anchor, config=config)

        assert qsecbit.config.amber_threshold == 0.40
        assert qsecbit.config.red_threshold == 0.60

    def test_history_tracking(self, qsecbit_instance):
        """Test that history is tracked"""
        initial_len = len(qsecbit_instance.history)
        assert initial_len == 0

    def test_baseline_entropy_calculation(self, qsecbit_instance):
        """Test baseline entropy is calculated"""
        assert hasattr(qsecbit_instance, 'baseline_entropy')
        assert isinstance(qsecbit_instance.baseline_entropy, float)

    def test_inv_cov_precomputation(self, qsecbit_instance):
        """Test inverse covariance is precomputed"""
        assert hasattr(qsecbit_instance, 'inv_cov')
        assert qsecbit_instance.inv_cov.shape == (3, 3)


class TestQsecbitIntegration:
    """Integration tests for Qsecbit"""

    def test_normal_operation_scenario(self):
        """Test normal operation (GREEN status)"""
        # Setup baseline
        mu = np.array([10.0, 20.0, 30.0])
        cov = np.eye(3) * 2.0
        q_anchor = 1.5

        qsecbit = Qsecbit(mu, cov, q_anchor)

        # Test point close to baseline
        x_t = np.array([10.1, 20.1, 30.1])
        drift = qsecbit._drift(x_t)

        # Should indicate normal operation
        assert drift < qsecbit.config.amber_threshold

    def test_anomaly_scenario(self):
        """Test anomaly detection (AMBER/RED status)"""
        # Setup baseline
        mu = np.array([10.0, 20.0, 30.0])
        cov = np.eye(3) * 2.0
        q_anchor = 1.5

        qsecbit = Qsecbit(mu, cov, q_anchor)

        # Test point far from baseline
        x_t = np.array([50.0, 60.0, 70.0])
        drift = qsecbit._drift(x_t)

        # Should indicate anomaly
        assert drift > qsecbit.config.amber_threshold

    def test_different_baseline_sizes(self):
        """Test Qsecbit with different baseline dimensions"""
        for dim in [2, 5, 10]:
            mu = np.zeros(dim)
            cov = np.eye(dim)
            q_anchor = 1.0

            qsecbit = Qsecbit(mu, cov, q_anchor)

            x_t = np.ones(dim)
            drift = qsecbit._drift(x_t)

            assert 0.0 <= drift <= 1.0


class TestQsecbitEdgeCases:
    """Test edge cases and error handling"""

    def test_zero_covariance_handling(self):
        """Test handling of near-zero covariance"""
        mu = np.array([0.0, 0.0])
        cov = np.eye(2) * 0.0001  # Very small but not zero
        q_anchor = 1.0

        # Should not raise error
        qsecbit = Qsecbit(mu, cov, q_anchor)
        assert qsecbit is not None

    def test_large_drift_values(self):
        """Test with very large drift values"""
        mu = np.array([0.0, 0.0, 0.0])
        cov = np.eye(3)
        q_anchor = 1.0

        qsecbit = Qsecbit(mu, cov, q_anchor)

        # Test with very large values
        x_t = np.array([1000.0, 1000.0, 1000.0])
        drift = qsecbit._drift(x_t)

        # Should still be normalized to [0, 1]
        assert 0.0 <= drift <= 1.0

    def test_negative_values(self):
        """Test with negative values"""
        mu = np.array([0.0, 0.0, 0.0])
        cov = np.eye(3)
        q_anchor = 1.0

        qsecbit = Qsecbit(mu, cov, q_anchor)

        x_t = np.array([-5.0, -5.0, -5.0])
        drift = qsecbit._drift(x_t)

        assert 0.0 <= drift <= 1.0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
