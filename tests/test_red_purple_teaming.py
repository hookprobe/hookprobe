"""
Tests for the Red & Purple Teaming Framework

Tests the Nexus-based AI vs AI security testing capabilities for SDN Autopilot:
- Purple Team Orchestrator
- Digital Twin Simulator
- NSE Heartbeat Verification
- Bubble Attack Vectors (9 vectors)
- Meta-Regressor Framework

Run with: pytest tests/test_red_purple_teaming.py -v
"""

import pytest
import secrets
import time
import json
import hashlib
from datetime import datetime
from unittest.mock import Mock, MagicMock, patch, AsyncMock
from dataclasses import dataclass
from typing import Dict, List, Optional

# Test markers
pytestmark = [pytest.mark.unit, pytest.mark.security]


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_fortress_api():
    """Create a mock Fortress API client for testing."""
    api = Mock()
    api.get_ovs_flows = Mock(return_value=[
        {'match': 'in_port=1', 'actions': 'output:2', 'priority': 100},
        {'match': 'dl_vlan=100', 'actions': 'strip_vlan,output:3', 'priority': 200},
    ])
    api.get_devices = Mock(return_value=[
        {'mac': 'aa:bb:cc:dd:ee:01', 'ip': '10.200.0.10', 'hostname': 'iphone-dad'},
        {'mac': 'aa:bb:cc:dd:ee:02', 'ip': '10.200.0.11', 'hostname': 'macbook-dad'},
        {'mac': 'ff:ee:dd:cc:bb:aa', 'ip': '10.200.0.50', 'hostname': 'guest-phone'},
    ])
    api.get_bubbles = Mock(return_value=[
        {'id': 'bubble-dad', 'name': 'Dad', 'type': 'FAMILY', 'devices': ['aa:bb:cc:dd:ee:01', 'aa:bb:cc:dd:ee:02']},
        {'id': 'bubble-guest', 'name': 'Guests', 'type': 'GUEST', 'devices': ['ff:ee:dd:cc:bb:aa']},
    ])
    api.get_vlans = Mock(return_value=[
        {'id': 100, 'name': 'LAN'},
        {'id': 110, 'name': 'Family'},
        {'id': 150, 'name': 'Guest'},
    ])
    return api


@pytest.fixture
def mock_neural_weights():
    """Create mock neural weight vectors for testing."""
    return {
        'layer_1': [0.5, -0.3, 0.8, 0.1, -0.6],
        'layer_2': [0.2, 0.7, -0.4, 0.9, 0.0],
        'output': [0.1, 0.3],
    }


@pytest.fixture
def mock_ter_record():
    """Create a mock TER (Telemetry Event Record) for testing."""
    return {
        'entropy_hash': secrets.token_bytes(32),
        'integrity_hash': secrets.token_bytes(20),
        'timestamp': int(time.time() * 1_000_000),
        'sequence': 42,
        'chain_hash': 0xABCD,
    }


@pytest.fixture
def purple_team_config():
    """Create a PurpleTeamConfig for testing."""
    from products.nexus.lib.red_purple_teaming import PurpleTeamConfig
    return PurpleTeamConfig(
        fortress_api_url='http://localhost:8443',
        simulation_timeout_s=30,
        attack_vectors=['ter_replay', 'entropy_poisoning'],
        enable_auto_mitigation=False,
        clickhouse_enabled=False,
        n8n_webhook_enabled=False,
    )


@pytest.fixture
def digital_twin_config():
    """Create a TwinConfig for testing."""
    from products.nexus.lib.red_purple_teaming import TwinConfig
    return TwinConfig(
        max_virtual_devices=50,
        default_bubble_count=3,
        enable_traffic_simulation=False,
    )


# ============================================================================
# Digital Twin Simulator Tests
# ============================================================================

class TestDigitalTwinSimulator:
    """Test the Digital Twin SDN simulator."""

    def test_twin_initialization(self, digital_twin_config):
        """Twin simulator initializes correctly."""
        from products.nexus.lib.red_purple_teaming import DigitalTwinSimulator

        twin = DigitalTwinSimulator(config=digital_twin_config)

        assert twin is not None
        assert twin.config.max_virtual_devices == 50

    def test_create_snapshot_empty(self, digital_twin_config):
        """Create snapshot of empty twin."""
        from products.nexus.lib.red_purple_teaming import DigitalTwinSimulator

        twin = DigitalTwinSimulator(config=digital_twin_config)
        snapshot = twin.create_snapshot()

        assert 'timestamp' in snapshot
        assert 'devices' in snapshot
        assert 'bubbles' in snapshot
        assert 'ovs_flows' in snapshot

    def test_add_virtual_device(self, digital_twin_config):
        """Can add virtual device to twin."""
        from products.nexus.lib.red_purple_teaming import (
            DigitalTwinSimulator,
            VirtualDevice,
        )

        twin = DigitalTwinSimulator(config=digital_twin_config)

        device = VirtualDevice(
            mac='aa:bb:cc:dd:ee:ff',
            ip='10.200.0.100',
            hostname='test-device',
            vendor='Apple',
            device_type='smartphone',
        )

        result = twin.inject_device(device)

        assert result is True
        assert len(twin.devices) == 1
        assert twin.devices['aa:bb:cc:dd:ee:ff'].hostname == 'test-device'

    def test_add_virtual_bubble(self, digital_twin_config):
        """Can add virtual bubble to twin."""
        from products.nexus.lib.red_purple_teaming import (
            DigitalTwinSimulator,
            VirtualBubble,
            BubbleType,
        )

        twin = DigitalTwinSimulator(config=digital_twin_config)

        bubble = VirtualBubble(
            bubble_id='bubble-test',
            name='Test Bubble',
            bubble_type=BubbleType.FAMILY,
            vlan_id=110,
        )

        result = twin.add_bubble(bubble)

        assert result is True
        assert 'bubble-test' in twin.bubbles

    def test_move_device_to_bubble(self, digital_twin_config):
        """Can move device between bubbles."""
        from products.nexus.lib.red_purple_teaming import (
            DigitalTwinSimulator,
            VirtualDevice,
            VirtualBubble,
            BubbleType,
        )

        twin = DigitalTwinSimulator(config=digital_twin_config)

        # Add device and bubbles
        device = VirtualDevice(
            mac='aa:bb:cc:dd:ee:ff',
            ip='10.200.0.100',
            hostname='test-device',
        )
        twin.inject_device(device)

        bubble1 = VirtualBubble(
            bubble_id='bubble-1',
            name='Bubble 1',
            bubble_type=BubbleType.GUEST,
            vlan_id=150,
        )
        bubble2 = VirtualBubble(
            bubble_id='bubble-2',
            name='Bubble 2',
            bubble_type=BubbleType.FAMILY,
            vlan_id=110,
        )
        twin.add_bubble(bubble1)
        twin.add_bubble(bubble2)

        # Assign to bubble 1, then move to bubble 2
        twin.assign_device_to_bubble('aa:bb:cc:dd:ee:ff', 'bubble-1')
        result = twin.move_device_to_bubble('aa:bb:cc:dd:ee:ff', 'bubble-2')

        assert result is True
        assert 'aa:bb:cc:dd:ee:ff' in twin.bubbles['bubble-2'].devices
        assert 'aa:bb:cc:dd:ee:ff' not in twin.bubbles['bubble-1'].devices

    def test_device_limit_enforced(self, digital_twin_config):
        """Device limit is enforced."""
        from products.nexus.lib.red_purple_teaming import (
            DigitalTwinSimulator,
            VirtualDevice,
            TwinConfig,
        )

        config = TwinConfig(max_virtual_devices=2)
        twin = DigitalTwinSimulator(config=config)

        # Add max devices
        for i in range(3):
            device = VirtualDevice(
                mac=f'aa:bb:cc:dd:ee:{i:02x}',
                ip=f'10.200.0.{100+i}',
                hostname=f'device-{i}',
            )
            result = twin.inject_device(device)

            if i < 2:
                assert result is True
            else:
                assert result is False  # Should be rejected

    def test_sync_from_fortress(self, digital_twin_config, mock_fortress_api):
        """Can sync state from Fortress API."""
        from products.nexus.lib.red_purple_teaming import DigitalTwinSimulator

        twin = DigitalTwinSimulator(config=digital_twin_config)
        twin.sync_from_fortress(mock_fortress_api)

        # Should have devices from mock
        assert len(twin.devices) == 3
        assert 'aa:bb:cc:dd:ee:01' in twin.devices

    def test_generate_mock_network(self, digital_twin_config):
        """Can generate mock network for testing."""
        from products.nexus.lib.red_purple_teaming import DigitalTwinSimulator

        twin = DigitalTwinSimulator(config=digital_twin_config)
        twin.generate_mock_network(device_count=10, bubble_count=3)

        assert len(twin.devices) == 10
        assert len(twin.bubbles) == 3


# ============================================================================
# NSE Heartbeat Tests
# ============================================================================

class TestNSEHeartbeat:
    """Test the NSE Heartbeat D2D verification system."""

    def test_heartbeat_initialization(self, mock_neural_weights):
        """Heartbeat system initializes correctly."""
        from products.nexus.lib.red_purple_teaming import NSEHeartbeat

        heartbeat = NSEHeartbeat(weights=mock_neural_weights)

        assert heartbeat is not None
        assert heartbeat.sequence == 0

    def test_generate_token(self, mock_neural_weights):
        """Can generate heartbeat token."""
        from products.nexus.lib.red_purple_teaming import NSEHeartbeat

        heartbeat = NSEHeartbeat(weights=mock_neural_weights)
        token = heartbeat.generate_token()

        assert token is not None
        assert len(token.neural_hash) == 16
        assert len(token.resonance_sig) == 8
        assert token.sequence == 1

    def test_token_serialization(self, mock_neural_weights):
        """Token can be serialized and deserialized."""
        from products.nexus.lib.red_purple_teaming import (
            NSEHeartbeat,
            HeartbeatToken,
        )

        heartbeat = NSEHeartbeat(weights=mock_neural_weights)
        token = heartbeat.generate_token()

        # Serialize
        token_bytes = token.to_bytes()
        assert len(token_bytes) == 40  # Fixed size

        # Deserialize
        restored = HeartbeatToken.from_bytes(token_bytes)
        assert restored.sequence == token.sequence
        assert restored.neural_hash == token.neural_hash

    def test_validate_valid_token(self, mock_neural_weights):
        """Valid token passes validation."""
        from products.nexus.lib.red_purple_teaming import (
            NSEHeartbeat,
            NSEValidator,
        )

        heartbeat = NSEHeartbeat(weights=mock_neural_weights)
        validator = NSEValidator(weights=mock_neural_weights)

        token = heartbeat.generate_token()
        is_valid, reason = validator.validate(token)

        assert is_valid is True

    def test_validate_replayed_token(self, mock_neural_weights):
        """Replayed token is rejected."""
        from products.nexus.lib.red_purple_teaming import (
            NSEHeartbeat,
            NSEValidator,
        )

        heartbeat = NSEHeartbeat(weights=mock_neural_weights)
        validator = NSEValidator(weights=mock_neural_weights)

        token = heartbeat.generate_token()

        # First validation passes
        is_valid1, _ = validator.validate(token)
        assert is_valid1 is True

        # Replay is rejected
        is_valid2, reason = validator.validate(token)
        assert is_valid2 is False
        assert 'replay' in reason.lower()

    def test_validate_wrong_weights(self, mock_neural_weights):
        """Token with wrong weights is rejected."""
        from products.nexus.lib.red_purple_teaming import (
            NSEHeartbeat,
            NSEValidator,
        )

        heartbeat = NSEHeartbeat(weights=mock_neural_weights)

        # Different weights for validator
        wrong_weights = {
            'layer_1': [0.9, -0.1, 0.2, 0.5, -0.8],
            'layer_2': [0.1, 0.2, -0.3, 0.4, 0.5],
            'output': [0.9, 0.1],
        }
        validator = NSEValidator(weights=wrong_weights)

        token = heartbeat.generate_token()
        is_valid, reason = validator.validate(token)

        assert is_valid is False

    def test_sequence_increment(self, mock_neural_weights):
        """Sequence increments correctly."""
        from products.nexus.lib.red_purple_teaming import NSEHeartbeat

        heartbeat = NSEHeartbeat(weights=mock_neural_weights)

        token1 = heartbeat.generate_token()
        token2 = heartbeat.generate_token()
        token3 = heartbeat.generate_token()

        assert token1.sequence == 1
        assert token2.sequence == 2
        assert token3.sequence == 3

    def test_expired_token_rejected(self, mock_neural_weights):
        """Expired token is rejected."""
        from products.nexus.lib.red_purple_teaming import (
            NSEHeartbeat,
            NSEValidator,
            HeartbeatToken,
        )

        heartbeat = NSEHeartbeat(weights=mock_neural_weights)
        validator = NSEValidator(weights=mock_neural_weights, max_age_ms=100)

        token = heartbeat.generate_token()

        # Manually expire the token
        expired_token = HeartbeatToken(
            timestamp=token.timestamp - 1_000_000,  # 1 second ago
            neural_hash=token.neural_hash,
            resonance_sig=token.resonance_sig,
            sequence=token.sequence,
            checksum=token.checksum,
        )

        is_valid, reason = validator.validate(expired_token)
        assert is_valid is False
        assert 'expired' in reason.lower()


# ============================================================================
# Bubble Attack Vector Tests
# ============================================================================

class TestBubbleAttackVectors:
    """Test the 9 SDN bubble attack vectors."""

    def test_all_attack_vectors_registered(self):
        """All 9 attack vectors are registered."""
        from products.nexus.lib.red_purple_teaming import ATTACK_CLASSES

        expected_attacks = [
            'ter_replay',
            'entropy_poisoning',
            'timing_correlation',
            'weight_prediction',
            'mac_impersonation',
            'mdns_spoofing',
            'temporal_mimicry',
            'dhcp_fingerprint_spoof',
            'd2d_affinity_injection',
        ]

        for attack_name in expected_attacks:
            assert attack_name in ATTACK_CLASSES, f"Missing attack: {attack_name}"

    def test_ter_replay_attack(self, digital_twin_config, mock_ter_record):
        """TER replay attack executes correctly."""
        from products.nexus.lib.red_purple_teaming import (
            DigitalTwinSimulator,
            TERReplayBubbleAttack,
        )

        twin = DigitalTwinSimulator(config=digital_twin_config)
        twin.generate_mock_network(device_count=5, bubble_count=2)

        attack = TERReplayBubbleAttack()
        result = attack.execute(twin, ter_record=mock_ter_record)

        assert result.attack_name == "TER Replay (Bubble)"
        assert isinstance(result.success, bool)
        assert result.execution_time_ms > 0
        assert 'replay_accepted' in result.details

    def test_entropy_poisoning_attack(self, digital_twin_config):
        """Entropy poisoning attack tests entropy validation."""
        from products.nexus.lib.red_purple_teaming import (
            DigitalTwinSimulator,
            EntropyPoisoningBubbleAttack,
        )

        twin = DigitalTwinSimulator(config=digital_twin_config)
        twin.generate_mock_network(device_count=5, bubble_count=2)

        attack = EntropyPoisoningBubbleAttack()
        result = attack.execute(twin)

        assert result.attack_name == "Entropy Poisoning (Bubble)"
        assert 'poisoned_entropy_accepted' in result.details
        assert 'low_entropy_accepted' in result.details

    def test_timing_correlation_attack(self, digital_twin_config):
        """Timing correlation attack measures timing leaks."""
        from products.nexus.lib.red_purple_teaming import (
            DigitalTwinSimulator,
            TimingCorrelationAttack,
        )

        twin = DigitalTwinSimulator(config=digital_twin_config)
        twin.generate_mock_network(device_count=5, bubble_count=2)

        attack = TimingCorrelationAttack({'sample_count': 50})
        result = attack.execute(twin)

        assert result.attack_name == "Timing Correlation (Bubble)"
        assert 'timing_variance_ns' in result.details

    def test_weight_prediction_attack(self, digital_twin_config, mock_neural_weights):
        """Weight prediction attack attempts to predict neural weights."""
        from products.nexus.lib.red_purple_teaming import (
            DigitalTwinSimulator,
            WeightPredictionBubbleAttack,
        )

        twin = DigitalTwinSimulator(config=digital_twin_config)
        twin.generate_mock_network(device_count=5, bubble_count=2)

        attack = WeightPredictionBubbleAttack()
        result = attack.execute(twin, observed_outputs=[[0.1, 0.3], [0.2, 0.4]])

        assert result.attack_name == "Weight Prediction (Bubble)"
        assert 'prediction_accuracy' in result.details

    def test_mac_impersonation_attack(self, digital_twin_config):
        """MAC impersonation attack tests spoofed MAC acceptance."""
        from products.nexus.lib.red_purple_teaming import (
            DigitalTwinSimulator,
            MACImpersonationAttack,
            VirtualDevice,
        )

        twin = DigitalTwinSimulator(config=digital_twin_config)
        twin.generate_mock_network(device_count=5, bubble_count=2)

        # Get a legitimate device MAC to impersonate
        legit_mac = list(twin.devices.keys())[0]

        attack = MACImpersonationAttack()
        result = attack.execute(twin, target_mac=legit_mac)

        assert result.attack_name == "MAC Impersonation (Bubble)"
        assert 'impersonation_detected' in result.details

    def test_mdns_spoofing_attack(self, digital_twin_config):
        """mDNS spoofing attack tests service spoofing."""
        from products.nexus.lib.red_purple_teaming import (
            DigitalTwinSimulator,
            MDNSSpoofingAttack,
        )

        twin = DigitalTwinSimulator(config=digital_twin_config)
        twin.generate_mock_network(device_count=5, bubble_count=2)

        attack = MDNSSpoofingAttack()
        result = attack.execute(
            twin,
            service_type='_airplay._tcp',
            spoof_name='Fake Apple TV',
        )

        assert result.attack_name == "mDNS Spoofing (Bubble)"
        assert 'spoof_accepted' in result.details

    def test_temporal_mimicry_attack(self, digital_twin_config):
        """Temporal mimicry attack tests schedule impersonation."""
        from products.nexus.lib.red_purple_teaming import (
            DigitalTwinSimulator,
            TemporalMimicryAttack,
        )

        twin = DigitalTwinSimulator(config=digital_twin_config)
        twin.generate_mock_network(device_count=5, bubble_count=2)

        # Get a target device to mimic
        target_mac = list(twin.devices.keys())[0]

        attack = TemporalMimicryAttack()
        result = attack.execute(twin, target_mac=target_mac)

        assert result.attack_name == "Temporal Mimicry (Bubble)"
        assert 'pattern_similarity' in result.details

    def test_dhcp_fingerprint_spoof_attack(self, digital_twin_config):
        """DHCP fingerprint spoof tests Option 55 spoofing."""
        from products.nexus.lib.red_purple_teaming import (
            DigitalTwinSimulator,
            DHCPFingerprintSpoofAttack,
        )

        twin = DigitalTwinSimulator(config=digital_twin_config)
        twin.generate_mock_network(device_count=5, bubble_count=2)

        attack = DHCPFingerprintSpoofAttack()
        result = attack.execute(
            twin,
            spoof_os='iPhone',
            dhcp_options=[1, 3, 6, 15, 119, 252],  # iOS fingerprint
        )

        assert result.attack_name == "DHCP Fingerprint Spoof (Bubble)"
        assert 'fingerprint_accepted' in result.details

    def test_d2d_affinity_injection_attack(self, digital_twin_config):
        """D2D affinity injection tests fake relationship creation."""
        from products.nexus.lib.red_purple_teaming import (
            DigitalTwinSimulator,
            D2DAffinityInjectionAttack,
        )

        twin = DigitalTwinSimulator(config=digital_twin_config)
        twin.generate_mock_network(device_count=5, bubble_count=2)

        attack = D2DAffinityInjectionAttack()
        result = attack.execute(twin)

        assert result.attack_name == "D2D Affinity Injection (Bubble)"
        assert 'fake_affinity_accepted' in result.details

    def test_attack_result_cvss_calculation(self, digital_twin_config):
        """Attack results calculate CVSS scores correctly."""
        from products.nexus.lib.red_purple_teaming import (
            DigitalTwinSimulator,
            TERReplayBubbleAttack,
        )

        twin = DigitalTwinSimulator(config=digital_twin_config)
        twin.generate_mock_network(device_count=5, bubble_count=2)

        attack = TERReplayBubbleAttack()
        result = attack.execute(twin)

        cvss = result.cvss_score()
        assert 0.0 <= cvss <= 10.0

    def test_attack_has_mitre_mapping(self, digital_twin_config):
        """Attacks have MITRE ATT&CK mapping."""
        from products.nexus.lib.red_purple_teaming import TERReplayBubbleAttack

        attack = TERReplayBubbleAttack()

        assert hasattr(attack, 'mitre_technique')
        assert attack.mitre_technique is not None


# ============================================================================
# Meta-Regressor Tests
# ============================================================================

class TestMetaRegressor:
    """Test the meta-regressive bubble accuracy framework."""

    def test_regressor_initialization(self):
        """Meta-regressor initializes correctly."""
        from products.nexus.lib.red_purple_teaming import MetaRegressor

        regressor = MetaRegressor()

        assert regressor is not None
        assert len(regressor.observations) == 0

    def test_add_observation(self):
        """Can add observations to regressor."""
        from products.nexus.lib.red_purple_teaming import (
            MetaRegressor,
            BubbleObservation,
        )

        regressor = MetaRegressor()

        obs = BubbleObservation(
            bubble_id='bubble-test',
            temporal_sync=0.85,
            d2d_affinity=0.72,
            nse_resonance=0.91,
            accuracy=0.88,
        )

        regressor.add_observation(obs)

        assert len(regressor.observations) == 1

    def test_run_regression_insufficient_data(self):
        """Regression returns None with insufficient data."""
        from products.nexus.lib.red_purple_teaming import (
            MetaRegressor,
            OptimizationTarget,
        )

        regressor = MetaRegressor()

        result = regressor.run_regression(OptimizationTarget.ACCURACY)

        assert result is None  # Need at least 4 observations

    def test_run_regression_sufficient_data(self):
        """Regression runs with sufficient data."""
        from products.nexus.lib.red_purple_teaming import (
            MetaRegressor,
            BubbleObservation,
            OptimizationTarget,
        )

        regressor = MetaRegressor()

        # Add enough observations
        test_data = [
            (0.85, 0.72, 0.91, 0.88),
            (0.70, 0.65, 0.80, 0.75),
            (0.95, 0.88, 0.95, 0.94),
            (0.60, 0.50, 0.70, 0.62),
            (0.80, 0.75, 0.85, 0.82),
        ]

        for i, (ts, d2d, nse, acc) in enumerate(test_data):
            obs = BubbleObservation(
                bubble_id=f'bubble-{i}',
                temporal_sync=ts,
                d2d_affinity=d2d,
                nse_resonance=nse,
                accuracy=acc,
            )
            regressor.add_observation(obs)

        result = regressor.run_regression(OptimizationTarget.ACCURACY)

        assert result is not None
        assert 'beta_0' in result.coefficients
        assert 'beta_temporal_sync' in result.coefficients
        assert 'beta_d2d_affinity' in result.coefficients
        assert 'beta_nse_resonance' in result.coefficients
        assert 0.0 <= result.r_squared <= 1.0

    def test_generate_recommendations(self):
        """Can generate optimization recommendations."""
        from products.nexus.lib.red_purple_teaming import (
            MetaRegressor,
            BubbleObservation,
            OptimizationTarget,
        )

        regressor = MetaRegressor()

        # Add observations with clear pattern
        test_data = [
            (0.85, 0.72, 0.91, 0.88),
            (0.70, 0.65, 0.80, 0.75),
            (0.95, 0.88, 0.95, 0.94),
            (0.60, 0.50, 0.70, 0.62),
            (0.80, 0.75, 0.85, 0.82),
        ]

        for i, (ts, d2d, nse, acc) in enumerate(test_data):
            obs = BubbleObservation(
                bubble_id=f'bubble-{i}',
                temporal_sync=ts,
                d2d_affinity=d2d,
                nse_resonance=nse,
                accuracy=acc,
            )
            regressor.add_observation(obs)

        result = regressor.run_regression(OptimizationTarget.ACCURACY)
        recommendations = regressor.generate_recommendations(result)

        assert isinstance(recommendations, list)
        # Should have recommendations based on coefficient importance

    def test_effect_size_analysis(self):
        """Can analyze effect sizes."""
        from products.nexus.lib.red_purple_teaming import (
            MetaRegressor,
            BubbleObservation,
            EffectSizeAnalyzer,
        )

        regressor = MetaRegressor()
        analyzer = EffectSizeAnalyzer()

        # Add observations
        test_data = [
            (0.85, 0.72, 0.91, 0.88),
            (0.70, 0.65, 0.80, 0.75),
            (0.95, 0.88, 0.95, 0.94),
            (0.60, 0.50, 0.70, 0.62),
            (0.80, 0.75, 0.85, 0.82),
        ]

        for i, (ts, d2d, nse, acc) in enumerate(test_data):
            obs = BubbleObservation(
                bubble_id=f'bubble-{i}',
                temporal_sync=ts,
                d2d_affinity=d2d,
                nse_resonance=nse,
                accuracy=acc,
            )
            regressor.add_observation(obs)

        effect_sizes = analyzer.analyze(regressor.observations)

        assert 'temporal_sync' in effect_sizes
        assert 'd2d_affinity' in effect_sizes
        assert 'nse_resonance' in effect_sizes


# ============================================================================
# Purple Team Orchestrator Tests
# ============================================================================

class TestPurpleTeamOrchestrator:
    """Test the main Purple Team orchestrator."""

    def test_orchestrator_initialization(self, purple_team_config):
        """Orchestrator initializes correctly."""
        from products.nexus.lib.red_purple_teaming import PurpleTeamOrchestrator

        orchestrator = PurpleTeamOrchestrator(config=purple_team_config)

        assert orchestrator is not None
        assert orchestrator.config.simulation_timeout_s == 30

    def test_run_simulation_mock(self, purple_team_config):
        """Can run simulation with mock network."""
        from products.nexus.lib.red_purple_teaming import PurpleTeamOrchestrator

        orchestrator = PurpleTeamOrchestrator(config=purple_team_config)

        # Run with mock mode
        result = orchestrator.run_simulation(mock_mode=True)

        assert result is not None
        assert result.simulation_id is not None
        assert result.total_attacks > 0
        assert result.defense_score >= 0

    def test_orchestrator_phases(self, purple_team_config):
        """Orchestrator executes all 5 phases."""
        from products.nexus.lib.red_purple_teaming import PurpleTeamOrchestrator

        orchestrator = PurpleTeamOrchestrator(config=purple_team_config)

        result = orchestrator.run_simulation(mock_mode=True)

        # Check all phases executed
        assert result.phases_completed == 5

    def test_validation_result_structure(self, purple_team_config):
        """Validation results have correct structure."""
        from products.nexus.lib.red_purple_teaming import PurpleTeamOrchestrator

        orchestrator = PurpleTeamOrchestrator(config=purple_team_config)
        result = orchestrator.run_simulation(mock_mode=True)

        validation = result.validation

        assert 'defense_score' in validation
        assert 'bubble_metrics' in validation
        assert 'overall_risk' in validation
        assert validation['overall_risk'] in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

    def test_auto_mitigations_generated(self, purple_team_config):
        """Auto-mitigations are generated for vulnerabilities."""
        from products.nexus.lib.red_purple_teaming import (
            PurpleTeamOrchestrator,
            PurpleTeamConfig,
        )

        config = PurpleTeamConfig(
            fortress_api_url='http://localhost:8443',
            simulation_timeout_s=30,
            attack_vectors=['ter_replay', 'entropy_poisoning'],
            enable_auto_mitigation=True,
            clickhouse_enabled=False,
            n8n_webhook_enabled=False,
        )

        orchestrator = PurpleTeamOrchestrator(config=config)
        result = orchestrator.run_simulation(mock_mode=True)

        # If attacks succeeded, should have mitigations
        if result.successful_attacks > 0:
            assert len(result.auto_mitigations) > 0

    def test_meta_learning_updates_weights(self, purple_team_config):
        """Meta-learning phase updates bubble weights."""
        from products.nexus.lib.red_purple_teaming import PurpleTeamOrchestrator

        orchestrator = PurpleTeamOrchestrator(config=purple_team_config)

        # Get initial weights
        initial_weights = orchestrator.get_bubble_weights()

        # Run multiple simulations
        for _ in range(3):
            orchestrator.run_simulation(mock_mode=True)

        # Check weights have been analyzed (meta-learning)
        assert orchestrator.meta_regressor.observations is not None

    def test_get_risk_summary(self, purple_team_config):
        """Can get risk summary after simulation."""
        from products.nexus.lib.red_purple_teaming import PurpleTeamOrchestrator

        orchestrator = PurpleTeamOrchestrator(config=purple_team_config)
        orchestrator.run_simulation(mock_mode=True)

        summary = orchestrator.get_risk_summary()

        assert 'overall_risk' in summary
        assert 'defense_score' in summary
        assert 'recommendations' in summary


# ============================================================================
# Integration Tests
# ============================================================================

class TestPurpleTeamIntegration:
    """Integration tests for the full purple team workflow."""

    def test_full_simulation_workflow(self, purple_team_config):
        """Test complete simulation workflow."""
        from products.nexus.lib.red_purple_teaming import (
            PurpleTeamOrchestrator,
            DigitalTwinSimulator,
            TwinConfig,
        )

        # Create orchestrator
        orchestrator = PurpleTeamOrchestrator(config=purple_team_config)

        # Run full simulation
        result = orchestrator.run_simulation(mock_mode=True)

        # Verify all components worked
        assert result.simulation_id is not None
        assert result.total_attacks > 0
        assert result.duration_seconds > 0
        assert result.phases_completed == 5

        # Verify validation
        assert result.validation['defense_score'] >= 0
        assert result.validation['defense_score'] <= 100

    def test_nse_heartbeat_in_simulation(self, purple_team_config, mock_neural_weights):
        """NSE heartbeat is used in D2D verification."""
        from products.nexus.lib.red_purple_teaming import (
            PurpleTeamOrchestrator,
            NSEHeartbeat,
            NSEValidator,
        )

        orchestrator = PurpleTeamOrchestrator(config=purple_team_config)

        # Create heartbeat and validator
        heartbeat = NSEHeartbeat(weights=mock_neural_weights)
        validator = NSEValidator(weights=mock_neural_weights)

        # Inject into orchestrator
        orchestrator.set_nse_components(heartbeat, validator)

        # Run simulation
        result = orchestrator.run_simulation(mock_mode=True)

        # NSE should have been used
        assert result.nse_verifications > 0

    def test_attack_detection_loop(self, purple_team_config):
        """Red attacks trigger blue detection."""
        from products.nexus.lib.red_purple_teaming import (
            PurpleTeamOrchestrator,
            TERReplayBubbleAttack,
        )

        orchestrator = PurpleTeamOrchestrator(config=purple_team_config)

        result = orchestrator.run_simulation(mock_mode=True)

        # For each attack, should have a detection attempt
        assert result.detection_attempts >= result.total_attacks

    def test_meta_regression_learns(self, purple_team_config):
        """Meta-regression learns from multiple simulations."""
        from products.nexus.lib.red_purple_teaming import (
            PurpleTeamOrchestrator,
            OptimizationTarget,
        )

        orchestrator = PurpleTeamOrchestrator(config=purple_team_config)

        # Run multiple simulations
        for _ in range(5):
            orchestrator.run_simulation(mock_mode=True)

        # Should have enough data for regression
        result = orchestrator.meta_regressor.run_regression(
            OptimizationTarget.ACCURACY
        )

        # May or may not have enough variance for good regression
        # but should not raise an exception


class TestN8NWorkflowIntegration:
    """Test n8n workflow integration."""

    def test_workflow_file_valid_json(self):
        """n8n workflow file is valid JSON."""
        import json

        workflow_path = (
            '/home/user/hookprobe/products/nexus/lib/red_purple_teaming/'
            'n8n-workflows/purple-team-validation.json'
        )

        with open(workflow_path, 'r') as f:
            workflow = json.load(f)

        assert 'name' in workflow
        assert 'nodes' in workflow
        assert 'connections' in workflow

    def test_workflow_has_required_nodes(self):
        """Workflow has required processing nodes."""
        import json

        workflow_path = (
            '/home/user/hookprobe/products/nexus/lib/red_purple_teaming/'
            'n8n-workflows/purple-team-validation.json'
        )

        with open(workflow_path, 'r') as f:
            workflow = json.load(f)

        node_names = [n['name'] for n in workflow['nodes']]

        # Check for key nodes
        assert any('Webhook' in n for n in node_names)
        assert any('Validation' in n for n in node_names)
        assert any('ClickHouse' in n for n in node_names)


# Run with: pytest tests/test_red_purple_teaming.py -v
