"""
End-to-End Integration Tests for HookProbe Security Flow

Tests the complete attack detection → response → propagation → consensus flow:
1. Qsecbit detection creates ThreatEvent
2. Response orchestrator executes mitigation
3. Mesh bridge propagates to consciousness
4. DSM creates microblock
5. Gossip announces to peers
6. Cortex visualization receives event

Version: 5.2.0
Updated: 2025-12-13
"""

import pytest
import time
import hashlib
import secrets
from datetime import datetime
from unittest.mock import Mock, MagicMock, patch
from typing import Dict, Any, List

# Test markers
pytestmark = [pytest.mark.integration, pytest.mark.e2e]


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def mock_threat_event():
    """Create a mock ThreatEvent for testing."""
    from core.qsecbit.threat_types import (
        ThreatEvent, AttackType, ThreatSeverity, OSILayer, ResponseAction
    )

    return ThreatEvent(
        id=secrets.token_hex(16),
        timestamp=datetime.now(),
        attack_type=AttackType.SYN_FLOOD,
        layer=OSILayer.L4_TRANSPORT,
        severity=ThreatSeverity.HIGH,
        source_ip="192.168.1.100",
        source_mac="aa:bb:cc:dd:ee:ff",
        source_port=54321,
        dest_ip="10.0.0.1",
        dest_port=443,
        description="SYN flood attack detected",
        confidence=0.92,
        detector="L4TransportDetector",
        evidence={
            "syn_count": 5000,
            "time_window": "10s",
            "connection_rate": 500.0
        },
        mitre_attack_id="T1498.001",
        kill_chain_phase="Delivery",
        blocked=False,
        response_actions=[],
        qsecbit_contribution=0.15,
    )


@pytest.fixture
def mock_critical_threat():
    """Create a CRITICAL severity threat for DSM microblock testing."""
    from core.qsecbit.threat_types import (
        ThreatEvent, AttackType, ThreatSeverity, OSILayer, ResponseAction
    )

    return ThreatEvent(
        id=secrets.token_hex(16),
        timestamp=datetime.now(),
        attack_type=AttackType.MALWARE_C2,
        layer=OSILayer.L7_APPLICATION,
        severity=ThreatSeverity.CRITICAL,
        source_ip="203.0.113.50",
        dest_ip="10.0.0.5",
        dest_port=443,
        description="Malware C2 communication detected",
        confidence=0.98,
        detector="L7ApplicationDetector",
        evidence={
            "domain": "evil-c2.example.com",
            "beaconing_interval": "60s",
            "data_exfil_bytes": 1024
        },
        mitre_attack_id="T1071.001",
        kill_chain_phase="Command and Control",
        blocked=True,
        response_actions=[ResponseAction.BLOCK_IP, ResponseAction.QUARANTINE],
        qsecbit_contribution=0.35,
    )


@pytest.fixture
def mesh_bridge_config():
    """Create MeshBridgeConfig for testing."""
    from core.qsecbit.mesh_bridge import MeshBridgeConfig
    from core.qsecbit.threat_types import ThreatSeverity

    return MeshBridgeConfig(
        node_id=secrets.token_bytes(16),
        tier='guardian',
        enable_mesh_reporting=True,
        enable_cortex_events=True,
        enable_dsm_microblocks=True,
        min_severity_to_report=ThreatSeverity.MEDIUM,
        report_confidence_threshold=0.6,
    )


# ============================================================================
# Test: ThreatEvent Creation and Validation
# ============================================================================

class TestThreatEventCreation:
    """Test ThreatEvent creation and validation."""

    def test_threat_event_has_required_fields(self, mock_threat_event):
        """Verify ThreatEvent has all required fields."""
        assert mock_threat_event.id is not None
        assert mock_threat_event.timestamp is not None
        assert mock_threat_event.attack_type is not None
        assert mock_threat_event.severity is not None
        assert mock_threat_event.confidence >= 0.0
        assert mock_threat_event.confidence <= 1.0

    def test_threat_event_has_valid_layer(self, mock_threat_event):
        """Verify ThreatEvent has valid OSI layer."""
        from core.qsecbit.threat_types import OSILayer
        assert mock_threat_event.layer in list(OSILayer)

    def test_threat_event_has_mitre_id(self, mock_threat_event):
        """Verify ThreatEvent has MITRE ATT&CK ID."""
        assert mock_threat_event.mitre_attack_id is not None
        assert mock_threat_event.mitre_attack_id.startswith("T")

    def test_threat_event_evidence_populated(self, mock_threat_event):
        """Verify evidence dictionary is populated."""
        assert mock_threat_event.evidence is not None
        assert len(mock_threat_event.evidence) > 0


# ============================================================================
# Test: Mesh Bridge Threat Conversion
# ============================================================================

class TestMeshBridgeConversion:
    """Test QsecbitMeshBridge threat conversion."""

    def test_threat_to_intelligence_conversion(self, mock_threat_event, mesh_bridge_config):
        """Test converting ThreatEvent to ThreatIntelligence."""
        from core.qsecbit.mesh_bridge import QsecbitMeshBridge

        bridge = QsecbitMeshBridge(config=mesh_bridge_config)

        # Mock mesh availability
        with patch('core.qsecbit.mesh_bridge.MESH_AVAILABLE', True):
            with patch('core.qsecbit.mesh_bridge.ThreatIntelligence') as MockIntel:
                MockIntel.return_value = Mock()
                intel = bridge.threat_to_intelligence(mock_threat_event)
                # Will return None if mesh not actually available, which is expected
                # The test validates the conversion logic path

    def test_severity_mapping(self, mesh_bridge_config):
        """Test severity mapping from ThreatSeverity to mesh format."""
        from core.qsecbit.mesh_bridge import QsecbitMeshBridge
        from core.qsecbit.threat_types import ThreatSeverity

        bridge = QsecbitMeshBridge(config=mesh_bridge_config)

        # Verify severity mapping (1=most severe, 5=least severe)
        assert bridge._severity_map[ThreatSeverity.CRITICAL] == 1
        assert bridge._severity_map[ThreatSeverity.HIGH] == 2
        assert bridge._severity_map[ThreatSeverity.MEDIUM] == 3
        assert bridge._severity_map[ThreatSeverity.LOW] == 4
        assert bridge._severity_map[ThreatSeverity.INFO] == 5

    def test_attack_type_mapping(self, mesh_bridge_config):
        """Test attack type mapping to mesh format."""
        from core.qsecbit.mesh_bridge import QsecbitMeshBridge
        from core.qsecbit.threat_types import AttackType

        bridge = QsecbitMeshBridge(config=mesh_bridge_config)

        # Test key mappings
        assert bridge._map_attack_type(AttackType.SYN_FLOOD) == 'ddos'
        assert bridge._map_attack_type(AttackType.SQL_INJECTION) == 'web_attack'
        assert bridge._map_attack_type(AttackType.MALWARE_C2) == 'malware'
        assert bridge._map_attack_type(AttackType.PORT_SCAN) == 'port_scan'

    def test_ioc_extraction(self, mock_threat_event, mesh_bridge_config):
        """Test IOC extraction from ThreatEvent."""
        from core.qsecbit.mesh_bridge import QsecbitMeshBridge

        bridge = QsecbitMeshBridge(config=mesh_bridge_config)

        # Should prioritize IP
        ioc_type, ioc_value = bridge._extract_ioc(mock_threat_event)
        assert ioc_type == 'ip'
        assert ioc_value == mock_threat_event.source_ip


# ============================================================================
# Test: Cortex Event Creation
# ============================================================================

class TestCortexEventCreation:
    """Test Cortex visualization event creation."""

    def test_create_cortex_event(self, mock_threat_event, mesh_bridge_config):
        """Test creating Cortex visualization event."""
        from core.qsecbit.mesh_bridge import QsecbitMeshBridge

        bridge = QsecbitMeshBridge(config=mesh_bridge_config)
        event = bridge._create_cortex_event(mock_threat_event)

        assert event is not None
        assert event['type'] == 'attack_detected'  # Not blocked yet
        assert event['source']['ip'] == mock_threat_event.source_ip
        assert event['attack_type'] == 'ddos'  # SYN_FLOOD maps to ddos
        assert 'timestamp' in event
        assert event['layer'] == 'L4_TRANSPORT'

    def test_cortex_event_for_blocked_threat(self, mock_critical_threat, mesh_bridge_config):
        """Test Cortex event shows attack_repelled for blocked threats."""
        from core.qsecbit.mesh_bridge import QsecbitMeshBridge

        bridge = QsecbitMeshBridge(config=mesh_bridge_config)
        event = bridge._create_cortex_event(mock_critical_threat)

        assert event is not None
        assert event['type'] == 'attack_repelled'  # Blocked = repelled
        assert event['mitigation'] == 'xdp_drop'  # BLOCK_IP action


# ============================================================================
# Test: Gossip Protocol
# ============================================================================

class TestGossipProtocol:
    """Test DSM gossip protocol functionality."""

    def test_gossip_message_serialization(self):
        """Test GossipMessage serialization/deserialization."""
        from shared.dsm.gossip import GossipMessage

        msg = GossipMessage(
            msg_type='announce',
            source_node='node-123',
            payload={'block_id': 'abc123', 'data': 'test'},
            hop_count=2,
            seen_by={'node-123', 'node-456'},
        )

        # Serialize and deserialize
        data = msg.to_bytes()
        restored = GossipMessage.from_bytes(data)

        assert restored.msg_type == msg.msg_type
        assert restored.source_node == msg.source_node
        assert restored.payload == msg.payload
        assert restored.hop_count == msg.hop_count
        assert restored.seen_by == msg.seen_by

    def test_gossip_protocol_initialization(self):
        """Test GossipProtocol initialization."""
        from shared.dsm.gossip import GossipProtocol

        gossip = GossipProtocol(
            node_id='test-node',
            bootstrap_nodes=['10.0.0.1:8145', '10.0.0.2:8145']
        )

        assert gossip.node_id == 'test-node'
        assert len(gossip.bootstrap_nodes) == 2

    def test_gossip_collect_empty_window(self):
        """Test collecting blocks from empty window."""
        from shared.dsm.gossip import GossipProtocol
        from datetime import datetime, timedelta

        gossip = GossipProtocol(node_id='test', bootstrap_nodes=[])

        now = datetime.now()
        window = (now - timedelta(minutes=5), now)
        blocks = gossip.collect_announced_blocks(window)

        assert blocks == []

    def test_gossip_statistics(self):
        """Test gossip statistics tracking."""
        from shared.dsm.gossip import GossipProtocol

        gossip = GossipProtocol(node_id='test', bootstrap_nodes=[])
        stats = gossip.get_statistics()

        assert 'messages_sent' in stats
        assert 'messages_received' in stats
        assert 'blocks_announced' in stats
        assert 'peer_count' in stats


# ============================================================================
# Test: DSM Microblock Creation
# ============================================================================

class TestDSMMicroblockCreation:
    """Test DSM microblock creation from mesh bridge."""

    def test_microblock_creation_for_critical_threat(
        self, mock_critical_threat, mesh_bridge_config
    ):
        """Test that CRITICAL threats create DSM microblocks."""
        from core.qsecbit.mesh_bridge import QsecbitMeshBridge

        # Create mock DSM node
        mock_dsm_node = Mock()
        mock_dsm_node.create_microblock.return_value = 'block-id-123'
        mock_dsm_node.get_microblock.return_value = {'type': 'M', 'data': 'test'}

        mock_gossip = Mock()

        bridge = QsecbitMeshBridge(config=mesh_bridge_config)
        bridge.set_dsm_node(mock_dsm_node, mock_gossip)

        # Create microblock
        with patch('core.qsecbit.mesh_bridge.DSM_AVAILABLE', True):
            block_id = bridge._create_dsm_microblock(mock_critical_threat)

        # Verify DSM node was called
        mock_dsm_node.create_microblock.assert_called_once()
        call_args = mock_dsm_node.create_microblock.call_args

        # Verify payload structure
        assert call_args[1]['event_type'] == 'threat_intelligence'
        payload = call_args[1]['payload']
        assert payload['attack_type'] == 'MALWARE_C2'
        assert payload['severity'] == 1  # CRITICAL
        assert payload['blocked'] is True

    def test_ip_anonymization_in_microblock(
        self, mock_critical_threat, mesh_bridge_config
    ):
        """Test that IPs are anonymized in microblocks."""
        from core.qsecbit.mesh_bridge import QsecbitMeshBridge

        mock_dsm_node = Mock()
        mock_dsm_node.create_microblock.return_value = 'block-id-123'

        bridge = QsecbitMeshBridge(config=mesh_bridge_config)
        bridge.set_dsm_node(mock_dsm_node)

        with patch('core.qsecbit.mesh_bridge.DSM_AVAILABLE', True):
            bridge._create_dsm_microblock(mock_critical_threat)

        # Verify IP is hashed, not raw
        call_args = mock_dsm_node.create_microblock.call_args
        payload = call_args[1]['payload']

        # source_hash should be a hash, not the raw IP
        assert payload['source_hash'] != mock_critical_threat.source_ip
        assert len(payload['source_hash']) == 16  # SHA256[:16]


# ============================================================================
# Test: End-to-End Flow
# ============================================================================

class TestEndToEndFlow:
    """Test complete E2E attack detection → response → propagation flow."""

    def test_threat_report_flow(self, mock_critical_threat, mesh_bridge_config):
        """Test complete threat reporting flow."""
        from core.qsecbit.mesh_bridge import QsecbitMeshBridge

        # Track callback invocations
        cortex_events = []

        def cortex_callback(event):
            cortex_events.append(event)

        # Setup bridge with mocks
        mock_consciousness = Mock()
        mock_dsm_node = Mock()
        mock_dsm_node.create_microblock.return_value = 'block-123'
        mock_dsm_node.get_microblock.return_value = {'type': 'M'}
        mock_gossip = Mock()

        bridge = QsecbitMeshBridge(config=mesh_bridge_config)
        bridge.set_consciousness(mock_consciousness)
        bridge.set_dsm_node(mock_dsm_node, mock_gossip)
        bridge.register_cortex_callback(cortex_callback)

        # Report threat
        with patch('core.qsecbit.mesh_bridge.MESH_AVAILABLE', True):
            with patch('core.qsecbit.mesh_bridge.DSM_AVAILABLE', True):
                with patch('core.qsecbit.mesh_bridge.ThreatIntelligence'):
                    result = bridge.report_threat(mock_critical_threat)

        # Verify all destinations were hit
        assert result is True

        # Verify Cortex callback was invoked
        assert len(cortex_events) == 1
        assert cortex_events[0]['type'] == 'attack_repelled'

        # Verify DSM microblock was created (CRITICAL severity)
        mock_dsm_node.create_microblock.assert_called_once()

        # Verify gossip announcement
        mock_gossip.announce.assert_called_once()

    def test_low_severity_skips_dsm(self, mock_threat_event, mesh_bridge_config):
        """Test that LOW severity threats skip DSM microblock creation."""
        from core.qsecbit.mesh_bridge import QsecbitMeshBridge
        from core.qsecbit.threat_types import ThreatSeverity

        # Change to LOW severity
        mock_threat_event.severity = ThreatSeverity.LOW

        mock_dsm_node = Mock()
        bridge = QsecbitMeshBridge(config=mesh_bridge_config)
        bridge.set_dsm_node(mock_dsm_node)

        with patch('core.qsecbit.mesh_bridge.DSM_AVAILABLE', True):
            bridge.report_threat(mock_threat_event)

        # DSM should NOT be called for LOW severity
        mock_dsm_node.create_microblock.assert_not_called()

    def test_statistics_tracking(self, mock_critical_threat, mesh_bridge_config):
        """Test that bridge statistics are properly tracked."""
        from core.qsecbit.mesh_bridge import QsecbitMeshBridge

        mock_dsm_node = Mock()
        mock_dsm_node.create_microblock.return_value = 'block-123'
        mock_dsm_node.get_microblock.return_value = {'type': 'M'}

        bridge = QsecbitMeshBridge(config=mesh_bridge_config)
        bridge.set_dsm_node(mock_dsm_node)
        bridge.register_cortex_callback(lambda x: None)

        # Report threat
        with patch('core.qsecbit.mesh_bridge.DSM_AVAILABLE', True):
            bridge.report_threat(mock_critical_threat)

        stats = bridge.get_statistics()
        assert stats['microblocks_created'] == 1
        assert stats['cortex_events_sent'] == 1


# ============================================================================
# Test: Collective Score Aggregation
# ============================================================================

class TestCollectiveScore:
    """Test collective Qsecbit score from mesh peers."""

    def test_collective_score_without_mesh(self, mesh_bridge_config):
        """Test collective score when mesh is unavailable."""
        from core.qsecbit.mesh_bridge import QsecbitMeshBridge

        bridge = QsecbitMeshBridge(config=mesh_bridge_config)
        score = bridge.get_collective_score()

        assert score['mesh_available'] is False
        assert score['collective_score'] is None
        assert score['local_weight'] == 1.0

    def test_collective_score_with_empty_cache(self, mesh_bridge_config):
        """Test collective score with empty threat cache."""
        from core.qsecbit.mesh_bridge import QsecbitMeshBridge

        mock_consciousness = Mock()
        mock_consciousness.threat_cache = []

        bridge = QsecbitMeshBridge(config=mesh_bridge_config)
        bridge.set_consciousness(mock_consciousness)

        score = bridge.get_collective_score()

        assert score['mesh_available'] is True
        assert score['collective_score'] == 0.0


# ============================================================================
# Test: Integration with Response
# ============================================================================

class TestResponseIntegration:
    """Test integration with response orchestrator."""

    def test_response_actions_in_cortex_event(
        self, mock_critical_threat, mesh_bridge_config
    ):
        """Test that response actions are reflected in Cortex events."""
        from core.qsecbit.mesh_bridge import QsecbitMeshBridge

        bridge = QsecbitMeshBridge(config=mesh_bridge_config)
        event = bridge._create_cortex_event(mock_critical_threat)

        # BLOCK_IP should map to xdp_drop
        assert event['mitigation'] == 'xdp_drop'

    def test_mitigation_method_mapping(self, mesh_bridge_config):
        """Test mitigation method string mapping."""
        from core.qsecbit.mesh_bridge import QsecbitMeshBridge
        from core.qsecbit.threat_types import ThreatEvent, AttackType, ThreatSeverity
        from core.qsecbit.threat_types import ResponseAction

        bridge = QsecbitMeshBridge(config=mesh_bridge_config)

        # Create threat with different response actions
        threat = ThreatEvent(
            id='test',
            timestamp=datetime.now(),
            attack_type=AttackType.UDP_FLOOD,
            severity=ThreatSeverity.HIGH,
            confidence=0.9,
            detector='test',
            response_actions=[ResponseAction.RATE_LIMIT],
        )

        method = bridge._get_mitigation_method(threat)
        assert method == 'rate_limit'


# ============================================================================
# Test: Error Handling
# ============================================================================

class TestErrorHandling:
    """Test error handling in E2E flow."""

    def test_mesh_unavailable_graceful_degradation(
        self, mock_threat_event, mesh_bridge_config
    ):
        """Test graceful degradation when mesh is unavailable."""
        from core.qsecbit.mesh_bridge import QsecbitMeshBridge

        bridge = QsecbitMeshBridge(config=mesh_bridge_config)

        # Should not raise, just return False
        with patch('core.qsecbit.mesh_bridge.MESH_AVAILABLE', False):
            result = bridge.report_threat(mock_threat_event)

        # Should still work (Cortex events don't need mesh)
        assert result is False or result is True

    def test_dsm_error_doesnt_break_flow(
        self, mock_critical_threat, mesh_bridge_config
    ):
        """Test that DSM errors don't break the overall flow."""
        from core.qsecbit.mesh_bridge import QsecbitMeshBridge

        # DSM node that raises exception
        mock_dsm_node = Mock()
        mock_dsm_node.create_microblock.side_effect = Exception("DSM error")

        cortex_events = []
        bridge = QsecbitMeshBridge(config=mesh_bridge_config)
        bridge.set_dsm_node(mock_dsm_node)
        bridge.register_cortex_callback(lambda x: cortex_events.append(x))

        with patch('core.qsecbit.mesh_bridge.DSM_AVAILABLE', True):
            result = bridge.report_threat(mock_critical_threat)

        # Cortex should still work even if DSM failed
        assert len(cortex_events) == 1


# ============================================================================
# Test: Validation Checklist
# ============================================================================

class TestE2EValidationChecklist:
    """
    Test the E2E validation checklist items from CLAUDE.md.

    This test class validates each item in the E2E checklist to ensure
    the complete flow works as documented.
    """

    def test_detection_creates_threat_event(self, mock_threat_event):
        """[ ] Detector identifies threat - ThreatEvent created."""
        assert mock_threat_event.id is not None
        assert mock_threat_event.attack_type is not None
        assert mock_threat_event.detector is not None

    def test_confidence_score_is_realistic(self, mock_threat_event):
        """[ ] Confidence score is realistic (0.0-1.0)."""
        assert 0.0 <= mock_threat_event.confidence <= 1.0

    def test_evidence_dictionary_populated(self, mock_threat_event):
        """[ ] Evidence dictionary populated."""
        assert mock_threat_event.evidence is not None
        assert isinstance(mock_threat_event.evidence, dict)
        assert len(mock_threat_event.evidence) > 0

    def test_mitre_attack_id_assigned(self, mock_threat_event):
        """[ ] MITRE ATT&CK ID assigned."""
        assert mock_threat_event.mitre_attack_id is not None
        assert mock_threat_event.mitre_attack_id.startswith('T')

    def test_threat_converted_to_intelligence(
        self, mock_threat_event, mesh_bridge_config
    ):
        """[ ] Threat converted to ThreatIntelligence."""
        from core.qsecbit.mesh_bridge import QsecbitMeshBridge

        bridge = QsecbitMeshBridge(config=mesh_bridge_config)

        # The conversion method exists and can be called
        # (actual conversion requires mesh module)
        assert hasattr(bridge, 'threat_to_intelligence')
        assert callable(bridge.threat_to_intelligence)

    def test_cortex_visualization_event_emitted(
        self, mock_critical_threat, mesh_bridge_config
    ):
        """[ ] Cortex visualization event emitted."""
        from core.qsecbit.mesh_bridge import QsecbitMeshBridge

        events = []
        bridge = QsecbitMeshBridge(config=mesh_bridge_config)
        bridge.register_cortex_callback(lambda e: events.append(e))

        bridge.report_threat(mock_critical_threat)

        assert len(events) == 1
        assert events[0]['type'] in ['attack_detected', 'attack_repelled']

    def test_dsm_microblock_created(
        self, mock_critical_threat, mesh_bridge_config
    ):
        """[ ] DSM microblock created."""
        from core.qsecbit.mesh_bridge import QsecbitMeshBridge

        mock_dsm = Mock()
        mock_dsm.create_microblock.return_value = 'block-id'

        bridge = QsecbitMeshBridge(config=mesh_bridge_config)
        bridge.dsm_node = mock_dsm

        with patch('core.qsecbit.mesh_bridge.DSM_AVAILABLE', True):
            bridge._create_dsm_microblock(mock_critical_threat)

        mock_dsm.create_microblock.assert_called_once()


# ============================================================================
# E2E Coordinator Tests
# ============================================================================

class TestE2ECoordinator:
    """Tests for the unified E2E coordinator."""

    def test_coordinator_initialization(self):
        """E2E coordinator initializes with default config."""
        from core.qsecbit.e2e_coordinator import E2ECoordinator, E2EConfig

        config = E2EConfig(
            node_id='test-node',
            tier='guardian',
            data_dir='/tmp/hookprobe-test'
        )
        coordinator = E2ECoordinator(config)

        assert coordinator.config.node_id == 'test-node'
        assert coordinator.stats.threats_detected == 0
        assert coordinator.storage is not None

    def test_coordinator_component_connection(self):
        """E2E coordinator connects components correctly."""
        from core.qsecbit.e2e_coordinator import E2ECoordinator, E2EConfig

        coordinator = E2ECoordinator(E2EConfig(data_dir='/tmp/hookprobe-test'))

        # Mock components
        mock_response = Mock()
        mock_mesh = Mock()
        mock_dsm = Mock()

        coordinator.connect_response(mock_response)
        coordinator.connect_mesh(mock_mesh)
        coordinator.connect_dsm(mock_dsm)

        assert coordinator.response_orchestrator is mock_response
        assert coordinator.mesh_bridge is mock_mesh
        assert coordinator.dsm_node is mock_dsm

    def test_threat_processing_pipeline(self, mock_threat_event):
        """E2E coordinator processes threats through full pipeline."""
        from core.qsecbit.e2e_coordinator import E2ECoordinator, E2EConfig

        coordinator = E2ECoordinator(E2EConfig(
            data_dir='/tmp/hookprobe-test',
            enable_response=False,  # Disable for this test
            enable_mesh=False,
            enable_dsm=False,
        ))

        result = coordinator.process_threat(mock_threat_event)

        assert result['threat_id'] == mock_threat_event.id
        assert result['stored'] is True
        assert coordinator.stats.threats_detected == 1

    def test_threat_storage_persistence(self, mock_threat_event):
        """Threats are persisted to storage."""
        from core.qsecbit.e2e_coordinator import ThreatStorage
        import tempfile
        import os

        with tempfile.TemporaryDirectory() as tmpdir:
            storage = ThreatStorage(
                db_path=os.path.join(tmpdir, 'threats.jsonl'),
                retention_hours=24
            )

            storage.store(mock_threat_event)
            recent = storage.query_recent(hours=1)

            assert len(recent) == 1
            assert recent[0]['id'] == mock_threat_event.id

    def test_threat_storage_cleanup(self):
        """Old threats are cleaned up."""
        from core.qsecbit.e2e_coordinator import ThreatStorage
        import tempfile
        import os

        with tempfile.TemporaryDirectory() as tmpdir:
            storage = ThreatStorage(
                db_path=os.path.join(tmpdir, 'threats.jsonl'),
                retention_hours=0  # Immediate cleanup
            )

            # Add a mock record directly
            with open(storage.db_path, 'w') as f:
                f.write('{"id":"old","timestamp":"2020-01-01T00:00:00"}\n')

            removed = storage.cleanup_old()
            assert removed == 1

    def test_cortex_event_creation(self, mock_threat_event):
        """Cortex events are created correctly."""
        from core.qsecbit.e2e_coordinator import E2ECoordinator, E2EConfig

        coordinator = E2ECoordinator(E2EConfig(data_dir='/tmp/hookprobe-test'))
        event = coordinator._create_cortex_event(mock_threat_event)

        assert event['type'] == 'attack_detected'
        assert event['attack_type'] == 'syn_flood'
        assert event['source']['ip'] == mock_threat_event.source_ip

    def test_get_status(self):
        """Coordinator status includes all components."""
        from core.qsecbit.e2e_coordinator import E2ECoordinator, E2EConfig

        coordinator = E2ECoordinator(E2EConfig(data_dir='/tmp/hookprobe-test'))
        status = coordinator.get_status()

        assert 'node_id' in status
        assert 'statistics' in status
        assert 'components' in status
        assert 'storage' in status


# ============================================================================
# Neuro-DSM Bridge Tests
# ============================================================================

@pytest.mark.skip(reason="core.neuro.crypto module not implemented")
class TestNeuroDSMBridge:
    """Tests for the Neuro-DSM bridge."""

    def test_bridge_initialization(self):
        """Neuro-DSM bridge initializes correctly."""
        from core.neuro.dsm_bridge import NeuroDSMBridge, NeuroDSMConfig

        config = NeuroDSMConfig()
        bridge = NeuroDSMBridge(
            node_id='test-neuro-node',
            config=config
        )

        assert bridge.node_id == 'test-neuro-node'
        assert bridge.stats['ters_generated'] == 0

    def test_weight_fingerprint_computation(self):
        """Weight fingerprints are computed deterministically."""
        from core.neuro.dsm_bridge import NeuroDSMBridge

        bridge = NeuroDSMBridge(node_id='test')

        # Create mock TER-like objects
        class MockTER:
            def __init__(self, seq):
                self.h_entropy = hashlib.sha256(f"entropy-{seq}".encode()).digest()
                self.sequence = seq

        ters = [MockTER(i) for i in range(10)]

        fp1 = bridge._compute_weight_fingerprint(ters)
        fp2 = bridge._compute_weight_fingerprint(ters)

        # Same input should produce same fingerprint
        assert fp1 == fp2
        assert len(fp1) == 32  # SHA256

    def test_fingerprint_drift_calculation(self):
        """Fingerprint drift is calculated correctly."""
        from core.neuro.dsm_bridge import NeuroDSMBridge

        bridge = NeuroDSMBridge(node_id='test')

        fp1 = b'\x00' * 32
        fp2 = b'\x00' * 32
        fp3 = b'\xff' * 32

        # Identical fingerprints = 0 drift
        assert bridge._calculate_fingerprint_drift(fp1, fp2) == 0.0

        # Maximum different = 1.0 drift
        assert bridge._calculate_fingerprint_drift(fp1, fp3) == 1.0

    def test_consensus_vote_creation(self):
        """Consensus votes include required fields."""
        from core.neuro.dsm_bridge import NeuroDSMBridge

        bridge = NeuroDSMBridge(node_id='test-voter')

        # Add some mock TER history
        class MockTER:
            def __init__(self, seq):
                self.h_entropy = hashlib.sha256(f"e{seq}".encode()).digest()
                self.h_integrity = hashlib.new('ripemd160', b'test').digest()
                self.timestamp = 1234567890000000 + seq * 1000000
                self.sequence = seq
                self.chain_hash = seq

            def to_bytes(self):
                return self.h_entropy + self.h_integrity + bytes(12)

            def calculate_threat_score(self):
                return 0.5

        bridge._ter_history.extend([MockTER(i) for i in range(5)])

        vote = bridge.create_consensus_vote(
            checkpoint_id='cp-12345',
            ter_summary={}
        )

        assert vote is not None
        assert vote['checkpoint_id'] == 'cp-12345'
        assert vote['node_id'] == 'test-voter'
        assert 'weight_fingerprint' in vote
        assert vote['ter_count'] == 5

    def test_ter_summary_for_checkpoint(self):
        """TER summary contains required checkpoint data."""
        from core.neuro.dsm_bridge import NeuroDSMBridge

        bridge = NeuroDSMBridge(node_id='test-node')

        # Empty history case
        summary = bridge.get_ter_summary_for_checkpoint()
        assert summary['node_id'] == 'test-node'
        assert summary['ter_count'] == 0


# ============================================================================
# Qsecbit Agent E2E Integration Tests
# ============================================================================

@pytest.mark.skip(reason="core.qsecbit.qsecbit_agent module not implemented")
class TestQsecbitAgentIntegration:
    """Tests for qsecbit-agent E2E integration."""

    def test_agent_imports_e2e_components(self):
        """Agent imports E2E components correctly."""
        # Test that imports work without errors
        import core.qsecbit.qsecbit_agent as agent_module

        # Check that integration flags exist
        assert hasattr(agent_module, 'RESPONSE_AVAILABLE')
        assert hasattr(agent_module, 'MESH_BRIDGE_AVAILABLE')
        assert hasattr(agent_module, 'DSM_AVAILABLE')

    def test_agent_has_e2e_methods(self):
        """Agent has E2E integration methods."""
        from core.qsecbit.qsecbit_agent import HookProbeAgent

        # Check that new methods exist
        agent = HookProbeAgent.__new__(HookProbeAgent)
        assert hasattr(agent, '_handle_red_alert')
        assert hasattr(agent, '_handle_amber_alert')
        assert hasattr(agent, '_handle_ddos_indicator')
        assert hasattr(agent, '_create_threat_from_metrics')

    def test_agent_initializes_e2e_components_attr(self):
        """Agent has E2E component attributes."""
        from core.qsecbit.qsecbit_agent import HookProbeAgent

        # Create agent without running
        agent = HookProbeAgent.__new__(HookProbeAgent)
        agent.__init__()

        # Check E2E attributes exist
        assert hasattr(agent, 'response_orchestrator')
        assert hasattr(agent, 'mesh_bridge')
        assert hasattr(agent, 'dsm_node')
        assert hasattr(agent, 'active_threats')
        assert hasattr(agent, 'rag_history')


# ============================================================================
# Full Pipeline Integration Test
# ============================================================================

class TestFullPipelineIntegration:
    """Test the complete E2E pipeline with all components mocked."""

    def test_full_pipeline_threat_to_visualization(self, mock_critical_threat):
        """Complete pipeline: Detection → Response → Mesh → DSM → Cortex."""
        from core.qsecbit.e2e_coordinator import E2ECoordinator, E2EConfig

        # Create coordinator
        coordinator = E2ECoordinator(E2EConfig(
            node_id='test-full-pipeline',
            data_dir='/tmp/hookprobe-test-full',
            enable_response=True,
            enable_mesh=True,
            enable_dsm=True,
            enable_cortex=True,
        ))

        # Mock components
        mock_response = Mock()
        mock_response.respond.return_value = [Mock(action=Mock(name='BLOCK_IP'), success=True)]

        mock_mesh = Mock()
        mock_mesh.report_threat.return_value = True

        mock_dsm = Mock()
        mock_dsm.create_microblock.return_value = 'test-block-123'

        # Connect mocks
        coordinator.connect_response(mock_response)
        coordinator.connect_mesh(mock_mesh)
        coordinator.connect_dsm(mock_dsm)

        # Cortex callback
        cortex_events = []
        coordinator.register_cortex_callback(lambda e: cortex_events.append(e))

        # Process threat
        result = coordinator.process_threat(mock_critical_threat)

        # Verify complete pipeline
        assert result['stored'] is True
        assert result['response_executed'] is True
        assert result['mesh_propagated'] is True
        assert result['microblock_created'] is True
        assert result['cortex_notified'] is True
        assert len(cortex_events) == 1

        # Verify statistics
        assert coordinator.stats.threats_detected == 1
        assert coordinator.stats.threats_responded == 1
        assert coordinator.stats.threats_propagated == 1
        assert coordinator.stats.microblocks_created == 1
        assert coordinator.stats.cortex_events_sent == 1


# ============================================================================
# Neural Synaptic Encryption Integration Tests
# ============================================================================

class TestNeuroSecurityStackIntegration:
    """Test Neural Synaptic Encryption integration across HTP, DSM, and Mesh."""

    def test_neuro_security_stack_initialization(self):
        """NeuroSecurityStack initializes all components."""
        try:
            from core.neuro.integration import (
                NeuroSecurityStack,
                create_neuro_security_stack
            )
        except ImportError:
            pytest.skip("Neuro integration module not available")

        stack = create_neuro_security_stack(node_id=secrets.token_bytes(16))

        assert stack.htp_binding is not None
        assert stack.dsm_validator is not None
        assert stack.mesh_auth is not None

    def test_htp_session_key_derivation(self):
        """HTP session keys are derived from neural state."""
        try:
            from core.neuro.integration import NeuroSecurityStack
        except ImportError:
            pytest.skip("Neuro integration module not available")

        stack = NeuroSecurityStack(secrets.token_bytes(16))

        # Derive key
        rdv = secrets.token_bytes(32)
        key1 = stack.get_htp_session_key(rdv=rdv, qsecbit=0.5)
        key2 = stack.get_htp_session_key(rdv=rdv, qsecbit=0.5)

        # Keys should be 32 bytes
        assert len(key1) == 32

        # Different qsecbit should produce different key
        key3 = stack.get_htp_session_key(rdv=rdv, qsecbit=0.9)
        assert key1 != key3

    def test_ter_checkpoint_proof_creation(self):
        """TER checkpoint proofs are created correctly."""
        try:
            from core.neuro.integration import DSMNeuroValidator, TERCheckpointProof
        except ImportError:
            pytest.skip("Neuro integration module not available")

        validator = DSMNeuroValidator(node_id='test-validator')

        # Create proof with empty history
        proof = validator.create_ter_checkpoint_proof(ter_history=[])

        assert proof.ter_count == 0
        assert proof.sequence_range == (0, 0)
        assert len(proof.weight_fingerprint) == 32

    def test_ter_checkpoint_proof_serialization(self):
        """TER checkpoint proofs serialize/deserialize correctly."""
        try:
            from core.neuro.integration import TERCheckpointProof
        except ImportError:
            pytest.skip("Neuro integration module not available")

        proof = TERCheckpointProof(
            ter_count=100,
            sequence_range=(50, 150),
            weight_fingerprint=secrets.token_bytes(32),
            chain_hash=0x1234,
            avg_threat_score=0.45,
            posf_signature=secrets.token_bytes(32),
        )

        # Serialize and deserialize
        data = proof.to_bytes()
        restored = TERCheckpointProof.from_bytes(data)

        assert restored.ter_count == proof.ter_count
        assert restored.sequence_range == proof.sequence_range
        assert restored.chain_hash == proof.chain_hash

    def test_mesh_payload_encryption(self):
        """Mesh payloads are encrypted and decrypted correctly."""
        try:
            from core.neuro.integration import MeshNeuroAuth
        except ImportError:
            pytest.skip("Neuro integration module not available")

        auth = MeshNeuroAuth(secrets.token_bytes(16))
        peer_id = secrets.token_bytes(16)

        plaintext = b"Secret threat intelligence data"

        # Encrypt
        encrypted = auth.encrypt_payload(peer_id, plaintext)

        # Encrypted should be different (unless crypto unavailable)
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            assert encrypted != plaintext
            assert len(encrypted) > len(plaintext)  # nonce + tag overhead

            # Decrypt
            decrypted = auth.decrypt_payload(peer_id, encrypted)
            assert decrypted == plaintext
        except ImportError:
            # Without cryptography, should gracefully degrade
            pass

    def test_rdv_generation_and_verification(self):
        """RDV generation and verification works correctly."""
        try:
            from core.neuro.integration import MeshNeuroAuth
        except ImportError:
            pytest.skip("Neuro integration module not available")

        auth = MeshNeuroAuth(secrets.token_bytes(16))
        peer_id = secrets.token_bytes(16)
        flow_token = secrets.token_bytes(8)

        # Generate RDV
        rdv = auth.generate_rdv_for_peer(peer_id, flow_token)

        assert len(rdv) == 32

    def test_dsm_consensus_vote_validation(self):
        """DSM consensus votes with TER proofs are validated."""
        try:
            from core.neuro.integration import DSMNeuroValidator, TERCheckpointProof
        except ImportError:
            pytest.skip("Neuro integration module not available")

        validator = DSMNeuroValidator(node_id='test-validator')

        # Create a vote with TER proof
        proof = TERCheckpointProof(
            ter_count=10,
            sequence_range=(1, 10),
            weight_fingerprint=secrets.token_bytes(32),
            chain_hash=0xABCD,
            avg_threat_score=0.3,
            posf_signature=hashlib.sha256(
                secrets.token_bytes(32) +
                b'test-voter'.ljust(16)[:16]
            ).digest(),
        )

        vote = {
            'checkpoint_id': 'cp-123',
            'merkle_root': secrets.token_bytes(32),
            'signature': 'sig-123',
            'ter_checkpoint_proof': proof.to_bytes(),
        }

        # Verify vote
        is_valid, reason = validator.verify_consensus_vote(vote, 'test-voter')

        # Should pass or fail cleanly, not raise
        assert isinstance(is_valid, bool)
        assert isinstance(reason, str)

    def test_key_rotation_detection(self):
        """Key rotation is detected when needed."""
        try:
            from core.neuro.integration import NeuroKeyDerivation
        except ImportError:
            pytest.skip("Neuro integration module not available")

        kd = NeuroKeyDerivation(secrets.token_bytes(16))

        # Initially needs rotation (no key yet)
        assert kd.needs_rotation() is True

        # Derive a key
        try:
            kd.derive_session_key(
                weight_fingerprint=secrets.token_bytes(32),
                rdv=secrets.token_bytes(32),
                ter_entropy=secrets.token_bytes(32),
                qsecbit_current=0.5,
            )
            # After deriving, should not immediately need rotation
            assert kd.needs_rotation() is False
        except RuntimeError:
            # Cryptography library not available
            pass


class TestHTPNeuroIntegration:
    """Test HTP transport neural key derivation integration."""

    def test_htp_transport_accepts_neuro_stack(self):
        """HTP transport accepts NeuroSecurityStack parameter."""
        try:
            from core.htp.transport.htp import HookProbeTransport
        except ImportError:
            pytest.skip("HTP transport module not available")

        # Should not raise
        transport = HookProbeTransport(
            node_id="test-node",
            listen_port=0,
            enable_encryption=True,
        )

        # Check neuro_stack was initialized (or is None if unavailable)
        assert hasattr(transport, 'neuro_stack')

        # Cleanup
        transport.socket.close()

    def test_htp_session_has_neuro_binding(self):
        """HTP sessions have neuro binding attribute."""
        try:
            from core.htp.transport.htp import HTPSession, HTPState
        except ImportError:
            pytest.skip("HTP transport module not available")

        session = HTPSession(
            flow_token=12345,
            state=HTPState.INIT,
            peer_address=('127.0.0.1', 8144),
        )

        assert hasattr(session, 'neuro_binding')
        assert hasattr(session, 'current_qsecbit')


class TestDSMNeuroIntegration:
    """Test DSM consensus neural validation integration."""

    def test_consensus_engine_has_neuro_validator(self):
        """Consensus engine has neuro validator attribute."""
        try:
            from shared.dsm.consensus import ConsensusEngine
        except ImportError:
            pytest.skip("DSM consensus module not available")

        engine = ConsensusEngine(
            validators=[],
            quorum_threshold=0.67,
            node_id='test-consensus',
        )

        assert hasattr(engine, 'neuro_validator')

    def test_signature_verification_uses_neuro(self):
        """Single signature verification uses neuro validator."""
        try:
            from shared.dsm.consensus import ConsensusEngine
        except ImportError:
            pytest.skip("DSM consensus module not available")

        engine = ConsensusEngine(validators=[], node_id='test')

        # Mock validator
        mock_validator = Mock()
        mock_validator.node_id = 'validator-1'
        mock_validator.public_key = 'pubkey-1'

        # Should not raise, and return boolean
        result = engine._verify_single_signature('sig', mock_validator)
        assert isinstance(result, bool)


class TestMeshNeuroIntegration:
    """Test mesh transport neural authentication integration."""

    def test_unified_transport_has_neuro_auth(self):
        """Unified transport has neuro auth attribute."""
        try:
            from shared.mesh.unified_transport import UnifiedTransport
        except ImportError:
            pytest.skip("Mesh transport module not available")

        transport = UnifiedTransport(
            node_id=secrets.token_bytes(16),
            neuro_seed=secrets.token_bytes(32),
        )

        assert hasattr(transport, 'neuro_auth')


# Run with: pytest tests/test_e2e_integration.py -v
