"""
Tests for DSM Consensus Persistence + Mesh Packet Types.

Validates:
1. Checkpoint persistence to disk
2. Gossip broadcast wiring
3. RECOMMENDATION packet type exists
4. MSSP routing rule in orchestrator
"""

import json
import os
import tempfile

import pytest


class TestCheckpointPersistence:
    """Test _commit_checkpoint() persists to disk."""

    def _make_engine(self):
        """Create a ConsensusEngine for testing."""
        from shared.dsm.consensus import ConsensusEngine
        return ConsensusEngine.__new__(ConsensusEngine)

    def test_checkpoint_persists_to_disk(self):
        engine = self._make_engine()
        checkpoint = {
            "epoch": 42,
            "merkle_root": "abc123",
            "validator_id": "v-001",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            os.environ["DSM_CHECKPOINT_DIR"] = tmpdir
            try:
                engine._commit_checkpoint(checkpoint)
                # Verify file was created
                path = os.path.join(tmpdir, "cp_42.json")
                assert os.path.isfile(path)
                with open(path) as f:
                    data = json.load(f)
                assert data["epoch"] == 42
                assert data["merkle_root"] == "abc123"
            finally:
                os.environ.pop("DSM_CHECKPOINT_DIR", None)

    def test_checkpoint_handles_readonly_gracefully(self):
        engine = self._make_engine()
        checkpoint = {"epoch": 99}
        os.environ["DSM_CHECKPOINT_DIR"] = "/nonexistent/readonly/path"
        try:
            # Should not raise — falls back to logging
            engine._commit_checkpoint(checkpoint)
        finally:
            os.environ.pop("DSM_CHECKPOINT_DIR", None)


class TestGossipBroadcast:
    """Test _broadcast_finalized_checkpoint() attempts gossip."""

    def _make_engine(self):
        from shared.dsm.consensus import ConsensusEngine
        return ConsensusEngine.__new__(ConsensusEngine)

    def test_broadcast_does_not_raise(self):
        engine = self._make_engine()
        checkpoint = {"epoch": 10}
        # Should not raise even if gossip is unavailable
        engine._broadcast_finalized_checkpoint(checkpoint)

    def test_metric_increment_logs(self):
        engine = self._make_engine()
        # Should not raise
        engine._increment_metric("test_metric", {"tag": "value"})


class TestRecommendationPacketType:
    """Test RECOMMENDATION packet type in unified_transport."""

    def test_recommendation_type_exists(self):
        from shared.mesh.unified_transport import PacketType
        assert hasattr(PacketType, "RECOMMENDATION")
        assert PacketType.RECOMMENDATION == 0x63

    def test_kernel_types_preserved(self):
        from shared.mesh.unified_transport import PacketType
        assert PacketType.KERNEL_FILTER == 0x60
        assert PacketType.KERNEL_VERDICT == 0x61
        assert PacketType.KERNEL_TELEMETRY == 0x62


class TestMSSPRoutingRule:
    """Test MSSP recommendation routing in AEGIS orchestrator."""

    def test_mssp_rule_exists(self):
        from core.aegis.orchestrator import ROUTING_RULES
        assert "mssp.recommendation" in ROUTING_RULES

    def test_mssp_routes_to_oracle_forge(self):
        from core.aegis.orchestrator import ROUTING_RULES
        agents = ROUTING_RULES["mssp.recommendation"]
        assert "ORACLE" in agents
        assert "FORGE" in agents
