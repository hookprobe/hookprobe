"""
AEGIS + NAPSE Cross-Tier Integration Test Suite

Tests for the complete intelligence loop:
    Sentinel → MSSP → Nexus → MSSP → Sentinel → Mesh

Covers:
- shared/mssp/ (types, client, auth, recommendation_handler, webhook, mesh_propagation)
- core/aegis/profiles/ (pico, lite, full, deep)
- core/aegis/bridges/napse_bridge.py
- products/sentinel/lib/ (aegis_pico, defense)
- products/nexus/lib/intelligence/ (correlator, recommender, analysis_engine)
- products/guardian/lib/aegis_lite.py
- products/nexus/lib/aegis_deep.py
- E2E intelligence loop flow
"""

import hashlib
import hmac
import json
import os
import sys
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

# Ensure PYTHONPATH includes repo root
sys.path.insert(0, str(Path(__file__).parent.parent))


# ==============================================================
# MSSP Types Tests
# ==============================================================

class TestMSSPTypes:
    """Tests for shared/mssp/types.py"""

    def test_threat_finding_defaults(self):
        from shared.mssp.types import ThreatFinding
        f = ThreatFinding()
        assert f.finding_id  # UUID auto-generated
        assert f.source_tier == "fortress"
        assert f.severity == "LOW"
        assert f.confidence == 0.0
        assert f.status == "submitted"

    def test_threat_finding_serialization(self):
        from shared.mssp.types import ThreatFinding
        f = ThreatFinding(
            threat_type="port_scan",
            severity="HIGH",
            confidence=0.85,
            ioc_type="ip",
            ioc_value="203.0.113.1",
        )
        d = f.to_dict()
        assert d["threat_type"] == "port_scan"
        assert d["severity"] == "HIGH"
        assert d["ioc_value"] == "203.0.113.1"

    def test_threat_finding_from_dict(self):
        from shared.mssp.types import ThreatFinding
        data = {
            "finding_id": "test-123",
            "threat_type": "dns_tunnel",
            "severity": "CRITICAL",
            "ioc_type": "domain",
            "ioc_value": "evil.example.com",
        }
        f = ThreatFinding.from_dict(data)
        assert f.finding_id == "test-123"
        assert f.threat_type == "dns_tunnel"

    def test_threat_finding_ignores_unknown_fields(self):
        from shared.mssp.types import ThreatFinding
        data = {"threat_type": "scan", "unknown_field": "should_be_ignored"}
        f = ThreatFinding.from_dict(data)
        assert f.threat_type == "scan"
        assert not hasattr(f, "unknown_field")

    def test_threat_finding_bytes_roundtrip(self):
        from shared.mssp.types import ThreatFinding
        f = ThreatFinding(threat_type="brute_force", ioc_value="10.0.0.1")
        b = f.to_bytes()
        f2 = ThreatFinding.from_bytes(b)
        assert f2.threat_type == "brute_force"
        assert f2.ioc_value == "10.0.0.1"

    def test_threat_finding_content_hash(self):
        from shared.mssp.types import ThreatFinding
        f = ThreatFinding(
            source_node_id="node-1",
            threat_type="scan",
            ioc_value="1.2.3.4",
            severity="HIGH",
        )
        h = f.content_hash
        assert len(h) == 16  # truncated SHA256
        # Same inputs → same hash
        f2 = ThreatFinding(
            source_node_id="node-1",
            threat_type="scan",
            ioc_value="1.2.3.4",
            severity="HIGH",
        )
        assert f2.content_hash == h

    def test_recommended_action_defaults(self):
        from shared.mssp.types import RecommendedAction
        a = RecommendedAction()
        assert a.action_id
        assert a.action_type == "alert"
        assert a.priority == 4  # LOW
        assert a.mesh_propagate is False

    def test_recommended_action_gossip_ttl(self):
        from shared.mssp.types import RecommendedAction, ActionPriority
        a = RecommendedAction(priority=ActionPriority.CRITICAL.value)
        assert a.gossip_ttl_hops == 10
        a2 = RecommendedAction(priority=ActionPriority.INFO.value)
        assert a2.gossip_ttl_hops == 2

    def test_recommended_action_requires_consensus(self):
        from shared.mssp.types import RecommendedAction, ActionPriority
        critical = RecommendedAction(priority=ActionPriority.CRITICAL.value)
        assert critical.requires_consensus is True
        high = RecommendedAction(priority=ActionPriority.HIGH.value)
        assert high.requires_consensus is False

    def test_recommended_action_serialization(self):
        from shared.mssp.types import RecommendedAction
        a = RecommendedAction(
            action_type="block_ip",
            target="203.0.113.5",
            confidence=0.9,
            priority=1,
            mesh_propagate=True,
        )
        d = a.to_dict()
        assert d["action_type"] == "block_ip"
        assert d["mesh_propagate"] is True

        a2 = RecommendedAction.from_dict(d)
        assert a2.target == "203.0.113.5"
        assert a2.priority == 1

    def test_execution_feedback(self):
        from shared.mssp.types import ExecutionFeedback
        fb = ExecutionFeedback(
            action_id="act-123",
            node_id="node-1",
            success=True,
            effect_observed="IP blocked successfully",
        )
        d = fb.to_dict()
        assert d["success"] is True
        assert d["action_id"] == "act-123"

    def test_device_metrics(self):
        from shared.mssp.types import DeviceMetrics
        m = DeviceMetrics(
            cpu_usage=45.2,
            ram_usage=78.3,
            aegis_tier="pico",
            napse_active=False,
        )
        d = m.to_dict()
        assert d["aegis_tier"] == "pico"
        assert d["napse_active"] is False

    def test_intelligence_report(self):
        from shared.mssp.types import IntelligenceReport, RecommendedAction
        rec = RecommendedAction(action_type="block_ip", target="1.2.3.4")
        report = IntelligenceReport(
            finding_id="f-123",
            analyzed_by="nexus-01",
            threat_assessment="confirmed",
            recommendations=[rec],
        )
        d = report.to_dict()
        assert d["threat_assessment"] == "confirmed"
        assert len(d["recommendations"]) == 1

    def test_action_priority_enum(self):
        from shared.mssp.types import ActionPriority
        assert ActionPriority.CRITICAL.value == 1
        assert ActionPriority.INFO.value == 5

    def test_action_type_enum(self):
        from shared.mssp.types import ActionType
        assert ActionType.BLOCK_IP.value == "block_ip"
        assert ActionType.DNS_SINKHOLE.value == "dns_sinkhole"


# ==============================================================
# MSSP Auth Tests
# ==============================================================

class TestMSSPAuth:
    """Tests for shared/mssp/auth.py"""

    def test_compute_digest_excludes_signature(self):
        from shared.mssp.auth import compute_recommendation_digest
        d1 = {"action": "block", "target": "1.2.3.4", "signature": "abc123"}
        d2 = {"action": "block", "target": "1.2.3.4", "signature": "xyz789"}
        assert compute_recommendation_digest(d1) == compute_recommendation_digest(d2)

    def test_compute_digest_deterministic(self):
        from shared.mssp.auth import compute_recommendation_digest
        d = {"b_field": 2, "a_field": 1}
        digest1 = compute_recommendation_digest(d)
        digest2 = compute_recommendation_digest(d)
        assert digest1 == digest2

    def test_sign_for_testing(self):
        from shared.mssp.auth import sign_for_testing, compute_recommendation_digest
        key = b"test-secret-key"
        action = {"action_type": "block_ip", "target": "1.2.3.4"}
        sig = sign_for_testing(action, key)
        assert len(sig) == 64  # SHA256 hex digest

        # Verify manually
        digest = compute_recommendation_digest(action)
        expected = hmac.new(key, digest, hashlib.sha256).hexdigest()
        assert sig == expected

    def test_verify_no_signature_rejects(self):
        from shared.mssp.auth import verify_recommendation_signature
        action = {"action_type": "block_ip", "target": "1.2.3.4"}
        assert verify_recommendation_signature(action) is False

    def test_verify_empty_signature_rejects(self):
        from shared.mssp.auth import verify_recommendation_signature
        action = {"action_type": "block_ip", "signature": ""}
        assert verify_recommendation_signature(action) is False

    def test_verify_with_hmac_key(self, tmp_path):
        from shared.mssp.auth import (
            verify_recommendation_signature,
            sign_for_testing,
        )
        hmac_key = b"test-hmac-secret-2026"
        key_file = tmp_path / "mssp-hmac.key"
        key_file.write_bytes(hmac_key)

        action = {"action_type": "block_ip", "target": "203.0.113.10"}
        sig = sign_for_testing(action, hmac_key)
        action["signature"] = sig

        with patch("shared.mssp.auth.MSSP_HMAC_KEY_PATH", key_file):
            assert verify_recommendation_signature(action) is True

    def test_verify_wrong_hmac_rejects(self, tmp_path):
        from shared.mssp.auth import verify_recommendation_signature
        key_file = tmp_path / "mssp-hmac.key"
        key_file.write_bytes(b"correct-key")

        action = {"action_type": "block_ip", "target": "1.2.3.4", "signature": "deadbeef" * 8}
        with patch("shared.mssp.auth.MSSP_HMAC_KEY_PATH", key_file):
            assert verify_recommendation_signature(action) is False

    def test_verify_dev_mode_allows_without_keys(self):
        from shared.mssp.auth import verify_recommendation_signature
        action = {"action_type": "block_ip", "signature": "anything"}

        with patch("shared.mssp.auth.MSSP_PUBLIC_KEY_PATH", Path("/nonexistent")), \
             patch("shared.mssp.auth.MSSP_HMAC_KEY_PATH", Path("/nonexistent")), \
             patch.dict(os.environ, {"HOOKPROBE_DEV_MODE": "true"}):
            assert verify_recommendation_signature(action) is True

    def test_verify_no_keys_no_dev_mode_rejects(self):
        from shared.mssp.auth import verify_recommendation_signature
        action = {"action_type": "block_ip", "signature": "anything"}

        with patch("shared.mssp.auth.MSSP_PUBLIC_KEY_PATH", Path("/nonexistent")), \
             patch("shared.mssp.auth.MSSP_HMAC_KEY_PATH", Path("/nonexistent")), \
             patch.dict(os.environ, {"HOOKPROBE_DEV_MODE": ""}, clear=False):
            assert verify_recommendation_signature(action) is False


# ==============================================================
# MSSP Client Tests
# ==============================================================

class TestMSSPClient:
    """Tests for shared/mssp/client.py"""

    def test_url_validation_rejects_http(self):
        from shared.mssp.client import _validate_mssp_url, DEFAULT_MSSP_URL
        assert _validate_mssp_url("http://evil.com") == DEFAULT_MSSP_URL

    def test_url_validation_rejects_localhost(self):
        from shared.mssp.client import _validate_mssp_url, DEFAULT_MSSP_URL
        assert _validate_mssp_url("https://localhost") == DEFAULT_MSSP_URL

    def test_url_validation_rejects_metadata(self):
        from shared.mssp.client import _validate_mssp_url, DEFAULT_MSSP_URL
        assert _validate_mssp_url("https://169.254.169.254") == DEFAULT_MSSP_URL

    def test_url_validation_accepts_valid(self):
        from shared.mssp.client import _validate_mssp_url
        assert _validate_mssp_url("https://mssp.hookprobe.com") == "https://mssp.hookprobe.com"

    def test_client_initialization(self):
        from shared.mssp.client import HookProbeMSSPClient
        client = HookProbeMSSPClient(tier="sentinel", mssp_url="https://mssp.hookprobe.com")
        assert client.tier == "sentinel"
        assert client.mssp_url == "https://mssp.hookprobe.com"

    def test_client_stats_initial(self):
        from shared.mssp.client import HookProbeMSSPClient
        client = HookProbeMSSPClient(tier="guardian")
        stats = client.get_stats()
        assert stats["heartbeats_sent"] == 0
        assert stats["findings_submitted"] == 0
        assert stats["tier"] == "guardian"

    def test_device_id_generation(self):
        from shared.mssp.client import _generate_device_id
        id1 = _generate_device_id("sentinel")
        assert id1.startswith("sentinel-")
        assert len(id1) > 15

    def test_submit_finding_sets_node_id(self):
        from shared.mssp.client import HookProbeMSSPClient
        from shared.mssp.types import ThreatFinding

        client = HookProbeMSSPClient(tier="sentinel", device_id="test-node")
        finding = ThreatFinding(threat_type="scan")
        assert finding.source_node_id == ""

        with patch.object(client, '_request', return_value={"status": "ok"}):
            client.submit_finding(finding)
        assert finding.source_node_id == "test-node"

    def test_poll_recommendations_parses_results(self):
        from shared.mssp.client import HookProbeMSSPClient
        client = HookProbeMSSPClient(tier="fortress")

        mock_response = {
            "recommendations": [
                {
                    "action_id": "act-1",
                    "action_type": "block_ip",
                    "target": "1.2.3.4",
                    "confidence": 0.9,
                    "priority": 2,
                },
            ]
        }
        with patch.object(client, '_request', return_value=mock_response):
            recs = client.poll_recommendations()
        assert len(recs) == 1
        assert recs[0].action_type == "block_ip"
        assert recs[0].target == "1.2.3.4"

    def test_poll_recommendations_handles_none(self):
        from shared.mssp.client import HookProbeMSSPClient
        client = HookProbeMSSPClient(tier="fortress")
        with patch.object(client, '_request', return_value=None):
            recs = client.poll_recommendations()
        assert recs == []

    def test_singleton_factory(self):
        from shared.mssp.client import get_mssp_client, _clients, _client_lock
        # Clear any existing singletons
        with _client_lock:
            _clients.pop("test_singleton", None)

        c1 = get_mssp_client(tier="test_singleton")
        c2 = get_mssp_client(tier="test_singleton")
        assert c1 is c2

        # Cleanup
        with _client_lock:
            _clients.pop("test_singleton", None)


# ==============================================================
# Recommendation Handler Tests
# ==============================================================

class TestRecommendationHandler:
    """Tests for shared/mssp/recommendation_handler.py"""

    def _make_handler(self, execute_callback=None):
        from shared.mssp.recommendation_handler import RecommendationHandler
        return RecommendationHandler(
            mssp_client=MagicMock(),
            execute_callback=execute_callback or (lambda d: True),
        )

    def _make_action(self, **kwargs):
        from shared.mssp.types import RecommendedAction
        defaults = {
            "action_type": "block_ip",
            "target": "203.0.113.1",
            "confidence": 0.85,
            "priority": 2,
            "ttl_seconds": 3600,
            "signature": "valid",
        }
        defaults.update(kwargs)
        return RecommendedAction(**defaults)

    @patch("shared.mssp.recommendation_handler.verify_recommendation_signature", return_value=True)
    def test_handle_success(self, mock_verify):
        handler = self._make_handler()
        action = self._make_action()
        assert handler.handle(action) is True
        assert handler.get_stats()["executed"] == 1

    @patch("shared.mssp.recommendation_handler.verify_recommendation_signature", return_value=False)
    def test_handle_rejects_invalid_signature(self, mock_verify):
        handler = self._make_handler()
        action = self._make_action()
        assert handler.handle(action) is False
        assert handler.get_stats()["rejected_signature"] == 1

    @patch("shared.mssp.recommendation_handler.verify_recommendation_signature", return_value=True)
    def test_handle_rejects_forbidden_action(self, mock_verify):
        handler = self._make_handler()
        action = self._make_action(action_type="disable_firewall")
        assert handler.handle(action) is False
        assert handler.get_stats()["rejected_principle"] == 1

    @patch("shared.mssp.recommendation_handler.verify_recommendation_signature", return_value=True)
    def test_handle_rejects_zero_confidence(self, mock_verify):
        handler = self._make_handler()
        action = self._make_action(confidence=0.0)
        assert handler.handle(action) is False
        assert handler.get_stats()["rejected_principle"] == 1

    @patch("shared.mssp.recommendation_handler.verify_recommendation_signature", return_value=True)
    def test_handle_rejects_excessive_ttl(self, mock_verify):
        handler = self._make_handler()
        action = self._make_action(ttl_seconds=999999)  # > 7 days
        assert handler.handle(action) is False

    @patch("shared.mssp.recommendation_handler.verify_recommendation_signature", return_value=True)
    def test_handle_batch_sorted_by_priority(self, mock_verify):
        handler = self._make_handler()
        actions = [
            self._make_action(priority=4),
            self._make_action(priority=1),
            self._make_action(priority=3),
        ]
        results = handler.handle_batch(actions)
        assert len(results) == 3
        # All should succeed
        assert all(results.values())

    @patch("shared.mssp.recommendation_handler.verify_recommendation_signature", return_value=True)
    def test_rate_limiting(self, mock_verify):
        from shared.mssp.recommendation_handler import MAX_RECOMMENDATIONS_PER_MINUTE
        handler = self._make_handler()
        # Exhaust rate limit
        for _ in range(MAX_RECOMMENDATIONS_PER_MINUTE):
            handler.handle(self._make_action())
        # Next should be rate limited
        assert handler.handle(self._make_action()) is False
        assert handler.get_stats()["rejected_rate_limit"] >= 1

    @patch("shared.mssp.recommendation_handler.verify_recommendation_signature", return_value=True)
    def test_audit_trail(self, mock_verify):
        handler = self._make_handler()
        action = self._make_action()
        handler.handle(action)
        trail = handler.get_audit_trail()
        assert len(trail) == 1
        assert trail[0]["status"] == "executed"

    @patch("shared.mssp.recommendation_handler.verify_recommendation_signature", return_value=True)
    def test_execute_callback_failure(self, mock_verify):
        handler = self._make_handler(execute_callback=lambda d: False)
        action = self._make_action()
        assert handler.handle(action) is False
        assert handler.get_stats()["failed"] == 1

    @patch("shared.mssp.recommendation_handler.verify_recommendation_signature", return_value=True)
    def test_no_execute_callback(self, mock_verify):
        from shared.mssp.recommendation_handler import RecommendationHandler
        handler = RecommendationHandler()
        action = self._make_action()
        assert handler.handle(action) is False


# ==============================================================
# Mesh Propagation Tests
# ==============================================================

class TestMeshPropagation:
    """Tests for shared/mssp/mesh_propagation.py"""

    def test_propagator_no_mesh(self):
        from shared.mssp.mesh_propagation import MeshPropagator
        from shared.mssp.types import RecommendedAction
        p = MeshPropagator()
        action = RecommendedAction(mesh_propagate=True)
        assert p.propagate(action) is False

    def test_propagator_not_mesh_propagate(self):
        from shared.mssp.mesh_propagation import MeshPropagator
        from shared.mssp.types import RecommendedAction
        p = MeshPropagator(mesh_consciousness=MagicMock())
        action = RecommendedAction(mesh_propagate=False)
        assert p.propagate(action) is False

    @patch("shared.mssp.mesh_propagation.verify_recommendation_signature", return_value=True)
    def test_propagate_success(self, mock_verify):
        from shared.mssp.mesh_propagation import MeshPropagator
        from shared.mssp.types import RecommendedAction

        mesh = MagicMock()
        dsm = MagicMock()
        p = MeshPropagator(mesh_consciousness=mesh, dsm_node=dsm)

        action = RecommendedAction(
            action_type="block_ip",
            target="203.0.113.1",
            mesh_propagate=True,
            confidence=0.9,
            priority=2,
            signature="valid",
        )

        assert p.propagate(action) is True
        mesh.report_threat.assert_called_once()
        dsm.create_microblock.assert_called_once()
        assert p.get_stats()["propagated"] == 1

    @patch("shared.mssp.mesh_propagation.verify_recommendation_signature", return_value=False)
    def test_propagate_invalid_signature(self, mock_verify):
        from shared.mssp.mesh_propagation import MeshPropagator
        from shared.mssp.types import RecommendedAction

        p = MeshPropagator(mesh_consciousness=MagicMock())
        action = RecommendedAction(
            mesh_propagate=True,
            signature="invalid",
        )
        assert p.propagate(action) is False
        assert p.get_stats()["rejected_signature"] == 1

    @patch("shared.mssp.mesh_propagation.verify_recommendation_signature", return_value=True)
    def test_handle_mesh_intel_dispatches(self, mock_verify):
        from shared.mssp.mesh_propagation import MeshPropagator, RECOMMENDATION_INTEL_TYPE
        from shared.mssp.types import RecommendedAction

        callback = MagicMock()
        p = MeshPropagator()
        p.on_recommendation(callback)

        action = RecommendedAction(action_type="block_ip", target="1.2.3.4")
        intel = MagicMock()
        intel.context = {
            "type": RECOMMENDATION_INTEL_TYPE,
            "action": action.to_dict(),
        }

        p.handle_mesh_intel(intel)
        callback.assert_called_once()
        assert p.get_stats()["received_from_mesh"] == 1

    def test_handle_mesh_intel_ignores_non_recommendation(self):
        from shared.mssp.mesh_propagation import MeshPropagator
        p = MeshPropagator()
        intel = MagicMock()
        intel.context = {"type": "threat_intel"}
        p.handle_mesh_intel(intel)
        assert p.get_stats()["received_from_mesh"] == 0

    @patch("shared.mssp.mesh_propagation.verify_recommendation_signature", return_value=False)
    def test_handle_mesh_intel_rejects_bad_signature(self, mock_verify):
        from shared.mssp.mesh_propagation import MeshPropagator, RECOMMENDATION_INTEL_TYPE
        p = MeshPropagator()
        intel = MagicMock()
        intel.context = {
            "type": RECOMMENDATION_INTEL_TYPE,
            "action": {"action_type": "block_ip", "signature": "bad"},
        }
        p.handle_mesh_intel(intel)
        assert p.get_stats()["rejected_signature"] == 1

    def test_priority_to_severity(self):
        from shared.mssp.mesh_propagation import MeshPropagator
        assert MeshPropagator._priority_to_severity(1) == 1
        assert MeshPropagator._priority_to_severity(5) == 5
        assert MeshPropagator._priority_to_severity(0) == 1  # clamped
        assert MeshPropagator._priority_to_severity(10) == 5  # clamped

    def test_infer_ioc_type(self):
        from shared.mssp.mesh_propagation import MeshPropagator
        assert MeshPropagator._infer_ioc_type("192.168.1.1") == "ip"
        assert MeshPropagator._infer_ioc_type("evil.example.com") == "domain"
        assert MeshPropagator._infer_ioc_type("a" * 64) == "sha256"
        assert MeshPropagator._infer_ioc_type("aa:bb:cc:dd:ee:ff") == "mac"
        assert MeshPropagator._infer_ioc_type("something") == "pattern"
        assert MeshPropagator._infer_ioc_type("") == "unknown"


# ==============================================================
# AEGIS Profile Tests
# ==============================================================

class TestAEGISProfiles:
    """Tests for core/aegis/profiles/"""

    def test_get_profile_by_tier(self):
        from core.aegis.profiles import get_profile
        p = get_profile("sentinel")
        assert p["name"] == "pico"
        assert p["tier"] == "sentinel"

    def test_get_profile_by_name(self):
        from core.aegis.profiles import get_profile
        p = get_profile("deep")
        assert p["name"] == "deep"
        assert p["tier"] == "nexus"

    def test_unknown_tier_defaults_to_full(self):
        from core.aegis.profiles import get_profile
        p = get_profile("unknown_tier")
        assert p["name"] == "full"

    def test_pico_profile(self):
        from core.aegis.profiles.pico import PICO_PROFILE
        assert PICO_PROFILE["ram_budget_mb"] == 25
        assert PICO_PROFILE["inference"]["mode"] == "template"
        assert "ORACLE" in PICO_PROFILE["agents"]["enabled"]
        assert len(PICO_PROFILE["memory"]["layers"]) == 2
        assert PICO_PROFILE["bridges"]["mesh_relay"] is True

    def test_lite_profile(self):
        from core.aegis.profiles.lite import LITE_PROFILE
        assert LITE_PROFILE["tier"] == "guardian"
        assert LITE_PROFILE["inference"]["mode"] == "cloud"
        assert len(LITE_PROFILE["agents"]["enabled"]) == 8
        assert len(LITE_PROFILE["memory"]["layers"]) == 3

    def test_full_profile(self):
        from core.aegis.profiles.full import FULL_PROFILE
        assert FULL_PROFILE["tier"] == "fortress"
        assert FULL_PROFILE["inference"]["mode"] == "auto"
        assert len(FULL_PROFILE["memory"]["layers"]) == 5
        assert "napse" in FULL_PROFILE["bridges"]["enabled"]

    def test_deep_profile(self):
        from core.aegis.profiles.deep import DEEP_PROFILE
        assert DEEP_PROFILE["tier"] == "nexus"
        assert DEEP_PROFILE["ram_budget_mb"] == 4096
        assert DEEP_PROFILE["inference"]["mode"] == "auto"
        assert DEEP_PROFILE["mssp"]["nexus_worker"] is True

    def test_all_profiles_have_required_keys(self):
        from core.aegis.profiles import PROFILES
        required_keys = {"name", "tier", "ram_budget_mb", "inference", "agents", "memory", "bridges"}
        for name, profile in PROFILES.items():
            for key in required_keys:
                assert key in profile, f"Profile '{name}' missing key '{key}'"

    def test_tier_profile_mapping(self):
        from core.aegis.profiles import TIER_PROFILES
        assert TIER_PROFILES["sentinel"] == "pico"
        assert TIER_PROFILES["guardian"] == "lite"
        assert TIER_PROFILES["fortress"] == "full"
        assert TIER_PROFILES["nexus"] == "deep"


# ==============================================================
# NAPSE Bridge Tests
# ==============================================================

class TestNAPSEBridge:
    """Tests for core/aegis/bridges/napse_bridge.py"""

    @pytest.fixture
    def eve_file(self, tmp_path):
        """Create a temporary eve.json file."""
        eve = tmp_path / "eve.json"
        eve.touch()
        return eve

    def _make_bridge(self, eve_path):
        from core.aegis.bridges.napse_bridge import NAPSEBridge
        return NAPSEBridge(str(eve_path))

    def test_poll_empty_file(self, eve_file):
        bridge = self._make_bridge(eve_file)
        signals = bridge.poll()
        assert signals == []

    def test_poll_alert_event(self, eve_file):
        event = {
            "event_type": "alert",
            "src_ip": "203.0.113.10",
            "dest_ip": "10.0.0.1",
            "src_port": 12345,
            "dest_port": 443,
            "proto": "TCP",
            "timestamp": "2026-02-18T10:00:00Z",
            "alert": {
                "signature_id": 2001,
                "signature": "ET SCAN Potential SSH Scan",
                "severity": 2,
                "category": "Attempted Information Leak",
                "action": "allowed",
            },
        }
        eve_file.write_text(json.dumps(event) + "\n")

        bridge = self._make_bridge(eve_file)
        signals = bridge.poll()
        assert len(signals) == 1
        s = signals[0]
        assert s.source == "napse"
        assert s.event_type == "ids_alert"
        assert s.severity == "HIGH"  # severity 2 = HIGH
        assert s.data["src_ip"] == "203.0.113.10"
        assert s.data["signature"] == "ET SCAN Potential SSH Scan"

    def test_poll_dns_event(self, eve_file):
        event = {
            "event_type": "dns",
            "src_ip": "10.0.0.5",
            "dest_ip": "10.0.0.1",
            "dns": {
                "rrname": "normal.example.com",
                "rrtype": "A",
                "rcode": "NOERROR",
            },
        }
        eve_file.write_text(json.dumps(event) + "\n")
        bridge = self._make_bridge(eve_file)
        signals = bridge.poll()
        assert len(signals) == 1
        assert signals[0].event_type == "dns_event"
        assert signals[0].severity == "LOW"

    def test_poll_dns_tunneling_detection(self, eve_file):
        """Long DNS query → HIGH severity (potential tunneling)."""
        event = {
            "event_type": "dns",
            "src_ip": "10.0.0.5",
            "dest_ip": "10.0.0.1",
            "dns": {
                "rrname": "a" * 65 + ".evil.com",  # > 60 chars = suspicious
                "rrtype": "TXT",
            },
        }
        eve_file.write_text(json.dumps(event) + "\n")
        bridge = self._make_bridge(eve_file)
        signals = bridge.poll()
        assert signals[0].severity == "HIGH"

    def test_poll_tls_downgrade(self, eve_file):
        event = {
            "event_type": "tls",
            "src_ip": "10.0.0.5",
            "dest_ip": "1.2.3.4",
            "tls": {"version": "TLSv1.0", "sni": "old.example.com"},
        }
        eve_file.write_text(json.dumps(event) + "\n")
        bridge = self._make_bridge(eve_file)
        signals = bridge.poll()
        assert signals[0].severity == "MEDIUM"
        assert signals[0].data["tls_version"] == "TLSv1.0"

    def test_poll_ignores_stats(self, eve_file):
        event = {"event_type": "stats", "uptime": 12345}
        eve_file.write_text(json.dumps(event) + "\n")
        bridge = self._make_bridge(eve_file)
        signals = bridge.poll()
        assert signals == []

    def test_poll_ignores_unknown_event(self, eve_file):
        event = {"event_type": "custom_unknown_type"}
        eve_file.write_text(json.dumps(event) + "\n")
        bridge = self._make_bridge(eve_file)
        signals = bridge.poll()
        assert signals == []

    def test_poll_handles_invalid_json(self, eve_file):
        eve_file.write_text("not valid json\n")
        bridge = self._make_bridge(eve_file)
        signals = bridge.poll()
        assert signals == []
        assert bridge._events_errors == 1

    def test_poll_tracks_offset(self, eve_file):
        """Only reads new lines on subsequent polls."""
        event1 = {"event_type": "alert", "alert": {"severity": 1, "signature": "test1"}}
        event2 = {"event_type": "alert", "alert": {"severity": 1, "signature": "test2"}}

        eve_file.write_text(json.dumps(event1) + "\n")
        bridge = self._make_bridge(eve_file)
        signals1 = bridge.poll()
        assert len(signals1) == 1

        # Append new event
        with open(eve_file, 'a') as f:
            f.write(json.dumps(event2) + "\n")

        signals2 = bridge.poll()
        assert len(signals2) == 1
        assert signals2[0].data.get("signature") == "test2"

    def test_poll_handles_file_rotation(self, tmp_path):
        """File rotation resets offset when inode changes."""
        eve1 = tmp_path / "eve.json"
        event = {"event_type": "alert", "alert": {"severity": 1}}
        eve1.write_text(json.dumps(event) + "\n")
        bridge = self._make_bridge(eve1)
        bridge.poll()
        old_offset = bridge._file_offset
        assert old_offset > 0

        # Simulate truncation (common log rotation pattern)
        eve1.write_text("")
        signals = bridge.poll()
        assert bridge._file_offset == 0  # offset reset on truncation

    def test_poll_handles_truncation(self, eve_file):
        long_event = {"event_type": "alert", "alert": {"severity": 1}, "extra": "x" * 500}
        eve_file.write_text(json.dumps(long_event) + "\n")
        bridge = self._make_bridge(eve_file)
        bridge.poll()
        assert bridge._file_offset > 0

        # Truncate file
        eve_file.write_text("")
        signals = bridge.poll()
        assert signals == []

    def test_nonexistent_file(self):
        from core.aegis.bridges.napse_bridge import NAPSEBridge
        bridge = NAPSEBridge("/nonexistent/path/eve.json")
        signals = bridge.poll()
        assert signals == []

    def test_get_stats(self, eve_file):
        bridge = self._make_bridge(eve_file)
        stats = bridge.get_stats()
        assert "eve_path" in stats
        assert stats["events_processed"] == 0

    def test_flow_event(self, eve_file):
        event = {
            "event_type": "flow",
            "src_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "proto": "TCP",
        }
        eve_file.write_text(json.dumps(event) + "\n")
        bridge = self._make_bridge(eve_file)
        signals = bridge.poll()
        assert len(signals) == 1
        assert signals[0].event_type == "flow_event"
        assert signals[0].severity == "INFO"

    def test_http_event(self, eve_file):
        event = {
            "event_type": "http",
            "src_ip": "10.0.0.5",
            "dest_ip": "1.2.3.4",
            "http": {
                "hostname": "example.com",
                "url": "/api/test",
                "http_method": "GET",
                "status": 200,
            },
        }
        eve_file.write_text(json.dumps(event) + "\n")
        bridge = self._make_bridge(eve_file)
        signals = bridge.poll()
        assert len(signals) == 1
        assert signals[0].event_type == "http_event"
        assert signals[0].data["hostname"] == "example.com"

    def test_fileinfo_event(self, eve_file):
        event = {
            "event_type": "fileinfo",
            "src_ip": "10.0.0.5",
            "fileinfo": {
                "filename": "malware.exe",
                "size": 12345,
                "sha256": "a" * 64,
            },
        }
        eve_file.write_text(json.dumps(event) + "\n")
        bridge = self._make_bridge(eve_file)
        signals = bridge.poll()
        assert len(signals) == 1
        assert signals[0].event_type == "file_detected"
        assert signals[0].data["filename"] == "malware.exe"


# ==============================================================
# Sentinel Defense Engine Tests
# ==============================================================

class TestSentinelDefense:
    """Tests for products/sentinel/lib/defense.py"""

    def test_validate_ip_valid(self):
        from products.sentinel.lib.defense import _validate_ip
        assert _validate_ip("203.0.113.1") is True
        assert _validate_ip("8.8.8.8") is True

    def test_validate_ip_invalid(self):
        from products.sentinel.lib.defense import _validate_ip
        assert _validate_ip("") is False
        assert _validate_ip("not_an_ip") is False
        assert _validate_ip("256.0.0.1") is False
        assert _validate_ip("1.2.3") is False

    def test_validate_domain_valid(self):
        from products.sentinel.lib.defense import _validate_domain
        assert _validate_domain("example.com") is True
        assert _validate_domain("sub.domain.example.com") is True

    def test_validate_domain_invalid(self):
        from products.sentinel.lib.defense import _validate_domain
        assert _validate_domain("") is False
        assert _validate_domain("a" * 254) is False  # too long

    @patch("products.sentinel.lib.defense.subprocess.run")
    def test_block_ip_success(self, mock_run):
        from products.sentinel.lib.defense import SentinelDefenseEngine
        engine = SentinelDefenseEngine()
        try:
            assert engine.block_ip("203.0.113.1", 3600, "test") is True
            mock_run.assert_called_once()
            blocked = engine.get_blocked()
            assert "203.0.113.1" in blocked
        finally:
            engine.stop()

    @patch("products.sentinel.lib.defense.subprocess.run")
    def test_block_ip_rejects_private(self, mock_run):
        from products.sentinel.lib.defense import SentinelDefenseEngine
        engine = SentinelDefenseEngine()
        try:
            assert engine.block_ip("192.168.1.1") is False
            assert engine.block_ip("10.0.0.1") is False
            assert engine.block_ip("127.0.0.1") is False
            mock_run.assert_not_called()
        finally:
            engine.stop()

    @patch("products.sentinel.lib.defense.subprocess.run")
    def test_block_ip_max_duration(self, mock_run):
        from products.sentinel.lib.defense import SentinelDefenseEngine, MAX_BLOCK_DURATION
        engine = SentinelDefenseEngine()
        try:
            engine.block_ip("203.0.113.1", 999999, "test")
            blocked = engine.get_blocked()
            # Duration should be clamped
            remaining = blocked["203.0.113.1"]["expires"] - time.time()
            assert remaining <= MAX_BLOCK_DURATION + 1
        finally:
            engine.stop()

    @patch("products.sentinel.lib.defense.subprocess.run")
    def test_block_ip_max_count(self, mock_run):
        from products.sentinel.lib.defense import SentinelDefenseEngine, MAX_BLOCKED_IPS
        engine = SentinelDefenseEngine()
        try:
            # Fill to max
            for i in range(MAX_BLOCKED_IPS):
                engine.block_ip(f"203.0.{i // 256}.{i % 256}", 3600, "fill")
            # Next should fail
            assert engine.block_ip("198.51.100.1", 3600, "overflow") is False
        finally:
            engine.stop()

    @patch("products.sentinel.lib.defense.subprocess.run")
    def test_dns_sinkhole(self, mock_run):
        from products.sentinel.lib.defense import SentinelDefenseEngine
        engine = SentinelDefenseEngine()
        try:
            with patch.object(engine, '_write_sinkhole_file'):
                assert engine.dns_sinkhole("evil.example.com", "malware") is True
            sinkholed = engine.get_sinkholed()
            assert "evil.example.com" in sinkholed
        finally:
            engine.stop()

    @patch("products.sentinel.lib.defense.subprocess.run")
    def test_dns_sinkhole_invalid_domain(self, mock_run):
        from products.sentinel.lib.defense import SentinelDefenseEngine
        engine = SentinelDefenseEngine()
        try:
            assert engine.dns_sinkhole("") is False
        finally:
            engine.stop()

    @patch("products.sentinel.lib.defense.subprocess.run")
    def test_rate_limit(self, mock_run):
        from products.sentinel.lib.defense import SentinelDefenseEngine
        engine = SentinelDefenseEngine()
        try:
            assert engine.rate_limit("203.0.113.1", "flood", 100) is True
            mock_run.assert_called_once()
        finally:
            engine.stop()

    @patch("products.sentinel.lib.defense.subprocess.run")
    def test_rate_limit_clamped(self, mock_run):
        from products.sentinel.lib.defense import SentinelDefenseEngine
        engine = SentinelDefenseEngine()
        try:
            # pps should be clamped to 10-1000
            engine.rate_limit("203.0.113.1", "test", 1)  # below min
            args = mock_run.call_args[0][0]
            assert "10/second" in " ".join(args)  # clamped to 10
        finally:
            engine.stop()

    def test_get_stats(self):
        from products.sentinel.lib.defense import SentinelDefenseEngine
        engine = SentinelDefenseEngine()
        try:
            stats = engine.get_stats()
            assert stats["blocked_ips"] == 0
            assert stats["running"] is True
        finally:
            engine.stop()


# ==============================================================
# AEGIS-Pico Tests
# ==============================================================

class TestAegisPico:
    """Tests for products/sentinel/lib/aegis_pico.py"""

    def test_pico_memory_store_and_lookup(self):
        from products.sentinel.lib.aegis_pico import PicoMemory
        mem = PicoMemory(max_session=5, max_threat=10)
        mem.store_threat("1.2.3.4", {"severity": "HIGH"})
        result = mem.lookup_threat("1.2.3.4")
        assert result["severity"] == "HIGH"

    def test_pico_memory_eviction(self):
        from products.sentinel.lib.aegis_pico import PicoMemory
        mem = PicoMemory(max_session=2, max_threat=2)
        mem.store_threat("a", {"v": 1})
        mem.store_threat("b", {"v": 2})
        mem.store_threat("c", {"v": 3})  # should evict "a"
        assert mem.lookup_threat("a") is None
        assert mem.lookup_threat("c") is not None

    def test_pico_memory_session(self):
        from products.sentinel.lib.aegis_pico import PicoMemory
        mem = PicoMemory(max_session=2)
        mem.store_session("k1", "v1")
        mem.store_session("k2", "v2")
        mem.store_session("k3", "v3")  # evicts k1
        stats = mem.get_stats()
        assert stats["session_entries"] == 2

    def test_pico_signal_router_ids_alert(self):
        from products.sentinel.lib.aegis_pico import PicoSignalRouter
        from core.aegis.types import StandardSignal

        actions = []
        router = PicoSignalRouter(defense_callback=lambda a: actions.append(a))

        signal = StandardSignal(
            source="napse",
            event_type="ids_alert",
            severity="HIGH",
            data={"src_ip": "203.0.113.1", "signature": "ET SCAN"},
        )
        result = router.process_signal(signal)
        assert result is not None
        assert result["type"] == "block_ip"
        assert len(actions) == 1

    def test_pico_signal_router_low_severity_no_action(self):
        from products.sentinel.lib.aegis_pico import PicoSignalRouter
        from core.aegis.types import StandardSignal

        router = PicoSignalRouter()
        signal = StandardSignal(
            source="napse",
            event_type="ids_alert",
            severity="LOW",
            data={"src_ip": "1.2.3.4"},
        )
        result = router.process_signal(signal)
        assert result is None

    def test_pico_signal_router_dns_suspicious(self):
        from products.sentinel.lib.aegis_pico import PicoSignalRouter
        from core.aegis.types import StandardSignal

        router = PicoSignalRouter()
        signal = StandardSignal(
            source="napse",
            event_type="dns_suspicious",
            severity="HIGH",
            data={"query": "evil.example.com"},
        )
        result = router.process_signal(signal)
        assert result is not None
        assert result["type"] == "dns_sinkhole"

    def test_aegis_pico_initialization(self):
        from products.sentinel.lib.aegis_pico import AegisPico
        pico = AegisPico()
        assert pico.profile["name"] == "pico"
        assert pico.VERSION == "1.0.0"

    def test_aegis_pico_respond_status(self):
        from products.sentinel.lib.aegis_pico import AegisPico
        pico = AegisPico()
        pico.start()
        response = pico.respond("What is my status?")
        assert "active" in response
        pico.stop()

    def test_aegis_pico_respond_unknown(self):
        from products.sentinel.lib.aegis_pico import AegisPico
        pico = AegisPico()
        response = pico.respond("tell me a joke")
        assert "AEGIS-Pico" in response

    def test_aegis_pico_process_mesh_signal(self):
        from products.sentinel.lib.aegis_pico import AegisPico
        from core.aegis.types import StandardSignal

        pico = AegisPico()
        signal = StandardSignal(
            source="mesh",
            event_type="ids_alert",
            severity="MEDIUM",
            data={"src_ip": "203.0.113.5"},
        )
        pico.process_mesh_signal(signal)
        threat = pico.memory.lookup_threat("203.0.113.5")
        assert threat is not None

    def test_aegis_pico_principle_guard(self):
        from products.sentinel.lib.aegis_pico import AegisPico
        pico = AegisPico()
        # Forbidden actions should be rejected
        assert pico.execute_recommendation({"action_type": "disable_firewall"}) is False
        assert pico.execute_recommendation({"action_type": "stop_aegis"}) is False

    def test_aegis_pico_get_status(self):
        from products.sentinel.lib.aegis_pico import AegisPico
        pico = AegisPico()
        status = pico.get_status()
        assert status["profile"] == "pico"
        assert status["tier"] == "sentinel"
        assert "principles" in status


# ==============================================================
# Nexus Threat Correlator Tests
# ==============================================================

class TestThreatCorrelator:
    """Tests for products/nexus/lib/intelligence/correlator.py"""

    def test_ingest_single(self):
        from products.nexus.lib.intelligence.correlator import ThreatCorrelator
        c = ThreatCorrelator()
        result = c.ingest("1.2.3.4", "ip", "node-1", "HIGH")
        assert result.hit_count == 1
        assert result.ioc_value == "1.2.3.4"
        assert "node-1" in result.source_nodes
        assert result.is_campaign is False

    def test_ingest_multiple_sources(self):
        from products.nexus.lib.intelligence.correlator import ThreatCorrelator
        c = ThreatCorrelator()
        c.ingest("1.2.3.4", "ip", "node-1")
        c.ingest("1.2.3.4", "ip", "node-2")
        result = c.ingest("1.2.3.4", "ip", "node-3")
        assert result.hit_count == 3
        assert len(result.source_nodes) == 3
        assert result.is_campaign is True  # 3+ nodes

    def test_campaign_detection(self):
        from products.nexus.lib.intelligence.correlator import ThreatCorrelator
        c = ThreatCorrelator()
        for i in range(5):
            c.ingest("evil.com", "domain", f"node-{i}")
        campaigns = c.get_campaigns()
        assert len(campaigns) == 1
        assert campaigns[0].ioc_value == "evil.com"

    def test_correlate_found(self):
        from products.nexus.lib.intelligence.correlator import ThreatCorrelator
        c = ThreatCorrelator()
        c.ingest("1.2.3.4", "ip", "node-1", "HIGH")
        result = c.correlate("1.2.3.4", "ip")
        assert result is not None
        assert result.severity_max == "HIGH"

    def test_correlate_not_found(self):
        from products.nexus.lib.intelligence.correlator import ThreatCorrelator
        c = ThreatCorrelator()
        assert c.correlate("5.6.7.8", "ip") is None

    def test_severity_tracking(self):
        from products.nexus.lib.intelligence.correlator import ThreatCorrelator
        c = ThreatCorrelator()
        c.ingest("1.2.3.4", "ip", "node-1", "LOW")
        c.ingest("1.2.3.4", "ip", "node-2", "CRITICAL")
        result = c.correlate("1.2.3.4", "ip")
        assert result.severity_max == "CRITICAL"

    def test_get_node_iocs(self):
        from products.nexus.lib.intelligence.correlator import ThreatCorrelator
        c = ThreatCorrelator()
        c.ingest("1.2.3.4", "ip", "node-1")
        c.ingest("evil.com", "domain", "node-1")
        iocs = c.get_node_iocs("node-1")
        assert len(iocs) == 2

    def test_cleanup_expired(self):
        from products.nexus.lib.intelligence.correlator import ThreatCorrelator
        c = ThreatCorrelator()
        c.IOC_TTL = 0  # Expire immediately
        c.ingest("1.2.3.4", "ip", "node-1")
        time.sleep(0.01)
        removed = c.cleanup()
        assert removed == 1
        assert c.correlate("1.2.3.4", "ip") is None

    def test_eviction_at_max(self):
        from products.nexus.lib.intelligence.correlator import ThreatCorrelator
        c = ThreatCorrelator()
        c.MAX_IOCS = 3
        c.ingest("a", "ip", "n1")
        time.sleep(0.01)
        c.ingest("b", "ip", "n1")
        time.sleep(0.01)
        c.ingest("c", "ip", "n1")
        time.sleep(0.01)
        c.ingest("d", "ip", "n1")  # Should evict "a"
        assert c.correlate("a", "ip") is None
        assert c.correlate("d", "ip") is not None

    def test_get_stats(self):
        from products.nexus.lib.intelligence.correlator import ThreatCorrelator
        c = ThreatCorrelator()
        c.ingest("1.2.3.4", "ip", "node-1")
        stats = c.get_stats()
        assert stats["total_iocs"] == 1
        assert stats["tracked_nodes"] == 1


# ==============================================================
# Nexus Action Recommender Tests
# ==============================================================

class TestActionRecommender:
    """Tests for products/nexus/lib/intelligence/recommender.py"""

    def test_recommend_by_mitre(self):
        from products.nexus.lib.intelligence.recommender import ActionRecommender
        r = ActionRecommender("nexus-test")
        recs = r.recommend(
            finding={"finding_id": "f1", "severity": "HIGH", "ioc_value": "1.2.3.4"},
            mitre_id="T1190",  # Exploit Public-Facing Application → block_ip
        )
        assert len(recs) >= 1
        assert recs[0].action_type == "block_ip"
        assert recs[0].priority <= 2  # HIGH

    def test_recommend_by_severity_fallback(self):
        from products.nexus.lib.intelligence.recommender import ActionRecommender
        r = ActionRecommender("nexus-test")
        recs = r.recommend(
            finding={"finding_id": "f1", "severity": "MEDIUM", "ioc_value": "1.2.3.4"},
        )
        assert len(recs) >= 1
        assert recs[0].action_type == "rate_limit"

    def test_recommend_campaign_boost(self):
        from products.nexus.lib.intelligence.recommender import ActionRecommender
        from products.nexus.lib.intelligence.correlator import CorrelationResult

        r = ActionRecommender("nexus-test")
        corr = CorrelationResult("1.2.3.4", "ip")
        corr.is_campaign = True
        corr.source_nodes = {"n1", "n2", "n3", "n4"}

        recs = r.recommend(
            finding={"finding_id": "f1", "severity": "MEDIUM", "ioc_value": "1.2.3.4"},
            correlation=corr,
        )
        assert recs[0].mesh_propagate is True
        assert "CAMPAIGN" in recs[0].reasoning

    def test_recommend_mesh_propagate_high(self):
        from products.nexus.lib.intelligence.recommender import ActionRecommender
        r = ActionRecommender("nexus-test")
        recs = r.recommend(
            finding={"finding_id": "f1", "severity": "HIGH", "ioc_value": "1.2.3.4"},
        )
        # HIGH priority → mesh_propagate = True
        assert recs[0].mesh_propagate is True

    def test_recommend_ttl_by_priority(self):
        from products.nexus.lib.intelligence.recommender import ActionRecommender
        r = ActionRecommender()
        recs = r.recommend(
            finding={"finding_id": "f1", "severity": "CRITICAL", "ioc_value": "1.2.3.4"},
        )
        assert recs[0].ttl_seconds == 86400  # CRITICAL = 24h

    def test_recommend_info_severity(self):
        from products.nexus.lib.intelligence.recommender import ActionRecommender
        r = ActionRecommender()
        recs = r.recommend(
            finding={"finding_id": "f1", "severity": "INFO", "ioc_value": "1.2.3.4"},
        )
        assert recs[0].action_type == "alert"
        assert recs[0].priority == 5  # INFO

    def test_get_stats(self):
        from products.nexus.lib.intelligence.recommender import ActionRecommender
        r = ActionRecommender()
        r.recommend(finding={"severity": "LOW", "ioc_value": "x"})
        stats = r.get_stats()
        assert stats["recommendations_generated"] >= 1


# ==============================================================
# Nexus Analysis Engine Tests
# ==============================================================

class TestNexusAnalysisEngine:
    """Tests for products/nexus/lib/intelligence/analysis_engine.py"""

    def test_analyze_basic(self):
        from products.nexus.lib.intelligence.analysis_engine import NexusAnalysisEngine
        from shared.mssp.types import ThreatFinding

        engine = NexusAnalysisEngine("nexus-test")
        finding = ThreatFinding(
            threat_type="port_scan",
            severity="MEDIUM",
            confidence=0.6,
            ioc_value="203.0.113.1",
            ioc_type="ip",
            source_node_id="guardian-01",
        )
        result = engine.analyze(finding)
        assert result.threat_assessment in ("confirmed", "likely", "possible", "false_positive")
        assert result.confidence > 0
        assert result.analysis_duration_ms >= 0
        assert result.summary != ""

    def test_analyze_mitre_classification(self):
        from products.nexus.lib.intelligence.analysis_engine import NexusAnalysisEngine
        from shared.mssp.types import ThreatFinding

        engine = NexusAnalysisEngine()
        finding = ThreatFinding(
            threat_type="brute_force",  # Maps to T1110
            severity="HIGH",
            confidence=0.8,
            ioc_value="1.2.3.4",
            ioc_type="ip",
            source_node_id="sentinel-01",
        )
        result = engine.analyze(finding)
        assert "T1110" in result.mitre_techniques

    def test_analyze_campaign_detection(self):
        from products.nexus.lib.intelligence.analysis_engine import NexusAnalysisEngine
        from shared.mssp.types import ThreatFinding

        engine = NexusAnalysisEngine()
        # Ingest same IOC from multiple nodes
        for i in range(4):
            finding = ThreatFinding(
                threat_type="ids_alert",
                severity="HIGH",
                ioc_value="evil.example.com",
                ioc_type="domain",
                source_node_id=f"node-{i}",
            )
            result = engine.analyze(finding)

        assert result.is_campaign is True
        assert result.threat_assessment == "confirmed"

    def test_analyze_generates_recommendations(self):
        from products.nexus.lib.intelligence.analysis_engine import NexusAnalysisEngine
        from shared.mssp.types import ThreatFinding

        engine = NexusAnalysisEngine()
        finding = ThreatFinding(
            threat_type="dns_suspicious",  # Maps to T1568
            severity="HIGH",
            confidence=0.9,
            ioc_value="dga.evil.com",
            ioc_type="domain",
            source_node_id="guardian-01",
        )
        result = engine.analyze(finding)
        assert len(result.recommendations) >= 1

    def test_to_intelligence_report(self):
        from products.nexus.lib.intelligence.analysis_engine import NexusAnalysisEngine
        from shared.mssp.types import ThreatFinding

        engine = NexusAnalysisEngine("nexus-01")
        finding = ThreatFinding(
            threat_type="port_scan",
            severity="LOW",
            ioc_value="1.2.3.4",
            ioc_type="ip",
            source_node_id="sentinel-01",
        )
        result = engine.analyze(finding)
        report = engine.to_intelligence_report(result)
        assert report.analyzed_by == "nexus-01"
        d = report.to_dict()
        assert "threat_assessment" in d

    def test_confidence_boosted_by_correlation(self):
        from products.nexus.lib.intelligence.analysis_engine import NexusAnalysisEngine
        from shared.mssp.types import ThreatFinding

        engine = NexusAnalysisEngine()
        # Single observation
        f1 = ThreatFinding(
            threat_type="ids_alert", severity="MEDIUM",
            confidence=0.5, ioc_value="scan-ip", ioc_type="ip",
            source_node_id="node-1",
        )
        r1 = engine.analyze(f1)

        # Same IOC from another node
        f2 = ThreatFinding(
            threat_type="ids_alert", severity="MEDIUM",
            confidence=0.5, ioc_value="scan-ip", ioc_type="ip",
            source_node_id="node-2",
        )
        r2 = engine.analyze(f2)
        assert r2.confidence >= r1.confidence  # Multi-source boost

    def test_get_stats(self):
        from products.nexus.lib.intelligence.analysis_engine import NexusAnalysisEngine
        from shared.mssp.types import ThreatFinding

        engine = NexusAnalysisEngine()
        engine.analyze(ThreatFinding(
            threat_type="scan", ioc_value="x", ioc_type="ip", source_node_id="n1",
        ))
        stats = engine.get_stats()
        assert stats["findings_analyzed"] == 1

    def test_summary_format(self):
        from products.nexus.lib.intelligence.analysis_engine import NexusAnalysisEngine
        from shared.mssp.types import ThreatFinding

        engine = NexusAnalysisEngine()
        finding = ThreatFinding(
            threat_type="malware_c2",
            severity="CRITICAL",
            confidence=0.95,
            ioc_value="c2.evil.com",
            ioc_type="domain",
            source_node_id="fortress-01",
        )
        result = engine.analyze(finding)
        assert "malware_c2" in result.summary
        assert "fortress" in result.summary
        assert "Assessment:" in result.summary


# ==============================================================
# AEGIS-Deep Tests
# ==============================================================

class TestAegisDeep:
    """Tests for products/nexus/lib/aegis_deep.py"""

    @patch("core.aegis.client.AegisClient")
    @patch("core.aegis.signal_fabric.SignalFabricConfig")
    def test_initialize(self, mock_config, mock_client):
        from products.nexus.lib.aegis_deep import AegisDeep
        deep = AegisDeep("nexus-01")
        assert deep.initialize() is True
        assert deep._aegis_client is not None

    def test_get_status(self):
        from products.nexus.lib.aegis_deep import AegisDeep
        deep = AegisDeep("nexus-test")
        status = deep.get_status()
        assert status["version"] == "1.0.0"
        assert status["tier"] == "nexus"
        assert status["node_id"] == "nexus-test"


# ==============================================================
# AEGIS-Lite Tests
# ==============================================================

class TestAegisLite:
    """Tests for products/guardian/lib/aegis_lite.py"""

    def test_version(self):
        from products.guardian.lib.aegis_lite import AegisLite
        lite = AegisLite()
        assert lite.VERSION == "1.0.0"

    def test_get_status_uninitialized(self):
        from products.guardian.lib.aegis_lite import AegisLite
        lite = AegisLite()
        status = lite.get_status()
        assert status["profile"] == "lite"
        assert status["tier"] == "guardian"

    def test_submit_finding_no_client(self):
        from products.guardian.lib.aegis_lite import AegisLite
        lite = AegisLite()
        assert lite.submit_finding(MagicMock()) is False

    def test_handle_recommendation_no_handler(self):
        from products.guardian.lib.aegis_lite import AegisLite
        lite = AegisLite()
        assert lite.handle_recommendation(MagicMock()) is False

    def test_chat_no_client(self):
        from products.guardian.lib.aegis_lite import AegisLite
        lite = AegisLite()
        assert lite.chat("session-1", "hello") is None


# ==============================================================
# Nexus MSSP Worker Tests
# ==============================================================

class TestNexusMSSPWorker:
    """Tests for products/nexus/lib/intelligence/mssp_worker.py"""

    def test_worker_initialization(self):
        from products.nexus.lib.intelligence.mssp_worker import NexusMSSPWorker
        worker = NexusMSSPWorker(nexus_node_id="nexus-01", poll_interval=10)
        assert worker._nexus_node_id == "nexus-01"
        assert worker._poll_interval == 10

    def test_analyze_finding(self):
        from products.nexus.lib.intelligence.mssp_worker import NexusMSSPWorker
        from shared.mssp.types import ThreatFinding

        worker = NexusMSSPWorker(
            nexus_node_id="nexus-01",
            mssp_client=MagicMock(),
        )
        finding = ThreatFinding(
            threat_type="port_scan",
            severity="HIGH",
            ioc_value="1.2.3.4",
            ioc_type="ip",
            source_node_id="sentinel-01",
        )
        assert worker.analyze_finding(finding) is True
        assert worker.get_stats()["jobs_completed"] == 1

    def test_get_stats(self):
        from products.nexus.lib.intelligence.mssp_worker import NexusMSSPWorker
        worker = NexusMSSPWorker()
        stats = worker.get_stats()
        assert stats["jobs_pulled"] == 0
        assert stats["running"] is False


# ==============================================================
# E2E Intelligence Loop Tests
# ==============================================================

class TestIntelligenceLoopE2E:
    """End-to-end tests for the intelligence loop:
    Detection → Finding → Analysis → Recommendation → Propagation → Execution
    """

    def test_finding_to_analysis_to_recommendation(self):
        """Simulate: Guardian detects threat → Nexus analyzes → produces recommendation."""
        from shared.mssp.types import ThreatFinding
        from products.nexus.lib.intelligence.analysis_engine import NexusAnalysisEngine

        # Step 1: Guardian creates a finding
        finding = ThreatFinding(
            source_tier="guardian",
            source_node_id="guardian-home-01",
            threat_type="dns_suspicious",
            severity="HIGH",
            confidence=0.85,
            ioc_type="domain",
            ioc_value="c2-server.evil.net",
            needs_deep_analysis=True,
        )

        # Step 2: Nexus analyzes it
        engine = NexusAnalysisEngine("nexus-central")
        result = engine.analyze(finding)

        # Step 3: Verify recommendations produced
        assert result.threat_assessment in ("likely", "possible", "confirmed")
        assert len(result.recommendations) >= 1

        rec = result.recommendations[0]
        assert rec.target == "c2-server.evil.net"
        assert rec.confidence > 0

    @patch("shared.mssp.mesh_propagation.verify_recommendation_signature", return_value=True)
    def test_recommendation_mesh_propagation(self, mock_verify):
        """Simulate: Nexus recommendation → mesh gossip → edge node receives."""
        from shared.mssp.mesh_propagation import MeshPropagator
        from shared.mssp.types import RecommendedAction, ActionPriority

        # Create recommendation
        action = RecommendedAction(
            action_type="block_ip",
            target="203.0.113.50",
            confidence=0.9,
            priority=ActionPriority.HIGH.value,
            mesh_propagate=True,
            reasoning="Nexus analysis: malware C2 server",
            signature="valid-sig",
        )

        # Step 1: Propagate to mesh
        mesh = MagicMock()
        dsm = MagicMock()
        propagator = MeshPropagator(mesh_consciousness=mesh, dsm_node=dsm)
        assert propagator.propagate(action) is True
        mesh.report_threat.assert_called_once()

        # Step 2: Simulate receiving on another node
        received_actions = []
        receiving_propagator = MeshPropagator()
        receiving_propagator.on_recommendation(lambda a: received_actions.append(a))

        # Simulate incoming gossip
        from shared.mssp.mesh_propagation import RECOMMENDATION_INTEL_TYPE
        intel = MagicMock()
        intel.context = {
            "type": RECOMMENDATION_INTEL_TYPE,
            "action": action.to_dict(),
        }
        receiving_propagator.handle_mesh_intel(intel)
        assert len(received_actions) == 1
        assert received_actions[0].target == "203.0.113.50"

    def test_napse_to_aegis_pico_defense(self):
        """Simulate: NAPSE alert → AEGIS-Pico → defense action."""
        from core.aegis.types import StandardSignal
        from products.sentinel.lib.aegis_pico import AegisPico

        pico = AegisPico()
        defense_actions = []

        mock_engine = MagicMock()
        mock_engine.block_ip.return_value = True
        pico.set_defense_engine(mock_engine)

        # Simulate NAPSE alert arriving via mesh
        signal = StandardSignal(
            source="napse",
            event_type="ids_alert",
            severity="HIGH",
            data={
                "src_ip": "198.51.100.5",
                "signature": "ET SCAN SSH Brute Force",
                "signature_id": 2001219,
            },
        )
        pico.process_mesh_signal(signal)

        # Defense engine should have been called
        mock_engine.block_ip.assert_called_once_with(
            "198.51.100.5", 3600, "ET SCAN SSH Brute Force",
        )

    def test_napse_bridge_to_analysis(self, tmp_path):
        """Simulate: NAPSE eve.json → bridge → signal → analysis engine."""
        from core.aegis.bridges.napse_bridge import NAPSEBridge
        from products.nexus.lib.intelligence.analysis_engine import NexusAnalysisEngine
        from shared.mssp.types import ThreatFinding

        # Create eve.json with alert
        eve_file = tmp_path / "eve.json"
        event = {
            "event_type": "alert",
            "src_ip": "198.51.100.10",
            "dest_ip": "10.0.0.1",
            "alert": {
                "signature_id": 2100,
                "signature": "ET MALWARE C2 Beacon",
                "severity": 1,  # CRITICAL
                "category": "Malware Command and Control",
            },
        }
        eve_file.write_text(json.dumps(event) + "\n")

        # Bridge reads the event
        bridge = NAPSEBridge(str(eve_file))
        signals = bridge.poll()
        assert len(signals) == 1
        assert signals[0].severity == "CRITICAL"

        # Convert signal to finding for Nexus analysis
        s = signals[0]
        finding = ThreatFinding(
            source_tier="fortress",
            source_node_id="fortress-01",
            threat_type=s.event_type,
            severity=s.severity,
            confidence=0.9,
            ioc_type="ip",
            ioc_value=s.data["src_ip"],
            raw_evidence=s.data,
            needs_deep_analysis=True,
        )

        # Nexus analyzes
        engine = NexusAnalysisEngine("nexus-01")
        result = engine.analyze(finding)
        assert result.threat_assessment in ("likely", "confirmed", "possible")
        assert len(result.recommendations) >= 1

    @patch("shared.mssp.recommendation_handler.verify_recommendation_signature", return_value=True)
    def test_full_loop_sentinel_to_nexus_and_back(self, mock_verify):
        """Full intelligence loop: Sentinel → MSSP → Nexus → Recommendation → Sentinel."""
        from core.aegis.types import StandardSignal
        from products.sentinel.lib.aegis_pico import AegisPico
        from products.nexus.lib.intelligence.analysis_engine import NexusAnalysisEngine
        from shared.mssp.types import ThreatFinding, RecommendedAction
        from shared.mssp.recommendation_handler import RecommendationHandler

        # Step 1: Sentinel detects threat via mesh relay
        pico = AegisPico()
        mock_defense = MagicMock()
        mock_defense.block_ip.return_value = True
        pico.set_defense_engine(mock_defense)

        signal = StandardSignal(
            source="mesh",
            event_type="ids_alert",
            severity="HIGH",
            data={"src_ip": "198.51.100.20", "signature": "Port Scan"},
        )
        pico.process_mesh_signal(signal)

        # Step 2: Finding would be submitted to MSSP (simulated)
        finding = ThreatFinding(
            source_tier="sentinel",
            source_node_id="sentinel-01",
            threat_type="ids_alert",
            severity="HIGH",
            confidence=0.7,
            ioc_type="ip",
            ioc_value="198.51.100.20",
            needs_deep_analysis=True,
        )

        # Step 3: Nexus analyzes the finding
        engine = NexusAnalysisEngine("nexus-01")
        result = engine.analyze(finding)
        assert len(result.recommendations) >= 1

        # Step 4: Recommendation comes back to Sentinel
        rec = result.recommendations[0]
        rec.signature = "valid"  # Would be signed by MSSP

        executed_actions = []
        handler = RecommendationHandler(
            mssp_client=MagicMock(),
            execute_callback=lambda d: executed_actions.append(d) or True,
        )
        assert handler.handle(rec) is True
        assert len(executed_actions) == 1

    def test_multi_tier_correlation(self):
        """Multiple tiers report same IOC → campaign detected."""
        from shared.mssp.types import ThreatFinding
        from products.nexus.lib.intelligence.analysis_engine import NexusAnalysisEngine

        engine = NexusAnalysisEngine("nexus-01")
        ioc = "evil-campaign.example.com"

        # Multiple tiers report same IOC
        tiers = [
            ("sentinel", "sentinel-01"),
            ("guardian", "guardian-01"),
            ("fortress", "fortress-01"),
            ("guardian", "guardian-02"),
        ]

        for tier, node_id in tiers:
            finding = ThreatFinding(
                source_tier=tier,
                source_node_id=node_id,
                threat_type="dns_suspicious",
                severity="HIGH",
                confidence=0.8,
                ioc_type="domain",
                ioc_value=ioc,
            )
            result = engine.analyze(finding)

        # After 4 nodes report same IOC, should be a campaign
        assert result.is_campaign is True
        assert result.threat_assessment == "confirmed"
        assert "CAMPAIGN" in result.summary


# ==============================================================
# Webhook Receiver Tests
# ==============================================================

class TestWebhookReceiver:
    """Tests for shared/mssp/webhook_receiver.py"""

    def test_receiver_initialization(self):
        from shared.mssp.webhook_receiver import MSSPWebhookReceiver
        receiver = MSSPWebhookReceiver(port=9999)
        assert receiver._port == 9999
        assert receiver._running is False

    def test_receiver_start_stop(self):
        from shared.mssp.webhook_receiver import MSSPWebhookReceiver
        receiver = MSSPWebhookReceiver(port=0)  # port 0 = random available port
        try:
            receiver.start()
            assert receiver._running is True
        finally:
            receiver.stop()
        assert receiver._running is False


# ==============================================================
# Module Export Tests
# ==============================================================

class TestModuleExports:
    """Verify all modules export correctly."""

    def test_shared_mssp_exports(self):
        from shared.mssp import (
            ThreatFinding,
            RecommendedAction,
            ExecutionFeedback,
            DeviceMetrics,
            IntelligenceReport,
            FindingStatus,
            ActionType,
            ActionPriority,
            HookProbeMSSPClient,
            get_mssp_client,
            verify_recommendation_signature,
            RecommendationHandler,
            MSSPWebhookReceiver,
            MeshPropagator,
        )
        assert ThreatFinding is not None
        assert MeshPropagator is not None

    def test_aegis_profiles_exports(self):
        from core.aegis.profiles import (
            PROFILES,
            TIER_PROFILES,
            get_profile,
            PICO_PROFILE,
            LITE_PROFILE,
            FULL_PROFILE,
            DEEP_PROFILE,
        )
        assert len(PROFILES) == 4
        assert len(TIER_PROFILES) == 4

    def test_nexus_intelligence_exports(self):
        from products.nexus.lib.intelligence import (
            NexusAnalysisEngine,
            ThreatCorrelator,
            ActionRecommender,
            NexusMSSPWorker,
        )
        assert NexusAnalysisEngine is not None


# ==============================================================
# Orchestrator NAPSE Routing Tests
# ==============================================================

class TestOrchestratorNAPSERouting:
    """Test that NAPSE routing rules are present in the orchestrator."""

    def test_napse_routing_rules_exist(self):
        from core.aegis.orchestrator import ROUTING_RULES
        napse_rules = {k: v for k, v in ROUTING_RULES.items() if k.startswith("napse.")}
        assert "napse.ids_alert" in napse_rules
        assert "napse.anomaly" in napse_rules
        assert "napse.dns" in napse_rules
        assert "napse.tls" in napse_rules
        assert "napse.http" in napse_rules
        assert "napse.file" in napse_rules
        assert "napse.flow" in napse_rules

    def test_napse_ids_alert_routes_to_guardian(self):
        from core.aegis.orchestrator import ROUTING_RULES
        assert "GUARDIAN" in ROUTING_RULES["napse.ids_alert"]

    def test_napse_anomaly_routes_to_watchdog(self):
        from core.aegis.orchestrator import ROUTING_RULES
        assert "WATCHDOG" in ROUTING_RULES["napse.anomaly"]

    def test_napse_tls_routes_to_vigil(self):
        from core.aegis.orchestrator import ROUTING_RULES
        assert "VIGIL" in ROUTING_RULES["napse.tls"]
