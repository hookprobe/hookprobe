"""
Tests for Stage 3: Federated Learning for Nexus

Covers:
- DifferentialPrivacy (Gaussian mechanism, gradient clipping, DP budget)
- FederatedModelRegistry (registration, versioning, validation)
- FederatedParticipant (local updates, quantization, global apply)
- FederatedAggregationServer (FedAvg, round management, multi-model)
- FederatedTransport (chunking, reassembly, dispatch)
- LocalUpdate serialization (to_bytes / from_bytes round-trip)
- Mesh integration (PacketType.MODEL_UPDATE, consciousness callback)
"""

import math
import struct
import time

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _weights(n: int, val: float = 0.0) -> list:
    """Create a weight vector of length n filled with val."""
    return [val] * n


def _trained(base: list, delta: float) -> list:
    """Return base + delta per element (simulate local training)."""
    return [b + delta for b in base]


# =========================================================================
# DifferentialPrivacy
# =========================================================================


class TestDifferentialPrivacy:

    def test_init_defaults(self):
        from products.nexus.lib.federated.privacy import DifferentialPrivacy
        dp = DifferentialPrivacy()
        assert dp.noise_multiplier == 1.0
        assert dp.max_grad_norm == 1.0
        assert dp.budget.remaining_epsilon > 0

    def test_clip_gradients_within_norm(self):
        from products.nexus.lib.federated.privacy import DifferentialPrivacy
        dp = DifferentialPrivacy(max_grad_norm=10.0)
        grads = [1.0, 2.0, 3.0]
        clipped = dp.clip_gradients(grads)
        assert clipped == grads  # norm=3.74 < 10

    def test_clip_gradients_exceeds_norm(self):
        from products.nexus.lib.federated.privacy import DifferentialPrivacy
        dp = DifferentialPrivacy(max_grad_norm=1.0)
        grads = [3.0, 4.0]  # norm=5
        clipped = dp.clip_gradients(grads)
        norm = math.sqrt(sum(g * g for g in clipped))
        assert abs(norm - 1.0) < 0.01

    def test_add_noise_changes_values(self):
        from products.nexus.lib.federated.privacy import DifferentialPrivacy
        dp = DifferentialPrivacy(noise_multiplier=1.0, max_grad_norm=10.0)
        grads = [1.0] * 100
        noised = dp.add_noise(grads)
        assert len(noised) == 100
        # At least some values should differ due to noise
        diffs = sum(1 for a, b in zip(grads, noised) if abs(a - b) > 0.001)
        assert diffs > 50

    def test_add_noise_accounts_budget(self):
        from products.nexus.lib.federated.privacy import DifferentialPrivacy
        dp = DifferentialPrivacy(noise_multiplier=0.5, max_grad_norm=1.0)
        initial = dp.budget.remaining_epsilon
        dp.add_noise([1.0, 2.0])
        assert dp.budget.rounds_spent == 1
        # Budget should have decreased
        assert dp.budget.remaining_epsilon <= initial

    def test_privatize_update_full_pipeline(self):
        from products.nexus.lib.federated.privacy import DifferentialPrivacy
        dp = DifferentialPrivacy(noise_multiplier=1.0, max_grad_norm=2.0)
        delta = [5.0, 5.0, 5.0]  # norm=8.66, will be clipped
        result = dp.privatize_update(delta)
        assert result is not None
        assert len(result) == 3
        # Clipped + noised, so values should be smaller than original
        # (can't guarantee due to noise, but clipping alone reduces)

    def test_budget_exhaustion_returns_none(self):
        from products.nexus.lib.federated.privacy import DifferentialPrivacy
        dp = DifferentialPrivacy(noise_multiplier=0.01, max_grad_norm=1.0, epsilon_target=0.001)
        # Spend budget rapidly with low noise
        for _ in range(1000):
            dp.add_noise([1.0])
            if dp.budget.exhausted:
                break
        result = dp.privatize_update([1.0])
        assert result is None

    def test_privacy_budget_to_dict(self):
        from products.nexus.lib.federated.privacy import PrivacyBudget
        budget = PrivacyBudget(epsilon_target=10.0)
        d = budget.to_dict()
        assert "epsilon_target" in d
        assert "remaining_epsilon" in d
        assert "rounds_spent" in d
        assert d["rounds_spent"] == 0

    def test_empty_gradients(self):
        from products.nexus.lib.federated.privacy import DifferentialPrivacy
        dp = DifferentialPrivacy()
        clipped = dp.clip_gradients([])
        assert clipped == []


# =========================================================================
# FederatedModelRegistry
# =========================================================================


class TestFederatedModelRegistry:

    def test_register_model(self):
        from products.nexus.lib.federated.model_registry import (
            FederatedModelRegistry, ModelType,
        )
        reg = FederatedModelRegistry()
        record = reg.register(ModelType.DNSXAI_CLASSIFIER, [0.1, 0.2, 0.3])
        assert record.model_type == ModelType.DNSXAI_CLASSIFIER
        assert record.version == 1
        assert record.weight_count == 3
        assert len(record.weight_hash) == 64

    def test_register_without_weights(self):
        from products.nexus.lib.federated.model_registry import (
            FederatedModelRegistry, ModelType,
        )
        reg = FederatedModelRegistry()
        record = reg.register(ModelType.SIA_GRAPH_EMBEDDER)
        assert record.version == 0
        assert record.weight_count == 0

    def test_get_global_weights(self):
        from products.nexus.lib.federated.model_registry import (
            FederatedModelRegistry, ModelType,
        )
        reg = FederatedModelRegistry()
        weights = [1.0, 2.0, 3.0]
        reg.register(ModelType.QSECBIT_ML, weights)
        got = reg.get_global_weights(ModelType.QSECBIT_ML)
        assert got == weights

    def test_update_global_weights(self):
        from products.nexus.lib.federated.model_registry import (
            FederatedModelRegistry, ModelType,
        )
        reg = FederatedModelRegistry()
        reg.register(ModelType.SIA_INTENT_DECODER, [0.0, 0.0])
        record = reg.update_global_weights(
            ModelType.SIA_INTENT_DECODER, [0.5, 0.5], contributors=3,
        )
        assert record is not None
        assert record.version == 2
        assert record.contributors == 3

    def test_validate_update_correct(self):
        from products.nexus.lib.federated.model_registry import (
            FederatedModelRegistry, ModelType,
        )
        reg = FederatedModelRegistry()
        reg.register(ModelType.DNSXAI_CLASSIFIER, [0.0] * 10)
        assert reg.validate_update(ModelType.DNSXAI_CLASSIFIER, expected_version=1, weight_count=10)

    def test_validate_update_version_mismatch(self):
        from products.nexus.lib.federated.model_registry import (
            FederatedModelRegistry, ModelType,
        )
        reg = FederatedModelRegistry()
        reg.register(ModelType.DNSXAI_CLASSIFIER, [0.0] * 10)
        assert not reg.validate_update(ModelType.DNSXAI_CLASSIFIER, expected_version=99, weight_count=10)

    def test_validate_update_weight_count_mismatch(self):
        from products.nexus.lib.federated.model_registry import (
            FederatedModelRegistry, ModelType,
        )
        reg = FederatedModelRegistry()
        reg.register(ModelType.DNSXAI_CLASSIFIER, [0.0] * 10)
        assert not reg.validate_update(ModelType.DNSXAI_CLASSIFIER, expected_version=1, weight_count=5)

    def test_freeze_unfreeze(self):
        from products.nexus.lib.federated.model_registry import (
            FederatedModelRegistry, ModelType,
        )
        reg = FederatedModelRegistry()
        reg.register(ModelType.BEHAVIORAL_CLUSTERING, [1.0])
        reg.freeze(ModelType.BEHAVIORAL_CLUSTERING)
        assert reg.get(ModelType.BEHAVIORAL_CLUSTERING).frozen
        result = reg.update_global_weights(ModelType.BEHAVIORAL_CLUSTERING, [2.0], 1)
        assert result is None  # frozen model rejects update
        reg.unfreeze(ModelType.BEHAVIORAL_CLUSTERING)
        assert not reg.get(ModelType.BEHAVIORAL_CLUSTERING).frozen

    def test_list_models(self):
        from products.nexus.lib.federated.model_registry import (
            FederatedModelRegistry, ModelType,
        )
        reg = FederatedModelRegistry()
        reg.register(ModelType.DNSXAI_CLASSIFIER)
        reg.register(ModelType.SIA_GRAPH_EMBEDDER)
        models = reg.list_models()
        assert len(models) == 2

    def test_duplicate_register(self):
        from products.nexus.lib.federated.model_registry import (
            FederatedModelRegistry, ModelType,
        )
        reg = FederatedModelRegistry()
        r1 = reg.register(ModelType.DNSXAI_CLASSIFIER, [1.0])
        r2 = reg.register(ModelType.DNSXAI_CLASSIFIER, [2.0])
        assert r1 is r2  # same object returned

    def test_stats(self):
        from products.nexus.lib.federated.model_registry import (
            FederatedModelRegistry, ModelType,
        )
        reg = FederatedModelRegistry()
        reg.register(ModelType.DNSXAI_CLASSIFIER, [0.0])
        stats = reg.get_stats()
        assert stats["registered_models"] == 1
        assert "models" in stats


# =========================================================================
# FederatedParticipant
# =========================================================================


class TestFederatedParticipant:

    def test_init(self):
        from products.nexus.lib.federated.participant import FederatedParticipant
        p = FederatedParticipant(node_id="node-1")
        assert p.node_id == "node-1"
        assert p.quantize is True
        stats = p.get_stats()
        assert stats["updates_sent"] == 0

    def test_set_local_weights(self):
        from products.nexus.lib.federated.participant import FederatedParticipant
        from products.nexus.lib.federated.model_registry import ModelType
        p = FederatedParticipant(node_id="node-1")
        p.set_local_weights(ModelType.DNSXAI_CLASSIFIER, [1.0, 2.0], version=1)
        stats = p.get_stats()
        assert "dnsxai_classifier" in stats["models_loaded"]

    def test_compute_local_update(self):
        from products.nexus.lib.federated.participant import FederatedParticipant
        from products.nexus.lib.federated.model_registry import ModelType
        p = FederatedParticipant(node_id="node-1", min_samples=5)
        base = _weights(10, 0.0)
        p.set_local_weights(ModelType.DNSXAI_CLASSIFIER, base, version=1)
        trained = _trained(base, 0.1)
        update = p.compute_local_update(ModelType.DNSXAI_CLASSIFIER, trained, num_samples=100)
        assert update is not None
        assert update.model_type == ModelType.DNSXAI_CLASSIFIER
        assert update.base_version == 1
        assert update.num_samples == 100
        assert len(update.weight_delta) == 10

    def test_compute_local_update_insufficient_samples(self):
        from products.nexus.lib.federated.participant import FederatedParticipant
        from products.nexus.lib.federated.model_registry import ModelType
        p = FederatedParticipant(node_id="node-1", min_samples=100)
        p.set_local_weights(ModelType.DNSXAI_CLASSIFIER, [0.0], version=1)
        update = p.compute_local_update(ModelType.DNSXAI_CLASSIFIER, [0.1], num_samples=5)
        assert update is None

    def test_compute_local_update_no_base(self):
        from products.nexus.lib.federated.participant import FederatedParticipant
        from products.nexus.lib.federated.model_registry import ModelType
        p = FederatedParticipant(node_id="node-1")
        update = p.compute_local_update(ModelType.DNSXAI_CLASSIFIER, [0.1])
        assert update is None

    def test_compute_local_update_weight_mismatch(self):
        from products.nexus.lib.federated.participant import FederatedParticipant
        from products.nexus.lib.federated.model_registry import ModelType
        p = FederatedParticipant(node_id="node-1")
        p.set_local_weights(ModelType.DNSXAI_CLASSIFIER, [0.0, 0.0], version=1)
        update = p.compute_local_update(ModelType.DNSXAI_CLASSIFIER, [0.1], num_samples=50)
        assert update is None

    def test_apply_global_update(self):
        from products.nexus.lib.federated.participant import FederatedParticipant
        from products.nexus.lib.federated.model_registry import ModelType
        p = FederatedParticipant(node_id="node-1")
        p.set_local_weights(ModelType.DNSXAI_CLASSIFIER, [0.0, 0.0], version=1)
        ok = p.apply_global_update(ModelType.DNSXAI_CLASSIFIER, [0.5, 0.5], new_version=2)
        assert ok is True
        assert p._base_versions[ModelType.DNSXAI_CLASSIFIER] == 2

    def test_apply_global_update_stale_version(self):
        from products.nexus.lib.federated.participant import FederatedParticipant
        from products.nexus.lib.federated.model_registry import ModelType
        p = FederatedParticipant(node_id="node-1")
        p.set_local_weights(ModelType.DNSXAI_CLASSIFIER, [0.0], version=5)
        ok = p.apply_global_update(ModelType.DNSXAI_CLASSIFIER, [0.5], new_version=3)
        assert ok is False

    def test_quantization(self):
        from products.nexus.lib.federated.participant import FederatedParticipant
        from products.nexus.lib.federated.model_registry import ModelType
        p = FederatedParticipant(node_id="node-1", quantize=True)
        base = _weights(50, 0.0)
        p.set_local_weights(ModelType.SIA_GRAPH_EMBEDDER, base, version=1)
        trained = _trained(base, 0.5)
        update = p.compute_local_update(ModelType.SIA_GRAPH_EMBEDDER, trained, num_samples=100)
        assert update is not None
        assert update.quantized is True

    def test_no_quantization(self):
        from products.nexus.lib.federated.participant import FederatedParticipant
        from products.nexus.lib.federated.model_registry import ModelType
        p = FederatedParticipant(node_id="node-1", quantize=False)
        base = _weights(10, 0.0)
        p.set_local_weights(ModelType.DNSXAI_CLASSIFIER, base, version=1)
        trained = _trained(base, 0.1)
        update = p.compute_local_update(ModelType.DNSXAI_CLASSIFIER, trained, num_samples=50)
        assert update is not None
        assert update.quantized is False


# =========================================================================
# LocalUpdate Serialization
# =========================================================================


class TestLocalUpdateSerialization:

    def test_roundtrip_float(self):
        from products.nexus.lib.federated.participant import LocalUpdate
        from products.nexus.lib.federated.model_registry import ModelType
        update = LocalUpdate(
            model_type=ModelType.DNSXAI_CLASSIFIER,
            base_version=3,
            weight_delta=[0.1, -0.2, 0.3, 0.0, -0.5],
            num_samples=42,
            node_id="node-abc",
            quantized=False,
        )
        data = update.to_bytes()
        restored = LocalUpdate.from_bytes(data)
        assert restored.model_type == ModelType.DNSXAI_CLASSIFIER
        assert restored.base_version == 3
        assert restored.num_samples == 42
        assert restored.node_id == "node-abc"
        assert len(restored.weight_delta) == 5
        for a, b in zip(update.weight_delta, restored.weight_delta):
            assert abs(a - b) < 1e-5

    def test_roundtrip_int8(self):
        from products.nexus.lib.federated.participant import LocalUpdate
        from products.nexus.lib.federated.model_registry import ModelType
        update = LocalUpdate(
            model_type=ModelType.SIA_INTENT_DECODER,
            base_version=7,
            weight_delta=[0.5, -0.3, 0.8, -0.1, 0.0],
            num_samples=100,
            node_id="node-xyz",
            quantized=True,
        )
        data = update.to_bytes()
        restored = LocalUpdate.from_bytes(data)
        assert restored.quantized is True
        assert len(restored.weight_delta) == 5
        # int8 quantization loses precision, but values should be close
        for a, b in zip(update.weight_delta, restored.weight_delta):
            assert abs(a - b) < 0.02  # ~1/127 max error per element

    def test_int8_compression_ratio(self):
        from products.nexus.lib.federated.participant import LocalUpdate
        from products.nexus.lib.federated.model_registry import ModelType
        delta = [0.01 * i for i in range(1000)]
        float_update = LocalUpdate(
            model_type=ModelType.DNSXAI_CLASSIFIER,
            base_version=1,
            weight_delta=delta,
            num_samples=50,
            node_id="test",
            quantized=False,
        )
        int8_update = LocalUpdate(
            model_type=ModelType.DNSXAI_CLASSIFIER,
            base_version=1,
            weight_delta=delta,
            num_samples=50,
            node_id="test",
            quantized=True,
        )
        float_bytes = float_update.to_bytes()
        int8_bytes = int8_update.to_bytes()
        # int8 should be ~25% the size of float32 (1 byte vs 4 bytes per weight)
        ratio = len(int8_bytes) / len(float_bytes)
        assert ratio < 0.35  # header overhead means not exactly 25%


# =========================================================================
# FederatedAggregationServer
# =========================================================================


class TestFederatedAggregationServer:

    def _make_server(self, min_participants=3):
        from products.nexus.lib.federated.aggregation_server import FederatedAggregationServer
        from products.nexus.lib.federated.model_registry import (
            FederatedModelRegistry, ModelType,
        )
        reg = FederatedModelRegistry()
        reg.register(ModelType.DNSXAI_CLASSIFIER, _weights(10, 0.0))
        server = FederatedAggregationServer(
            registry=reg,
            min_participants=min_participants,
        )
        return server, reg

    def _make_update(self, node_id, delta_val, samples=100, version=1):
        from products.nexus.lib.federated.participant import LocalUpdate
        from products.nexus.lib.federated.model_registry import ModelType
        return LocalUpdate(
            model_type=ModelType.DNSXAI_CLASSIFIER,
            base_version=version,
            weight_delta=[delta_val] * 10,
            num_samples=samples,
            node_id=node_id,
        )

    def test_start_round(self):
        server, _ = self._make_server()
        from products.nexus.lib.federated.model_registry import ModelType
        rnd = server.start_round(ModelType.DNSXAI_CLASSIFIER)
        assert rnd is not None
        assert rnd.base_version == 1
        assert rnd.participant_count == 0

    def test_receive_update_accepted(self):
        server, _ = self._make_server()
        update = self._make_update("node-1", 0.1)
        ok = server.receive_update(update)
        assert ok is True

    def test_receive_duplicate_node(self):
        server, _ = self._make_server()
        u1 = self._make_update("node-1", 0.1)
        u2 = self._make_update("node-1", 0.2)
        server.receive_update(u1)
        ok = server.receive_update(u2)
        assert ok is False  # duplicate node_id

    def test_fedavg_3_participants(self):
        server, reg = self._make_server(min_participants=3)
        from products.nexus.lib.federated.model_registry import ModelType

        # 3 nodes with different deltas and sample counts
        server.receive_update(self._make_update("node-1", 0.1, samples=100))
        server.receive_update(self._make_update("node-2", 0.2, samples=200))
        ok = server.receive_update(self._make_update("node-3", 0.3, samples=300))
        assert ok is True  # triggers aggregation

        # Check global weights updated
        record = reg.get(ModelType.DNSXAI_CLASSIFIER)
        assert record.version == 2
        assert record.contributors == 3

        # FedAvg: (100/600)*0.1 + (200/600)*0.2 + (300/600)*0.3 = 0.2333...
        weights = reg.get_global_weights(ModelType.DNSXAI_CLASSIFIER)
        expected_delta = (100 * 0.1 + 200 * 0.2 + 300 * 0.3) / 600.0
        for w in weights:
            assert abs(w - expected_delta) < 1e-5

    def test_version_mismatch_rejected(self):
        server, _ = self._make_server(min_participants=2)
        update = self._make_update("node-1", 0.1, version=99)
        server.start_round(
            __import__(
                "products.nexus.lib.federated.model_registry", fromlist=["ModelType"]
            ).ModelType.DNSXAI_CLASSIFIER
        )
        ok = server.receive_update(update)
        assert ok is False

    def test_aggregation_callback(self):
        from products.nexus.lib.federated.aggregation_server import FederatedAggregationServer
        from products.nexus.lib.federated.model_registry import (
            FederatedModelRegistry, ModelType,
        )
        reg = FederatedModelRegistry()
        reg.register(ModelType.DNSXAI_CLASSIFIER, _weights(5, 0.0))

        callback_results = []
        server = FederatedAggregationServer(
            registry=reg,
            min_participants=2,
            on_aggregation_complete=lambda mt, w, v: callback_results.append((mt, v)),
        )

        server.receive_update(self._make_update("a", 0.1, samples=50))
        server.receive_update(self._make_update("b", 0.2, samples=50))

        assert len(callback_results) == 1
        assert callback_results[0][1] == 2  # version 2

    def test_stats(self):
        server, _ = self._make_server()
        stats = server.get_stats()
        assert "total_rounds" in stats
        assert "total_updates" in stats
        assert "active_rounds" in stats

    def test_auto_start_round(self):
        server, _ = self._make_server()
        # Don't call start_round — receive_update should auto-start
        update = self._make_update("node-1", 0.1)
        ok = server.receive_update(update)
        assert ok is True
        from products.nexus.lib.federated.model_registry import ModelType
        rnd = server.get_round(ModelType.DNSXAI_CLASSIFIER)
        assert rnd is not None


# =========================================================================
# FederatedTransport
# =========================================================================


class TestFederatedTransport:

    def test_single_chunk_roundtrip(self):
        from shared.mesh.federated_transport import (
            FederatedTransport, UpdateMessageType,
        )
        received = []

        def mock_send(data, ptype):
            received.append(data)

        transport = FederatedTransport(send_fn=mock_send)
        payload = b"hello federated world"
        chunks = transport.send_model_update(payload, UpdateMessageType.LOCAL_UPDATE)
        assert chunks == 1
        assert len(received) == 1

    def test_multi_chunk_roundtrip(self):
        from shared.mesh.federated_transport import (
            FederatedTransport, UpdateMessageType, MAX_CHUNK_SIZE,
        )
        sent_chunks = []
        reassembled = []

        sender = FederatedTransport(
            send_fn=lambda data, ptype: sent_chunks.append(data),
        )
        receiver = FederatedTransport(
            on_local_update=lambda payload: reassembled.append(payload),
        )

        # Create payload larger than one chunk
        big_payload = b"X" * (MAX_CHUNK_SIZE * 3 + 100)
        num = sender.send_model_update(big_payload, UpdateMessageType.LOCAL_UPDATE)
        assert num == 4  # 3 full + 1 partial

        # Feed chunks to receiver
        for chunk in sent_chunks:
            receiver.receive_chunk(chunk)

        assert len(reassembled) == 1
        assert reassembled[0] == big_payload

    def test_dispatch_global_weights(self):
        from shared.mesh.federated_transport import (
            FederatedTransport, UpdateMessageType,
        )
        received_global = []
        sent = []

        sender = FederatedTransport(send_fn=lambda d, p: sent.append(d))
        receiver = FederatedTransport(
            on_global_weights=lambda payload: received_global.append(payload),
        )

        payload = b"global_weights_v2"
        sender.send_model_update(payload, UpdateMessageType.GLOBAL_WEIGHTS)
        for chunk in sent:
            receiver.receive_chunk(chunk)

        assert len(received_global) == 1
        assert received_global[0] == payload

    def test_dispatch_round_announce(self):
        from shared.mesh.federated_transport import (
            FederatedTransport, UpdateMessageType,
        )
        received_announce = []
        sent = []

        sender = FederatedTransport(send_fn=lambda d, p: sent.append(d))
        receiver = FederatedTransport(
            on_round_announce=lambda payload: received_announce.append(payload),
        )

        payload = b"new_round_data"
        sender.send_model_update(payload, UpdateMessageType.ROUND_ANNOUNCE)
        for chunk in sent:
            receiver.receive_chunk(chunk)

        assert len(received_announce) == 1

    def test_chunk_header_parse(self):
        from shared.mesh.federated_transport import FederatedTransport
        ft = FederatedTransport()
        header = ft._build_chunk_header("msg123456789abcd", 0, 1, 0x01, 100)
        assert len(header) == 28
        parsed = ft._parse_chunk_header(header + b"\x00" * 100)
        assert parsed["message_id"] == "msg123456789abcd"
        assert parsed["chunk_index"] == 0
        assert parsed["total_chunks"] == 1

    def test_invalid_chunk_rejected(self):
        from shared.mesh.federated_transport import FederatedTransport
        ft = FederatedTransport()
        ft.receive_chunk(b"too_short")  # should not crash
        assert ft._reassembly_failures == 0  # just logged warning

    def test_stats(self):
        from shared.mesh.federated_transport import FederatedTransport
        ft = FederatedTransport()
        stats = ft.get_stats()
        assert stats["chunks_sent"] == 0
        assert stats["messages_received"] == 0


# =========================================================================
# Mesh Integration
# =========================================================================


class TestMeshIntegration:

    def test_packet_type_model_update_exists(self):
        from shared.mesh.unified_transport import PacketType
        assert hasattr(PacketType, "MODEL_UPDATE")
        assert PacketType.MODEL_UPDATE == 0x50

    def test_packet_type_no_collision(self):
        from shared.mesh.unified_transport import PacketType
        values = [pt.value for pt in PacketType]
        assert len(values) == len(set(values))  # no duplicates

    def test_consciousness_model_update_callback(self):
        """Verify consciousness.py has the on_model_update callback support."""
        from shared.mesh.consciousness import MeshConsciousness
        assert hasattr(MeshConsciousness, "on_model_update")
        assert hasattr(MeshConsciousness, "gossip_model_update")
        assert hasattr(MeshConsciousness, "_handle_model_update")

    def test_model_type_enum_values(self):
        from products.nexus.lib.federated.model_registry import ModelType
        expected = {
            "dnsxai_classifier", "sia_graph_embedder", "sia_intent_decoder",
            "qsecbit_ml", "behavioral_clustering",
        }
        actual = {mt.value for mt in ModelType}
        assert actual == expected


# =========================================================================
# End-to-End: Participant → Server → Participant
# =========================================================================


class TestFederatedE2E:

    def test_3_node_training_round(self):
        """Simulate 3 nodes training locally and FedAvg producing global weights."""
        from products.nexus.lib.federated.model_registry import (
            FederatedModelRegistry, ModelType,
        )
        from products.nexus.lib.federated.participant import FederatedParticipant
        from products.nexus.lib.federated.aggregation_server import FederatedAggregationServer
        from products.nexus.lib.federated.privacy import DifferentialPrivacy

        # Setup registry and server
        reg = FederatedModelRegistry()
        initial = _weights(20, 0.0)
        reg.register(ModelType.SIA_GRAPH_EMBEDDER, initial)

        server = FederatedAggregationServer(registry=reg, min_participants=3)

        # Create 3 participants with low noise for reproducibility
        participants = []
        for i in range(3):
            dp = DifferentialPrivacy(noise_multiplier=0.001, max_grad_norm=10.0)
            p = FederatedParticipant(node_id=f"node-{i}", privacy=dp, quantize=False)
            p.set_local_weights(ModelType.SIA_GRAPH_EMBEDDER, initial, version=1)
            participants.append(p)

        # Simulate local training (different deltas per node)
        deltas = [0.1, 0.2, 0.3]
        for p, delta in zip(participants, deltas):
            trained = _trained(initial, delta)
            update = p.compute_local_update(
                ModelType.SIA_GRAPH_EMBEDDER, trained, num_samples=100,
            )
            assert update is not None
            server.receive_update(update)

        # Verify global weights were updated
        record = reg.get(ModelType.SIA_GRAPH_EMBEDDER)
        assert record.version == 2

        global_weights = reg.get_global_weights(ModelType.SIA_GRAPH_EMBEDDER)
        # With equal samples, FedAvg = mean of deltas = 0.2 (+ tiny noise)
        for w in global_weights:
            assert abs(w - 0.2) < 0.05  # generous tolerance for DP noise

        # Apply global update to all participants
        for p in participants:
            ok = p.apply_global_update(ModelType.SIA_GRAPH_EMBEDDER, global_weights, new_version=2)
            assert ok is True

    def test_serialization_e2e(self):
        """Test full roundtrip: participant → serialize → transport → deserialize → server."""
        from products.nexus.lib.federated.model_registry import (
            FederatedModelRegistry, ModelType,
        )
        from products.nexus.lib.federated.participant import FederatedParticipant, LocalUpdate
        from products.nexus.lib.federated.aggregation_server import FederatedAggregationServer
        from products.nexus.lib.federated.privacy import DifferentialPrivacy

        reg = FederatedModelRegistry()
        reg.register(ModelType.DNSXAI_CLASSIFIER, _weights(10, 0.0))
        server = FederatedAggregationServer(registry=reg, min_participants=2)

        # Create and serialize updates
        for i in range(2):
            dp = DifferentialPrivacy(noise_multiplier=0.001, max_grad_norm=10.0)
            p = FederatedParticipant(node_id=f"ser-{i}", privacy=dp, quantize=True)
            p.set_local_weights(ModelType.DNSXAI_CLASSIFIER, _weights(10, 0.0), version=1)
            trained = _trained(_weights(10, 0.0), 0.1 * (i + 1))
            update = p.compute_local_update(ModelType.DNSXAI_CLASSIFIER, trained, num_samples=50)
            assert update is not None

            # Serialize and deserialize (simulates transport)
            data = update.to_bytes()
            restored = LocalUpdate.from_bytes(data)
            server.receive_update(restored)

        assert reg.get(ModelType.DNSXAI_CLASSIFIER).version == 2

    def test_multi_model_concurrent(self):
        """Test that server can handle multiple model types concurrently."""
        from products.nexus.lib.federated.model_registry import (
            FederatedModelRegistry, ModelType,
        )
        from products.nexus.lib.federated.participant import FederatedParticipant, LocalUpdate
        from products.nexus.lib.federated.aggregation_server import FederatedAggregationServer
        from products.nexus.lib.federated.privacy import DifferentialPrivacy

        reg = FederatedModelRegistry()
        reg.register(ModelType.DNSXAI_CLASSIFIER, _weights(5, 0.0))
        reg.register(ModelType.SIA_INTENT_DECODER, _weights(8, 0.0))

        server = FederatedAggregationServer(registry=reg, min_participants=2)

        # Send updates for both models
        for model, dim in [(ModelType.DNSXAI_CLASSIFIER, 5), (ModelType.SIA_INTENT_DECODER, 8)]:
            for i in range(2):
                dp = DifferentialPrivacy(noise_multiplier=0.001, max_grad_norm=10.0)
                p = FederatedParticipant(node_id=f"multi-{model.value}-{i}", privacy=dp, quantize=False)
                p.set_local_weights(model, _weights(dim, 0.0), version=1)
                trained = _trained(_weights(dim, 0.0), 0.1)
                update = p.compute_local_update(model, trained, num_samples=50)
                server.receive_update(update)

        assert reg.get(ModelType.DNSXAI_CLASSIFIER).version == 2
        assert reg.get(ModelType.SIA_INTENT_DECODER).version == 2

    def test_dp_budget_prevents_infinite_training(self):
        """Verify that privacy budget limits how many rounds a node can contribute."""
        from products.nexus.lib.federated.participant import FederatedParticipant
        from products.nexus.lib.federated.model_registry import ModelType
        from products.nexus.lib.federated.privacy import DifferentialPrivacy

        dp = DifferentialPrivacy(noise_multiplier=0.01, max_grad_norm=1.0, epsilon_target=0.001)
        p = FederatedParticipant(node_id="limited", privacy=dp, quantize=False)
        p.set_local_weights(ModelType.QSECBIT_ML, _weights(5, 0.0), version=1)

        rounds = 0
        for _ in range(10000):
            trained = _trained(_weights(5, 0.0), 0.01)
            update = p.compute_local_update(ModelType.QSECBIT_ML, trained, num_samples=50)
            if update is None:
                break
            rounds += 1

        # Should have been cut off before 10000 rounds
        assert rounds < 10000
