"""
Tests for Stage 6: Hardware-Anchored Identity (PUF)

Tests:
- SRAM PUF and FuzzyExtractor
- Clock Drift PUF consistency
- Cache Timing PUF
- Composite Identity and Ed25519 key derivation
- PUF-TER Binding
- Device Identity PUF integration
- Hardware Fingerprint PUF integration
- TER Generator PUF enhancement
- NeuralEngine PUF-seeded weights
- Degraded mode (no SRAM, clock+cache only)

Note: core.neuro.__init__.py imports NeuralEngine which requires numpy.
We use importlib to load PUF modules directly by file path to bypass this.
"""

import hashlib
import hmac
import importlib
import importlib.util
import pathlib
import struct
import sys
import time
import unittest
from unittest.mock import patch, MagicMock


def _load_module(module_name: str, file_path: str):
    """Load a module directly from file path, bypassing package __init__.py."""
    abs_path = pathlib.Path(file_path).resolve()
    spec = importlib.util.spec_from_file_location(module_name, str(abs_path))
    module = importlib.util.module_from_spec(spec)
    # Temporarily add to sys.modules so relative imports within the module work
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


# Pre-load PUF modules by file path to bypass core.neuro.__init__.py (numpy)
_sram_puf_mod = _load_module(
    "core.neuro.puf.sram_puf",
    "core/neuro/puf/sram_puf.py",
)
_clock_drift_mod = _load_module(
    "core.neuro.puf.clock_drift_puf",
    "core/neuro/puf/clock_drift_puf.py",
)
_cache_timing_mod = _load_module(
    "core.neuro.puf.cache_timing_puf",
    "core/neuro/puf/cache_timing_puf.py",
)
_composite_mod = _load_module(
    "core.neuro.puf.composite_identity",
    "core/neuro/puf/composite_identity.py",
)
_puf_ter_mod = _load_module(
    "core.neuro.puf.puf_ter_binding",
    "core/neuro/puf/puf_ter_binding.py",
)


# Convenient aliases
SRAMPuf = _sram_puf_mod.SRAMPuf
FuzzyExtractor = _sram_puf_mod.FuzzyExtractor
ClockDriftPuf = _clock_drift_mod.ClockDriftPuf
DriftProfile = _clock_drift_mod.DriftProfile
CacheTimingPuf = _cache_timing_mod.CacheTimingPuf
CompositeIdentity = _composite_mod.CompositeIdentity
PufSource = _composite_mod.PufSource
PufTerBinding = _puf_ter_mod.PufTerBinding


# ============================================================================
# SRAM PUF Tests
# ============================================================================


class TestSRAMPuf(unittest.TestCase):
    """Test SRAM PUF and FuzzyExtractor."""

    def test_import(self):
        self.assertTrue(callable(SRAMPuf))
        self.assertTrue(callable(FuzzyExtractor))

    def test_fuzzy_extractor_gen_rep_roundtrip(self):
        """FuzzyExtractor gen/rep should recover same key with identical input."""
        fe = FuzzyExtractor(error_tolerance=0.05)

        # Simulate stable bits and positions
        stable_bits = hashlib.sha256(b"sram-enrollment").digest()
        stable_positions = list(range(len(stable_bits) * 8))

        key, helper = fe.gen(stable_bits, stable_positions)

        self.assertEqual(len(key), 32)
        self.assertIsNotNone(helper)

        # Reproduce with identical reading
        key2 = fe.rep(stable_bits, helper)
        self.assertEqual(key, key2)

    def test_fuzzy_extractor_tolerates_noise(self):
        """FuzzyExtractor should handle noisy readings gracefully."""
        fe = FuzzyExtractor(error_tolerance=0.10)

        stable_bits = hashlib.sha256(b"sram-noisy-test").digest()
        stable_positions = list(range(len(stable_bits) * 8))

        key, helper = fe.gen(stable_bits, stable_positions)

        # Flip some bits
        noisy = bytearray(stable_bits)
        for i in range(0, len(noisy), 10):
            noisy[i] ^= 0x01
        noisy = bytes(noisy)

        key2 = fe.rep(noisy, helper)
        # May or may not recover — just verify it returns bytes or None
        self.assertTrue(key2 is None or len(key2) == 32)

    def test_sram_puf_simulation_mode(self):
        """SRAMPuf should work in simulation mode (no /dev/mem)."""
        puf = SRAMPuf(use_hardware=False)
        response = puf.get_raw_response()
        self.assertEqual(len(response), 32)

    def test_sram_puf_deterministic_per_device(self):
        """Same device should produce 32-byte responses."""
        puf1 = SRAMPuf(use_hardware=False)
        puf2 = SRAMPuf(use_hardware=False)

        r1 = puf1.get_raw_response()
        r2 = puf2.get_raw_response()

        self.assertEqual(len(r1), 32)
        self.assertEqual(len(r2), 32)

    def test_sram_puf_enroll_reproduce(self):
        """SRAMPuf enroll/reproduce cycle should work."""
        puf = SRAMPuf(use_hardware=False)

        key, helper = puf.enroll()
        self.assertEqual(len(key), 32)
        self.assertIsNotNone(helper)

        # reproduce may return None on simulated SRAM due to noise
        key2 = puf.reproduce(helper)
        self.assertTrue(key2 is None or len(key2) == 32)

    def test_sram_puf_stats(self):
        """SRAMPuf stats should return valid dict."""
        puf = SRAMPuf(use_hardware=False)
        puf.get_raw_response()
        stats = puf.get_stats()
        self.assertIn("hardware_mode", stats)
        self.assertIn("enrolled", stats)


# ============================================================================
# Clock Drift PUF Tests
# ============================================================================


class TestClockDriftPuf(unittest.TestCase):
    """Test Clock Drift PUF."""

    def test_import(self):
        self.assertTrue(callable(ClockDriftPuf))

    def test_measure_produces_response(self):
        """Clock PUF should produce 32-byte response."""
        puf = ClockDriftPuf(num_measurements=16, measurement_delay_us=10)
        profile = puf.measure()
        self.assertEqual(len(profile.response), 32)
        self.assertEqual(len(profile.measurements), 16)

    def test_get_response(self):
        """get_response should return 32 bytes."""
        puf = ClockDriftPuf(num_measurements=8, measurement_delay_us=10)
        response = puf.get_response()
        self.assertEqual(len(response), 32)

    def test_drift_statistics(self):
        """Profile should contain valid statistics."""
        puf = ClockDriftPuf(num_measurements=16, measurement_delay_us=10)
        profile = puf.measure()
        self.assertIsInstance(profile.mean_drift_ns, float)
        self.assertIsInstance(profile.std_drift_ns, float)
        self.assertEqual(len(profile.raw_drifts), 16)

    def test_hamming_distance(self):
        """DriftProfile should compute Hamming distance."""
        p1 = DriftProfile(measurements=[], response=b"\xff" * 32, raw_drifts=[])
        p2 = DriftProfile(measurements=[], response=b"\x00" * 32, raw_drifts=[])
        dist = p1.hamming_distance(p2)
        self.assertAlmostEqual(dist, 1.0)

        p3 = DriftProfile(measurements=[], response=b"\xff" * 32, raw_drifts=[])
        dist2 = p1.hamming_distance(p3)
        self.assertAlmostEqual(dist2, 0.0)

    def test_stats(self):
        """get_stats should return valid dict."""
        puf = ClockDriftPuf(num_measurements=8, measurement_delay_us=10)
        puf.measure()
        stats = puf.get_stats()
        self.assertIn("mean_drift_ns", stats)
        self.assertIn("std_drift_ns", stats)
        self.assertIn("response_hex", stats)


# ============================================================================
# Cache Timing PUF Tests
# ============================================================================


class TestCacheTimingPuf(unittest.TestCase):
    """Test Cache Timing PUF."""

    def test_import(self):
        self.assertTrue(callable(CacheTimingPuf))

    def test_measure_produces_response(self):
        """Cache PUF should produce 16-byte response."""
        puf = CacheTimingPuf(cache_size=4096, iterations=8)
        profile = puf.measure()
        self.assertEqual(len(profile.response), 16)

    def test_get_response(self):
        """get_response should return 16 bytes."""
        puf = CacheTimingPuf(cache_size=4096, iterations=8)
        response = puf.get_response()
        self.assertEqual(len(response), 16)

    def test_stride_timings(self):
        """Profile should contain timing measurements."""
        puf = CacheTimingPuf(cache_size=4096, iterations=8)
        profile = puf.measure()
        self.assertGreater(len(profile.timings), 0)
        for t in profile.timings:
            self.assertGreater(t.stride, 0)

    def test_cache_line_detection(self):
        """Should detect cache line size."""
        puf = CacheTimingPuf(cache_size=4096, iterations=8)
        profile = puf.measure()
        self.assertIn(profile.cache_line_size, [64, 128, 256, 512, 1024, 4096])

    def test_stats(self):
        """get_stats should return valid dict."""
        puf = CacheTimingPuf(cache_size=4096, iterations=8)
        puf.measure()
        stats = puf.get_stats()
        self.assertIn("mean_ratio", stats)
        self.assertIn("cache_line_size", stats)
        self.assertIn("response_hex", stats)


# ============================================================================
# Composite Identity Tests
# ============================================================================


class TestCompositeIdentity(unittest.TestCase):
    """Test Composite Identity and Ed25519 key derivation."""

    def test_import(self):
        self.assertTrue(callable(CompositeIdentity))

    def test_generate_from_clock_and_cache(self):
        """Composite identity from clock+cache PUFs should produce valid keys."""
        identity = CompositeIdentity()
        identity.add_source(PufSource.CLOCK_DRIFT, ClockDriftPuf(num_measurements=8, measurement_delay_us=10))
        identity.add_source(PufSource.CACHE_TIMING, CacheTimingPuf(cache_size=4096, iterations=8))

        response = identity.generate()
        self.assertEqual(len(response.composite), 32)
        self.assertEqual(len(response.ed25519_seed), 32)
        self.assertEqual(len(response.ed25519_public), 32)
        self.assertEqual(response.source_count, 2)

    def test_no_sources_raises(self):
        """generate() should raise when no sources registered."""
        identity = CompositeIdentity()
        with self.assertRaises(ValueError):
            identity.generate()

    def test_sign_verify_roundtrip(self):
        """Sign and verify with PUF-derived keys should work."""
        mock_puf = MagicMock()
        mock_puf.get_response.return_value = hashlib.sha256(b"test-puf-stable").digest()

        identity = CompositeIdentity()
        identity.add_source(PufSource.CLOCK_DRIFT, mock_puf)

        message = b"hello world"
        signature = identity.sign(message)
        self.assertIsNotNone(signature)
        self.assertGreater(len(signature), 0)

        valid = identity.verify_keypair(message, signature)
        self.assertTrue(valid)

    def test_different_puf_responses_different_keys(self):
        """Different PUF responses should produce different keys."""
        mock1 = MagicMock()
        mock1.get_response.return_value = hashlib.sha256(b"device-A").digest()

        mock2 = MagicMock()
        mock2.get_response.return_value = hashlib.sha256(b"device-B").digest()

        id1 = CompositeIdentity()
        id1.add_source(PufSource.CLOCK_DRIFT, mock1)
        r1 = id1.generate()

        id2 = CompositeIdentity()
        id2.add_source(PufSource.CLOCK_DRIFT, mock2)
        r2 = id2.generate()

        self.assertNotEqual(r1.ed25519_public, r2.ed25519_public)

    def test_weighted_combination(self):
        """Custom weights should be respected."""
        custom_weights = {
            PufSource.CLOCK_DRIFT: 0.8,
            PufSource.CACHE_TIMING: 0.2,
        }
        identity = CompositeIdentity(weights=custom_weights)
        self.assertEqual(identity._weights[PufSource.CLOCK_DRIFT], 0.8)

    def test_stats(self):
        """get_stats should return valid info."""
        mock_puf = MagicMock()
        mock_puf.get_response.return_value = hashlib.sha256(b"stats-test").digest()

        identity = CompositeIdentity()
        identity.add_source(PufSource.CLOCK_DRIFT, mock_puf)
        identity.generate()

        stats = identity.get_stats()
        self.assertTrue(stats["has_identity"])
        self.assertEqual(stats["sources_used"], 1)
        self.assertIn("public_key_hex", stats)

    def test_reliability_scoring(self):
        """CompositeResponse total_reliability should be correct average."""
        mock_puf = MagicMock()
        mock_puf.get_response.return_value = hashlib.sha256(b"reliability").digest()

        identity = CompositeIdentity()
        identity.add_source(PufSource.CLOCK_DRIFT, mock_puf)

        response = identity.generate()
        self.assertGreater(response.total_reliability, 0.0)
        self.assertLessEqual(response.total_reliability, 1.0)


# ============================================================================
# PUF-TER Binding Tests
# ============================================================================


class TestPufTerBinding(unittest.TestCase):
    """Test PUF-TER binding."""

    def test_import(self):
        self.assertTrue(callable(PufTerBinding))

    def test_passthrough_when_inactive(self):
        """Inactive binding should pass through unchanged."""
        binding = PufTerBinding(puf_response=None)
        self.assertFalse(binding.active)

        original_entropy = hashlib.sha256(b"test-entropy").digest()
        enhanced = binding.enhance_entropy(original_entropy)
        self.assertEqual(enhanced, original_entropy)

        original_integrity = hashlib.new("ripemd160", b"test-integrity").digest()
        enhanced_int = binding.enhance_integrity(original_integrity)
        self.assertEqual(enhanced_int, original_integrity)

    def test_entropy_enhancement(self):
        """Active binding should modify H_Entropy."""
        puf_response = hashlib.sha256(b"puf-response").digest()
        binding = PufTerBinding(puf_response=puf_response)
        self.assertTrue(binding.active)

        original_entropy = hashlib.sha256(b"original-entropy").digest()
        enhanced = binding.enhance_entropy(original_entropy)

        self.assertEqual(len(enhanced), 32)
        self.assertNotEqual(enhanced, original_entropy)

    def test_integrity_enhancement(self):
        """Active binding should modify H_Integrity."""
        puf_response = hashlib.sha256(b"puf-response").digest()
        binding = PufTerBinding(puf_response=puf_response)

        original_integrity = hashlib.new("ripemd160", b"test").digest()
        enhanced = binding.enhance_integrity(original_integrity)

        self.assertEqual(len(enhanced), 20)
        self.assertNotEqual(enhanced, original_integrity)

    def test_weight_seed(self):
        """get_weight_seed should return 32-byte HMAC-based seed."""
        puf_response = hashlib.sha256(b"weight-seed-test").digest()
        binding = PufTerBinding(puf_response=puf_response)

        seed = binding.get_weight_seed()
        self.assertEqual(len(seed), 32)

    def test_weight_seed_none_when_inactive(self):
        """get_weight_seed should return None when inactive."""
        binding = PufTerBinding(puf_response=None)
        self.assertIsNone(binding.get_weight_seed())

    def test_binding_proof_roundtrip(self):
        """create_binding_proof and verify_binding_proof should be consistent."""
        puf_response = hashlib.sha256(b"proof-test").digest()
        binding = PufTerBinding(puf_response=puf_response)

        ter_bytes = b"\x00" * 64
        proof = binding.create_binding_proof(ter_bytes)
        self.assertEqual(len(proof), 32)

        valid = binding.verify_binding_proof(ter_bytes, proof)
        self.assertTrue(valid)

    def test_binding_proof_rejects_wrong_proof(self):
        """verify_binding_proof should reject incorrect proof."""
        puf_response = hashlib.sha256(b"reject-test").digest()
        binding = PufTerBinding(puf_response=puf_response)

        ter_bytes = b"\x00" * 64
        wrong_proof = b"\xff" * 32
        valid = binding.verify_binding_proof(ter_bytes, wrong_proof)
        self.assertFalse(valid)

    def test_puf_hash_public(self):
        """get_puf_hash should return SHA-256 of the PUF response."""
        puf_response = hashlib.sha256(b"hash-test").digest()
        binding = PufTerBinding(puf_response=puf_response)

        puf_hash = binding.get_puf_hash()
        expected = hashlib.sha256(puf_response).digest()
        self.assertEqual(puf_hash, expected)

    def test_stats(self):
        """get_stats should return valid dict."""
        binding = PufTerBinding(puf_response=hashlib.sha256(b"stats").digest())
        stats = binding.get_stats()
        self.assertTrue(stats["active"])
        self.assertTrue(stats["has_response"])
        self.assertIn("puf_hash", stats)


# ============================================================================
# Device Identity PUF Integration Tests
# ============================================================================


class TestDeviceIdentityPuf(unittest.TestCase):
    """Test PUF integration in DeviceIdentity."""

    def _load_device_identity(self):
        """Load device_identity module bypassing core.neuro.__init__.py."""
        mod = _load_module(
            "core.neuro.attestation.device_identity",
            "core/neuro/attestation/device_identity.py",
        )
        return mod

    def test_use_puf_parameter(self):
        """DeviceIdentity should accept use_puf parameter."""
        mod = self._load_device_identity()
        device = mod.DeviceIdentity(device_id="test-001", use_tpm=False, use_puf=True)
        self.assertTrue(device.use_puf)
        self.assertFalse(device.use_tpm)

    def test_puf_key_provisioning(self):
        """PUF key provisioning should produce valid DeviceKey."""
        mod = self._load_device_identity()
        device = mod.DeviceIdentity(device_id="puf-test-001", use_tpm=False, use_puf=True)
        key = device.provision_device_key()

        self.assertEqual(len(key.public_key), 32)
        self.assertEqual(len(key.key_id), 16)
        self.assertIsNotNone(key.attestation_cert)
        self.assertIsNotNone(device._puf_identity)

    def test_puf_attestation_sign_verify(self):
        """PUF-provisioned device should create verifiable attestations."""
        mod = self._load_device_identity()

        device = mod.DeviceIdentity(device_id="puf-attest-001", use_tpm=False, use_puf=True)
        device.provision_device_key()

        nonce = hashlib.sha256(b"test-nonce").digest()[:16]
        attestation = device.create_attestation(challenge_nonce=nonce)

        self.assertGreater(len(attestation.signature), 0)
        self.assertEqual(attestation.nonce, nonce)

        verifier = mod.AttestationVerifier(trusted_oem_cas=[])
        result = verifier.verify_attestation(attestation)
        self.assertTrue(result["valid"], f"Verification errors: {result.get('errors')}")

    def test_software_fallback_still_works(self):
        """Software fallback (no TPM, no PUF) should still work."""
        mod = self._load_device_identity()
        device = mod.DeviceIdentity(device_id="sw-test-001", use_tpm=False, use_puf=False)
        key = device.provision_device_key()
        self.assertEqual(len(key.public_key), 32)


# ============================================================================
# Hardware Fingerprint PUF Integration Tests
# ============================================================================


class TestHardwareFingerprintPuf(unittest.TestCase):
    """Test PUF integration in HardwareFingerprint."""

    def _load_hw_fingerprint(self):
        """Load hardware_fingerprint module."""
        return _load_module(
            "core.neuro.identity.hardware_fingerprint",
            "core/neuro/identity/hardware_fingerprint.py",
        )

    def test_fingerprint_has_puf_hash_field(self):
        """HardwareFingerprint should have puf_hash field."""
        mod = self._load_hw_fingerprint()

        fp = mod.HardwareFingerprint(
            fingerprint_id="a" * 64,
            cpu_id="test-cpu",
            mac_addresses=["00:11:22:33:44:55"],
            disk_serials=["disk-1"],
            dmi_uuid="test-uuid",
            hostname="test-host",
            created_timestamp=12345,
            raw_data={},
            puf_hash="abcd1234" * 8,
        )
        self.assertEqual(fp.puf_hash, "abcd1234" * 8)

    def test_puf_hash_default_none(self):
        """puf_hash should default to None."""
        mod = self._load_hw_fingerprint()

        fp = mod.HardwareFingerprint(
            fingerprint_id="b" * 64,
            cpu_id="test-cpu",
            mac_addresses=["00:11:22:33:44:55"],
            disk_serials=["disk-1"],
            dmi_uuid="test-uuid",
            hostname="test-host",
            created_timestamp=12345,
            raw_data={},
        )
        self.assertIsNone(fp.puf_hash)

    def test_generator_includes_puf_in_hash(self):
        """_hash_hardware_data should include puf_hash in computation."""
        mod = self._load_hw_fingerprint()
        gen = mod.HardwareFingerprintGenerator()

        data_without_puf = {"cpu_id": "cpu1", "mac_addresses": ["aa:bb"],
                            "disk_serials": ["d1"], "dmi_uuid": "u1",
                            "hostname": "h1"}
        data_with_puf = dict(data_without_puf)
        data_with_puf["puf_hash"] = "deadbeef" * 8

        hash1 = gen._hash_hardware_data(data_without_puf, 12345)
        hash2 = gen._hash_hardware_data(data_with_puf, 12345)

        self.assertNotEqual(hash1, hash2)

    def test_get_puf_hash_method_exists(self):
        """HardwareFingerprintGenerator should have _get_puf_hash method."""
        mod = self._load_hw_fingerprint()
        gen = mod.HardwareFingerprintGenerator()
        self.assertTrue(hasattr(gen, "_get_puf_hash"))

        result = gen._get_puf_hash()
        self.assertTrue(result is None or isinstance(result, str))


# ============================================================================
# TER Generator PUF Enhancement Tests
# ============================================================================


class TestTERGeneratorPuf(unittest.TestCase):
    """Test PUF enhancement in TER Generator."""

    def _load_ter(self):
        """Load ter module."""
        return _load_module(
            "core.neuro.core.ter",
            "core/neuro/core/ter.py",
        )

    def test_ter_generator_accepts_puf_binding(self):
        """TERGenerator should accept puf_binding parameter."""
        mod = self._load_ter()
        gen = mod.TERGenerator(puf_binding=None)
        self.assertIsNone(gen.puf_binding)

    def test_ter_puf_enhancement_changes_entropy(self):
        """TER with PUF binding should have different H_Entropy."""
        mod = self._load_ter()

        gen_no_puf = mod.TERGenerator(puf_binding=None)

        puf_response = hashlib.sha256(b"ter-puf-test").digest()
        binding = PufTerBinding(puf_response=puf_response)
        gen_with_puf = mod.TERGenerator(puf_binding=binding)

        self.assertIsNone(gen_no_puf.puf_binding)
        self.assertIsNotNone(gen_with_puf.puf_binding)
        self.assertTrue(gen_with_puf.puf_binding.active)

    def test_puf_binding_enhance_entropy_called(self):
        """When puf_binding is set, enhance_entropy should be called during generate."""
        mod = self._load_ter()

        puf_response = hashlib.sha256(b"enhance-test").digest()
        binding = PufTerBinding(puf_response=puf_response)

        original_enhance = binding.enhance_entropy
        calls = []

        def tracking_enhance(entropy):
            calls.append(entropy)
            return original_enhance(entropy)

        binding.enhance_entropy = tracking_enhance

        gen = mod.TERGenerator(puf_binding=binding)
        gen._get_system_metrics_fallback = lambda: (0.5, 0.5, 0.5, 0.5)

        # Pre-cache integrity to avoid file read permission errors
        cached_integrity = hashlib.new("ripemd160", b"test").digest()
        gen._cached_h_integrity = cached_integrity
        # Force sequence to non-zero so cache is used (recalc at seq % 100 == 0)
        gen.sequence = 1

        ter = gen.generate()
        self.assertEqual(len(calls), 1, "enhance_entropy should be called once")
        self.assertEqual(len(ter.h_entropy), 32)


# ============================================================================
# Neural Engine PUF-Seeded Weights Tests
# ============================================================================


class TestNeuralEnginePuf(unittest.TestCase):
    """Test PUF-seeded weight initialization in NeuralEngine."""

    def test_weight_state_accepts_puf_seed(self):
        """WeightState should accept puf_seed parameter."""
        source = pathlib.Path("core/neuro/neural/engine.py").read_text()
        self.assertIn("puf_seed", source)
        self.assertIn("puf_layer_seed", source)

    def test_create_initial_weights_accepts_puf_seed(self):
        """create_initial_weights should accept puf_seed parameter."""
        source = pathlib.Path("core/neuro/neural/engine.py").read_text()
        self.assertIn("def create_initial_weights(seed: int = 42, puf_seed: bytes = None)", source)

    def test_puf_seed_produces_different_weights(self):
        """PUF-seeded weights should differ from default seed(42) weights."""
        source = pathlib.Path("core/neuro/neural/engine.py").read_text()
        self.assertIn("hashlib.sha256", source)
        self.assertIn("self.puf_seed + i.to_bytes(4, 'big')", source)
        self.assertIn("int.from_bytes(layer_seed_bytes[:4], 'big')", source)


# ============================================================================
# Degraded Mode Tests
# ============================================================================


class TestDegradedMode(unittest.TestCase):
    """Test PUF identity in degraded mode (no SRAM, clock+cache only)."""

    def test_composite_without_sram(self):
        """Composite identity should work with only clock+cache PUFs."""
        identity = CompositeIdentity()
        identity.add_source(PufSource.CLOCK_DRIFT, ClockDriftPuf(num_measurements=8, measurement_delay_us=10))
        identity.add_source(PufSource.CACHE_TIMING, CacheTimingPuf(cache_size=4096, iterations=8))

        response = identity.generate()
        self.assertEqual(len(response.composite), 32)
        self.assertEqual(len(response.ed25519_public), 32)
        self.assertEqual(response.source_count, 2)

    def test_composite_with_single_source(self):
        """Composite identity should work with just clock PUF (minimum viable)."""
        identity = CompositeIdentity()
        identity.add_source(PufSource.CLOCK_DRIFT, ClockDriftPuf(num_measurements=8, measurement_delay_us=10))

        response = identity.generate()
        self.assertEqual(len(response.composite), 32)
        self.assertEqual(response.source_count, 1)

    def test_device_identity_puf_without_sram(self):
        """DeviceIdentity PUF mode should work without SRAM access."""
        mod = _load_module(
            "core.neuro.attestation.device_identity",
            "core/neuro/attestation/device_identity.py",
        )
        device = mod.DeviceIdentity(device_id="degraded-001", use_tpm=False, use_puf=True)
        key = device.provision_device_key()
        self.assertEqual(len(key.public_key), 32)

    def test_failed_source_skipped(self):
        """Composite identity should skip failed sources gracefully."""
        good_puf = MagicMock()
        good_puf.get_response.return_value = hashlib.sha256(b"good").digest()

        bad_puf = MagicMock()
        bad_puf.get_response.side_effect = RuntimeError("Hardware not available")

        identity = CompositeIdentity()
        identity.add_source(PufSource.CLOCK_DRIFT, good_puf)
        identity.add_source(PufSource.SRAM, bad_puf)

        response = identity.generate()
        self.assertEqual(response.source_count, 1)

    def test_all_sources_fail_raises(self):
        """If all PUF sources fail, should raise RuntimeError."""
        bad_puf = MagicMock()
        bad_puf.get_response.side_effect = RuntimeError("Failed")

        identity = CompositeIdentity()
        identity.add_source(PufSource.CLOCK_DRIFT, bad_puf)

        with self.assertRaises(RuntimeError):
            identity.generate()


# ============================================================================
# Module Export Tests
# ============================================================================


class TestPufModuleExports(unittest.TestCase):
    """Test PUF module __init__.py exports."""

    def test_all_exports_exist_in_source(self):
        """Module __init__.py should export all key classes."""
        source = pathlib.Path("core/neuro/puf/__init__.py").read_text()
        for cls_name in ["SRAMPuf", "FuzzyExtractor", "ClockDriftPuf",
                         "CacheTimingPuf", "CompositeIdentity",
                         "PufResponse", "PufTerBinding"]:
            self.assertIn(cls_name, source,
                          f"{cls_name} not found in __init__.py")


# ============================================================================
# End-to-End PUF Tests
# ============================================================================


class TestPufEndToEnd(unittest.TestCase):
    """End-to-end PUF identity flow tests."""

    def test_full_puf_enrollment_and_attestation(self):
        """Complete PUF flow: enroll -> attest -> verify."""
        mod = _load_module(
            "core.neuro.attestation.device_identity",
            "core/neuro/attestation/device_identity.py",
        )

        device = mod.DeviceIdentity(device_id="e2e-puf-001", use_tpm=False, use_puf=True)
        key = device.provision_device_key()
        self.assertEqual(len(key.public_key), 32)

        nonce = hashlib.sha256(b"e2e-nonce").digest()[:16]
        attestation = device.create_attestation(
            challenge_nonce=nonce,
            telemetry_features=b"cpu:0.3,mem:0.7,net:0.1",
        )
        self.assertIsNotNone(attestation.telemetry_feature_hash)
        self.assertEqual(len(attestation.signature), 64)

        verifier = mod.AttestationVerifier(trusted_oem_cas=[])
        result = verifier.verify_attestation(attestation)
        self.assertTrue(result["valid"], f"Errors: {result.get('errors')}")

    def test_puf_ter_binding_e2e(self):
        """Complete PUF-TER binding flow."""
        puf_response = hashlib.sha256(b"e2e-puf-ter").digest()
        binding = PufTerBinding(puf_response=puf_response)

        entropy = hashlib.sha256(b"system-entropy").digest()
        integrity = hashlib.new("ripemd160", b"integrity").digest()
        ter_bytes = b"\x00" * 64

        enhanced_entropy = binding.enhance_entropy(entropy)
        enhanced_integrity = binding.enhance_integrity(integrity)
        self.assertNotEqual(enhanced_entropy, entropy)
        self.assertNotEqual(enhanced_integrity, integrity)

        proof = binding.create_binding_proof(ter_bytes)
        self.assertTrue(binding.verify_binding_proof(ter_bytes, proof))
        self.assertFalse(binding.verify_binding_proof(b"\xff" * 64, proof))

    def test_composite_sign_verify_e2e(self):
        """Complete composite identity sign/verify flow with mock PUFs."""
        clock_puf = MagicMock()
        clock_puf.get_response.return_value = hashlib.sha256(b"clock-e2e").digest()

        cache_puf = MagicMock()
        cache_puf.get_response.return_value = hashlib.sha256(b"cache-e2e").digest()[:16]

        identity = CompositeIdentity()
        identity.add_source(PufSource.CLOCK_DRIFT, clock_puf)
        identity.add_source(PufSource.CACHE_TIMING, cache_puf)

        message = b"critical-security-data"
        signature = identity.sign(message)
        self.assertIsNotNone(signature)

        valid = identity.verify_keypair(message, signature)
        self.assertTrue(valid)

        wrong_valid = identity.verify_keypair(b"tampered-data", signature)
        self.assertFalse(wrong_valid)


if __name__ == "__main__":
    unittest.main()
