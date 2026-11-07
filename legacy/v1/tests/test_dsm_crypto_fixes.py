"""
Tests for DSM crypto verification fixes.

Covers:
- attestation.py: verify_platform_attestation with real checks
- tpm.py: config-driven PCR reading
- bls.py: PoP epoch validation and nonce/signature checks
"""

import base64
import json
import os
import tempfile
import time

import pytest

from shared.dsm.crypto.attestation import (
    verify_platform_attestation,
    get_expected_pcr_baseline,
)


# =========================================================================
# Attestation Tests
# =========================================================================


class TestAttestationVerification:
    """Tests for verify_platform_attestation."""

    def test_rejects_empty_data(self):
        assert verify_platform_attestation({}) is False
        assert verify_platform_attestation(None) is False

    def test_rejects_missing_quote_data(self):
        assert verify_platform_attestation({"signature": "abc"}) is False

    def test_rejects_missing_signature(self):
        assert verify_platform_attestation({"quote_data": {"nonce": "abc"}}) is False

    def test_rejects_missing_nonce(self):
        attestation = {
            "quote_data": {"timestamp": str(time.monotonic())},
            "signature": "abc123",
        }
        assert verify_platform_attestation(attestation) is False

    def test_rejects_stale_attestation(self):
        """Attestation older than max_age_s should be rejected."""
        nonce = base64.b64encode(b"test-nonce-123456").decode()
        attestation = {
            "quote_data": {
                "nonce": nonce,
                "timestamp": str(time.monotonic() - 120),  # 2 minutes old
            },
            "signature": "abc",
        }
        assert verify_platform_attestation(attestation, max_age_s=60) is False

    def test_accepts_fresh_attestation(self):
        """Fresh attestation with valid structure should pass."""
        nonce_bytes = b"test-nonce-for-valid"
        nonce_b64 = base64.b64encode(nonce_bytes).decode()
        attestation = {
            "quote_data": {
                "nonce": nonce_b64,
                "timestamp": str(time.monotonic()),
            },
            "signature": "valid-sig",
        }
        assert verify_platform_attestation(attestation) is True

    def test_nonce_mismatch_rejected(self):
        """When expected_nonce is provided, it must match."""
        nonce_b64 = base64.b64encode(b"actual-nonce").decode()
        attestation = {
            "quote_data": {
                "nonce": nonce_b64,
                "timestamp": str(time.monotonic()),
            },
            "signature": "sig",
        }
        result = verify_platform_attestation(
            attestation, expected_nonce=b"different-nonce"
        )
        assert result is False

    def test_nonce_match_accepted(self):
        """When expected_nonce matches, attestation passes."""
        nonce = b"matching-nonce-value!"
        nonce_b64 = base64.b64encode(nonce).decode()
        attestation = {
            "quote_data": {
                "nonce": nonce_b64,
                "timestamp": str(time.monotonic()),
            },
            "signature": "sig",
        }
        result = verify_platform_attestation(attestation, expected_nonce=nonce)
        assert result is True


class TestPCRBaseline:
    """Tests for get_expected_pcr_baseline config loading."""

    def test_returns_empty_when_no_config(self, tmp_path, monkeypatch):
        """Without config file, returns empty dict (no enforcement)."""
        monkeypatch.setenv("DSM_PCR_CONFIG", str(tmp_path / "nonexistent.json"))
        baseline = get_expected_pcr_baseline()
        assert baseline == {}

    def test_loads_from_config_file(self, tmp_path, monkeypatch):
        """Loads PCR baseline from JSON config."""
        config_data = {"0": "hash_bios", "7": "hash_secureboot"}
        config_path = tmp_path / "pcr.json"
        config_path.write_text(json.dumps(config_data))
        monkeypatch.setenv("DSM_PCR_CONFIG", str(config_path))

        baseline = get_expected_pcr_baseline()
        assert baseline == {0: "hash_bios", 7: "hash_secureboot"}

    def test_handles_corrupt_config(self, tmp_path, monkeypatch):
        """Corrupt config file returns empty dict."""
        config_path = tmp_path / "bad.json"
        config_path.write_text("not json {{{")
        monkeypatch.setenv("DSM_PCR_CONFIG", str(config_path))

        baseline = get_expected_pcr_baseline()
        assert baseline == {}


# =========================================================================
# TPM PCR Tests
# =========================================================================


class TestTPMPCRRead:
    """Tests for tpm2_pcr_read config-driven approach."""

    def test_returns_empty_without_config(self, tmp_path, monkeypatch):
        """Without config and without TPM, returns empty dict."""
        monkeypatch.setenv("DSM_PCR_CONFIG", str(tmp_path / "no.json"))
        # Reset TPM availability cache
        import shared.dsm.crypto.tpm as tpm_mod
        tpm_mod._tpm_available = False

        result = tpm_mod.tpm2_pcr_read([0, 1, 7])
        assert result == {}

    def test_loads_pcr_from_config(self, tmp_path, monkeypatch):
        """Loads requested PCR indices from config file."""
        config_data = {"0": "bios_hash", "1": "bios_data_hash", "7": "sb_hash"}
        config_path = tmp_path / "pcr.json"
        config_path.write_text(json.dumps(config_data))
        monkeypatch.setenv("DSM_PCR_CONFIG", str(config_path))

        import shared.dsm.crypto.tpm as tpm_mod
        tpm_mod._tpm_available = False

        result = tpm_mod.tpm2_pcr_read([0, 7])
        assert result == {0: "bios_hash", 7: "sb_hash"}

    def test_missing_pcr_index_skipped(self, tmp_path, monkeypatch):
        """Requesting a PCR index not in config is silently skipped."""
        config_data = {"0": "hash0"}
        config_path = tmp_path / "pcr.json"
        config_path.write_text(json.dumps(config_data))
        monkeypatch.setenv("DSM_PCR_CONFIG", str(config_path))

        import shared.dsm.crypto.tpm as tpm_mod
        tpm_mod._tpm_available = False

        result = tpm_mod.tpm2_pcr_read([0, 5, 7])
        assert result == {0: "hash0"}
        assert 5 not in result
        assert 7 not in result


# =========================================================================
# BLS PoP Epoch Validation Tests
# =========================================================================


class TestPoPEpochValidation:
    """Tests for verify_proof_of_possession epoch checks."""

    def _make_pop(self, epoch=100, nonce_len=32, has_sig=True):
        """Helper to create a mock PoP object."""
        from shared.dsm.crypto.bls import ProofOfPossession
        return ProofOfPossession(
            public_key=b"fake-pubkey-pem",
            validator_id="validator-001",
            epoch=epoch,
            nonce=os.urandom(nonce_len) if nonce_len > 0 else b"",
            signature=b"fake-signature" if has_sig else b"",
            key_type="RSA",
        )

    def test_epoch_mismatch_rejected(self):
        """PoP with epoch far from expected is rejected (too old)."""
        from shared.dsm.crypto.bls import verify_proof_of_possession
        pop = self._make_pop(epoch=50)
        valid, reason = verify_proof_of_possession(pop, expected_epoch=100)
        assert not valid
        assert "too old" in reason

    def test_future_epoch_rejected(self):
        """PoP with epoch ahead of current is rejected."""
        from shared.dsm.crypto.bls import verify_proof_of_possession
        pop = self._make_pop(epoch=110)
        valid, reason = verify_proof_of_possession(pop, expected_epoch=100)
        assert not valid
        assert "future" in reason

    def test_epoch_too_old_rejected(self):
        """PoP with epoch too far behind current is rejected."""
        from shared.dsm.crypto.bls import verify_proof_of_possession
        pop = self._make_pop(epoch=80)
        valid, reason = verify_proof_of_possession(
            pop, expected_epoch=80, max_epoch_age=5
        )
        # epoch matches exactly so should pass epoch check, but sig fails
        # Let's test with epoch 70 vs expected 80 with max_age 5
        pop2 = self._make_pop(epoch=70)
        valid2, reason2 = verify_proof_of_possession(
            pop2, expected_epoch=80, max_epoch_age=5
        )
        assert not valid2
        assert "too old" in reason2

    def test_negative_epoch_rejected(self):
        """Negative epoch value is rejected."""
        from shared.dsm.crypto.bls import verify_proof_of_possession
        pop = self._make_pop(epoch=-1)
        valid, reason = verify_proof_of_possession(pop)
        assert not valid
        assert "Invalid epoch" in reason

    def test_short_nonce_rejected(self):
        """Nonce shorter than 16 bytes is rejected."""
        from shared.dsm.crypto.bls import verify_proof_of_possession
        pop = self._make_pop(nonce_len=8)
        valid, reason = verify_proof_of_possession(pop, expected_epoch=100)
        assert not valid
        assert "nonce" in reason.lower()

    def test_empty_signature_rejected(self):
        """Empty signature is rejected."""
        from shared.dsm.crypto.bls import verify_proof_of_possession
        pop = self._make_pop(has_sig=False)
        valid, reason = verify_proof_of_possession(pop, expected_epoch=100)
        assert not valid
        assert "signature" in reason.lower()

    def test_valid_epoch_passes_to_signature_check(self):
        """PoP with valid epoch proceeds to signature verification."""
        from shared.dsm.crypto.bls import verify_proof_of_possession
        pop = self._make_pop(epoch=100)
        valid, reason = verify_proof_of_possession(pop, expected_epoch=100)
        # Signature will fail (fake key), but we shouldn't get epoch errors
        assert "Epoch" not in reason
        assert "epoch" not in reason.lower() or "too old" not in reason.lower()
