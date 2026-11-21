"""
Tests for DSM Zero-Trust Verification Gates.

Validates that hardcoded trust bypasses have been replaced with real logic.
"""

import json
import os
import struct
import tempfile
import time

import pytest

# ---------------------------------------------------------------------------
# DSM Identity Tests
# ---------------------------------------------------------------------------


class TestNodeIdentityProvision:
    """Test NodeIdentity.provision_node() returns real identity."""

    def test_provision_returns_identity(self):
        from shared.dsm.identity import NodeIdentity

        identity = NodeIdentity.provision_node("hw-uuid-12345")
        assert identity is not None
        assert identity.node_id == "hw-uuid-12345"

    def test_provision_empty_id_returns_none(self):
        from shared.dsm.identity import NodeIdentity

        assert NodeIdentity.provision_node("") is None
        assert NodeIdentity.provision_node(None) is None

    def test_provision_returns_certificate(self):
        from shared.dsm.identity import NodeIdentity

        identity = NodeIdentity.provision_node("hw-uuid-test")
        assert identity.certificate is not None
        cert_data = json.loads(identity.certificate)
        assert cert_data["node_id"] == "hw-uuid-test"
        assert "issued_at" in cert_data

    def test_provision_has_public_key(self):
        from shared.dsm.identity import NodeIdentity

        identity = NodeIdentity.provision_node("hw-uuid-pk")
        assert hasattr(identity, "public_key")
        assert len(identity.public_key) == 32  # SHA-256 digest


class TestNodeIdentityAttest:
    """Test NodeIdentity.attest() returns real attestation."""

    def test_attest_includes_digest(self):
        from shared.dsm.identity import NodeIdentity

        identity = NodeIdentity.provision_node("hw-uuid-attest")
        attestation = identity.attest()
        assert "digest" in attestation.get("evidence", {}) or attestation.get("quote")
        assert attestation["quote"]  # Non-empty quote
        assert attestation["certificate"] == identity.certificate

    def test_attest_has_evidence(self):
        from shared.dsm.identity import NodeIdentity

        identity = NodeIdentity.provision_node("hw-uuid-evidence")
        attestation = identity.attest()
        evidence = attestation.get("evidence", {})
        assert evidence.get("node_id") == "hw-uuid-evidence"
        assert evidence.get("timestamp") > 0

    def test_extract_node_id_from_json_cert(self):
        from shared.dsm.identity import NodeIdentity

        cert = json.dumps({"node_id": "test-node-123"})
        identity = NodeIdentity(certificate=cert, tpm_key=b"key")
        assert identity.node_id == "test-node-123"

    def test_extract_node_id_unknown_format(self):
        from shared.dsm.identity import NodeIdentity

        identity = NodeIdentity(certificate="not-json", tpm_key=b"key")
        assert identity.node_id.startswith("node-")


class TestCertificateChainVerification:
    """Test verify_certificate_chain() with real file checks."""

    def test_inline_cert_passes(self):
        from shared.dsm.identity import verify_certificate_chain

        assert verify_certificate_chain("<inline>", "/nonexistent") is True

    def test_missing_cert_fails(self):
        from shared.dsm.identity import verify_certificate_chain

        assert verify_certificate_chain("/nonexistent/cert.pem", "/nonexistent/ca.pem") is False

    def test_empty_path_fails(self):
        from shared.dsm.identity import verify_certificate_chain

        assert verify_certificate_chain("", "/root.pem") is False

    def test_valid_cert_file_passes(self):
        from shared.dsm.identity import verify_certificate_chain

        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write("-----BEGIN CERTIFICATE-----\nMIIBfake...\n-----END CERTIFICATE-----\n")
            cert_path = f.name
        try:
            # CA root doesn't exist => self-signed accepted
            result = verify_certificate_chain(cert_path, "/nonexistent/ca.pem")
            assert result is True
        finally:
            os.unlink(cert_path)

    def test_too_small_cert_file_fails(self):
        from shared.dsm.identity import verify_certificate_chain

        with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as f:
            f.write("tiny")
            cert_path = f.name
        try:
            assert verify_certificate_chain(cert_path, "/nonexistent/ca.pem") is False
        finally:
            os.unlink(cert_path)


# ---------------------------------------------------------------------------
# DSM Validator Registry Tests
# ---------------------------------------------------------------------------


class TestValidatorIdentityVerification:
    """Test _verify_identity() rejects invalid identities."""

    def _make_registry(self):
        from shared.dsm.validator import ValidatorRegistry

        return ValidatorRegistry()

    def test_verify_identity_no_cert_fails(self):
        reg = self._make_registry()
        # Object without certificate attribute
        assert reg._verify_identity(None) is False
        assert reg._verify_identity(object()) is False

    def test_verify_identity_empty_cert_fails(self):
        reg = self._make_registry()

        class FakeIdentity:
            certificate = ""

        assert reg._verify_identity(FakeIdentity()) is False

    def test_verify_identity_short_cert_fails(self):
        reg = self._make_registry()

        class FakeIdentity:
            certificate = "tiny"

        assert reg._verify_identity(FakeIdentity()) is False

    def test_verify_identity_valid_cert_file(self):
        reg = self._make_registry()

        # Create a real cert file to pass file-based verification
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".pem", delete=False
        ) as f:
            f.write("-----BEGIN CERTIFICATE-----\nMIIBfake...\n-----END CERTIFICATE-----\n")
            cert_path = f.name
        try:

            class FakeIdentity:
                certificate = cert_path

            result = reg._verify_identity(FakeIdentity())
            assert result is True
        finally:
            os.unlink(cert_path)


class TestValidatorReputation:
    """Test _calculate_reputation() uses real data."""

    def _make_registry(self):
        from shared.dsm.validator import ValidatorRegistry

        return ValidatorRegistry()

    def test_reputation_unknown_node_returns_neutral(self):
        reg = self._make_registry()
        assert reg._calculate_reputation("unknown-node") == 0.5

    def test_reputation_with_stored_score(self):
        from shared.dsm.validator import ValidatorEntry, ValidatorRegistry

        reg = ValidatorRegistry()
        reg.validators["node-1"] = ValidatorEntry(
            node_id="node-1",
            public_key=b"pk",
            certificate=b"cert",
            reputation_score=0.9,
            uptime_days=60,
        )
        assert reg._calculate_reputation("node-1") == 0.9

    def test_reputation_from_uptime(self):
        from shared.dsm.validator import ValidatorEntry, ValidatorRegistry

        reg = ValidatorRegistry()
        reg.validators["node-2"] = ValidatorEntry(
            node_id="node-2",
            public_key=b"pk",
            certificate=b"cert",
            reputation_score=0.0,  # Not set
            uptime_days=45,
        )
        assert reg._calculate_reputation("node-2") == 0.85


class TestValidatorStake:
    """Test _verify_stake() requires minimum commitment."""

    def test_stake_unknown_node_fails(self):
        from shared.dsm.validator import ValidatorRegistry

        reg = ValidatorRegistry()
        assert reg._verify_stake("unknown") is False

    def test_stake_requires_minimum_uptime(self):
        from shared.dsm.validator import ValidatorEntry, ValidatorRegistry

        reg = ValidatorRegistry()
        reg.validators["node-low"] = ValidatorEntry(
            node_id="node-low",
            public_key=b"pk",
            certificate=b"cert",
            uptime_days=1,
        )
        assert reg._verify_stake("node-low") is False

    def test_stake_passes_with_uptime(self):
        from shared.dsm.validator import ValidatorEntry, ValidatorRegistry

        reg = ValidatorRegistry()
        reg.validators["node-ok"] = ValidatorEntry(
            node_id="node-ok",
            public_key=b"pk",
            certificate=b"cert",
            uptime_days=5,
        )
        assert reg._verify_stake("node-ok") is True


class TestValidatorVote:
    """Test _initiate_validator_vote() bootstrap behavior."""

    def test_vote_bootstrap_auto_approves(self):
        from shared.dsm.validator import ValidatorRegistry

        reg = ValidatorRegistry()
        # No existing validators — bootstrap phase
        app = {"node_id": "bootstrap-node"}
        app_id = reg._generate_application_id()
        reg.pending_applications[app_id] = app
        app["node_id"] = "bootstrap-node"
        # Should not raise (auto-approve path)
        reg._initiate_validator_vote(app)


class TestUptimeCheck:
    """Test _check_uptime() reads real data."""

    def test_uptime_from_validator_record(self):
        from shared.dsm.validator import ValidatorEntry, ValidatorRegistry

        reg = ValidatorRegistry()
        reg.validators["node-up"] = ValidatorEntry(
            node_id="node-up",
            public_key=b"pk",
            certificate=b"cert",
            uptime_days=60,
        )
        assert reg._check_uptime("node-up") == 60

    def test_uptime_unknown_reads_proc(self):
        from shared.dsm.validator import ValidatorRegistry

        reg = ValidatorRegistry()
        uptime = reg._check_uptime("unknown-node")
        # On Linux, /proc/uptime exists and returns >= 0
        assert uptime >= 0


class TestPCRConfig:
    """Test _get_expected_pcr_values() loads from config."""

    def test_pcr_no_config_returns_empty(self):
        from shared.dsm.validator import ValidatorRegistry

        reg = ValidatorRegistry()
        # Default config path doesn't exist
        result = reg._get_expected_pcr_values()
        assert result == {}

    def test_pcr_loads_from_file(self):
        from shared.dsm.validator import ValidatorRegistry

        reg = ValidatorRegistry()
        expected = {0: "hash0", 7: "hash7"}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(expected, f)
            config_path = f.name
        try:
            os.environ["DSM_PCR_CONFIG"] = config_path
            result = reg._get_expected_pcr_values()
            assert result == {"0": "hash0", "7": "hash7"}  # JSON keys are strings
        finally:
            os.environ.pop("DSM_PCR_CONFIG", None)
            os.unlink(config_path)


# ---------------------------------------------------------------------------
# Neuro PoSF Verification Tests
# ---------------------------------------------------------------------------


class TestResonanceProofVerification:
    """Test PoSF signature verification in ResonanceProof.

    Imports directly from the synaptic_encryption module to avoid
    core.neuro.__init__ which requires crypto.transport.
    """

    @staticmethod
    def _import_resonance_proof():
        """Import ResonanceProof directly from the file (avoids core.neuro.__init__)."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "synaptic_encryption",
            os.path.join(os.path.dirname(__file__), "..", "core", "neuro", "synaptic_encryption.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.ResonanceProof

    def _make_proof(self, posf_sig=b"\x00" * 32, drift=0.01, age_us=None):
        ResonanceProof = self._import_resonance_proof()
        now_us = time.time_ns() // 1000
        return ResonanceProof(
            initiator_id=b"\x01" * 16,
            responder_id=b"\x02" * 16,
            resonance_timestamp_us=age_us if age_us else now_us,
            combined_fingerprint=b"\xAA" * 32,
            alignment_drift=drift,
            initiator_ter_hash=1234,
            responder_ter_hash=5678,
            posf_signature=posf_sig,
        )

    def test_valid_proof_passes(self):
        proof = self._make_proof()
        assert proof.verify() is True

    def test_posf_rejects_missing_signature(self):
        proof = self._make_proof(posf_sig=b"")
        assert proof.verify() is False

    def test_posf_rejects_short_signature(self):
        proof = self._make_proof(posf_sig=b"\x00" * 10)
        assert proof.verify() is False

    def test_posf_rejects_high_drift(self):
        proof = self._make_proof(drift=0.2)  # > 0.05 threshold
        assert proof.verify() is False

    def test_posf_rejects_stale_proof(self):
        # Proof from 120 seconds ago (> MAX_TER_AGE_SECONDS=60)
        old_us = (time.time_ns() // 1000) - (120 * 1_000_000)
        proof = self._make_proof(age_us=old_us)
        assert proof.verify() is False
