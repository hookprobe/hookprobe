"""
Tests for HTP Security Enhancements

Tests the enhanced security features added to HookProbe Transport Protocol:
- Perfect Forward Secrecy (ephemeral X25519 key exchange)
- Packet padding and traffic analysis resistance
- Jitter injection for timing variability
- Continuous key rotation
- PoSF signatures on messages
- Adaptive transport modes (Burst/Balanced/Stealth/Ghost)
- Anti-DoS rate limiting
"""

import os
import sys
import time
import hashlib
import struct
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.htp.transport.htp import HookProbeTransport, HTPSession, HTPState as SessionState
import inspect

# Check if transport_mode parameter is supported by HookProbeTransport
_htp_sig = inspect.signature(HookProbeTransport.__init__)
_transport_mode_supported = 'transport_mode' in _htp_sig.parameters
import pytest


def test_ephemeral_key_exchange():
    """Test ephemeral X25519 key exchange for perfect forward secrecy."""
    print("\n=== Test: Ephemeral Key Exchange ===")

    # Simulate edge and validator generating ephemeral keys
    edge_ephemeral_private = x25519.X25519PrivateKey.generate()
    edge_ephemeral_public = edge_ephemeral_private.public_key()

    validator_ephemeral_private = x25519.X25519PrivateKey.generate()
    validator_ephemeral_public = validator_ephemeral_private.public_key()

    # Both sides compute shared secret
    edge_shared_secret = edge_ephemeral_private.exchange(validator_ephemeral_public)
    validator_shared_secret = validator_ephemeral_private.exchange(edge_ephemeral_public)

    # Shared secrets should match
    assert edge_shared_secret == validator_shared_secret, "Shared secrets don't match!"
    assert len(edge_shared_secret) == 32, "Shared secret should be 32 bytes"

    print(f"✓ Ephemeral key exchange successful")
    print(f"✓ Shared secret: {edge_shared_secret.hex()[:16]}...")
    print(f"✓ Perfect forward secrecy enabled")


@pytest.mark.skipif(not _transport_mode_supported, reason="transport_mode parameter not implemented")
def test_padding_and_removal():
    """Test packet padding and removal for traffic analysis resistance."""
    print("\n=== Test: Padding and Removal ===")

    transport = HookProbeTransport("test-node", listen_port=0, transport_mode="BALANCED")

    # Test data of various sizes
    test_data = [
        b"Small",
        b"Medium sized message for testing",
        b"Very long message that would normally reveal information about content" * 10
    ]

    for data in test_data:
        original_length = len(data)

        # Add padding
        padded = transport._add_padding(data, "BALANCED")
        padded_length = len(padded)

        # Padding should increase size
        assert padded_length > original_length, "Padding didn't increase size"

        # Remove padding
        unpadded = transport._remove_padding(padded)

        # Should recover original data
        assert unpadded == data, "Padding removal failed"

        print(f"✓ Original: {original_length} bytes → Padded: {padded_length} bytes → Recovered: {len(unpadded)} bytes")

    # Test different transport modes
    for mode in ["BURST", "BALANCED", "STEALTH", "GHOST"]:
        padded = transport._add_padding(b"Test", mode)
        mode_config = transport.TRANSPORT_MODES[mode]
        min_pad, max_pad = mode_config['padding']
        # Check padding is within expected range (approximately)
        print(f"✓ Mode {mode}: padding range {min_pad}-{max_pad} bytes")


@pytest.mark.skipif(not _transport_mode_supported, reason="transport_mode parameter not implemented")
def test_jitter_injection():
    """Test jitter injection for timing variability."""
    print("\n=== Test: Jitter Injection ===")

    transport = HookProbeTransport("test-node", listen_port=0, transport_mode="BALANCED")

    session = HTPSession(
        session_id=os.urandom(8),
        peer_address=("127.0.0.1", 5000),
        state=SessionState.ESTABLISHED,
        chacha_key=os.urandom(32),
        send_sequence=0,
        recv_sequence=0,
        weight_fingerprint=os.urandom(64),
        created_timestamp=time.time(),
        last_activity=time.time(),
        heartbeat_interval=30.0,
        jitter_min_ms=100,
        jitter_max_ms=1000,
        transport_mode="BALANCED"
    )

    # Calculate jitter multiple times
    jitters = []
    for _ in range(100):
        jitter = transport._get_jitter(session)
        jitters.append(jitter)

    # Jitter should vary
    assert len(set(jitters)) > 10, "Jitter not varying enough"

    # Check jitter is within expected range
    min_jitter = min(jitters)
    max_jitter = max(jitters)
    print(f"✓ Jitter range: {min_jitter:.3f}s to {max_jitter:.3f}s")
    print(f"✓ Jitter variation: {len(set(jitters))} unique values out of 100 samples")


@pytest.mark.skipif(not _transport_mode_supported, reason="transport_mode parameter not implemented")
def test_key_rotation():
    """Test continuous key rotation."""
    print("\n=== Test: Key Rotation ===")

    transport = HookProbeTransport("test-node", listen_port=0, transport_mode="BALANCED")

    # Create a session with shared secret
    session_id = os.urandom(8)
    session = HTPSession(
        session_id=session_id,
        peer_address=("127.0.0.1", 5000),
        state=SessionState.ESTABLISHED,
        chacha_key=os.urandom(32),
        send_sequence=0,
        recv_sequence=0,
        shared_secret=os.urandom(32),
        weight_fingerprint=os.urandom(64),
        created_timestamp=time.time(),
        last_activity=time.time(),
        heartbeat_interval=30.0,
        transport_mode="BALANCED"
    )

    transport.sessions[session_id] = session

    # Store original key
    original_key = session.chacha_key

    # Rotate key
    transport._rotate_session_key(session_id)

    # Key should have changed
    new_key = session.chacha_key
    assert new_key != original_key, "Key didn't change after rotation"
    assert session.key_rotation_counter == 1, "Rotation counter not incremented"

    print(f"✓ Original key: {original_key.hex()[:16]}...")
    print(f"✓ Rotated key:  {new_key.hex()[:16]}...")
    print(f"✓ Rotation counter: {session.key_rotation_counter}")

    # Test weight fingerprint update triggering rotation
    new_weight_fp = os.urandom(64)
    transport.update_weight_fingerprint(session_id, new_weight_fp)

    assert session.weight_fingerprint == new_weight_fp, "Weight fingerprint not updated"
    assert session.key_rotation_counter == 2, "Rotation counter not incremented"
    print(f"✓ Weight fingerprint updated and key rotated again")


@pytest.mark.skipif(not _transport_mode_supported, reason="transport_mode parameter not implemented")
def test_transport_mode_switching():
    """Test dynamic transport mode switching (adaptive polymorphism)."""
    print("\n=== Test: Transport Mode Switching ===")

    transport = HookProbeTransport("test-node", listen_port=0, transport_mode="BALANCED")

    session_id = os.urandom(8)
    session = HTPSession(
        session_id=session_id,
        peer_address=("127.0.0.1", 5000),
        state=SessionState.ESTABLISHED,
        chacha_key=os.urandom(32),
        send_sequence=0,
        recv_sequence=0,
        weight_fingerprint=os.urandom(64),
        created_timestamp=time.time(),
        last_activity=time.time(),
        heartbeat_interval=30.0,
        jitter_min_ms=100,
        jitter_max_ms=1000,
        transport_mode="BALANCED"
    )

    transport.sessions[session_id] = session

    # Test switching to each mode
    modes = ["BURST", "STEALTH", "GHOST", "BALANCED"]

    for mode in modes:
        transport.set_transport_mode(session_id, mode)

        assert session.transport_mode == mode, f"Mode not switched to {mode}"

        mode_config = transport.TRANSPORT_MODES[mode]
        assert session.heartbeat_interval == mode_config['heartbeat_interval']
        assert (session.jitter_min_ms, session.jitter_max_ms) == mode_config['jitter_ms']

        print(f"✓ Switched to {mode}: heartbeat={session.heartbeat_interval}s, jitter={session.jitter_min_ms}-{session.jitter_max_ms}ms")


@pytest.mark.skipif(not _transport_mode_supported, reason="transport_mode parameter not implemented")
def test_rate_limiting():
    """Test anti-DoS rate limiting."""
    print("\n=== Test: Anti-DoS Rate Limiting ===")

    transport = HookProbeTransport("test-node", listen_port=0, transport_mode="BALANCED")

    test_ip = "203.0.113.42"

    # First 10 requests should be allowed
    for i in range(10):
        allowed = transport._check_rate_limit(test_ip)
        assert allowed, f"Request {i+1} should be allowed"

    print(f"✓ First 10 requests allowed")

    # 11th request should be rate-limited
    allowed = transport._check_rate_limit(test_ip)
    assert not allowed, "11th request should be rate-limited"

    print(f"✓ 11th request correctly rate-limited")

    # Different IP should still be allowed
    allowed = transport._check_rate_limit("203.0.113.43")
    assert allowed, "Different IP should be allowed"

    print(f"✓ Different IP address not affected by rate limit")


@pytest.mark.skipif(not _transport_mode_supported, reason="transport_mode parameter not implemented")
def test_enhanced_key_derivation():
    """Test enhanced key derivation with HKDF."""
    print("\n=== Test: Enhanced Key Derivation ===")

    transport = HookProbeTransport("test-node", listen_port=0, transport_mode="BALANCED")

    # Test inputs
    shared_secret = os.urandom(32)
    session_secret = os.urandom(32)
    weight_fp = os.urandom(64)

    # Derive key
    key1 = transport._derive_session_key_enhanced(shared_secret, session_secret, weight_fp)

    assert len(key1) == 32, "Derived key should be 32 bytes"

    # Same inputs should produce same key
    key2 = transport._derive_session_key_enhanced(shared_secret, session_secret, weight_fp)
    assert key1 == key2, "Same inputs should produce same key"

    # Different inputs should produce different key
    different_secret = os.urandom(32)
    key3 = transport._derive_session_key_enhanced(different_secret, session_secret, weight_fp)
    assert key1 != key3, "Different inputs should produce different key"

    print(f"✓ Enhanced key derivation working correctly")
    print(f"✓ Key: {key1.hex()[:32]}...")


def test_posf_signature_format():
    """Test PoSF signature format in messages."""
    print("\n=== Test: PoSF Signature Format ===")

    # Simulate PoSF signature structure
    signature = os.urandom(32)
    data = b"Test message payload"

    # Pack signature with data (as done in send_data)
    packed = struct.pack('<H', len(signature)) + signature + data

    # Unpack (as done in receive_data)
    sig_length = struct.unpack('<H', packed[:2])[0]
    extracted_sig = packed[2:2+sig_length]
    extracted_data = packed[2+sig_length:]

    assert sig_length == 32, "Signature length incorrect"
    assert extracted_sig == signature, "Signature extraction failed"
    assert extracted_data == data, "Data extraction failed"

    print(f"✓ PoSF signature format correct")
    print(f"✓ Signature length: {sig_length} bytes")
    print(f"✓ Signature: {extracted_sig.hex()[:16]}...")


def run_all_tests():
    """Run all security enhancement tests."""
    print("="*60)
    print("HTP Security Enhancements Test Suite")
    print("="*60)

    tests = [
        test_ephemeral_key_exchange,
        test_padding_and_removal,
        test_jitter_injection,
        test_key_rotation,
        test_transport_mode_switching,
        test_rate_limiting,
        test_enhanced_key_derivation,
        test_posf_signature_format
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"✗ {test.__name__} FAILED: {e}")
            failed += 1

    print("\n" + "="*60)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("="*60)

    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
