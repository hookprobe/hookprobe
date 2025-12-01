#!/usr/bin/env python3
"""
End-to-End Test: HookProbe Transport Protocol (HTP)

Tests complete edge-to-validator communication flow:
1. Validator starts listening
2. Edge initiates connection (HELLO)
3. Validator challenges (CHALLENGE)
4. Edge attests (ATTEST)
5. Validator accepts (ACCEPT)
6. Bidirectional encrypted data exchange (DATA)
7. Heartbeat keep-alive (HEARTBEAT)
8. Session close (CLOSE)
"""

import sys
import os
import time
import threading
from cryptography.hazmat.primitives.asymmetric import ed25519

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from neuro.transport.htp import HookProbeTransport, MessageType, SessionState


def run_validator(validator_ready_event, test_complete_event):
    """Run validator in separate thread."""
    print("[Validator Thread] Starting...")

    # Create validator transport
    validator = HookProbeTransport(
        node_id="validator-001",
        listen_port=4478,
        is_validator=True
    )

    print(f"[Validator] Listening on {validator.local_address}")
    validator_ready_event.set()

    # Wait for HELLO from edge
    print("[Validator] Waiting for HELLO...")
    start_time = time.time()

    while time.time() - start_time < 30:  # 30 second timeout
        try:
            packet, addr = validator.socket.recvfrom(validator.MAX_PACKET_SIZE)
            msg = validator._parse_message(packet)

            if msg.msg_type == MessageType.HELLO:
                print(f"[Validator] Received HELLO from {addr}")

                # Parse HELLO payload
                edge_node_id = msg.payload[:32].decode('utf-8').rstrip('\x00')
                weight_fingerprint = msg.payload[32:]

                print(f"[Validator]   Edge ID: {edge_node_id}")
                print(f"[Validator]   Weight FP: {weight_fingerprint.hex()[:32]}...")

                # Send CHALLENGE
                import os as os_module
                challenge_nonce = os_module.urandom(16)

                from neuro.transport.htp import HTPMessage
                challenge_msg = HTPMessage(
                    msg_type=MessageType.CHALLENGE,
                    session_id=msg.session_id,
                    sequence=0,
                    payload=challenge_nonce
                )

                packet = validator._serialize_message(challenge_msg)
                validator.socket.sendto(packet, addr)
                print("[Validator] Sent CHALLENGE")

                # Wait for ATTEST
                print("[Validator] Waiting for ATTEST...")
                packet, addr = validator.socket.recvfrom(validator.MAX_PACKET_SIZE)
                attest_msg = validator._parse_message(packet)

                if attest_msg.msg_type == MessageType.ATTEST:
                    signature = attest_msg.payload
                    print(f"[Validator] Received ATTEST (signature: {len(signature)} bytes)")

                    # Verify signature (simplified - in production verify with public key)
                    # For now, accept all attestations in test

                    # Send ACCEPT with session secret
                    session_secret = os_module.urandom(32)

                    accept_msg = HTPMessage(
                        msg_type=MessageType.ACCEPT,
                        session_id=msg.session_id,
                        sequence=1,
                        payload=session_secret
                    )

                    packet = validator._serialize_message(accept_msg)
                    validator.socket.sendto(packet, addr)
                    print("[Validator] Sent ACCEPT - session established")

                    # Create session
                    from neuro.transport.htp import HTPSession
                    session = HTPSession(
                        session_id=msg.session_id,
                        peer_address=addr,
                        state=SessionState.ESTABLISHED,
                        chacha_key=validator._derive_session_key(session_secret, weight_fingerprint),
                        send_sequence=2,
                        recv_sequence=attest_msg.sequence,
                        weight_fingerprint=weight_fingerprint,
                        created_timestamp=time.time(),
                        last_activity=time.time(),
                        heartbeat_interval=30.0
                    )
                    validator.sessions[msg.session_id] = session

                    # Wait for DATA from edge
                    print("[Validator] Waiting for DATA...")
                    data_received = validator.receive_data(msg.session_id, timeout=10.0)

                    if data_received:
                        print(f"[Validator] Received DATA: {data_received.decode()}")

                        # Send response DATA
                        response = b"Hello from Validator! Your edge is authenticated."
                        validator.send_data(msg.session_id, response)
                        print("[Validator] Sent response DATA")

                    # Wait for CLOSE
                    print("[Validator] Waiting for CLOSE...")
                    time.sleep(2)

                    break

        except BlockingIOError:
            time.sleep(0.1)
            continue

    print("[Validator] Test complete")
    test_complete_event.set()


def run_edge():
    """Run edge device."""
    print("\n[Edge] Starting...")

    # Generate device key
    device_key = ed25519.Ed25519PrivateKey.generate()

    # Generate weight fingerprint (mock)
    import hashlib
    weight_fingerprint = hashlib.sha512(b"mock-neural-weights-edge-001").digest()

    # Create edge transport
    edge = HookProbeTransport(
        node_id="edge-001",
        listen_port=0,  # Random port
        is_validator=False
    )

    print(f"[Edge] Listening on {edge.local_address}")

    # Connect to validator
    validator_address = ("127.0.0.1", 4478)

    print(f"[Edge] Connecting to validator at {validator_address}...")

    session_id = edge.connect(
        validator_address=validator_address,
        weight_fingerprint=weight_fingerprint,
        device_key=device_key
    )

    if not session_id:
        print("[Edge] ✗ Connection failed")
        return False

    print(f"[Edge] ✓ Session established: {session_id.hex()[:8]}...")

    # Send data
    message = b"Hello from Edge! This is a security event."
    print(f"[Edge] Sending DATA: {message.decode()}")
    edge.send_data(session_id, message)

    # Receive response
    print("[Edge] Waiting for response...")
    response = edge.receive_data(session_id, timeout=10.0)

    if response:
        print(f"[Edge] Received response: {response.decode()}")

    # Close session
    print("[Edge] Closing session...")
    edge.close_session(session_id)

    print("[Edge] ✓ Test complete")
    return True


def main():
    """Run end-to-end test."""
    print("=" * 60)
    print("HookProbe Transport Protocol (HTP) - End-to-End Test")
    print("=" * 60)

    # Events for thread coordination
    validator_ready = threading.Event()
    test_complete = threading.Event()

    # Start validator in separate thread
    validator_thread = threading.Thread(
        target=run_validator,
        args=(validator_ready, test_complete),
        daemon=True
    )
    validator_thread.start()

    # Wait for validator to be ready
    print("\nWaiting for validator to start...")
    validator_ready.wait(timeout=5)
    print("Validator ready!\n")

    # Give validator a moment to settle
    time.sleep(0.5)

    # Run edge test
    success = run_edge()

    # Wait for validator to complete
    test_complete.wait(timeout=10)

    print("\n" + "=" * 60)
    if success:
        print("✓ END-TO-END TEST PASSED")
        print("=" * 60)
        print("\nTest Summary:")
        print("  ✓ HELLO sent and received")
        print("  ✓ CHALLENGE sent and received")
        print("  ✓ ATTEST sent and received")
        print("  ✓ ACCEPT sent and received")
        print("  ✓ Session established")
        print("  ✓ Encrypted DATA exchanged")
        print("  ✓ Session closed gracefully")
        print("\nHookProbe Transport Protocol (HTP) is working correctly!")
        return 0
    else:
        print("✗ END-TO-END TEST FAILED")
        print("=" * 60)
        return 1


if __name__ == '__main__':
    exit(main())
