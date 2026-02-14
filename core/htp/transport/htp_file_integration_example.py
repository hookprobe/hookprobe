#!/usr/bin/env python3
"""
HTP File Transfer Integration Example

Shows how htp_file.py integrates with your existing HookProbe Transport Protocol.

This demonstrates:
1. Client-side file operations (Guardian/Nexus edge devices)
2. Server-side file handling (mesh backend)
3. Security properties maintained from Neuro Protocol
"""

import asyncio
import hashlib
from dataclasses import dataclass
from typing import Any, Optional

# Import from your existing HTP implementation
# from neuro.transport.htp import HookProbeTransport, MessageType
# from neuro.core.posf import PoSFSigner
# from neuro.neural.engine import NeuralEngine

# Import the new file transfer extension
from htp_file import (
    HTPFileTransfer,
    HTPFileServer,
    FileOperation,
    FileFlags,
    FileMetadata,
    HTPFileError
)


# =============================================================================
# MOCK HTP SESSION (Replace with your actual HTP implementation)
# =============================================================================

@dataclass
class MockHTPSession:
    """
    Mock HTP session for demonstration.
    
    In production, this would be your actual HookProbeTransport class
    from src/neuro/transport/htp.py
    """
    node_id: str
    weight_fingerprint: bytes
    session_key: bytes
    is_authenticated: bool = True
    
    # Message queue (simulates network)
    _send_queue: list = None
    _recv_queue: list = None
    
    def __post_init__(self):
        self._send_queue = []
        self._recv_queue = []
    
    async def send_data(self, data: dict):
        """Send data over HTP (encrypted with session key)."""
        # In real implementation:
        # 1. Serialize data
        # 2. Encrypt with ChaCha20-Poly1305 using session_key
        # 3. Add PoSF signature using current weights
        # 4. Send over UDP
        self._send_queue.append(data)
        print(f"[HTP SEND] {data.get('type', 'data')}")
    
    async def receive_data(self) -> dict:
        """Receive data from HTP (decrypted)."""
        # In real implementation:
        # 1. Receive UDP packet
        # 2. Verify PoSF signature
        # 3. Decrypt with ChaCha20-Poly1305
        # 4. Return deserialized data
        if self._recv_queue:
            return self._recv_queue.pop(0)
        
        # Simulate response (in production this comes from network)
        await asyncio.sleep(0.01)
        return {'file_id': 1, 'ready': True}
    
    def inject_response(self, response: dict):
        """Helper for testing - inject a response."""
        self._recv_queue.append(response)


# =============================================================================
# GUARDIAN/NEXUS EDGE CLIENT EXAMPLE
# =============================================================================

async def edge_client_example():
    """
    Example: Guardian edge device uploading logs to mesh backend backend.
    
    This shows how an edge device uses HTP file transfer to:
    1. Upload security logs
    2. Download updated WAF rules
    3. Sync configuration files
    """
    print("\n" + "=" * 70)
    print("GUARDIAN EDGE CLIENT EXAMPLE")
    print("=" * 70)
    
    # Create HTP session (in production, this comes from HTP handshake)
    htp_session = MockHTPSession(
        node_id="guardian-edge-001",
        weight_fingerprint=hashlib.sha512(b"neural_weights_state").digest(),
        session_key=hashlib.sha256(b"session_secret" + b"weight_fingerprint").digest()
    )
    
    # Initialize file transfer over HTP
    async with HTPFileTransfer(
        htp_session,
        chunk_size=8192,      # 8KB chunks (good for SBC memory)
        compress=True,        # Enable compression for logs
        verify_hash=True      # Always verify integrity
    ) as ft:
        
        # ------------------------------------------
        # 1. UPLOAD: Send security logs to backend
        # ------------------------------------------
        print("\n[1] Uploading security logs...")
        
        log_data = b"""
        2025-01-15 10:23:45 [ALERT] NAPSE: ET SCAN Nmap Scripting Engine
        2025-01-15 10:23:46 [BLOCK] NAXSI: XSS attempt blocked
        2025-01-15 10:23:47 [INFO] Qsecbit score: 0.42 (GREEN)
        2025-01-15 10:24:01 [ALERT] NAPSE: SQL Injection Attempt
        2025-01-15 10:24:02 [BLOCK] NAXSI: SQLi blocked
        2025-01-15 10:24:03 [WARN] Qsecbit score: 0.51 (AMBER)
        """
        
        # Inject mock server responses
        htp_session.inject_response({'file_id': 1, 'ready': True})
        htp_session.inject_response({'file_id': 1, 'verified': True, 'size': len(log_data)})
        
        try:
            success = await ft.create(
                remote_path='/logs/guardian-001/security-2025-01-15.log',
                data=log_data,
                create_dirs=True
            )
            print(f"   Upload result: {'SUCCESS' if success else 'FAILED'}")
        except HTPFileError as e:
            print(f"   Upload error: {e}")
        
        # ------------------------------------------
        # 2. DOWNLOAD: Get updated WAF rules
        # ------------------------------------------
        print("\n[2] Downloading WAF rules update...")
        
        # Mock server sends file metadata then chunks
        waf_rules = b"""
        # NAXSI Custom Rules - Updated 2025-01-15
        MainRule "str:<script" "msg:XSS script tag" "mz:$BODY" "s:$XSS:8" id:9001;
        MainRule "str:union select" "msg:SQL union" "mz:$ARGS" "s:$SQL:8" id:9002;
        """
        
        file_hash = hashlib.sha256(waf_rules).digest()
        
        htp_session.inject_response({
            'file_id': 2,
            'size': len(waf_rules),
            'total_chunks': 1,
            'file_hash': file_hash,
            'compressed': False
        })
        htp_session.inject_response({
            'file_id': 2,
            'chunk_index': 0,
            'data': waf_rules
        })
        
        try:
            rules = await ft.read('/config/waf/naxsi-custom.rules')
            print(f"   Downloaded: {len(rules)} bytes")
            print(f"   First line: {rules.decode().split(chr(10))[1].strip()}")
        except HTPFileError as e:
            print(f"   Download error: {e}")
        
        # ------------------------------------------
        # 3. STAT: Check if config needs update
        # ------------------------------------------
        print("\n[3] Checking remote config status...")
        
        htp_session.inject_response({
            'file_id': 3,
            'size': 4096,
            'hash': hashlib.sha256(b"config_content").digest(),
            'mtime': 1705312000000000,  # Timestamp
            'ctime': 1705000000000000,
            'permissions': 0o644,
            'is_directory': False
        })
        
        try:
            meta = await ft.stat('/config/hookprobe.yaml')
            print(f"   File size: {meta.size} bytes")
            print(f"   Last modified: {meta.mtime}")
            print(f"   Is directory: {meta.is_directory}")
        except HTPFileError as e:
            print(f"   Stat error: {e}")
        
        # ------------------------------------------
        # 4. LIST: Get available threat intel files
        # ------------------------------------------
        print("\n[4] Listing threat intelligence files...")
        
        from htp_file import DirectoryEntry
        htp_session.inject_response({
            'file_id': 4,
            'entries': [
                DirectoryEntry('cve-2025-001.json', False, 2048, 1705312000000000),
                DirectoryEntry('ioc-malware.csv', False, 10240, 1705311000000000),
                DirectoryEntry('blacklist-ips.txt', False, 5120, 1705310000000000),
            ]
        })
        
        try:
            entries = await ft.list('/threat-intel/')
            print(f"   Found {len(entries)} files:")
            for entry in entries:
                print(f"     - {entry.name} ({entry.size} bytes)")
        except HTPFileError as e:
            print(f"   List error: {e}")


# =============================================================================
# MESH BACKEND SERVER EXAMPLE
# =============================================================================

async def mesh_server_example():
    """
    Example: Mesh backend handling file requests from edge devices.

    This shows how the server:
    1. Validates paths (prevents traversal attacks)
    2. Handles CRUD operations
    3. Maintains security properties
    """
    print("\n" + "=" * 70)
    print("MESH BACKEND SERVER EXAMPLE")
    print("=" * 70)
    
    # Create HTP session (in production, from accepted connection)
    htp_session = MockHTPSession(
        node_id="mesh-backend",
        weight_fingerprint=hashlib.sha512(b"server_weights").digest(),
        session_key=hashlib.sha256(b"server_session").digest()
    )
    
    # Create file server with security restrictions
    import tempfile
    import os
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Initialize server
        server = HTPFileServer(
            htp_session,
            base_path=tmpdir,
            allowed_extensions=['.log', '.json', '.yaml', '.txt', '.rules'],
            max_file_size=100 * 1024 * 1024,  # 100MB
            read_only=False
        )
        
        print(f"\n[Server] Base path: {tmpdir}")
        print(f"[Server] Allowed extensions: {server.allowed_extensions}")
        print(f"[Server] Max file size: {server.max_file_size}")
        
        # Create test directory structure
        os.makedirs(os.path.join(tmpdir, 'logs', 'guardian-001'), exist_ok=True)
        os.makedirs(os.path.join(tmpdir, 'config'), exist_ok=True)
        
        # Create test file
        test_file = os.path.join(tmpdir, 'config', 'test.yaml')
        with open(test_file, 'w') as f:
            f.write("hookprobe:\n  version: 5.0\n  mode: production\n")
        
        print(f"\n[Server] Created test file: {test_file}")
        
        # Demonstrate path validation
        print("\n[Server] Path validation tests:")
        
        try:
            # Valid path
            valid = server._validate_path('/logs/guardian-001/test.log')
            print(f"   ✓ Valid path: {valid}")
        except HTPFileError as e:
            print(f"   ✗ Valid path rejected: {e}")
        
        try:
            # Path traversal attempt (should fail)
            invalid = server._validate_path('/../../../etc/passwd')
            print(f"   ✗ Traversal allowed: {invalid}")
        except HTPFileError as e:
            print(f"   ✓ Traversal blocked: {e.code.name}")


# =============================================================================
# FULL INTEGRATION EXAMPLE: EDGE TO CLOUD
# =============================================================================

async def full_integration_example():
    """
    Complete integration showing HTP file transfer flow.

    Guardian (Edge) ←→ HTP ←→ Mesh (Cloud)

    Security properties:
    - All traffic encrypted with weight-bound session key
    - PoSF signatures on each packet
    - Integrity verification via SHA256
    - Path validation prevents traversal
    """
    print("\n" + "=" * 70)
    print("FULL INTEGRATION: EDGE TO CLOUD FILE TRANSFER")
    print("=" * 70)

    print("""
    ┌─────────────────────────────────────────────────────────────────┐
    │                    HTP FILE TRANSFER FLOW                       │
    ├─────────────────────────────────────────────────────────────────┤
    │                                                                 │
    │  ┌──────────────┐          HTP (UDP)         ┌──────────────┐  │
    │  │   Guardian   │ ◄───────────────────────► │    Mesh      │  │
    │  │   (Edge)     │    ChaCha20-Poly1305      │   (Cloud)    │  │
    │  │              │    PoSF Signatures        │              │  │
    │  │  HTPFile     │    Weight-Bound Keys      │  HTPFile     │  │
    │  │  Transfer    │                           │  Server      │  │
    │  └──────────────┘                           └──────────────┘  │
    │                                                                 │
    │  Security Properties:                                          │
    │  ✓ Session key = SHA256(secret + W_fingerprint)               │
    │  ✓ Every packet signed with PoSF (neural network output)      │
    │  ✓ File integrity verified via SHA256                          │
    │  ✓ Path traversal prevented by server validation               │
    │  ✓ All data encrypted at transport layer                       │
    │                                                                 │
    └─────────────────────────────────────────────────────────────────┘
    """)
    
    # Simulate complete flow
    print("[Flow] 1. Guardian generates TER and evolves weights")
    print("[Flow] 2. Guardian initiates HTP connection (HELLO)")
    print("[Flow] 3. mesh backend sends CHALLENGE")
    print("[Flow] 4. Guardian signs with PoSF and sends ATTEST")
    print("[Flow] 5. mesh backend verifies via deterministic replay")
    print("[Flow] 6. Session established (ACCEPT)")
    print("[Flow] 7. Guardian sends FILE_CREATE request")
    print("[Flow] 8. Mesh validates path, sends ACK")
    print("[Flow] 9. Guardian sends FILE_CHUNKs (encrypted)")
    print("[Flow] 10. Guardian sends FILE_COMPLETE with hash")
    print("[Flow] 11. Mesh verifies hash, writes file, sends ACK")
    print()
    print("[Result] File transferred securely with neural resonance verification")


# =============================================================================
# QSECBIT INTEGRATION EXAMPLE
# =============================================================================

async def qsecbit_integration_example():
    """
    Shows how HTP file transfer integrates with Qsecbit threat analysis.

    When Qsecbit detects elevated threat levels, the system can:
    1. Upload detailed logs to mesh backend for analysis
    2. Download updated mitigation rules
    3. Sync Kali response reports
    """
    print("\n" + "=" * 70)
    print("QSECBIT INTEGRATION EXAMPLE")
    print("=" * 70)
    
    print("""
    Qsecbit Threat Detection → HTP File Transfer Actions:
    
    ┌─────────────────────────────────────────────────────────────────┐
    │  Qsecbit Score  │  RAG Status  │  File Transfer Action          │
    ├─────────────────┼──────────────┼────────────────────────────────┤
    │  < 0.45         │  GREEN       │  Normal log rotation           │
    │  0.45 - 0.70    │  AMBER       │  Upload detailed telemetry     │
    │  > 0.70         │  RED         │  Emergency log dump + sync     │
    └─────────────────┴──────────────┴────────────────────────────────┘
    """)
    
    # Simulate Qsecbit triggering file transfer
    qsecbit_score = 0.72  # RED
    rag_status = "RED"
    
    print(f"[Qsecbit] Current score: {qsecbit_score} ({rag_status})")
    
    if rag_status == "RED":
        print("[Action] Emergency protocol activated:")
        print("  1. CREATE /emergency/incident-{timestamp}.tar.gz")
        print("     - Full system telemetry")
        print("     - IDS/IPS alerts")
        print("     - WAF block logs")
        print("     - Network captures")
        print("  2. READ /response/kali-playbook-latest.sh")
        print("     - Download latest response script")
        print("  3. UPDATE /status/guardian-001.json")
        print("     - Report current threat status to mesh backend")


# =============================================================================
# MAIN
# =============================================================================

async def main():
    """Run all examples."""
    await edge_client_example()
    await mesh_server_example()
    await full_integration_example()
    await qsecbit_integration_example()
    
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print("""
    HTP File Transfer extends your existing protocol with CRUD operations
    while maintaining all security properties of the Neuro Protocol:
    
    ✓ Weight-bound encryption (session_key = SHA256(secret + W_fingerprint))
    ✓ PoSF authentication (neural network signatures)
    ✓ Integrity verification (SHA256 hash on completion)
    ✓ NAT/CGNAT traversal (UDP + heartbeat)
    ✓ Replay protection (monotonic sequence + TER chain)
    
    New message types (0x30-0x38):
      CREATE, READ, UPDATE, DELETE, STAT, LIST, CHUNK, COMPLETE, ERROR
    
    Files to add to your repository:
      src/neuro/transport/htp_file.py  (main implementation)

    Integration points:
      - Guardian/Nexus edge devices use HTPFileTransfer client
      - Mesh backend uses HTPFileServer
      - Qsecbit can trigger file transfers based on threat level
    """)


if __name__ == "__main__":
    asyncio.run(main())
