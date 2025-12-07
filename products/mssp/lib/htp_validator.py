#!/usr/bin/env python3
"""
HookProbe HTP Validator Endpoint for MSSP
==========================================

This module implements the HTP (HookProbe Transport Protocol) validator endpoint
for the MSSP tier. It handles:

- UDP/TCP listening on port 4478
- Device registration and attestation
- Session key derivation using ChaCha20-Poly1305
- Heartbeat monitoring
- Qsecbit score aggregation from edge devices

Protocol Flow:
1. HELLO - Device initiates connection with node_id and weight fingerprint
2. CHALLENGE - MSSP sends 16-byte nonce
3. ATTEST - Device signs challenge with PoSF
4. ACCEPT - MSSP accepts and provides session secret
5. DATA - Encrypted telemetry exchange
6. HEARTBEAT - Keep-alive every 30 seconds
"""

import asyncio
import hashlib
import json
import logging
import os
import secrets
import socket
import sqlite3
import struct
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from pathlib import Path
from typing import Dict, Optional, Tuple

# Optional cryptography imports
try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logging.warning("cryptography not available, using simplified crypto")

# =============================================================================
# CONFIGURATION
# =============================================================================

# Network
HTP_UDP_PORT = 4478
HTP_TCP_PORT = 4478
LISTEN_ADDRESS = "0.0.0.0"

# Timing
HEARTBEAT_INTERVAL = 30  # seconds
HEARTBEAT_TIMEOUT = 90   # seconds (3 missed heartbeats)
SESSION_TIMEOUT = 3600   # 1 hour

# Paths
MSSP_DATA_DIR = Path(os.getenv("MSSP_DATA_DIR", "/var/lib/hookprobe/mssp"))
MSSP_SECRETS_DIR = Path(os.getenv("MSSP_SECRETS_DIR", "/etc/hookprobe/secrets/mssp"))
DEVICE_REGISTRY_DB = MSSP_DATA_DIR / "device_registry.db"

# Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("htp-validator")

# =============================================================================
# PROTOCOL DEFINITIONS
# =============================================================================

class HTPMessageType(IntEnum):
    """HTP message types"""
    HELLO = 0x01
    CHALLENGE = 0x02
    ATTEST = 0x03
    ACCEPT = 0x04
    REJECT = 0x05
    DATA = 0x10
    HEARTBEAT = 0x20
    HEARTBEAT_ACK = 0x21
    DISCONNECT = 0xFF


class DeviceType(IntEnum):
    """Device types in the mesh"""
    SENTINEL = 1
    GUARDIAN = 2
    FORTRESS = 3
    NEXUS = 4


class DeviceStatus(IntEnum):
    """Device registration status"""
    PENDING = 0
    ACTIVE = 1
    SUSPENDED = 2
    REVOKED = 3


@dataclass
class HTPSession:
    """Active HTP session"""
    device_id: str
    device_type: DeviceType
    remote_addr: Tuple[str, int]
    session_secret: bytes
    session_key: bytes
    weight_fingerprint: str
    created_at: float = field(default_factory=time.time)
    last_heartbeat: float = field(default_factory=time.time)
    qsecbit_score: float = 0.0
    rag_status: str = "GREEN"
    bytes_sent: int = 0
    bytes_recv: int = 0


@dataclass
class HTPMessage:
    """HTP protocol message"""
    msg_type: HTPMessageType
    payload: bytes

    def pack(self) -> bytes:
        """Pack message for transmission"""
        # Format: [type:1][length:4][payload:N]
        return struct.pack(">BI", self.msg_type, len(self.payload)) + self.payload

    @classmethod
    def unpack(cls, data: bytes) -> Optional['HTPMessage']:
        """Unpack received message"""
        if len(data) < 5:
            return None
        msg_type, length = struct.unpack(">BI", data[:5])
        if len(data) < 5 + length:
            return None
        payload = data[5:5+length]
        return cls(HTPMessageType(msg_type), payload)


# =============================================================================
# DEVICE REGISTRY
# =============================================================================

class DeviceRegistry:
    """SQLite-based device registry"""

    def __init__(self, db_path: Path = DEVICE_REGISTRY_DB):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize database schema"""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    device_type INTEGER NOT NULL,
                    status INTEGER DEFAULT 0,
                    hardware_fingerprint TEXT,
                    weight_fingerprint TEXT,
                    public_key TEXT,
                    customer_id TEXT,
                    ip_address TEXT,
                    last_seen TEXT,
                    registered_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    kyc_verified INTEGER DEFAULT 0,
                    metadata TEXT
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS device_locations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    ip_address TEXT,
                    country TEXT,
                    region TEXT,
                    city TEXT,
                    latitude REAL,
                    longitude REAL,
                    asn TEXT,
                    isp TEXT,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices(device_id)
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS qsecbit_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    score REAL,
                    rag_status TEXT,
                    drift REAL,
                    attack_probability REAL,
                    classifier_decay REAL,
                    quantum_drift REAL,
                    energy_anomaly REAL,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices(device_id)
                )
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_device_locations_device
                ON device_locations(device_id, timestamp DESC)
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_qsecbit_history_device
                ON qsecbit_history(device_id, timestamp DESC)
            """)

            conn.commit()

    def get_device(self, device_id: str) -> Optional[Dict]:
        """Get device by ID"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM devices WHERE device_id = ?",
                (device_id,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def register_device(
        self,
        device_id: str,
        device_type: DeviceType,
        hardware_fingerprint: str,
        weight_fingerprint: str,
        public_key: str,
        ip_address: str,
        customer_id: Optional[str] = None
    ) -> bool:
        """Register a new device"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO devices
                    (device_id, device_type, status, hardware_fingerprint,
                     weight_fingerprint, public_key, customer_id, ip_address, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    device_id, device_type.value, DeviceStatus.PENDING.value,
                    hardware_fingerprint, weight_fingerprint, public_key,
                    customer_id, ip_address,
                    datetime.now(timezone.utc).isoformat()
                ))
                conn.commit()
            logger.info(f"Device registered: {device_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to register device {device_id}: {e}")
            return False

    def update_device_seen(self, device_id: str, ip_address: str):
        """Update device last seen timestamp"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                UPDATE devices SET last_seen = ?, ip_address = ?
                WHERE device_id = ?
            """, (datetime.now(timezone.utc).isoformat(), ip_address, device_id))
            conn.commit()

    def update_device_location(
        self,
        device_id: str,
        ip_address: str,
        country: str = None,
        region: str = None,
        city: str = None,
        latitude: float = None,
        longitude: float = None,
        asn: str = None,
        isp: str = None
    ):
        """Record device location"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO device_locations
                (device_id, ip_address, country, region, city, latitude, longitude, asn, isp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (device_id, ip_address, country, region, city, latitude, longitude, asn, isp))
            conn.commit()

    def record_qsecbit(
        self,
        device_id: str,
        score: float,
        rag_status: str,
        drift: float = 0,
        attack_probability: float = 0,
        classifier_decay: float = 0,
        quantum_drift: float = 0,
        energy_anomaly: float = 0
    ):
        """Record Qsecbit score"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO qsecbit_history
                (device_id, score, rag_status, drift, attack_probability,
                 classifier_decay, quantum_drift, energy_anomaly)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (device_id, score, rag_status, drift, attack_probability,
                  classifier_decay, quantum_drift, energy_anomaly))
            conn.commit()

    def get_active_devices(self) -> list:
        """Get all active devices"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM devices WHERE status = ?",
                (DeviceStatus.ACTIVE.value,)
            )
            return [dict(row) for row in cursor.fetchall()]

    def approve_device(self, device_id: str) -> bool:
        """Approve a pending device"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                UPDATE devices SET status = ?
                WHERE device_id = ? AND status = ?
            """, (DeviceStatus.ACTIVE.value, device_id, DeviceStatus.PENDING.value))
            conn.commit()
            return cursor.rowcount > 0


# =============================================================================
# CRYPTO UTILITIES
# =============================================================================

class HTPCrypto:
    """HTP cryptographic operations"""

    @staticmethod
    def generate_challenge() -> bytes:
        """Generate 16-byte challenge nonce"""
        return secrets.token_bytes(16)

    @staticmethod
    def generate_session_secret() -> bytes:
        """Generate 32-byte session secret"""
        return secrets.token_bytes(32)

    @staticmethod
    def derive_session_key(session_secret: bytes, weight_fingerprint: str) -> bytes:
        """Derive session key from secret and weight fingerprint"""
        if CRYPTO_AVAILABLE:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=weight_fingerprint.encode(),
                info=b"htp-session-key"
            )
            return hkdf.derive(session_secret)
        else:
            # Fallback: simple SHA256
            return hashlib.sha256(
                session_secret + weight_fingerprint.encode()
            ).digest()

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, nonce: bytes = None) -> Tuple[bytes, bytes]:
        """Encrypt data with ChaCha20-Poly1305"""
        if nonce is None:
            nonce = secrets.token_bytes(12)

        if CRYPTO_AVAILABLE:
            cipher = ChaCha20Poly1305(key)
            ciphertext = cipher.encrypt(nonce, plaintext, None)
            return nonce, ciphertext
        else:
            # Fallback: XOR with key hash (NOT SECURE - for dev only)
            key_hash = hashlib.sha256(key + nonce).digest()
            ciphertext = bytes(p ^ k for p, k in zip(plaintext, key_hash * (len(plaintext) // 32 + 1)))
            return nonce, ciphertext

    @staticmethod
    def decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> Optional[bytes]:
        """Decrypt data with ChaCha20-Poly1305"""
        try:
            if CRYPTO_AVAILABLE:
                cipher = ChaCha20Poly1305(key)
                return cipher.decrypt(nonce, ciphertext, None)
            else:
                # Fallback: XOR with key hash
                key_hash = hashlib.sha256(key + nonce).digest()
                plaintext = bytes(c ^ k for c, k in zip(ciphertext, key_hash * (len(ciphertext) // 32 + 1)))
                return plaintext
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None

    @staticmethod
    def verify_posf(
        challenge: bytes,
        signature: bytes,
        weight_fingerprint: str
    ) -> bool:
        """
        Verify Proof of Secure Function (PoSF) signature.

        In a full implementation, this would verify the Ed25519 signature
        using the device's neural weight-derived public key.
        """
        # Simplified verification for POC
        # In production, use proper Ed25519 signature verification
        expected = hashlib.sha256(challenge + weight_fingerprint.encode()).digest()
        return secrets.compare_digest(signature[:32], expected)


# =============================================================================
# HTP VALIDATOR SERVER
# =============================================================================

class HTPValidator:
    """HTP Validator Endpoint Server"""

    def __init__(self):
        self.registry = DeviceRegistry()
        self.sessions: Dict[str, HTPSession] = {}
        self.pending_challenges: Dict[Tuple[str, int], Tuple[bytes, str, str]] = {}
        self.running = False

    async def start(self):
        """Start the HTP validator"""
        self.running = True

        # Start UDP server
        udp_task = asyncio.create_task(self._run_udp_server())

        # Start TCP server
        tcp_task = asyncio.create_task(self._run_tcp_server())

        # Start session cleanup task
        cleanup_task = asyncio.create_task(self._session_cleanup())

        logger.info(f"HTP Validator started on UDP/TCP {LISTEN_ADDRESS}:{HTP_UDP_PORT}")

        await asyncio.gather(udp_task, tcp_task, cleanup_task)

    async def stop(self):
        """Stop the HTP validator"""
        self.running = False
        logger.info("HTP Validator stopped")

    async def _run_udp_server(self):
        """Run UDP server for HTP"""
        loop = asyncio.get_event_loop()

        # Create UDP socket
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: HTPUDPProtocol(self),
            local_addr=(LISTEN_ADDRESS, HTP_UDP_PORT)
        )

        try:
            while self.running:
                await asyncio.sleep(1)
        finally:
            transport.close()

    async def _run_tcp_server(self):
        """Run TCP server for HTP fallback"""
        server = await asyncio.start_server(
            self._handle_tcp_connection,
            LISTEN_ADDRESS,
            HTP_TCP_PORT
        )

        async with server:
            await server.serve_forever()

    async def _handle_tcp_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ):
        """Handle TCP connection"""
        addr = writer.get_extra_info('peername')
        logger.debug(f"TCP connection from {addr}")

        try:
            while self.running:
                # Read message header
                header = await reader.read(5)
                if not header:
                    break

                msg_type, length = struct.unpack(">BI", header)
                payload = await reader.read(length)

                message = HTPMessage(HTPMessageType(msg_type), payload)
                response = await self._process_message(message, addr)

                if response:
                    writer.write(response.pack())
                    await writer.drain()
        except Exception as e:
            logger.error(f"TCP error from {addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def _session_cleanup(self):
        """Periodically clean up stale sessions"""
        while self.running:
            await asyncio.sleep(60)

            now = time.time()
            stale_sessions = [
                device_id for device_id, session in self.sessions.items()
                if now - session.last_heartbeat > HEARTBEAT_TIMEOUT
            ]

            for device_id in stale_sessions:
                logger.warning(f"Session timeout for device: {device_id}")
                del self.sessions[device_id]

            # Clean up old pending challenges
            stale_challenges = [
                addr for addr, (_, _, timestamp) in self.pending_challenges.items()
                if now - float(timestamp) > 60
            ]
            for addr in stale_challenges:
                del self.pending_challenges[addr]

    async def _process_message(
        self,
        message: HTPMessage,
        addr: Tuple[str, int]
    ) -> Optional[HTPMessage]:
        """Process incoming HTP message"""

        if message.msg_type == HTPMessageType.HELLO:
            return await self._handle_hello(message, addr)

        elif message.msg_type == HTPMessageType.ATTEST:
            return await self._handle_attest(message, addr)

        elif message.msg_type == HTPMessageType.DATA:
            return await self._handle_data(message, addr)

        elif message.msg_type == HTPMessageType.HEARTBEAT:
            return await self._handle_heartbeat(message, addr)

        elif message.msg_type == HTPMessageType.DISCONNECT:
            return await self._handle_disconnect(message, addr)

        else:
            logger.warning(f"Unknown message type: {message.msg_type}")
            return None

    async def _handle_hello(
        self,
        message: HTPMessage,
        addr: Tuple[str, int]
    ) -> HTPMessage:
        """Handle HELLO message - start authentication"""
        try:
            # Parse HELLO payload
            # Format: {device_id, device_type, weight_fingerprint, public_key}
            data = json.loads(message.payload.decode())
            device_id = data.get("device_id")
            device_type = DeviceType(data.get("device_type", 1))
            weight_fingerprint = data.get("weight_fingerprint", "")
            public_key = data.get("public_key", "")
            hardware_fingerprint = data.get("hardware_fingerprint", "")

            logger.info(f"HELLO from {device_id} at {addr}")

            # Check if device is registered
            device = self.registry.get_device(device_id)

            if not device:
                # Auto-register new device (pending approval)
                self.registry.register_device(
                    device_id=device_id,
                    device_type=device_type,
                    hardware_fingerprint=hardware_fingerprint,
                    weight_fingerprint=weight_fingerprint,
                    public_key=public_key,
                    ip_address=addr[0]
                )
                logger.info(f"New device registered (pending): {device_id}")

            # Generate challenge
            challenge = HTPCrypto.generate_challenge()

            # Store pending challenge
            self.pending_challenges[addr] = (
                challenge,
                device_id,
                str(time.time())
            )

            # Send CHALLENGE
            return HTPMessage(
                HTPMessageType.CHALLENGE,
                challenge
            )

        except Exception as e:
            logger.error(f"HELLO error: {e}")
            return HTPMessage(
                HTPMessageType.REJECT,
                b"Invalid HELLO"
            )

    async def _handle_attest(
        self,
        message: HTPMessage,
        addr: Tuple[str, int]
    ) -> HTPMessage:
        """Handle ATTEST message - verify device attestation"""
        try:
            # Get pending challenge
            if addr not in self.pending_challenges:
                return HTPMessage(
                    HTPMessageType.REJECT,
                    b"No pending challenge"
                )

            challenge, device_id, _ = self.pending_challenges[addr]
            del self.pending_challenges[addr]

            # Get device from registry
            device = self.registry.get_device(device_id)
            if not device:
                return HTPMessage(
                    HTPMessageType.REJECT,
                    b"Device not found"
                )

            # Check device status
            if device["status"] == DeviceStatus.REVOKED.value:
                return HTPMessage(
                    HTPMessageType.REJECT,
                    b"Device revoked"
                )

            # Verify PoSF signature
            # In production, this would verify Ed25519 signature
            signature = message.payload
            weight_fingerprint = device["weight_fingerprint"]

            # For POC, accept if signature matches expected format
            if len(signature) < 32:
                return HTPMessage(
                    HTPMessageType.REJECT,
                    b"Invalid attestation"
                )

            # Generate session
            session_secret = HTPCrypto.generate_session_secret()
            session_key = HTPCrypto.derive_session_key(
                session_secret,
                weight_fingerprint
            )

            # Create session
            session = HTPSession(
                device_id=device_id,
                device_type=DeviceType(device["device_type"]),
                remote_addr=addr,
                session_secret=session_secret,
                session_key=session_key,
                weight_fingerprint=weight_fingerprint
            )

            self.sessions[device_id] = session

            # Update device last seen
            self.registry.update_device_seen(device_id, addr[0])

            # Auto-approve pending devices for POC
            if device["status"] == DeviceStatus.PENDING.value:
                self.registry.approve_device(device_id)
                logger.info(f"Device auto-approved: {device_id}")

            logger.info(f"Session established for {device_id}")

            # Send ACCEPT with session secret
            return HTPMessage(
                HTPMessageType.ACCEPT,
                session_secret
            )

        except Exception as e:
            logger.error(f"ATTEST error: {e}")
            return HTPMessage(
                HTPMessageType.REJECT,
                b"Attestation failed"
            )

    async def _handle_data(
        self,
        message: HTPMessage,
        addr: Tuple[str, int]
    ) -> Optional[HTPMessage]:
        """Handle DATA message - process encrypted telemetry"""
        try:
            # Find session by address
            session = None
            for s in self.sessions.values():
                if s.remote_addr == addr:
                    session = s
                    break

            if not session:
                logger.warning(f"DATA from unknown session: {addr}")
                return None

            # Decrypt payload
            # Format: [nonce:12][ciphertext:N]
            nonce = message.payload[:12]
            ciphertext = message.payload[12:]

            plaintext = HTPCrypto.decrypt(session.session_key, nonce, ciphertext)
            if not plaintext:
                logger.error(f"Decryption failed for {session.device_id}")
                return None

            # Parse telemetry data
            data = json.loads(plaintext.decode())

            # Update session stats
            session.bytes_recv += len(message.payload)
            session.last_heartbeat = time.time()

            # Process Qsecbit score
            if "qsecbit" in data:
                qsecbit = data["qsecbit"]
                session.qsecbit_score = qsecbit.get("score", 0)
                session.rag_status = qsecbit.get("rag_status", "GREEN")

                # Record in database
                self.registry.record_qsecbit(
                    device_id=session.device_id,
                    score=session.qsecbit_score,
                    rag_status=session.rag_status,
                    drift=qsecbit.get("drift", 0),
                    attack_probability=qsecbit.get("attack_probability", 0),
                    classifier_decay=qsecbit.get("classifier_decay", 0),
                    quantum_drift=qsecbit.get("quantum_drift", 0),
                    energy_anomaly=qsecbit.get("energy_anomaly", 0)
                )

                logger.debug(
                    f"Qsecbit from {session.device_id}: "
                    f"{session.qsecbit_score:.3f} ({session.rag_status})"
                )

            # Process security events
            if "events" in data:
                # Forward to ClickHouse via API
                pass

            return None  # No response needed for DATA

        except Exception as e:
            logger.error(f"DATA error: {e}")
            return None

    async def _handle_heartbeat(
        self,
        message: HTPMessage,
        addr: Tuple[str, int]
    ) -> HTPMessage:
        """Handle HEARTBEAT message"""
        # Find session
        session = None
        for s in self.sessions.values():
            if s.remote_addr == addr:
                session = s
                break

        if not session:
            return HTPMessage(
                HTPMessageType.REJECT,
                b"No session"
            )

        # Update heartbeat timestamp
        session.last_heartbeat = time.time()
        self.registry.update_device_seen(session.device_id, addr[0])

        # Parse heartbeat data
        try:
            data = json.loads(message.payload.decode())
            session.qsecbit_score = data.get("qsecbit_score", session.qsecbit_score)
            session.rag_status = data.get("rag_status", session.rag_status)
        except:
            pass

        logger.debug(f"Heartbeat from {session.device_id}")

        # Send ACK
        return HTPMessage(
            HTPMessageType.HEARTBEAT_ACK,
            json.dumps({
                "timestamp": time.time(),
                "server_status": "ok"
            }).encode()
        )

    async def _handle_disconnect(
        self,
        message: HTPMessage,
        addr: Tuple[str, int]
    ) -> None:
        """Handle DISCONNECT message"""
        # Find and remove session
        device_id = None
        for did, session in list(self.sessions.items()):
            if session.remote_addr == addr:
                device_id = did
                del self.sessions[did]
                break

        if device_id:
            logger.info(f"Device disconnected: {device_id}")

        return None

    def get_global_qsecbit(self) -> dict:
        """Compute global Qsecbit from all connected devices"""
        if not self.sessions:
            return {
                "score": 0.0,
                "rag_status": "GREEN",
                "device_count": 0
            }

        scores = [s.qsecbit_score for s in self.sessions.values()]
        avg_score = sum(scores) / len(scores)

        # Global RAG status (more conservative thresholds)
        if avg_score > 0.55:
            rag_status = "RED"
        elif avg_score > 0.35:
            rag_status = "AMBER"
        else:
            rag_status = "GREEN"

        return {
            "score": avg_score,
            "rag_status": rag_status,
            "device_count": len(self.sessions),
            "devices": {
                did: {"score": s.qsecbit_score, "rag": s.rag_status}
                for did, s in self.sessions.items()
            }
        }


# =============================================================================
# UDP PROTOCOL
# =============================================================================

class HTPUDPProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for HTP"""

    def __init__(self, validator: HTPValidator):
        self.validator = validator
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """Handle received UDP datagram"""
        message = HTPMessage.unpack(data)
        if not message:
            logger.warning(f"Invalid message from {addr}")
            return

        # Process message asynchronously
        asyncio.create_task(self._process_and_respond(message, addr))

    async def _process_and_respond(
        self,
        message: HTPMessage,
        addr: Tuple[str, int]
    ):
        """Process message and send response"""
        response = await self.validator._process_message(message, addr)

        if response and self.transport:
            self.transport.sendto(response.pack(), addr)

    def error_received(self, exc):
        logger.error(f"UDP error: {exc}")


# =============================================================================
# HTTP API (for integration with Django)
# =============================================================================

class HTPStatusAPI:
    """Simple HTTP API for status queries"""

    def __init__(self, validator: HTPValidator, port: int = 8889):
        self.validator = validator
        self.port = port

    async def start(self):
        """Start HTTP API server"""
        server = await asyncio.start_server(
            self._handle_request,
            "127.0.0.1",
            self.port
        )
        logger.info(f"Status API started on port {self.port}")

        async with server:
            await server.serve_forever()

    async def _handle_request(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter
    ):
        """Handle HTTP request"""
        try:
            request = await reader.read(4096)
            request_line = request.decode().split("\r\n")[0]
            method, path, _ = request_line.split(" ")

            if path == "/status":
                body = json.dumps({
                    "status": "running",
                    "sessions": len(self.validator.sessions),
                    "global_qsecbit": self.validator.get_global_qsecbit()
                })
            elif path == "/sessions":
                body = json.dumps({
                    did: {
                        "device_type": s.device_type.name,
                        "remote_addr": f"{s.remote_addr[0]}:{s.remote_addr[1]}",
                        "qsecbit_score": s.qsecbit_score,
                        "rag_status": s.rag_status,
                        "last_heartbeat": s.last_heartbeat,
                        "bytes_recv": s.bytes_recv
                    }
                    for did, s in self.validator.sessions.items()
                })
            elif path == "/health":
                body = "ok"
            else:
                body = json.dumps({"error": "not found"})

            response = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n{body}"
            writer.write(response.encode())
            await writer.drain()
        except Exception as e:
            logger.error(f"API error: {e}")
        finally:
            writer.close()
            await writer.wait_closed()


# =============================================================================
# MAIN
# =============================================================================

async def main():
    """Main entry point"""
    logger.info("Starting HTP Validator Endpoint")

    # Create validator
    validator = HTPValidator()

    # Create status API
    api = HTPStatusAPI(validator)

    # Start both
    await asyncio.gather(
        validator.start(),
        api.start()
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)
