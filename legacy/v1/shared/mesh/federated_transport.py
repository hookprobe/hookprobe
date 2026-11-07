"""
Federated Transport — Mesh Layer for Model Updates

Handles PacketType.MODEL_UPDATE (0x50) transport:
- 64KB chunking with reassembly for large weight vectors
- Lower priority than threat gossip
- int8-quantized weight deltas for bandwidth efficiency
- Integration with consciousness.py gossip handlers
"""

import hashlib
import logging
import struct
import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Maximum chunk size (64KB minus header overhead)
MAX_CHUNK_SIZE = 65000
# Model update packet type (must match unified_transport.PacketType.MODEL_UPDATE)
MODEL_UPDATE_PACKET_TYPE = 0x50


class UpdateMessageType(IntEnum):
    """Sub-types within MODEL_UPDATE packets."""
    LOCAL_UPDATE = 0x01       # Participant → Aggregation server
    GLOBAL_WEIGHTS = 0x02     # Aggregation server → All participants
    ROUND_ANNOUNCE = 0x03     # Server announces new round
    ROUND_COMPLETE = 0x04     # Server announces round result


@dataclass
class ChunkedMessage:
    """Tracks reassembly of a multi-chunk model update."""
    message_id: str
    total_chunks: int
    received_chunks: Dict[int, bytes] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    ttl_s: float = 120.0  # 2 minute reassembly timeout

    @property
    def complete(self) -> bool:
        return len(self.received_chunks) == self.total_chunks

    @property
    def expired(self) -> bool:
        return (time.time() - self.created_at) > self.ttl_s

    def add_chunk(self, chunk_index: int, data: bytes) -> bool:
        """Add a chunk. Returns True if message is now complete."""
        self.received_chunks[chunk_index] = data
        return self.complete

    def reassemble(self) -> Optional[bytes]:
        """Reassemble all chunks into the full message."""
        if not self.complete:
            return None
        parts = []
        for i in range(self.total_chunks):
            chunk = self.received_chunks.get(i)
            if chunk is None:
                return None
            parts.append(chunk)
        return b"".join(parts)


class FederatedTransport:
    """Transport layer for federated learning model updates.

    Provides chunking, reassembly, and routing for model weight
    updates sent over the mesh gossip protocol.
    """

    def __init__(
        self,
        send_fn: Optional[Callable[[bytes, int], None]] = None,
        on_local_update: Optional[Callable[[bytes], None]] = None,
        on_global_weights: Optional[Callable[[bytes], None]] = None,
        on_round_announce: Optional[Callable[[bytes], None]] = None,
    ):
        """
        Args:
            send_fn: Function to send raw bytes via mesh. Signature: (data, packet_type) -> None
            on_local_update: Callback when a local update is received (server-side).
            on_global_weights: Callback when global weights arrive (participant-side).
            on_round_announce: Callback when a new round is announced.
        """
        self._send_fn = send_fn
        self._on_local_update = on_local_update
        self._on_global_weights = on_global_weights
        self._on_round_announce = on_round_announce

        # Reassembly state
        self._pending: Dict[str, ChunkedMessage] = {}
        self._lock = threading.Lock()

        # Stats
        self._chunks_sent = 0
        self._chunks_received = 0
        self._messages_sent = 0
        self._messages_received = 0
        self._reassembly_failures = 0

    def send_model_update(
        self,
        payload: bytes,
        msg_type: UpdateMessageType,
    ) -> int:
        """Send a model update, chunking if necessary.

        Returns number of chunks sent.
        """
        if self._send_fn is None:
            logger.warning("No send function configured")
            return 0

        message_id = hashlib.sha256(
            payload[:64] + struct.pack(">d", time.time())
        ).hexdigest()[:16]

        chunks = self._chunk_payload(payload, message_id, msg_type)

        for chunk_data in chunks:
            self._send_fn(chunk_data, MODEL_UPDATE_PACKET_TYPE)
            self._chunks_sent += 1

        self._messages_sent += 1
        logger.debug(
            "Sent model update %s (%s) in %d chunks (%d bytes)",
            message_id, msg_type.name, len(chunks), len(payload),
        )
        return len(chunks)

    def receive_chunk(self, data: bytes):
        """Process a received MODEL_UPDATE chunk.

        Handles reassembly and dispatches complete messages.
        """
        self._chunks_received += 1

        # Parse chunk header
        try:
            header = self._parse_chunk_header(data)
        except Exception as e:
            logger.warning("Invalid chunk header: %s", e)
            return

        message_id = header["message_id"]
        chunk_index = header["chunk_index"]
        total_chunks = header["total_chunks"]
        msg_type = header["msg_type"]
        chunk_payload = header["payload"]

        with self._lock:
            # Clean expired reassembly buffers
            self._cleanup_expired()

            if message_id not in self._pending:
                self._pending[message_id] = ChunkedMessage(
                    message_id=message_id,
                    total_chunks=total_chunks,
                )

            msg = self._pending[message_id]
            complete = msg.add_chunk(chunk_index, chunk_payload)

        if complete:
            full_payload = msg.reassemble()
            with self._lock:
                del self._pending[message_id]

            if full_payload is None:
                self._reassembly_failures += 1
                return

            self._messages_received += 1
            self._dispatch_message(msg_type, full_payload)

    def _dispatch_message(self, msg_type: UpdateMessageType, payload: bytes):
        """Route a fully reassembled message to the appropriate callback."""
        if msg_type == UpdateMessageType.LOCAL_UPDATE and self._on_local_update:
            self._on_local_update(payload)
        elif msg_type == UpdateMessageType.GLOBAL_WEIGHTS and self._on_global_weights:
            self._on_global_weights(payload)
        elif msg_type == UpdateMessageType.ROUND_ANNOUNCE and self._on_round_announce:
            self._on_round_announce(payload)
        else:
            logger.debug("No handler for message type %s", msg_type.name)

    def _chunk_payload(
        self,
        payload: bytes,
        message_id: str,
        msg_type: UpdateMessageType,
    ) -> List[bytes]:
        """Split payload into chunks with headers."""
        chunks = []
        offset = 0
        total_chunks = max(1, (len(payload) + MAX_CHUNK_SIZE - 1) // MAX_CHUNK_SIZE)
        chunk_index = 0

        while offset < len(payload) or chunk_index == 0:
            end = min(offset + MAX_CHUNK_SIZE, len(payload))
            chunk_data = payload[offset:end]

            header = self._build_chunk_header(
                message_id, chunk_index, total_chunks, msg_type, len(chunk_data),
            )
            chunks.append(header + chunk_data)

            offset = end
            chunk_index += 1

        return chunks

    @staticmethod
    def _build_chunk_header(
        message_id: str,
        chunk_index: int,
        total_chunks: int,
        msg_type: UpdateMessageType,
        payload_len: int,
    ) -> bytes:
        """Build a chunk header.

        Format (28 bytes):
        - message_id: 16 bytes (truncated hex)
        - chunk_index: 2 bytes (uint16)
        - total_chunks: 2 bytes (uint16)
        - msg_type: 1 byte
        - reserved: 3 bytes
        - payload_len: 4 bytes (uint32)
        """
        mid_bytes = message_id.encode("ascii")[:16].ljust(16, b"\x00")
        return (
            mid_bytes
            + struct.pack(">HHB3xI", chunk_index, total_chunks, int(msg_type), payload_len)
        )

    @staticmethod
    def _parse_chunk_header(data: bytes) -> dict:
        """Parse chunk header and return components."""
        if len(data) < 28:
            raise ValueError(f"Chunk too short: {len(data)} < 28")

        mid_bytes = data[:16].rstrip(b"\x00")
        message_id = mid_bytes.decode("ascii")

        chunk_index, total_chunks, msg_type_val, payload_len = struct.unpack(
            ">HHB3xI", data[16:28],
        )

        payload = data[28:28 + payload_len]

        return {
            "message_id": message_id,
            "chunk_index": chunk_index,
            "total_chunks": total_chunks,
            "msg_type": UpdateMessageType(msg_type_val),
            "payload_len": payload_len,
            "payload": payload,
        }

    def _cleanup_expired(self):
        """Remove expired reassembly buffers."""
        expired = [
            mid for mid, msg in self._pending.items() if msg.expired
        ]
        for mid in expired:
            del self._pending[mid]
            self._reassembly_failures += 1
            logger.debug("Expired reassembly buffer: %s", mid)

    def get_stats(self) -> dict:
        return {
            "chunks_sent": self._chunks_sent,
            "chunks_received": self._chunks_received,
            "messages_sent": self._messages_sent,
            "messages_received": self._messages_received,
            "reassembly_failures": self._reassembly_failures,
            "pending_reassembly": len(self._pending),
        }
