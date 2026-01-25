"""
HookProbe DSM Microblock
Lightweight block structure for distributed state machine
"""

import hashlib
import time
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import IntEnum


class MicroblockType(IntEnum):
    """Types of microblocks in the DSM"""
    STATE_UPDATE = 0x01
    WEIGHT_SNAPSHOT = 0x02
    THREAT_REPORT = 0x03
    CONSENSUS_VOTE = 0x04
    HEARTBEAT = 0x05


@dataclass
class Microblock:
    """
    Lightweight block for DSM state updates.

    Structure (48 bytes header + variable payload):
        - version: 1 byte
        - type: 1 byte
        - timestamp: 8 bytes (unix timestamp ms)
        - prev_hash: 16 bytes (truncated SHA256)
        - payload_hash: 16 bytes (truncated SHA256)
        - signature: 6 bytes (truncated Ed25519)
        - payload: variable
    """
    version: int = 1
    block_type: MicroblockType = MicroblockType.STATE_UPDATE
    timestamp: int = field(default_factory=lambda: int(time.time() * 1000))
    prev_hash: bytes = field(default_factory=lambda: b'\x00' * 16)
    payload: bytes = b''
    signature: bytes = b''

    # Computed fields
    block_hash: bytes = field(default=b'', init=False)

    def __post_init__(self):
        """Compute block hash after initialization"""
        if not self.block_hash:
            self.block_hash = self._compute_hash()

    def _compute_hash(self) -> bytes:
        """Compute truncated SHA256 hash of block header"""
        header = self._serialize_header()
        return hashlib.sha256(header).digest()[:16]

    def _serialize_header(self) -> bytes:
        """Serialize block header (without signature)"""
        payload_hash = hashlib.sha256(self.payload).digest()[:16]
        return struct.pack(
            '>BB Q 16s 16s',
            self.version,
            self.block_type,
            self.timestamp,
            self.prev_hash,
            payload_hash
        )

    def serialize(self) -> bytes:
        """Serialize complete microblock"""
        header = self._serialize_header()
        sig = self.signature[:6] if self.signature else b'\x00' * 6
        payload_len = struct.pack('>H', len(self.payload))
        return header + sig + payload_len + self.payload

    @classmethod
    def deserialize(cls, data: bytes) -> 'Microblock':
        """Deserialize microblock from bytes"""
        if len(data) < 48:
            raise ValueError("Microblock data too short")

        version, block_type, timestamp = struct.unpack('>BB Q', data[:10])
        prev_hash = data[10:26]
        payload_hash = data[26:42]
        signature = data[42:48]
        payload_len = struct.unpack('>H', data[48:50])[0]
        payload = data[50:50 + payload_len]

        return cls(
            version=version,
            block_type=MicroblockType(block_type),
            timestamp=timestamp,
            prev_hash=prev_hash,
            payload=payload,
            signature=signature
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'version': self.version,
            'type': self.block_type.name,
            'timestamp': self.timestamp,
            'prev_hash': self.prev_hash.hex(),
            'block_hash': self.block_hash.hex(),
            'payload_size': len(self.payload),
        }


class MicroblockChain:
    """
    Simple chain of microblocks with validation.
    Used for local state tracking before DSM consensus.
    """

    def __init__(self, max_blocks: int = 1000):
        self.blocks: List[Microblock] = []
        self.max_blocks = max_blocks
        self._block_index: Dict[bytes, int] = {}

    def append(self, block: Microblock) -> bool:
        """
        Append a microblock to the chain.
        Returns True if successful, False if validation fails.
        """
        # Validate prev_hash
        if self.blocks:
            expected_prev = self.blocks[-1].block_hash
            if block.prev_hash != expected_prev:
                return False

        # Add to chain
        self.blocks.append(block)
        self._block_index[block.block_hash] = len(self.blocks) - 1

        # Prune old blocks if needed
        if len(self.blocks) > self.max_blocks:
            removed = self.blocks.pop(0)
            del self._block_index[removed.block_hash]
            # Reindex
            self._block_index = {
                b.block_hash: i for i, b in enumerate(self.blocks)
            }

        return True

    def get_latest(self) -> Optional[Microblock]:
        """Get the latest microblock"""
        return self.blocks[-1] if self.blocks else None

    def get_by_hash(self, block_hash: bytes) -> Optional[Microblock]:
        """Get microblock by hash"""
        idx = self._block_index.get(block_hash)
        return self.blocks[idx] if idx is not None else None

    def create_next(self, block_type: MicroblockType, payload: bytes) -> Microblock:
        """Create the next microblock in the chain"""
        prev_hash = self.blocks[-1].block_hash if self.blocks else b'\x00' * 16
        return Microblock(
            block_type=block_type,
            prev_hash=prev_hash,
            payload=payload
        )

    def verify_chain(self) -> bool:
        """Verify the integrity of the entire chain"""
        for i, block in enumerate(self.blocks):
            # Verify hash
            if block.block_hash != block._compute_hash():
                return False

            # Verify prev_hash linkage
            if i > 0:
                if block.prev_hash != self.blocks[i-1].block_hash:
                    return False

        return True

    def __len__(self) -> int:
        return len(self.blocks)


# ============================================================
# EXPORTS
# ============================================================

__all__ = [
    'MicroblockType',
    'Microblock',
    'MicroblockChain',
]
