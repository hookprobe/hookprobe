"""
Dream Log - Offline TER Storage

Stores TER sequence while edge node is offline for later replay verification.
Implements efficient append-only log with compression and integrity checks.
"""

import os
import struct
import zlib
import hashlib
from typing import List, Optional
from pathlib import Path
from dataclasses import dataclass
from ..core.ter import TER


@dataclass
class DreamLogMetadata:
    """Metadata for dream log file."""
    version: int
    node_id: str
    created_timestamp: int
    last_update_timestamp: int
    ter_count: int
    compressed_size_bytes: int
    uncompressed_size_bytes: int
    checksum: bytes  # SHA256 of entire log


class DreamLog:
    """
    Offline TER storage with compression and integrity verification.

    File Format:
    ┌─────────────────────────────────────────────────┐
    │ Header (128 bytes)                              │
    │  - Magic: "AXONZ-DREAM-LOG" (16 bytes)          │
    │  - Version: uint32                              │
    │  - Node ID: string (32 bytes)                   │
    │  - Created: uint64 (timestamp)                  │
    │  - Updated: uint64 (timestamp)                  │
    │  - TER Count: uint32                            │
    │  - Compressed Size: uint64                      │
    │  - Uncompressed Size: uint64                    │
    │  - Checksum: SHA256 (32 bytes)                  │
    │  - Reserved: (32 bytes)                         │
    ├─────────────────────────────────────────────────┤
    │ Compressed TER Blocks                           │
    │  - Each TER: 64 bytes (zstd compressed)         │
    │  - Append-only                                  │
    └─────────────────────────────────────────────────┘
    """

    MAGIC = b"AXONZ-DREAM-LOG\x00"
    VERSION = 1
    HEADER_SIZE = 128

    def __init__(self, storage_path: str, node_id: str, compression_level: int = 3):
        """
        Args:
            storage_path: Path to dream log file
            node_id: Edge node identifier
            compression_level: zlib compression level (0-9, default 3)
        """
        self.storage_path = Path(storage_path)
        self.node_id = node_id
        self.compression_level = compression_level

        self.ter_sequence: List[TER] = []
        self.metadata: Optional[DreamLogMetadata] = None

        # Load existing log if present
        if self.storage_path.exists():
            self._load()

    def append_ter(self, ter: TER) -> bool:
        """
        Append TER to dream log.

        Args:
            ter: Temporal Event Record to append

        Returns:
            True if successful
        """
        # Add to in-memory sequence
        self.ter_sequence.append(ter)

        # Persist to disk
        return self._persist()

    def get_sequence(self) -> List[TER]:
        """Get complete TER sequence."""
        return self.ter_sequence.copy()

    def get_metadata(self) -> Optional[DreamLogMetadata]:
        """Get dream log metadata."""
        return self.metadata

    def clear(self) -> bool:
        """
        Clear dream log (after successful cloud sync).

        Returns:
            True if successful
        """
        self.ter_sequence = []

        # Remove file
        if self.storage_path.exists():
            try:
                self.storage_path.unlink()
                return True
            except OSError:
                return False

        return True

    def verify_integrity(self) -> bool:
        """
        Verify dream log integrity via checksum.

        Returns:
            True if integrity check passes
        """
        if not self.storage_path.exists():
            return False

        # Read file
        with open(self.storage_path, 'rb') as f:
            data = f.read()

        # Extract stored checksum from header
        stored_checksum = data[96:128]

        # Calculate actual checksum (exclude checksum field itself)
        actual_data = data[:96] + b'\x00' * 32 + data[128:]
        actual_checksum = hashlib.sha256(actual_data).digest()

        return stored_checksum == actual_checksum

    def compress_for_upload(self) -> bytes:
        """
        Compress entire TER sequence for cloud upload.

        Returns:
            Compressed bytes (zlib)
        """
        # Concatenate all TERs
        ter_data = b''.join(ter.to_bytes() for ter in self.ter_sequence)

        # Compress
        compressed = zlib.compress(ter_data, level=self.compression_level)

        return compressed

    def _load(self):
        """Load dream log from disk."""
        with open(self.storage_path, 'rb') as f:
            # Read header
            header = f.read(self.HEADER_SIZE)

            # Parse header
            magic = header[:16]
            if magic != self.MAGIC:
                raise ValueError("Invalid dream log magic")

            version = struct.unpack('<I', header[16:20])[0]
            if version != self.VERSION:
                raise ValueError(f"Unsupported version: {version}")

            node_id = header[20:52].decode('utf-8').rstrip('\x00')
            created_ts = struct.unpack('<Q', header[52:60])[0]
            updated_ts = struct.unpack('<Q', header[60:68])[0]
            ter_count = struct.unpack('<I', header[68:72])[0]
            compressed_size = struct.unpack('<Q', header[72:80])[0]
            uncompressed_size = struct.unpack('<Q', header[80:88])[0]
            checksum = header[96:128]

            # Read compressed TER data
            compressed_data = f.read()

            # Decompress
            ter_data = zlib.decompress(compressed_data)

            # Parse TERs
            self.ter_sequence = []
            for i in range(ter_count):
                ter_bytes = ter_data[i * 64:(i + 1) * 64]
                ter = TER.from_bytes(ter_bytes)
                self.ter_sequence.append(ter)

            # Store metadata
            self.metadata = DreamLogMetadata(
                version=version,
                node_id=node_id,
                created_timestamp=created_ts,
                last_update_timestamp=updated_ts,
                ter_count=ter_count,
                compressed_size_bytes=compressed_size,
                uncompressed_size_bytes=uncompressed_size,
                checksum=checksum
            )

    def _persist(self) -> bool:
        """Persist dream log to disk."""
        import time

        # Ensure directory exists
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)

        # Concatenate all TERs
        ter_data = b''.join(ter.to_bytes() for ter in self.ter_sequence)

        # Compress
        compressed_data = zlib.compress(ter_data, level=self.compression_level)

        # Build header
        now_ts = int(time.time() * 1e6)  # microseconds

        if self.metadata is None:
            created_ts = now_ts
        else:
            created_ts = self.metadata.created_timestamp

        header = bytearray(self.HEADER_SIZE)

        # Magic
        header[:16] = self.MAGIC

        # Version
        struct.pack_into('<I', header, 16, self.VERSION)

        # Node ID (32 bytes, null-padded)
        node_id_bytes = self.node_id.encode('utf-8')[:32]
        header[20:20 + len(node_id_bytes)] = node_id_bytes

        # Timestamps
        struct.pack_into('<Q', header, 52, created_ts)
        struct.pack_into('<Q', header, 60, now_ts)

        # TER count
        struct.pack_into('<I', header, 68, len(self.ter_sequence))

        # Sizes
        struct.pack_into('<Q', header, 72, len(compressed_data))
        struct.pack_into('<Q', header, 80, len(ter_data))

        # Reserved (leave zeros)

        # Calculate checksum (entire file)
        file_data = bytes(header) + compressed_data
        # Zero out checksum field for calculation
        file_data_for_hash = file_data[:96] + b'\x00' * 32 + file_data[128:]
        checksum = hashlib.sha256(file_data_for_hash).digest()

        # Insert checksum
        header[96:128] = checksum

        # Write to file (atomic write via temp file)
        temp_path = self.storage_path.with_suffix('.tmp')
        try:
            with open(temp_path, 'wb') as f:
                f.write(header)
                f.write(compressed_data)

            # Atomic rename
            temp_path.replace(self.storage_path)

            # Update metadata
            self.metadata = DreamLogMetadata(
                version=self.VERSION,
                node_id=self.node_id,
                created_timestamp=created_ts,
                last_update_timestamp=now_ts,
                ter_count=len(self.ter_sequence),
                compressed_size_bytes=len(compressed_data),
                uncompressed_size_bytes=len(ter_data),
                checksum=checksum
            )

            return True

        except OSError as e:
            print(f"Failed to persist dream log: {e}")
            if temp_path.exists():
                temp_path.unlink()
            return False

    @staticmethod
    def decompress_upload(compressed_data: bytes) -> List[TER]:
        """
        Decompress TER sequence from cloud upload.

        Args:
            compressed_data: zlib-compressed TER sequence

        Returns:
            List of TERs
        """
        # Decompress
        ter_data = zlib.decompress(compressed_data)

        # Parse TERs
        ter_count = len(ter_data) // 64
        ter_sequence = []

        for i in range(ter_count):
            ter_bytes = ter_data[i * 64:(i + 1) * 64]
            ter = TER.from_bytes(ter_bytes)
            ter_sequence.append(ter)

        return ter_sequence


# Example usage
if __name__ == '__main__':
    from ..core.ter import TERGenerator
    import tempfile

    print("=== Testing Dream Log ===\n")

    # Create temporary dream log
    with tempfile.NamedTemporaryFile(suffix='.dreamlog', delete=False) as tmp:
        dream_log_path = tmp.name

    # Initialize dream log
    dream_log = DreamLog(dream_log_path, node_id='edge-001')

    # Generate and append TERs
    ter_gen = TERGenerator()

    print("Appending TERs to dream log...")
    for i in range(20):
        ter = ter_gen.generate()
        success = dream_log.append_ter(ter)
        print(f"  TER {i}: seq={ter.sequence}, appended={'✓' if success else '✗'}")

    # Get metadata
    metadata = dream_log.get_metadata()
    if metadata:
        print(f"\nDream Log Metadata:")
        print(f"  Node ID: {metadata.node_id}")
        print(f"  TER Count: {metadata.ter_count}")
        print(f"  Compressed Size: {metadata.compressed_size_bytes} bytes")
        print(f"  Uncompressed Size: {metadata.uncompressed_size_bytes} bytes")
        print(f"  Compression Ratio: {metadata.uncompressed_size_bytes / metadata.compressed_size_bytes:.2f}x")

    # Verify integrity
    is_valid = dream_log.verify_integrity()
    print(f"\nIntegrity Check: {'✓ PASS' if is_valid else '✗ FAIL'}")

    # Test reload
    print("\nReloading dream log from disk...")
    dream_log2 = DreamLog(dream_log_path, node_id='edge-001')
    sequence = dream_log2.get_sequence()
    print(f"  Loaded {len(sequence)} TERs")

    # Test compression for upload
    compressed = dream_log.compress_for_upload()
    print(f"\nCompressed for upload: {len(compressed)} bytes")

    # Test decompression
    sequence_restored = DreamLog.decompress_upload(compressed)
    print(f"Decompressed: {len(sequence_restored)} TERs")

    # Verify match
    if len(sequence) == len(sequence_restored):
        all_match = all(
            seq.to_bytes() == res.to_bytes()
            for seq, res in zip(sequence, sequence_restored)
        )
        print(f"Sequence integrity: {'✓ MATCH' if all_match else '✗ MISMATCH'}")

    # Cleanup
    os.unlink(dream_log_path)
    print("\n✓ Test complete")
