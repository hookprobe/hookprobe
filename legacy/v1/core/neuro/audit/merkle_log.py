"""
Append-Only Merkle Log for Auditability

Transparency log recording:
- Device attestations
- Validator proofs
- Revocation events
- Enrollment records

Features:
- Cryptographically verifiable append-only property
- Merkle tree for efficient proofs
- Distributed replication across validators
- Offline forensic verification
"""

import hashlib
import struct
import json
from typing import List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timezone


class EventType(Enum):
    """Types of events in the Merkle log."""
    ENROLLMENT = "enrollment"
    ATTESTATION = "attestation"
    VALIDATION = "validation"
    REVOCATION = "revocation"
    VALIDATOR_ROTATION = "validator_rotation"


@dataclass
class LogEntry:
    """Single entry in the Merkle log."""
    index: int  # Sequential index in log
    timestamp: int  # Unix timestamp (microseconds)
    event_type: EventType
    device_id: str
    data: dict  # Event-specific data
    merkle_hash: bytes  # SHA256 hash of this entry
    previous_hash: bytes  # Hash of previous entry (chain)


@dataclass
class MerkleProof:
    """Merkle inclusion proof for log entry."""
    entry_index: int
    entry_hash: bytes
    merkle_path: List[Tuple[bytes, str]]  # (hash, 'left' or 'right')
    root_hash: bytes


class MerkleLog:
    """
    Append-only Merkle log with cryptographic verifiability.

    Structure:
    - Sequential entries (cannot be deleted or reordered)
    - Each entry contains hash of previous entry (blockchain-like)
    - Merkle tree built over entries for efficient proofs
    - Root hash represents entire log state
    """

    def __init__(self, log_id: str, storage_path: str = "/var/lib/hookprobe/merkle-log"):
        """
        Args:
            log_id: Unique identifier for this log
            storage_path: Path to store log data
        """
        self.log_id = log_id
        self.storage_path = storage_path
        self.entries: List[LogEntry] = []
        self.merkle_tree: List[List[bytes]] = []  # Binary tree levels

        # Genesis entry
        self._init_genesis()

    def _init_genesis(self):
        """Initialize log with genesis entry."""
        genesis = LogEntry(
            index=0,
            timestamp=int(datetime.now(timezone.utc).timestamp() * 1e6),
            event_type=EventType.ENROLLMENT,
            device_id="genesis",
            data={'message': 'HookProbe Merkle Log Genesis'},
            merkle_hash=b'',
            previous_hash=b'\x00' * 32
        )

        # Calculate genesis hash
        genesis.merkle_hash = self._hash_entry(genesis)

        self.entries.append(genesis)
        self._rebuild_merkle_tree()

    def append(
        self,
        event_type: EventType,
        device_id: str,
        data: dict
    ) -> LogEntry:
        """
        Append new entry to log.

        Args:
            event_type: Type of event
            device_id: Device identifier
            data: Event-specific data

        Returns:
            Created log entry
        """
        index = len(self.entries)
        previous_entry = self.entries[-1]

        entry = LogEntry(
            index=index,
            timestamp=int(datetime.now(timezone.utc).timestamp() * 1e6),
            event_type=event_type,
            device_id=device_id,
            data=data,
            merkle_hash=b'',
            previous_hash=previous_entry.merkle_hash
        )

        # Calculate entry hash
        entry.merkle_hash = self._hash_entry(entry)

        # Append to log
        self.entries.append(entry)

        # Update Merkle tree
        self._rebuild_merkle_tree()

        return entry

    def get_root_hash(self) -> bytes:
        """
        Get current Merkle root hash.

        Returns:
            32-byte SHA256 root hash
        """
        if not self.merkle_tree:
            return b'\x00' * 32

        return self.merkle_tree[-1][0]  # Root is at top level

    def get_entry(self, index: int) -> Optional[LogEntry]:
        """
        Get entry by index.

        Args:
            index: Entry index

        Returns:
            Log entry or None if not found
        """
        if 0 <= index < len(self.entries):
            return self.entries[index]
        return None

    def generate_proof(self, index: int) -> Optional[MerkleProof]:
        """
        Generate Merkle inclusion proof for entry.

        Args:
            index: Entry index

        Returns:
            Merkle proof or None if invalid index
        """
        if index < 0 or index >= len(self.entries):
            return None

        entry = self.entries[index]
        merkle_path = []

        # Build path from leaf to root
        current_index = index
        current_level = 0

        while current_level < len(self.merkle_tree) - 1:
            level = self.merkle_tree[current_level]
            is_left = current_index % 2 == 0

            # Get sibling hash
            if is_left and current_index + 1 < len(level):
                sibling = level[current_index + 1]
                merkle_path.append((sibling, 'right'))
            elif not is_left:
                sibling = level[current_index - 1]
                merkle_path.append((sibling, 'left'))

            current_index = current_index // 2
            current_level += 1

        proof = MerkleProof(
            entry_index=index,
            entry_hash=entry.merkle_hash,
            merkle_path=merkle_path,
            root_hash=self.get_root_hash()
        )

        return proof

    def verify_proof(self, proof: MerkleProof) -> bool:
        """
        Verify Merkle inclusion proof.

        Args:
            proof: Merkle proof to verify

        Returns:
            True if proof is valid
        """
        # Start with entry hash
        current_hash = proof.entry_hash

        # Walk up the tree
        for sibling_hash, position in proof.merkle_path:
            if position == 'left':
                current_hash = self._hash_pair(sibling_hash, current_hash)
            else:
                current_hash = self._hash_pair(current_hash, sibling_hash)

        # Check if we reach the root
        return current_hash == proof.root_hash

    def verify_chain(self, start_index: int = 0, end_index: Optional[int] = None) -> bool:
        """
        Verify blockchain-like chain of entries.

        Args:
            start_index: Start verification from this index
            end_index: End verification at this index (None = end of log)

        Returns:
            True if chain is valid
        """
        if end_index is None:
            end_index = len(self.entries) - 1

        for i in range(start_index, end_index + 1):
            entry = self.entries[i]

            # Verify entry hash
            expected_hash = self._hash_entry(entry)
            if entry.merkle_hash != expected_hash:
                return False

            # Verify previous hash chain
            if i > 0:
                prev_entry = self.entries[i - 1]
                if entry.previous_hash != prev_entry.merkle_hash:
                    return False

        return True

    def get_entries_by_device(self, device_id: str) -> List[LogEntry]:
        """
        Get all entries for a specific device.

        Args:
            device_id: Device identifier

        Returns:
            List of log entries for device
        """
        return [e for e in self.entries if e.device_id == device_id]

    def get_entries_by_type(self, event_type: EventType) -> List[LogEntry]:
        """
        Get all entries of a specific type.

        Args:
            event_type: Event type

        Returns:
            List of log entries of this type
        """
        return [e for e in self.entries if e.event_type == event_type]

    def export_to_json(self, output_path: str):
        """
        Export log to JSON for offline verification.

        Args:
            output_path: Output file path
        """
        log_data = {
            'log_id': self.log_id,
            'root_hash': self.get_root_hash().hex(),
            'entry_count': len(self.entries),
            'entries': []
        }

        for entry in self.entries:
            entry_data = {
                'index': entry.index,
                'timestamp': entry.timestamp,
                'event_type': entry.event_type.value,
                'device_id': entry.device_id,
                'data': entry.data,
                'merkle_hash': entry.merkle_hash.hex(),
                'previous_hash': entry.previous_hash.hex()
            }
            log_data['entries'].append(entry_data)

        with open(output_path, 'w') as f:
            json.dump(log_data, f, indent=2)

    def _hash_entry(self, entry: LogEntry) -> bytes:
        """
        Calculate SHA256 hash of log entry.

        Args:
            entry: Log entry

        Returns:
            32-byte hash
        """
        # Serialize entry (excluding merkle_hash field)
        data = bytearray()

        data.extend(struct.pack('<Q', entry.index))
        data.extend(struct.pack('<Q', entry.timestamp))
        data.extend(entry.event_type.value.encode('utf-8')[:32].ljust(32, b'\x00'))
        data.extend(entry.device_id.encode('utf-8')[:32].ljust(32, b'\x00'))
        data.extend(json.dumps(entry.data, sort_keys=True).encode('utf-8'))
        data.extend(entry.previous_hash)

        return hashlib.sha256(bytes(data)).digest()

    def _hash_pair(self, left: bytes, right: bytes) -> bytes:
        """
        Hash pair of nodes in Merkle tree.

        Args:
            left: Left child hash
            right: Right child hash

        Returns:
            Parent node hash
        """
        return hashlib.sha256(left + right).digest()

    def _rebuild_merkle_tree(self):
        """Rebuild Merkle tree from current entries."""
        if not self.entries:
            self.merkle_tree = []
            return

        # Level 0: leaf hashes (entry hashes)
        current_level = [entry.merkle_hash for entry in self.entries]
        self.merkle_tree = [current_level[:]]  # Copy

        # Build tree bottom-up
        while len(current_level) > 1:
            next_level = []

            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    # Pair exists
                    parent = self._hash_pair(current_level[i], current_level[i + 1])
                else:
                    # Odd node - promote to next level
                    parent = current_level[i]

                next_level.append(parent)

            self.merkle_tree.append(next_level)
            current_level = next_level


# Example usage
if __name__ == '__main__':
    print("=== Merkle Log Test ===\n")

    # Create log
    log = MerkleLog(log_id="hookprobe-validator-001")
    print(f"1. Initialized Merkle log")
    print(f"   Genesis root: {log.get_root_hash().hex()[:32]}...\n")

    # Append enrollment event
    print("2. Appending enrollment event...")
    enrollment_entry = log.append(
        event_type=EventType.ENROLLMENT,
        device_id="edge-001",
        data={
            'device_key': '0x1234567890abcdef...',
            'firmware_version': '1.0.0',
            'oem': 'Raspberry Pi Foundation'
        }
    )
    print(f"   Entry #{enrollment_entry.index}: {enrollment_entry.merkle_hash.hex()[:32]}...")
    print(f"   New root: {log.get_root_hash().hex()[:32]}...\n")

    # Append attestation event
    print("3. Appending attestation event...")
    attestation_entry = log.append(
        event_type=EventType.ATTESTATION,
        device_id="edge-001",
        data={
            'attestation_hash': hashlib.sha256(b"attestation-data").hexdigest(),
            'pcr_count': 6,
            'secure_boot': True
        }
    )
    print(f"   Entry #{attestation_entry.index}: {attestation_entry.merkle_hash.hex()[:32]}...")
    print(f"   New root: {log.get_root_hash().hex()[:32]}...\n")

    # Append validation event
    print("4. Appending validation event...")
    validation_entry = log.append(
        event_type=EventType.VALIDATION,
        device_id="edge-001",
        data={
            'validators': ['validator-001', 'validator-002', 'validator-003'],
            'quorum': 3,
            'result': 'valid'
        }
    )
    print(f"   Entry #{validation_entry.index}: {validation_entry.merkle_hash.hex()[:32]}...")
    print(f"   New root: {log.get_root_hash().hex()[:32]}...\n")

    # Generate and verify proof
    print("5. Generating Merkle proof for attestation entry...")
    proof = log.generate_proof(attestation_entry.index)
    print(f"   Entry index: {proof.entry_index}")
    print(f"   Merkle path length: {len(proof.merkle_path)}")
    print(f"   Root hash: {proof.root_hash.hex()[:32]}...\n")

    print("6. Verifying Merkle proof...")
    is_valid = log.verify_proof(proof)
    print(f"   Proof valid: {is_valid}\n")

    # Verify chain
    print("7. Verifying entry chain...")
    chain_valid = log.verify_chain()
    print(f"   Chain valid: {chain_valid}\n")

    # Query by device
    print("8. Querying entries for edge-001...")
    device_entries = log.get_entries_by_device("edge-001")
    print(f"   Found {len(device_entries)} entries:")
    for entry in device_entries:
        print(f"     #{entry.index}: {entry.event_type.value}")

    # Export to JSON
    print("\n9. Exporting log to JSON...")
    log.export_to_json("/tmp/merkle-log.json")
    print("   Exported to /tmp/merkle-log.json")

    print("\n✓ Merkle log test complete")
