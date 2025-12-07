"""
DSM Local Ledger

Local storage for microblocks using LevelDB/RocksDB or in-memory fallback.
Provides fast key-value storage for blockchain-like data.
"""

import logging
import json
import os
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Global flag for LevelDB availability
_leveldb_available = None


def _check_leveldb_available() -> bool:
    """Check if plyvel (LevelDB) is available."""
    global _leveldb_available

    if _leveldb_available is not None:
        return _leveldb_available

    try:
        import plyvel  # noqa: F401
        logger.info("plyvel library available - using LevelDB")
        _leveldb_available = True
        return True
    except ImportError:
        logger.warning("plyvel not installed - using in-memory fallback")
        _leveldb_available = False
        return False


class LevelDBLedger:
    """
    Local microblock storage using LevelDB or in-memory fallback.

    Stores microblocks and their payloads for local query and verification.
    Retention policy: 30 days (configurable).

    Example:
        >>> ledger = LevelDBLedger("/var/lib/hookprobe/dsm/microblocks")
        >>> ledger.store(block_id, microblock, payload)
        >>> block = ledger.get(block_id)
    """

    def __init__(self, path: str, retention_days: int = 30):
        """
        Initialize ledger.

        Args:
            path: Directory path for LevelDB storage
            retention_days: Days to retain microblocks
        """
        self.path = path
        self.retention_days = retention_days
        self.db = None
        self.memory_store = {}  # Fallback

        if _check_leveldb_available():
            try:
                import plyvel
                os.makedirs(path, exist_ok=True)
                self.db = plyvel.DB(path, create_if_missing=True)
                logger.info(f"LevelDB initialized: {path}")
            except Exception as e:
                logger.warning(f"LevelDB initialization failed: {e}, using in-memory")
                self.db = None
        else:
            logger.info(f"Using in-memory storage (fallback): {path}")

    def store(
        self,
        block_id: str,
        microblock: Dict[str, Any],
        payload: Dict[str, Any]
    ):
        """
        Store microblock and payload.

        Args:
            block_id: Unique block identifier
            microblock: Microblock dictionary
            payload: Full event payload
        """
        # Combine microblock and payload
        full_data = {
            'microblock': microblock,
            'payload': payload,
            'stored_at': datetime.utcnow().isoformat() + 'Z'
        }

        data_bytes = json.dumps(full_data).encode('utf-8')

        if self.db:
            # LevelDB storage
            self.db.put(block_id.encode('utf-8'), data_bytes)
        else:
            # In-memory fallback
            self.memory_store[block_id] = full_data

        logger.debug(f"Stored microblock: {block_id[:8]}...")

    def get(self, block_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve microblock by ID.

        Args:
            block_id: Block identifier

        Returns:
            Microblock dictionary or None if not found
        """
        if self.db:
            # LevelDB retrieval
            data_bytes = self.db.get(block_id.encode('utf-8'))
            if data_bytes:
                full_data = json.loads(data_bytes.decode('utf-8'))
                return full_data['microblock']
            return None
        else:
            # In-memory retrieval
            full_data = self.memory_store.get(block_id)
            return full_data['microblock'] if full_data else None

    def get_with_payload(self, block_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve microblock with full payload.

        Args:
            block_id: Block identifier

        Returns:
            Dictionary with 'microblock' and 'payload' or None
        """
        if self.db:
            data_bytes = self.db.get(block_id.encode('utf-8'))
            if data_bytes:
                return json.loads(data_bytes.decode('utf-8'))
            return None
        else:
            return self.memory_store.get(block_id)

    def get_range(
        self,
        node_id: str,
        start_seq: int,
        end_seq: int
    ) -> List[Dict[str, Any]]:
        """
        Get microblocks in sequence range for a node.

        Args:
            node_id: Node identifier
            start_seq: Start sequence number
            end_seq: End sequence number

        Returns:
            List of microblocks
        """
        results = []

        if self.db:
            # LevelDB range scan
            prefix = f"node:{node_id}:".encode('utf-8')
            for key, value in self.db.iterator(prefix=prefix):
                full_data = json.loads(value.decode('utf-8'))
                microblock = full_data['microblock']
                seq = microblock.get('seq', 0)

                if start_seq <= seq <= end_seq:
                    results.append(microblock)
        else:
            # In-memory scan
            for block_id, full_data in self.memory_store.items():
                microblock = full_data['microblock']
                if microblock['node_id'] == node_id:
                    seq = microblock['seq']
                    if start_seq <= seq <= end_seq:
                        results.append(microblock)

        return sorted(results, key=lambda m: m['seq'])

    def cleanup_old(self):
        """Remove microblocks older than retention period."""
        cutoff = datetime.utcnow() - timedelta(days=self.retention_days)
        cutoff_iso = cutoff.isoformat() + 'Z'

        deleted = 0

        if self.db:
            # LevelDB cleanup
            to_delete = []
            for key, value in self.db.iterator():
                full_data = json.loads(value.decode('utf-8'))
                stored_at = full_data.get('stored_at', '')

                if stored_at < cutoff_iso:
                    to_delete.append(key)

            for key in to_delete:
                self.db.delete(key)
                deleted += 1
        else:
            # In-memory cleanup
            to_delete = []
            for block_id, full_data in self.memory_store.items():
                stored_at = full_data.get('stored_at', '')
                if stored_at < cutoff_iso:
                    to_delete.append(block_id)

            for block_id in to_delete:
                del self.memory_store[block_id]
                deleted += 1

        logger.info(f"Cleaned up {deleted} old microblocks (>{self.retention_days} days)")

    def close(self):
        """Close ledger connection."""
        if self.db:
            self.db.close()
            logger.info("LevelDB closed")
