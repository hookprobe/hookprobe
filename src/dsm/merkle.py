"""
DSM Merkle Tree

Implements Merkle tree construction for checkpoint aggregation.
"""

import hashlib
import logging
from typing import List

logger = logging.getLogger(__name__)


class MerkleTree:
    """
    Merkle tree for cryptographic aggregation of microblocks.

    Provides tamper-evident proof that a microblock is included
    in a checkpoint.

    Example:
        >>> tree = MerkleTree(['block1', 'block2', 'block3'])
        >>> root = tree.root()
        >>> proof = tree.proof('block2')
    """

    def __init__(self, leaf_ids: List[str]):
        """
        Build Merkle tree from leaf node IDs.

        Args:
            leaf_ids: List of microblock IDs
        """
        self.leaves = leaf_ids
        self.tree = self._build_tree()

    def root(self) -> str:
        """
        Get Merkle root hash.

        Returns:
            Root hash as hex string
        """
        if not self.tree:
            return ""
        return self.tree[0]

    def proof(self, leaf_id: str) -> List[str]:
        """
        Generate Merkle proof for a leaf.

        Args:
            leaf_id: Leaf to prove

        Returns:
            List of sibling hashes for verification path
        """
        # TODO: Implement Merkle proof generation
        return []

    def verify_proof(
        self,
        leaf_id: str,
        proof: List[str],
        root: str
    ) -> bool:
        """
        Verify Merkle proof.

        Args:
            leaf_id: Leaf to verify
            proof: Merkle proof
            root: Expected root hash

        Returns:
            True if proof is valid
        """
        # TODO: Implement Merkle proof verification
        return False

    def _build_tree(self) -> List[str]:
        """
        Build Merkle tree from leaves.

        Returns:
            List representing tree levels
        """
        if not self.leaves:
            return []

        # Hash all leaves
        current_level = [self._hash(leaf) for leaf in self.leaves]
        tree = list(current_level)

        # Build tree bottom-up
        while len(current_level) > 1:
            next_level = []

            # Pair up nodes and hash
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    combined = current_level[i] + current_level[i + 1]
                else:
                    combined = current_level[i] + current_level[i]

                next_level.append(self._hash(combined))

            tree.extend(next_level)
            current_level = next_level

        return tree

    def _hash(self, data: str) -> str:
        """
        Hash data with SHA-256.

        Args:
            data: Data to hash

        Returns:
            Hex digest
        """
        return hashlib.sha256(data.encode()).hexdigest()
