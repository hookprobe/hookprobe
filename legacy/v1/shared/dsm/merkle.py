"""
DSM Merkle Tree

Implements Merkle tree construction for checkpoint aggregation.

Security Features:
- SHA-256 for collision resistance
- Deterministic tree construction
- Inclusion proof generation and verification
- Constant-time verification to prevent timing attacks

Usage:
    tree = MerkleTree(['block1', 'block2', 'block3'])
    root = tree.root()
    proof = tree.proof('block2')
    assert tree.verify_proof('block2', proof, root)
"""

import hashlib
import hmac
import logging
from typing import List, Tuple, Optional, Dict
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class MerkleProof:
    """Merkle inclusion proof."""
    leaf_id: str
    leaf_hash: str
    siblings: List[Tuple[str, str]]  # List of (hash, position) where position is 'L' or 'R'
    root: str

    def to_bytes(self) -> bytes:
        """Serialize proof to bytes."""
        import json
        return json.dumps({
            'leaf_id': self.leaf_id,
            'leaf_hash': self.leaf_hash,
            'siblings': self.siblings,
            'root': self.root,
        }).encode()

    @classmethod
    def from_bytes(cls, data: bytes) -> 'MerkleProof':
        """Deserialize proof from bytes."""
        import json
        obj = json.loads(data.decode())
        return cls(
            leaf_id=obj['leaf_id'],
            leaf_hash=obj['leaf_hash'],
            siblings=[tuple(s) for s in obj['siblings']],
            root=obj['root'],
        )


class MerkleTree:
    """
    Merkle tree for cryptographic aggregation of microblocks.

    Provides tamper-evident proof that a microblock is included
    in a checkpoint.

    Tree Structure:
        Level 0 (leaves): H(leaf_0), H(leaf_1), H(leaf_2), H(leaf_3), ...
        Level 1:          H(H(l0)||H(l1)), H(H(l2)||H(l3)), ...
        Level n (root):   H(...)

    Example:
        >>> tree = MerkleTree(['block1', 'block2', 'block3'])
        >>> root = tree.root()
        >>> proof = tree.proof('block2')
        >>> assert tree.verify_proof('block2', proof, root)
    """

    def __init__(self, leaf_ids: List[str]):
        """
        Build Merkle tree from leaf node IDs.

        Args:
            leaf_ids: List of microblock IDs
        """
        self.leaves = leaf_ids
        self._leaf_to_index: Dict[str, int] = {leaf: i for i, leaf in enumerate(leaf_ids)}
        self._levels: List[List[str]] = []  # Tree levels from leaves to root
        self._build_tree_levels()

    @property
    def tree(self) -> List[str]:
        """Backward compatible tree property (flattened)."""
        result = []
        for level in reversed(self._levels):
            result.extend(level)
        return result

    def root(self) -> str:
        """
        Get Merkle root hash.

        Returns:
            Root hash as hex string
        """
        if not self._levels:
            return ""
        return self._levels[-1][0] if self._levels[-1] else ""

    def proof(self, leaf_id: str) -> List[Tuple[str, str]]:
        """
        Generate Merkle inclusion proof for a leaf.

        The proof consists of sibling hashes at each level, with position
        indicators ('L' for left sibling, 'R' for right sibling).

        Args:
            leaf_id: Leaf to prove

        Returns:
            List of (sibling_hash, position) tuples for verification path

        Raises:
            ValueError: If leaf_id not in tree
        """
        if leaf_id not in self._leaf_to_index:
            raise ValueError(f"Leaf '{leaf_id}' not in tree")

        proof_path: List[Tuple[str, str]] = []
        index = self._leaf_to_index[leaf_id]

        # Traverse from leaf to root
        for level_idx in range(len(self._levels) - 1):
            level = self._levels[level_idx]

            # Determine sibling index
            if index % 2 == 0:
                # Node is left child, sibling is right
                sibling_idx = index + 1
                position = 'R'
            else:
                # Node is right child, sibling is left
                sibling_idx = index - 1
                position = 'L'

            # Get sibling hash (duplicate last if odd number of nodes)
            if sibling_idx < len(level):
                sibling_hash = level[sibling_idx]
            else:
                sibling_hash = level[index]  # Self-duplicate

            proof_path.append((sibling_hash, position))

            # Move to parent index
            index = index // 2

        return proof_path

    def get_proof_object(self, leaf_id: str) -> MerkleProof:
        """
        Get proof as structured object.

        Args:
            leaf_id: Leaf to prove

        Returns:
            MerkleProof object
        """
        return MerkleProof(
            leaf_id=leaf_id,
            leaf_hash=self._hash(leaf_id),
            siblings=self.proof(leaf_id),
            root=self.root(),
        )

    def verify_proof(
        self,
        leaf_id: str,
        proof: List[Tuple[str, str]],
        root: str
    ) -> bool:
        """
        Verify Merkle inclusion proof.

        Recomputes the path from leaf to root using the provided
        sibling hashes and compares with expected root.

        Uses constant-time comparison to prevent timing attacks.

        Args:
            leaf_id: Leaf to verify
            proof: List of (sibling_hash, position) tuples
            root: Expected root hash

        Returns:
            True if proof is valid
        """
        if not proof and len(self.leaves) > 1:
            return False

        # Start with leaf hash
        current_hash = self._hash(leaf_id)

        # Traverse proof path
        for sibling_hash, position in proof:
            if position == 'L':
                # Sibling is on left
                combined = sibling_hash + current_hash
            else:
                # Sibling is on right
                combined = current_hash + sibling_hash

            current_hash = self._hash(combined)

        # Constant-time comparison
        return hmac.compare_digest(current_hash, root)

    @staticmethod
    def verify_proof_static(
        leaf_id: str,
        proof: List[Tuple[str, str]],
        expected_root: str
    ) -> bool:
        """
        Statically verify a Merkle proof without tree instance.

        Useful for external verification.

        Args:
            leaf_id: Leaf to verify
            proof: List of (sibling_hash, position) tuples
            expected_root: Expected root hash

        Returns:
            True if proof is valid
        """
        # Hash leaf
        current_hash = hashlib.sha256(leaf_id.encode()).hexdigest()

        # Traverse proof
        for sibling_hash, position in proof:
            if position == 'L':
                combined = sibling_hash + current_hash
            else:
                combined = current_hash + sibling_hash

            current_hash = hashlib.sha256(combined.encode()).hexdigest()

        return hmac.compare_digest(current_hash, expected_root)

    def _build_tree_levels(self) -> None:
        """
        Build Merkle tree and store by levels.
        """
        if not self.leaves:
            self._levels = []
            return

        # Level 0: leaf hashes
        current_level = [self._hash(leaf) for leaf in self.leaves]
        self._levels = [current_level]

        # Build tree bottom-up
        while len(current_level) > 1:
            next_level = []

            # Pair up nodes and hash
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    combined = current_level[i] + current_level[i + 1]
                else:
                    # Odd number: duplicate last node
                    combined = current_level[i] + current_level[i]

                next_level.append(self._hash(combined))

            self._levels.append(next_level)
            current_level = next_level

    def _hash(self, data: str) -> str:
        """
        Hash data with SHA-256.

        Args:
            data: Data to hash

        Returns:
            Hex digest
        """
        return hashlib.sha256(data.encode()).hexdigest()

    def get_leaf_hash(self, leaf_id: str) -> Optional[str]:
        """Get hash of a leaf."""
        if leaf_id not in self._leaf_to_index:
            return None
        return self._hash(leaf_id)

    def height(self) -> int:
        """Get tree height (number of levels)."""
        return len(self._levels)

    def leaf_count(self) -> int:
        """Get number of leaves."""
        return len(self.leaves)

    def __repr__(self) -> str:
        return f"MerkleTree(leaves={len(self.leaves)}, height={self.height()}, root={self.root()[:16]}...)"


def verify_merkle_proof(proof: MerkleProof) -> bool:
    """
    Verify a MerkleProof object.

    Args:
        proof: MerkleProof to verify

    Returns:
        True if proof is valid
    """
    return MerkleTree.verify_proof_static(
        proof.leaf_id,
        proof.siblings,
        proof.root
    )


# ============================================================================
# CLI for testing
# ============================================================================

if __name__ == '__main__':
    print("Merkle Tree Demo")
    print("=" * 50)

    # Create tree with test data
    leaves = ['block1', 'block2', 'block3', 'block4', 'block5']
    tree = MerkleTree(leaves)

    print(f"\nTree: {tree}")
    print(f"Root: {tree.root()}")
    print(f"Height: {tree.height()}")

    # Generate and verify proofs
    print("\nGenerating proofs...")
    for leaf in leaves:
        proof = tree.proof(leaf)
        valid = tree.verify_proof(leaf, proof, tree.root())
        print(f"  {leaf}: proof_len={len(proof)}, valid={valid}")

    # Test static verification
    print("\nTesting static verification...")
    proof_obj = tree.get_proof_object('block3')
    print(f"  Proof object: {proof_obj.leaf_id}")
    print(f"  Siblings: {len(proof_obj.siblings)}")

    valid_static = verify_merkle_proof(proof_obj)
    print(f"  Static verify: {valid_static}")

    # Test invalid proof
    print("\nTesting invalid proof detection...")
    tampered_proof = proof_obj.siblings.copy()
    if tampered_proof:
        # Tamper with first sibling
        tampered_proof[0] = ('0' * 64, tampered_proof[0][1])

    invalid_result = tree.verify_proof('block3', tampered_proof, tree.root())
    print(f"  Tampered proof valid: {invalid_result} (should be False)")

    print("\n✓ Merkle tree test complete")
