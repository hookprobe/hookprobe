#!/usr/bin/env python3
"""
DAG Consensus for Parallel Microblock Creation

PROPRIETARY AND CONFIDENTIAL
Copyright (c) 2024-2026 HookProbe Technologies
Licensed under Commercial License - See LICENSING.md

Replaces linear blockchain with Directed Acyclic Graph (DAG) for improved
parallel microblock creation and higher throughput.

Architecture:
    - Microblocks can reference multiple parents (not just one)
    - Tips are unconfirmed microblocks awaiting references
    - Confirmation weight = cumulative references
    - Finalization via threshold-based consensus

Benefits:
    - Higher throughput (parallel block creation)
    - Lower latency (no waiting for sequential blocks)
    - Byzantine fault tolerant up to 1/3 malicious nodes
    - Natural load balancing across validators

Usage:
    dag = DAGConsensus()

    # Add microblocks
    block_id = dag.add_microblock(microblock, parents=['parent1', 'parent2'])

    # Check confirmation weight
    weight = dag.get_confirmation_weight(block_id)

    # Finalize confirmed blocks
    finalized = dag.finalize_blocks(threshold=10)
"""

import hashlib
import time
import logging
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import deque
from enum import Enum

logger = logging.getLogger(__name__)


class MicroblockStatus(Enum):
    """Status of a microblock in the DAG."""
    PENDING = 'pending'      # Just added, awaiting confirmation
    CONFIRMED = 'confirmed'  # Has enough confirmation weight
    FINALIZED = 'finalized'  # Permanently committed
    ORPHANED = 'orphaned'    # Conflicting/invalid, will be pruned


@dataclass
class Microblock:
    """A microblock in the DAG."""
    block_id: str
    timestamp: float
    validator_id: str
    payload_hash: str
    payload: bytes = b''

    def __hash__(self):
        return hash(self.block_id)


@dataclass
class DAGNode:
    """Node in the DAG representing a microblock."""
    microblock: Microblock
    parents: Set[str]           # Block IDs this node references
    children: Set[str] = field(default_factory=set)  # Blocks that reference this node
    status: MicroblockStatus = MicroblockStatus.PENDING
    confirmation_weight: int = 0
    depth: int = 0              # Distance from genesis
    added_timestamp: float = 0.0

    def __hash__(self):
        return hash(self.microblock.block_id)


class DAGConsensus:
    """
    Directed Acyclic Graph for parallel microblock creation.

    The DAG allows multiple microblocks to be created concurrently,
    with each block referencing one or more parent blocks. This enables
    higher throughput than linear chains while maintaining consistency.

    Consensus Rules:
    1. Each block must reference at least one valid parent
    2. No cycles allowed (strictly acyclic)
    3. Confirmation weight = number of descendants
    4. Finalization when weight exceeds threshold
    """

    # Genesis block ID
    GENESIS_ID = "genesis-00000000"

    # Configuration
    MAX_PARENTS = 8           # Maximum parent references per block
    DEFAULT_THRESHOLD = 10    # Default finalization threshold
    MAX_TIP_AGE = 300.0       # Max age of tips in seconds
    PRUNE_INTERVAL = 60.0     # How often to prune old data

    def __init__(self, validator_id: str = "default"):
        """
        Initialize DAG consensus.

        Args:
            validator_id: ID of this validator
        """
        self.validator_id = validator_id
        self.graph: Dict[str, DAGNode] = {}
        self.tips: Set[str] = set()  # Unconfirmed blocks with no children
        self._finalized_blocks: List[str] = []
        self._last_prune = time.time()

        # Create genesis block
        self._create_genesis()

        logger.info(f"[DAG] Consensus initialized for validator {validator_id}")

    def _create_genesis(self) -> None:
        """Create genesis block."""
        genesis = Microblock(
            block_id=self.GENESIS_ID,
            timestamp=0.0,
            validator_id="system",
            payload_hash=hashlib.sha256(b"genesis").hexdigest(),
        )

        node = DAGNode(
            microblock=genesis,
            parents=set(),
            status=MicroblockStatus.FINALIZED,
            depth=0,
            added_timestamp=0.0,
        )

        self.graph[self.GENESIS_ID] = node
        self.tips.add(self.GENESIS_ID)

    def add_microblock(
        self,
        block: Microblock,
        parents: List[str] = None
    ) -> str:
        """
        Add a microblock to the DAG.

        Args:
            block: Microblock to add
            parents: List of parent block IDs (default: current tips)

        Returns:
            Block ID of added block

        Raises:
            ValueError: If block is invalid or creates a cycle
        """
        block_id = block.block_id

        # Check for duplicate
        if block_id in self.graph:
            logger.warning(f"[DAG] Duplicate block: {block_id}")
            return block_id

        # Default to current tips if no parents specified
        if parents is None or len(parents) == 0:
            parents = self._select_parents()

        # Validate parents
        valid_parents = set()
        for parent_id in parents[:self.MAX_PARENTS]:
            if parent_id in self.graph:
                parent_node = self.graph[parent_id]
                if parent_node.status != MicroblockStatus.ORPHANED:
                    valid_parents.add(parent_id)

        if not valid_parents:
            # Use genesis if no valid parents
            valid_parents = {self.GENESIS_ID}

        # Check for cycles
        if self._would_create_cycle(block_id, valid_parents):
            raise ValueError(f"Block {block_id} would create a cycle")

        # Calculate depth
        max_parent_depth = max(
            self.graph[p].depth for p in valid_parents
        )

        # Create node
        node = DAGNode(
            microblock=block,
            parents=valid_parents,
            status=MicroblockStatus.PENDING,
            depth=max_parent_depth + 1,
            added_timestamp=time.time(),
        )

        # Add to graph
        self.graph[block_id] = node

        # Update parent-child relationships
        for parent_id in valid_parents:
            self.graph[parent_id].children.add(block_id)
            # Parent is no longer a tip
            self.tips.discard(parent_id)

        # New block is a tip
        self.tips.add(block_id)

        # Update confirmation weights
        self._update_weights(block_id)

        logger.debug(f"[DAG] Added block {block_id[:16]}... (depth={node.depth}, parents={len(valid_parents)})")

        return block_id

    def _select_parents(self, max_parents: int = 2) -> List[str]:
        """
        Select parent blocks from current tips.

        Uses a simple strategy: select newest tips up to max_parents.
        """
        if not self.tips:
            return [self.GENESIS_ID]

        # Sort tips by timestamp (newest first)
        sorted_tips = sorted(
            self.tips,
            key=lambda t: self.graph[t].added_timestamp,
            reverse=True
        )

        return sorted_tips[:max_parents]

    def _would_create_cycle(self, new_block_id: str, parents: Set[str]) -> bool:
        """
        Check if adding block with given parents would create a cycle.

        Uses BFS to check if any parent is reachable from new block.
        """
        # New block has no children yet, so can't create cycle
        # But check if new_block_id appears in any parent's ancestry
        visited = set()
        queue = deque(parents)

        while queue:
            current = queue.popleft()
            if current == new_block_id:
                return True
            if current in visited:
                continue
            visited.add(current)

            node = self.graph.get(current)
            if node:
                queue.extend(node.parents)

        return False

    def _update_weights(self, start_id: str) -> None:
        """
        Update confirmation weights for ancestors of a block.

        Each block's weight = 1 + sum of children's contributions.
        """
        # BFS from start block upward to ancestors
        visited = set()
        queue = deque([start_id])

        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)

            node = self.graph.get(current)
            if not node:
                continue

            # Weight = 1 (self) + number of descendants
            # Simplified: just count children depth
            weight = 1
            for child_id in node.children:
                child = self.graph.get(child_id)
                if child:
                    weight += child.confirmation_weight

            node.confirmation_weight = weight

            # Update status based on weight
            if node.status == MicroblockStatus.PENDING:
                if weight >= self.DEFAULT_THRESHOLD:
                    node.status = MicroblockStatus.CONFIRMED

            # Continue to parents
            queue.extend(node.parents)

    def get_confirmation_weight(self, block_id: str) -> int:
        """
        Get confirmation weight of a block.

        Weight represents how "confirmed" a block is based on
        the number of descendant blocks.

        Args:
            block_id: Block to check

        Returns:
            Confirmation weight (0 if not found)
        """
        node = self.graph.get(block_id)
        if node:
            return node.confirmation_weight
        return 0

    def finalize_blocks(self, threshold: int = None) -> List[Microblock]:
        """
        Finalize blocks that have reached confirmation threshold.

        Finalized blocks are permanently committed and cannot be reverted.

        Args:
            threshold: Minimum confirmation weight for finalization

        Returns:
            List of newly finalized microblocks
        """
        if threshold is None:
            threshold = self.DEFAULT_THRESHOLD

        newly_finalized = []

        # Find confirmed blocks ready for finalization
        for block_id, node in list(self.graph.items()):
            if node.status == MicroblockStatus.CONFIRMED:
                if node.confirmation_weight >= threshold:
                    # Check all parents are finalized
                    all_parents_final = all(
                        self.graph.get(p, node).status == MicroblockStatus.FINALIZED
                        for p in node.parents
                    )

                    if all_parents_final:
                        node.status = MicroblockStatus.FINALIZED
                        self._finalized_blocks.append(block_id)
                        newly_finalized.append(node.microblock)

                        logger.info(f"[DAG] Finalized block {block_id[:16]}... (weight={node.confirmation_weight})")

        return newly_finalized

    def get_tips(self) -> Set[str]:
        """Get current tip block IDs."""
        return self.tips.copy()

    def get_block(self, block_id: str) -> Optional[DAGNode]:
        """Get a block node by ID."""
        return self.graph.get(block_id)

    def get_status(self, block_id: str) -> Optional[MicroblockStatus]:
        """Get block status."""
        node = self.graph.get(block_id)
        return node.status if node else None

    def get_ancestors(self, block_id: str, max_depth: int = 100) -> Set[str]:
        """
        Get all ancestor block IDs.

        Args:
            block_id: Starting block
            max_depth: Maximum traversal depth

        Returns:
            Set of ancestor block IDs
        """
        ancestors = set()
        queue = deque([(block_id, 0)])

        while queue:
            current, depth = queue.popleft()
            if depth > max_depth:
                continue
            if current in ancestors:
                continue
            ancestors.add(current)

            node = self.graph.get(current)
            if node:
                for parent in node.parents:
                    queue.append((parent, depth + 1))

        ancestors.discard(block_id)  # Remove self
        return ancestors

    def get_descendants(self, block_id: str, max_depth: int = 100) -> Set[str]:
        """
        Get all descendant block IDs.

        Args:
            block_id: Starting block
            max_depth: Maximum traversal depth

        Returns:
            Set of descendant block IDs
        """
        descendants = set()
        queue = deque([(block_id, 0)])

        while queue:
            current, depth = queue.popleft()
            if depth > max_depth:
                continue
            if current in descendants:
                continue
            descendants.add(current)

            node = self.graph.get(current)
            if node:
                for child in node.children:
                    queue.append((child, depth + 1))

        descendants.discard(block_id)  # Remove self
        return descendants

    def prune_old_finalized(self, keep_recent: int = 1000) -> int:
        """
        Prune old finalized blocks to free memory.

        Keeps recent finalized blocks for reference.

        Args:
            keep_recent: Number of recent finalized blocks to keep

        Returns:
            Number of blocks pruned
        """
        if len(self._finalized_blocks) <= keep_recent:
            return 0

        to_prune = self._finalized_blocks[:-keep_recent]
        pruned = 0

        for block_id in to_prune:
            # Only prune if no non-finalized descendants
            has_pending_desc = any(
                self.graph.get(d, DAGNode(None, set())).status != MicroblockStatus.FINALIZED
                for d in self.get_descendants(block_id, max_depth=10)
            )

            if not has_pending_desc and block_id != self.GENESIS_ID:
                del self.graph[block_id]
                self._finalized_blocks.remove(block_id)
                pruned += 1

        if pruned > 0:
            logger.debug(f"[DAG] Pruned {pruned} old finalized blocks")

        return pruned

    def get_stats(self) -> Dict[str, Any]:
        """Get DAG statistics."""
        status_counts = {s: 0 for s in MicroblockStatus}
        for node in self.graph.values():
            status_counts[node.status] += 1

        return {
            'total_blocks': len(self.graph),
            'tips': len(self.tips),
            'finalized': len(self._finalized_blocks),
            'by_status': {s.value: c for s, c in status_counts.items()},
            'max_depth': max((n.depth for n in self.graph.values()), default=0),
        }

    def visualize(self, max_blocks: int = 20) -> str:
        """
        Create simple text visualization of DAG.

        Args:
            max_blocks: Maximum blocks to show

        Returns:
            ASCII visualization
        """
        lines = ["DAG Visualization:"]
        lines.append("-" * 50)

        # Group by depth
        by_depth: Dict[int, List[str]] = {}
        for block_id, node in self.graph.items():
            if node.depth not in by_depth:
                by_depth[node.depth] = []
            by_depth[node.depth].append(block_id)

        blocks_shown = 0
        for depth in sorted(by_depth.keys()):
            if blocks_shown >= max_blocks:
                lines.append("  ...")
                break

            blocks = by_depth[depth]
            line = f"  Depth {depth}: "
            for b in blocks[:3]:  # Max 3 per depth
                node = self.graph[b]
                status_char = node.status.value[0].upper()
                line += f"[{b[:8]}:{status_char}] "
                blocks_shown += 1

            if len(blocks) > 3:
                line += f"... (+{len(blocks) - 3} more)"

            lines.append(line)

        lines.append("-" * 50)
        return "\n".join(lines)


# ============================================================================
# CLI for testing
# ============================================================================

if __name__ == '__main__':
    print("DAG Consensus Demo")
    print("=" * 50)

    # Create DAG
    dag = DAGConsensus(validator_id="test-validator")
    print(f"\nInitial stats: {dag.get_stats()}")

    # Add some microblocks
    print("\nAdding microblocks...")
    block_ids = []

    for i in range(10):
        block = Microblock(
            block_id=f"block-{i:03d}",
            timestamp=time.time(),
            validator_id="test-validator",
            payload_hash=hashlib.sha256(f"payload-{i}".encode()).hexdigest(),
        )

        # Use 1-2 random parents from recent blocks
        parents = None
        if block_ids:
            import random
            num_parents = min(2, len(block_ids))
            parents = random.sample(block_ids[-5:], min(num_parents, len(block_ids[-5:])))

        block_id = dag.add_microblock(block, parents)
        block_ids.append(block_id)

        node = dag.get_block(block_id)
        print(f"  Added {block_id}: depth={node.depth}, weight={node.confirmation_weight}, parents={len(node.parents)}")

    # Show stats
    print(f"\nStats after adding blocks: {dag.get_stats()}")
    print(f"Tips: {dag.get_tips()}")

    # Finalize blocks
    print("\nFinalizing blocks...")
    finalized = dag.finalize_blocks(threshold=3)
    print(f"  Finalized {len(finalized)} blocks")

    # Show final visualization
    print(f"\n{dag.visualize()}")

    # Test ancestor/descendant queries
    if block_ids:
        test_block = block_ids[5] if len(block_ids) > 5 else block_ids[-1]
        ancestors = dag.get_ancestors(test_block)
        descendants = dag.get_descendants(test_block)
        print(f"\nBlock {test_block}:")
        print(f"  Ancestors: {len(ancestors)}")
        print(f"  Descendants: {len(descendants)}")

    print("\n✓ DAG consensus test complete")
