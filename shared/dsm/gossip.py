"""
DSM Gossip Protocol

Implements peer-to-peer gossip for microblock announcement and propagation.

Version: 5.2.0
Updated: 2025-12-13
"""

import hmac
import json
import os
import socket
import hashlib
import logging
import threading
import time as _time
from collections import defaultdict
from typing import List, Dict, Any, Optional, Tuple, Set, Callable
from datetime import datetime
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Constants
GOSSIP_PORT = 8145
MAX_HOP_COUNT = 5
ANNOUNCEMENT_TTL_SECONDS = 300  # 5 minutes
MAX_PEERS = 50
FANOUT = 3  # Number of peers to gossip to
MAX_MESSAGE_SIZE = 16384  # 16KB max gossip message
RATE_LIMIT_WINDOW = 10  # seconds
RATE_LIMIT_MAX = 50  # max messages per peer per window


@dataclass
class GossipMessage:
    """A message in the gossip protocol."""
    msg_type: str  # 'announce', 'fetch_request', 'fetch_response', 'checkpoint'
    source_node: str
    payload: Dict[str, Any]
    hop_count: int = 0
    seen_by: Set[str] = field(default_factory=set)
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())

    def to_bytes(self, mesh_key: Optional[bytes] = None) -> bytes:
        """Serialize message to bytes with optional HMAC authentication."""
        data = {
            'msg_type': self.msg_type,
            'source_node': self.source_node,
            'payload': self.payload,
            'hop_count': self.hop_count,
            'seen_by': list(self.seen_by),
            'timestamp': self.timestamp,
        }
        body = json.dumps(data, sort_keys=True).encode('utf-8')
        if mesh_key:
            mac = hmac.new(mesh_key, body, hashlib.sha256).hexdigest()
            envelope = json.dumps({'body': body.decode('utf-8'), 'mac': mac})
            return envelope.encode('utf-8')
        return body

    @classmethod
    def from_bytes(cls, data: bytes, mesh_key: Optional[bytes] = None) -> 'GossipMessage':
        """Deserialize message from bytes with optional HMAC verification."""
        raw = data.decode('utf-8')
        obj = json.loads(raw)

        # If mesh_key is set, require HMAC authentication
        if mesh_key:
            if 'mac' not in obj or 'body' not in obj:
                raise ValueError("Message missing HMAC authentication")
            body = obj['body'].encode('utf-8')
            expected_mac = hmac.new(mesh_key, body, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(obj['mac'], expected_mac):
                raise ValueError("HMAC verification failed - message tampered or wrong key")
            obj = json.loads(body)

        return cls(
            msg_type=obj['msg_type'],
            source_node=obj['source_node'],
            payload=obj['payload'],
            hop_count=obj.get('hop_count', 0),
            seen_by=set(obj.get('seen_by', [])),
            timestamp=obj.get('timestamp', datetime.now().timestamp()),
        )


class GossipProtocol:
    """
    Gossip-based peer-to-peer communication for DSM mesh.

    Implements:
    - Microblock announcement with hop-limited propagation
    - Block request/response for fetching full blocks
    - Checkpoint broadcast to validator quorum
    - Peer discovery and management

    The protocol uses a push-based gossip with fanout to limit bandwidth
    while ensuring high probability of mesh-wide propagation.

    Example:
        >>> gossip = GossipProtocol("edge-123", bootstrap_nodes=["10.0.0.1:8145"])
        >>> gossip.start()
        >>> gossip.announce(block_id, microblock)
    """

    def __init__(self, node_id: str, bootstrap_nodes: List[str],
                 mesh_key: Optional[bytes] = None):
        """
        Initialize gossip protocol.

        Args:
            node_id: This node's identifier
            bootstrap_nodes: List of validator nodes to connect to (host:port format)
            mesh_key: Shared HMAC key for message authentication (from HTP key exchange)
        """
        self.node_id = node_id
        self.bootstrap_nodes = bootstrap_nodes
        self.peers: Dict[str, Dict[str, Any]] = {}  # peer_id -> {address, last_seen, ...}

        # HMAC authentication key (shared across mesh via HTP key exchange)
        self._mesh_key = mesh_key or os.environ.get(
            'DSM_MESH_KEY', ''
        ).encode('utf-8') or None

        # Per-peer rate limiting: peer_addr -> [(timestamp, ...)]
        self._peer_msg_times: Dict[str, list] = defaultdict(list)

        # Announced blocks cache (block_id -> (microblock, timestamp))
        self._announced_blocks: Dict[str, Tuple[Dict[str, Any], float]] = {}
        self._seen_messages: Set[str] = set()  # Message deduplication

        # Pending fetch requests
        self._pending_fetches: Dict[str, threading.Event] = {}
        self._fetch_results: Dict[str, Dict[str, Any]] = {}

        # Callbacks
        self._on_block_announced: List[Callable] = []
        self._on_checkpoint_received: List[Callable] = []

        # Threading
        self._running = threading.Event()
        self._lock = threading.RLock()
        self._listener_thread: Optional[threading.Thread] = None
        self._cleanup_thread: Optional[threading.Thread] = None

        # Statistics
        self.stats = {
            'messages_sent': 0,
            'messages_received': 0,
            'blocks_announced': 0,
            'blocks_fetched': 0,
            'checkpoints_broadcast': 0,
        }

        logger.info(f"Gossip protocol initialized: {len(bootstrap_nodes)} bootstrap nodes")

    def start(self):
        """Start the gossip protocol listener and maintenance threads."""
        if self._running.is_set():
            logger.warning("Gossip protocol already running")
            return

        self._running.set()

        # Connect to bootstrap nodes
        for node_addr in self.bootstrap_nodes:
            self._add_peer_from_address(node_addr)

        # Start listener thread
        self._listener_thread = threading.Thread(
            target=self._listen_loop,
            daemon=True,
            name="gossip-listener"
        )
        self._listener_thread.start()

        # Start cleanup thread
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop,
            daemon=True,
            name="gossip-cleanup"
        )
        self._cleanup_thread.start()

        logger.info(f"Gossip protocol started on port {GOSSIP_PORT}")

    def announce(self, block_id: str, microblock: Dict[str, Any]):
        """
        Announce new microblock to peers.

        The announcement is propagated to FANOUT random peers,
        who will re-gossip until MAX_HOP_COUNT is reached.

        Args:
            block_id: Block identifier
            microblock: Microblock to announce
        """
        with self._lock:
            # Store locally
            self._announced_blocks[block_id] = (microblock, datetime.now().timestamp())
            self.stats['blocks_announced'] += 1

        # Create gossip message
        msg = GossipMessage(
            msg_type='announce',
            source_node=self.node_id,
            payload={
                'block_id': block_id,
                'microblock': microblock,
            },
            hop_count=0,
            seen_by={self.node_id},
        )

        # Gossip to peers
        self._gossip_to_peers(msg)
        logger.debug(f"Announced microblock: {block_id[:16]}...")

    def collect_announced_blocks(
        self,
        time_window: Tuple[datetime, datetime]
    ) -> List[str]:
        """
        Collect all microblock IDs announced in time window.

        Args:
            time_window: (start_time, end_time) tuple

        Returns:
            List of microblock IDs within the time window
        """
        start_ts = time_window[0].timestamp()
        end_ts = time_window[1].timestamp()

        with self._lock:
            block_ids = [
                block_id
                for block_id, (_, ts) in self._announced_blocks.items()
                if start_ts <= ts <= end_ts
            ]

        logger.debug(f"Collected {len(block_ids)} blocks in time window")
        return block_ids

    def fetch_block(self, block_id: str, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
        """
        Fetch microblock from peer network.

        First checks local cache, then requests from peers.

        Args:
            block_id: Block identifier
            timeout: Seconds to wait for response

        Returns:
            Microblock dictionary or None if not found
        """
        # Check local cache first
        with self._lock:
            if block_id in self._announced_blocks:
                self.stats['blocks_fetched'] += 1
                return self._announced_blocks[block_id][0]

        # Create fetch request
        fetch_event = threading.Event()
        with self._lock:
            self._pending_fetches[block_id] = fetch_event

        # Request from peers
        msg = GossipMessage(
            msg_type='fetch_request',
            source_node=self.node_id,
            payload={'block_id': block_id},
        )
        self._gossip_to_peers(msg)

        # Wait for response
        if fetch_event.wait(timeout=timeout):
            with self._lock:
                result = self._fetch_results.pop(block_id, None)
                self._pending_fetches.pop(block_id, None)
                if result:
                    self.stats['blocks_fetched'] += 1
                return result

        # Cleanup on timeout
        with self._lock:
            self._pending_fetches.pop(block_id, None)

        logger.warning(f"Fetch timeout for block: {block_id[:16]}...")
        return None

    def broadcast_checkpoint(self, checkpoint: Dict[str, Any]):
        """
        Broadcast checkpoint to validator quorum.

        Checkpoints are broadcast with priority (lower hop limit tolerance).

        Args:
            checkpoint: Checkpoint to broadcast
        """
        msg = GossipMessage(
            msg_type='checkpoint',
            source_node=self.node_id,
            payload={'checkpoint': checkpoint},
            hop_count=0,
            seen_by={self.node_id},
        )

        # Broadcast to ALL peers for checkpoints (important)
        self._broadcast_to_all_peers(msg)
        self.stats['checkpoints_broadcast'] += 1

        logger.info(f"Broadcasting checkpoint: epoch={checkpoint.get('epoch', 'unknown')}")

    def on_block_announced(self, callback: Callable[[str, Dict[str, Any]], None]):
        """Register callback for block announcements."""
        self._on_block_announced.append(callback)

    def on_checkpoint_received(self, callback: Callable[[Dict[str, Any]], None]):
        """Register callback for checkpoint reception."""
        self._on_checkpoint_received.append(callback)

    def get_peer_count(self) -> int:
        """Get number of connected peers."""
        with self._lock:
            return len(self.peers)

    def get_statistics(self) -> Dict[str, Any]:
        """Get gossip protocol statistics."""
        with self._lock:
            return {
                **self.stats,
                'peer_count': len(self.peers),
                'cached_blocks': len(self._announced_blocks),
                'seen_messages': len(self._seen_messages),
            }

    def shutdown(self):
        """Shutdown gossip protocol."""
        logger.info("Shutting down gossip protocol...")
        self._running.clear()

        # Wait for threads
        if self._listener_thread and self._listener_thread.is_alive():
            self._listener_thread.join(timeout=2.0)
        if self._cleanup_thread and self._cleanup_thread.is_alive():
            self._cleanup_thread.join(timeout=2.0)

        logger.info("Gossip protocol shutdown complete")

    # ========================================================================
    # Private Methods
    # ========================================================================

    def _add_peer_from_address(self, address: str):
        """Add peer from address string (host:port)."""
        try:
            parts = address.split(':')
            host = parts[0]
            port = int(parts[1]) if len(parts) > 1 else GOSSIP_PORT

            peer_id = hashlib.sha256(address.encode()).hexdigest()[:16]
            with self._lock:
                self.peers[peer_id] = {
                    'address': (host, port),
                    'last_seen': datetime.now().timestamp(),
                    'is_bootstrap': True,
                }
            logger.debug(f"Added peer: {peer_id} ({host}:{port})")
        except Exception as e:
            logger.error(f"Failed to add peer {address}: {e}")

    def _gossip_to_peers(self, msg: GossipMessage):
        """Gossip message to FANOUT random peers."""
        import random

        with self._lock:
            # Select peers not in seen_by
            eligible_peers = [
                (peer_id, info)
                for peer_id, info in self.peers.items()
                if peer_id not in msg.seen_by
            ]

            # Select up to FANOUT peers
            targets = random.sample(
                eligible_peers,
                min(FANOUT, len(eligible_peers))
            )

        for peer_id, info in targets:
            self._send_to_peer(info['address'], msg)

    def _broadcast_to_all_peers(self, msg: GossipMessage):
        """Broadcast message to all peers (for checkpoints)."""
        with self._lock:
            targets = list(self.peers.items())

        for peer_id, info in targets:
            self._send_to_peer(info['address'], msg)

    def _send_to_peer(self, address: Tuple[str, int], msg: GossipMessage):
        """Send message to a specific peer."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1.0)
                sock.sendto(msg.to_bytes(mesh_key=self._mesh_key), address)
                self.stats['messages_sent'] += 1
        except Exception as e:
            logger.debug(f"Failed to send to {address}: {e}")

    def _listen_loop(self):
        """Listen for incoming gossip messages."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('0.0.0.0', GOSSIP_PORT))
            sock.settimeout(1.0)

            while self._running.is_set():
                try:
                    data, addr = sock.recvfrom(65535)
                    self._handle_message(data, addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error receiving message: {e}")

        except Exception as e:
            logger.error(f"Listener error: {e}")
        finally:
            sock.close()

    def _is_rate_limited(self, addr: Tuple[str, int]) -> bool:
        """Check if a peer has exceeded the message rate limit."""
        addr_key = f"{addr[0]}:{addr[1]}"
        now = _time.monotonic()
        cutoff = now - RATE_LIMIT_WINDOW

        # Prune old entries
        times = self._peer_msg_times[addr_key]
        self._peer_msg_times[addr_key] = [t for t in times if t > cutoff]

        if len(self._peer_msg_times[addr_key]) >= RATE_LIMIT_MAX:
            return True

        self._peer_msg_times[addr_key].append(now)
        return False

    def _handle_message(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming gossip message."""
        try:
            # Message size validation
            if len(data) > MAX_MESSAGE_SIZE:
                logger.warning("Oversized gossip message from %s (%d bytes)", addr, len(data))
                return

            # Per-peer rate limiting
            if self._is_rate_limited(addr):
                logger.warning("Rate-limited gossip from %s", addr)
                return

            msg = GossipMessage.from_bytes(data, mesh_key=self._mesh_key)
            self.stats['messages_received'] += 1

            # Reject messages with stale timestamps (>5 min old)
            msg_age = abs(datetime.now().timestamp() - msg.timestamp)
            if msg_age > ANNOUNCEMENT_TTL_SECONDS:
                logger.debug("Rejecting stale gossip message (age: %.0fs)", msg_age)
                return

            # Deduplication
            msg_hash = hashlib.sha256(data).hexdigest()[:32]
            with self._lock:
                if msg_hash in self._seen_messages:
                    return
                self._seen_messages.add(msg_hash)

            # Update peer info (only for known or bootstrap peers when mesh_key is set)
            peer_id = hashlib.sha256(f"{addr[0]}:{addr[1]}".encode()).hexdigest()[:16]
            with self._lock:
                if peer_id not in self.peers:
                    if self._mesh_key:
                        # With auth enabled, only add peers that pass HMAC
                        # (message already verified above)
                        if len(self.peers) >= MAX_PEERS:
                            logger.debug("Max peers reached, ignoring new peer %s", addr)
                            return
                    self.peers[peer_id] = {'address': addr, 'is_bootstrap': False}
                self.peers[peer_id]['last_seen'] = datetime.now().timestamp()

            # Handle by type
            if msg.msg_type == 'announce':
                self._handle_announce(msg)
            elif msg.msg_type == 'fetch_request':
                self._handle_fetch_request(msg, addr)
            elif msg.msg_type == 'fetch_response':
                self._handle_fetch_response(msg)
            elif msg.msg_type == 'checkpoint':
                self._handle_checkpoint(msg)

        except Exception as e:
            logger.error(f"Error handling message: {e}")

    def _handle_announce(self, msg: GossipMessage):
        """Handle block announcement."""
        block_id = msg.payload.get('block_id')
        microblock = msg.payload.get('microblock')

        if not block_id or not microblock:
            return

        # Store locally
        with self._lock:
            if block_id not in self._announced_blocks:
                self._announced_blocks[block_id] = (microblock, datetime.now().timestamp())

        # Invoke callbacks
        for callback in self._on_block_announced:
            try:
                callback(block_id, microblock)
            except Exception as e:
                logger.error(f"Announce callback error: {e}")

        # Re-gossip if hop count allows
        if msg.hop_count < MAX_HOP_COUNT:
            msg.hop_count += 1
            msg.seen_by.add(self.node_id)
            self._gossip_to_peers(msg)

    def _handle_fetch_request(self, msg: GossipMessage, addr: Tuple[str, int]):
        """Handle block fetch request."""
        block_id = msg.payload.get('block_id')
        if not block_id:
            return

        with self._lock:
            if block_id in self._announced_blocks:
                microblock, _ = self._announced_blocks[block_id]

                # Send response
                response = GossipMessage(
                    msg_type='fetch_response',
                    source_node=self.node_id,
                    payload={
                        'block_id': block_id,
                        'microblock': microblock,
                        'requesting_node': msg.source_node,
                    },
                )
                self._send_to_peer(addr, response)

    def _handle_fetch_response(self, msg: GossipMessage):
        """Handle block fetch response."""
        block_id = msg.payload.get('block_id')
        microblock = msg.payload.get('microblock')
        requesting_node = msg.payload.get('requesting_node')

        if requesting_node != self.node_id:
            return  # Not for us

        with self._lock:
            if block_id in self._pending_fetches:
                self._fetch_results[block_id] = microblock
                self._pending_fetches[block_id].set()

    def _handle_checkpoint(self, msg: GossipMessage):
        """Handle checkpoint broadcast."""
        checkpoint = msg.payload.get('checkpoint')
        if not checkpoint:
            return

        # Invoke callbacks
        for callback in self._on_checkpoint_received:
            try:
                callback(checkpoint)
            except Exception as e:
                logger.error(f"Checkpoint callback error: {e}")

        # Re-gossip checkpoints with lower hop limit (priority messages)
        if msg.hop_count < MAX_HOP_COUNT // 2:
            msg.hop_count += 1
            msg.seen_by.add(self.node_id)
            self._gossip_to_peers(msg)

    def _cleanup_loop(self):
        """Periodically clean up stale data."""
        import time

        while self._running.is_set():
            try:
                time.sleep(60)  # Run every minute

                now = datetime.now().timestamp()
                cutoff = now - ANNOUNCEMENT_TTL_SECONDS

                with self._lock:
                    # Clean old announcements
                    old_blocks = [
                        block_id
                        for block_id, (_, ts) in self._announced_blocks.items()
                        if ts < cutoff
                    ]
                    for block_id in old_blocks:
                        del self._announced_blocks[block_id]

                    # Clean stale peers (no activity in 5 minutes)
                    peer_cutoff = now - 300
                    stale_peers = [
                        peer_id
                        for peer_id, info in self.peers.items()
                        if info.get('last_seen', 0) < peer_cutoff and not info.get('is_bootstrap')
                    ]
                    for peer_id in stale_peers:
                        del self.peers[peer_id]

                    # Limit seen_messages size
                    if len(self._seen_messages) > 10000:
                        # Keep only recent half
                        self._seen_messages = set(list(self._seen_messages)[5000:])

                if old_blocks or stale_peers:
                    logger.debug(
                        f"Cleanup: removed {len(old_blocks)} blocks, {len(stale_peers)} stale peers"
                    )

            except Exception as e:
                logger.error(f"Cleanup error: {e}")
