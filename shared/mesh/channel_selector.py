"""
Channel Selector - Intelligent Channel Selection Using Neuro Weights

Uses neural resonance state to make unpredictable channel selection
decisions that an adversary cannot anticipate, while ensuring both
endpoints deterministically arrive at the same choice.

Selection Strategies:
- ENTROPY_WEIGHTED: Use weight state entropy to select channel
- ROUND_ROBIN: Simple rotation with neuro seeding
- LATENCY_OPTIMIZED: Choose fastest channel
- STEALTH_FIRST: Prioritize hard-to-block channels
- ADAPTIVE: ML-based selection from historical patterns
"""

import hashlib
import struct
import time
import threading
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from collections import deque

from .port_manager import PortConfig, TransportMode
from .neuro_encoder import NeuroResonanceEncoder, WeightFingerprint


class SelectionStrategy(Enum):
    """Channel selection strategies."""

    # Use weight state entropy to deterministically select
    ENTROPY_WEIGHTED = auto()

    # Simple rotation seeded by weight state
    ROUND_ROBIN = auto()

    # Choose fastest responding channel
    LATENCY_OPTIMIZED = auto()

    # Prioritize stealth channels (443, 853)
    STEALTH_FIRST = auto()

    # Adaptive based on success history
    ADAPTIVE = auto()

    # Emergency mode - try all channels
    EMERGENCY = auto()


@dataclass
class ChannelScore:
    """Score for a channel option."""

    port_config: PortConfig
    score: float  # 0.0 to 1.0, higher is better

    # Component scores
    latency_score: float = 0.0
    success_score: float = 0.0
    stealth_score: float = 0.0
    entropy_score: float = 0.0

    # Metadata
    last_used: float = 0.0
    selection_count: int = 0


class ChannelSelector:
    """
    Intelligent channel selector using neural resonance state.

    The key insight is that both endpoints share the same neural
    weight state (through resonance), so they can independently
    compute the same channel selection without communication.

    This makes channel hopping unpredictable to adversaries but
    deterministic between legitimate endpoints.
    """

    # Score weights for adaptive selection
    LATENCY_WEIGHT = 0.25
    SUCCESS_WEIGHT = 0.35
    STEALTH_WEIGHT = 0.20
    ENTROPY_WEIGHT = 0.20

    # Stealth scores by transport mode
    # Higher = more stealthy (harder to detect/block)
    STEALTH_SCORES = {
        # Primary modes - no obfuscation, easily fingerprinted
        TransportMode.PRIMARY_UDP: 0.2,
        TransportMode.PRIMARY_TCP: 0.2,

        # 443 stealth modes - excellent cover
        TransportMode.QUIC_STEALTH: 0.95,   # QUIC is encrypted, very common (HTTP/3)
        TransportMode.TLS_WRAPPED: 0.85,    # Blends with HTTPS traffic

        # 853 stealth modes - DNS privacy cover
        TransportMode.DOQ_STEALTH: 0.9,     # DoQ is newer but encrypted
        TransportMode.DOT_STEALTH: 0.85,    # DoT widely used for privacy

        # Fallback modes
        TransportMode.WEBSOCKET: 0.7,       # Common but can be fingerprinted
        TransportMode.ICMP_TUNNEL: 0.3,     # Unusual, often blocked
    }

    def __init__(
        self,
        encoder: NeuroResonanceEncoder,
        channels: List[PortConfig],
        strategy: SelectionStrategy = SelectionStrategy.ADAPTIVE,
    ):
        """
        Initialize channel selector.

        Args:
            encoder: Neuro resonance encoder for entropy source
            channels: Available channel configurations
            strategy: Selection strategy to use
        """
        self.encoder = encoder
        self.channels = channels
        self.strategy = strategy

        # Channel scores
        self._scores: Dict[int, ChannelScore] = {
            ch.port: ChannelScore(port_config=ch, score=0.5)
            for ch in channels
        }

        # Selection history for adaptive learning
        self._history: deque = deque(maxlen=1000)

        # Last selection for round-robin
        self._last_index = 0

        # Threading
        self._lock = threading.RLock()

    def select_channel(
        self,
        epoch: Optional[int] = None,
        exclude_ports: Optional[List[int]] = None,
    ) -> Optional[PortConfig]:
        """
        Select best channel based on strategy.

        Args:
            epoch: Optional epoch override for deterministic selection
            exclude_ports: Ports to exclude from selection

        Returns:
            Selected channel configuration or None
        """
        with self._lock:
            available = [
                ch for ch in self.channels
                if exclude_ports is None or ch.port not in exclude_ports
            ]

            if not available:
                return None

            if self.strategy == SelectionStrategy.ENTROPY_WEIGHTED:
                return self._select_entropy_weighted(available, epoch)
            elif self.strategy == SelectionStrategy.ROUND_ROBIN:
                return self._select_round_robin(available, epoch)
            elif self.strategy == SelectionStrategy.LATENCY_OPTIMIZED:
                return self._select_latency_optimized(available)
            elif self.strategy == SelectionStrategy.STEALTH_FIRST:
                return self._select_stealth_first(available)
            elif self.strategy == SelectionStrategy.ADAPTIVE:
                return self._select_adaptive(available, epoch)
            elif self.strategy == SelectionStrategy.EMERGENCY:
                return self._select_emergency(available)
            else:
                return available[0]

    def _select_entropy_weighted(
        self,
        channels: List[PortConfig],
        epoch: Optional[int] = None,
    ) -> PortConfig:
        """
        Select channel using weight state entropy.

        The selection is deterministic given the same weight state,
        so both endpoints will independently choose the same channel.
        """
        # Get weight fingerprint
        fp = self.encoder.get_weight_fingerprint()

        # Use epoch from fingerprint if not provided
        if epoch is None:
            epoch = fp.epoch

        # Create deterministic seed from weight state + epoch
        seed_input = fp.fingerprint + struct.pack('>I', epoch)
        seed_hash = hashlib.sha256(seed_input).digest()

        # Extract index from seed
        seed_value = struct.unpack('>Q', seed_hash[:8])[0]
        index = seed_value % len(channels)

        selected = channels[index]
        self._record_selection(selected.port, 'entropy_weighted')

        return selected

    def _select_round_robin(
        self,
        channels: List[PortConfig],
        epoch: Optional[int] = None,
    ) -> PortConfig:
        """
        Round-robin selection with neuro seeding.

        Uses weight state to determine starting point, then rotates.
        """
        # Seed starting point from weight state
        fp = self.encoder.get_weight_fingerprint()

        if epoch is not None:
            # Epoch-based selection for determinism
            seed = hashlib.sha256(
                fp.fingerprint + struct.pack('>I', epoch)
            ).digest()
            start_index = struct.unpack('>I', seed[:4])[0] % len(channels)
            index = (start_index + self._last_index) % len(channels)
        else:
            # Simple rotation
            index = (self._last_index + 1) % len(channels)

        self._last_index = index
        selected = channels[index]
        self._record_selection(selected.port, 'round_robin')

        return selected

    def _select_latency_optimized(
        self,
        channels: List[PortConfig],
    ) -> PortConfig:
        """Select channel with lowest latency."""
        # Score by latency
        scored = []
        for ch in channels:
            score = self._scores.get(ch.port)
            if score:
                latency = ch.avg_latency_ms
                # Normalize: 0ms = 1.0, 1000ms = 0.0
                lat_score = max(0, 1.0 - latency / 1000)
                scored.append((ch, lat_score))
            else:
                scored.append((ch, 0.5))  # Unknown

        # Sort by score descending
        scored.sort(key=lambda x: x[1], reverse=True)
        selected = scored[0][0]
        self._record_selection(selected.port, 'latency_optimized')

        return selected

    def _select_stealth_first(
        self,
        channels: List[PortConfig],
    ) -> PortConfig:
        """Prioritize stealth channels."""
        # Score by stealth capability
        scored = []
        for ch in channels:
            stealth = self.STEALTH_SCORES.get(ch.mode, 0.5)
            # Also consider success rate
            success = ch.success_rate / 100.0 if ch.success_rate > 0 else 0.5
            combined = stealth * 0.7 + success * 0.3
            scored.append((ch, combined))

        scored.sort(key=lambda x: x[1], reverse=True)
        selected = scored[0][0]
        self._record_selection(selected.port, 'stealth_first')

        return selected

    def _select_adaptive(
        self,
        channels: List[PortConfig],
        epoch: Optional[int] = None,
    ) -> PortConfig:
        """
        Adaptive selection based on historical performance.

        Combines multiple factors with neuro-seeded randomization.
        """
        # Calculate scores for each channel
        scored_channels = []

        for ch in channels:
            score = self._calculate_adaptive_score(ch)
            scored_channels.append((ch, score))

        # Sort by score
        scored_channels.sort(key=lambda x: x[1], reverse=True)

        # Use neuro entropy to add controlled randomization
        # This prevents attackers from predicting selection
        fp = self.encoder.get_weight_fingerprint()
        seed = hashlib.sha256(
            fp.fingerprint +
            struct.pack('>I', epoch or fp.epoch) +
            struct.pack('>Q', int(time.time()))
        ).digest()

        # With 70% probability, choose best; 30% choose randomly from top 3
        random_val = struct.unpack('>H', seed[:2])[0] / 65535.0

        if random_val < 0.7 or len(scored_channels) == 1:
            selected = scored_channels[0][0]
        else:
            # Random from top 3 (or fewer if not enough channels)
            top_n = min(3, len(scored_channels))
            random_idx = struct.unpack('>H', seed[2:4])[0] % top_n
            selected = scored_channels[random_idx][0]

        self._record_selection(selected.port, 'adaptive')
        return selected

    def _select_emergency(
        self,
        channels: List[PortConfig],
    ) -> PortConfig:
        """
        Emergency selection - return first non-blocked channel.

        Used when normal selection fails.
        """
        # Sort by priority
        sorted_channels = sorted(channels, key=lambda c: c.priority)

        for ch in sorted_channels:
            if ch.failure_count < 3:
                self._record_selection(ch.port, 'emergency')
                return ch

        # All blocked - return stealth option
        stealth = [c for c in sorted_channels if c.mode in (
            TransportMode.DOT_STEALTH,
            TransportMode.TLS_WRAPPED,
        )]

        if stealth:
            selected = stealth[0]
        else:
            selected = sorted_channels[0]

        self._record_selection(selected.port, 'emergency_fallback')
        return selected

    def _calculate_adaptive_score(self, channel: PortConfig) -> float:
        """Calculate adaptive score for a channel."""
        # Latency score: 0ms = 1.0, 1000ms = 0.0
        latency = channel.avg_latency_ms
        if latency == float('inf'):
            lat_score = 0.3  # Unknown
        else:
            lat_score = max(0, 1.0 - latency / 1000)

        # Success rate score
        success_score = channel.success_rate / 100.0

        # Stealth score
        stealth_score = self.STEALTH_SCORES.get(channel.mode, 0.5)

        # Entropy score from usage patterns
        # Less used channels get bonus (unpredictability)
        usage = self._get_usage_frequency(channel.port)
        entropy_score = 1.0 - min(1.0, usage * 2)  # Penalize heavily used

        # Combine scores
        total = (
            lat_score * self.LATENCY_WEIGHT +
            success_score * self.SUCCESS_WEIGHT +
            stealth_score * self.STEALTH_WEIGHT +
            entropy_score * self.ENTROPY_WEIGHT
        )

        # Update stored score
        if channel.port in self._scores:
            self._scores[channel.port].score = total
            self._scores[channel.port].latency_score = lat_score
            self._scores[channel.port].success_score = success_score
            self._scores[channel.port].stealth_score = stealth_score
            self._scores[channel.port].entropy_score = entropy_score

        return total

    def _get_usage_frequency(self, port: int) -> float:
        """Get usage frequency for a port (0.0 to 1.0)."""
        if not self._history:
            return 0.0

        recent = list(self._history)[-100:]  # Last 100 selections
        port_count = sum(1 for p, _, _ in recent if p == port)
        return port_count / len(recent)

    def _record_selection(self, port: int, method: str) -> None:
        """Record channel selection for learning."""
        self._history.append((port, time.time(), method))

        if port in self._scores:
            self._scores[port].last_used = time.time()
            self._scores[port].selection_count += 1

    def record_outcome(
        self,
        port: int,
        success: bool,
        latency_ms: float = 0.0,
    ) -> None:
        """
        Record outcome of using a channel.

        Used for adaptive learning.
        """
        with self._lock:
            if port in self._scores:
                score = self._scores[port]
                # Exponential moving average for success rate
                alpha = 0.1
                current_success = 1.0 if success else 0.0
                score.success_score = (
                    alpha * current_success +
                    (1 - alpha) * score.success_score
                )

    def get_deterministic_sequence(
        self,
        start_epoch: int,
        count: int,
    ) -> List[PortConfig]:
        """
        Get deterministic channel sequence for epoch range.

        Both endpoints will compute the same sequence.
        """
        sequence = []
        for epoch in range(start_epoch, start_epoch + count):
            channel = self._select_entropy_weighted(self.channels, epoch)
            sequence.append(channel)
        return sequence

    def synchronize_with_peer(
        self,
        peer_fingerprint: WeightFingerprint,
    ) -> bool:
        """
        Verify we're synchronized with peer.

        Checks that we have the same weight state for
        deterministic channel selection.
        """
        local_fp = self.encoder.get_weight_fingerprint()

        # Compare epochs
        epoch_diff = abs(local_fp.epoch - peer_fingerprint.epoch)
        if epoch_diff > 2:
            return False  # Too far apart

        # Compare fingerprints (allow small drift)
        matching_bytes = sum(
            1 for a, b in zip(local_fp.fingerprint, peer_fingerprint.fingerprint)
            if a == b
        )
        match_ratio = matching_bytes / len(local_fp.fingerprint)

        return match_ratio > 0.95  # 95% match required

    def get_scores(self) -> Dict[int, Dict[str, Any]]:
        """Get current channel scores."""
        with self._lock:
            return {
                port: {
                    'score': score.score,
                    'latency': score.latency_score,
                    'success': score.success_score,
                    'stealth': score.stealth_score,
                    'entropy': score.entropy_score,
                    'selection_count': score.selection_count,
                    'mode': score.port_config.mode.name,
                }
                for port, score in self._scores.items()
            }


class ChannelHopper:
    """
    Automatic channel hopping based on neuro resonance.

    Periodically switches channels using the shared weight state
    to ensure both endpoints hop in sync without communication.
    """

    # Hopping intervals (seconds)
    HOP_INTERVAL_MIN = 60      # 1 minute minimum
    HOP_INTERVAL_MAX = 600     # 10 minutes maximum

    def __init__(
        self,
        selector: ChannelSelector,
        encoder: NeuroResonanceEncoder,
    ):
        """Initialize channel hopper."""
        self.selector = selector
        self.encoder = encoder

        self._current_channel: Optional[PortConfig] = None
        self._hop_epoch = 0
        self._next_hop_time = 0.0

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Callbacks
        self._on_hop: List[Any] = []

    def start(self) -> None:
        """Start automatic channel hopping."""
        if self._running:
            return

        self._running = True
        self._schedule_next_hop()

        self._thread = threading.Thread(
            target=self._hop_loop,
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop automatic channel hopping."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)

    def get_current_channel(self) -> Optional[PortConfig]:
        """Get current channel."""
        with self._lock:
            return self._current_channel

    def force_hop(self) -> Optional[PortConfig]:
        """Force immediate channel hop."""
        with self._lock:
            self._hop_epoch += 1
            new_channel = self.selector.select_channel(epoch=self._hop_epoch)

            if new_channel and new_channel != self._current_channel:
                old_channel = self._current_channel
                self._current_channel = new_channel
                self._notify_hop(old_channel, new_channel)

            self._schedule_next_hop()
            return self._current_channel

    def _hop_loop(self) -> None:
        """Background hop loop."""
        while self._running:
            now = time.time()
            if now >= self._next_hop_time:
                self.force_hop()

            time.sleep(1.0)

    def _schedule_next_hop(self) -> None:
        """Schedule next channel hop."""
        # Use weight state to determine hop interval
        fp = self.encoder.get_weight_fingerprint()
        seed = hashlib.sha256(
            fp.fingerprint + struct.pack('>I', self._hop_epoch)
        ).digest()

        # Random interval within range
        random_val = struct.unpack('>H', seed[:2])[0] / 65535.0
        interval = (
            self.HOP_INTERVAL_MIN +
            random_val * (self.HOP_INTERVAL_MAX - self.HOP_INTERVAL_MIN)
        )

        self._next_hop_time = time.time() + interval

    def _notify_hop(
        self,
        old: Optional[PortConfig],
        new: PortConfig,
    ) -> None:
        """Notify listeners of channel hop."""
        for callback in self._on_hop:
            try:
                callback(old, new)
            except Exception:
                pass

    def on_hop(self, callback) -> None:
        """Register channel hop callback."""
        self._on_hop.append(callback)
