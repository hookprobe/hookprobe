"""
Signature Matcher - High-Performance Pattern Matching Engine

Optimized for sub-millisecond detection on resource-constrained devices.
Uses bloom filters for fast negative lookups and parallel pattern matching.

Performance targets:
- Lookup: <0.1ms average
- Memory: <50KB for matcher state
- CPU: Minimal overhead during idle

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import time
import hashlib
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Set, Any, Callable
from collections import defaultdict, deque
import threading

from .database import (
    SignatureDatabase, ThreatSignature, FeaturePattern,
    OSILayer, Severity, AttackCategory
)


@dataclass
class MatchResult:
    """
    Result of signature matching against traffic features.
    """
    matched: bool                          # True if signature matched
    signature: Optional[ThreatSignature]   # Matched signature (if any)
    confidence: float                      # Match confidence (0.0-1.0)
    matched_patterns: List[str]            # Which patterns matched
    match_time_us: int                     # Match time in microseconds
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            'matched': self.matched,
            'signature_id': self.signature.sig_id if self.signature else None,
            'signature_name': self.signature.name if self.signature else None,
            'confidence': self.confidence,
            'matched_patterns': self.matched_patterns,
            'match_time_us': self.match_time_us,
            'timestamp': self.timestamp.isoformat(),
        }


@dataclass
class DetectionEvent:
    """
    A detected threat event from signature matching.
    """
    signature: ThreatSignature
    confidence: float
    source_ip: Optional[str]
    source_mac: Optional[str]
    destination_ip: Optional[str]
    destination_port: Optional[int]
    protocol: Optional[str]
    features: Dict[str, Any]               # Features that triggered match
    timestamp: datetime = field(default_factory=datetime.now)
    auto_blocked: bool = False

    def to_dict(self) -> dict:
        return {
            'signature_id': self.signature.sig_id,
            'signature_name': self.signature.name,
            'layer': self.signature.layer.name,
            'severity': self.signature.severity.name,
            'category': self.signature.category.value,
            'confidence': self.confidence,
            'source_ip': self.source_ip,
            'source_mac': self.source_mac,
            'destination_ip': self.destination_ip,
            'destination_port': self.destination_port,
            'protocol': self.protocol,
            'mitre_technique': self.signature.mitre_technique,
            'recommended_action': self.signature.recommended_action,
            'auto_blocked': self.auto_blocked,
            'timestamp': self.timestamp.isoformat(),
        }


class BloomFilter:
    """
    Simple but effective bloom filter for fast negative lookups.

    Memory efficient: ~1KB per 1000 items with 1% false positive rate.
    """

    def __init__(self, size: int = 10000, hash_count: int = 7):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = [False] * size

    def _hashes(self, item: str) -> List[int]:
        """Generate multiple hash values for an item."""
        hashes = []
        for i in range(self.hash_count):
            h = hashlib.md5(f"{item}:{i}".encode(), usedforsecurity=False).hexdigest()
            hashes.append(int(h[:8], 16) % self.size)
        return hashes

    def add(self, item: str):
        """Add an item to the filter."""
        for h in self._hashes(item):
            self.bit_array[h] = True

    def contains(self, item: str) -> bool:
        """Check if item might be in the filter (may have false positives)."""
        return all(self.bit_array[h] for h in self._hashes(item))


class SignatureMatcher:
    """
    High-performance signature matching engine.

    Features:
    - Bloom filter for fast negative lookups
    - Layer-based pre-filtering
    - Protocol-based pre-filtering
    - Fast check expressions for early rejection
    - Parallel pattern matching
    - Match caching for repeated queries
    """

    def __init__(
        self,
        database: Optional[SignatureDatabase] = None,
        cache_size: int = 1000,
        enable_fast_check: bool = True
    ):
        self.db = database or SignatureDatabase()
        self.cache_size = cache_size
        self.enable_fast_check = enable_fast_check

        # Bloom filter for signature presence
        self._bloom = BloomFilter(size=10000)

        # Match cache (LRU-style)
        self._cache: Dict[str, List[MatchResult]] = {}
        self._cache_order: deque = deque()
        self._cache_lock = threading.Lock()

        # Pre-compiled fast checks
        self._fast_checks: Dict[str, Callable] = {}

        # Detection callbacks
        self._callbacks: List[Callable[[DetectionEvent], None]] = []

        # Statistics
        self.stats = {
            'total_matches': 0,
            'cache_hits': 0,
            'bloom_rejections': 0,
            'fast_check_rejections': 0,
            'full_pattern_checks': 0,
            'avg_match_time_us': 0.0,
            'detections': defaultdict(int),  # sig_id -> count
        }

        # Initialize bloom filter and fast checks
        self._initialize()

    def _initialize(self):
        """Initialize bloom filter and fast check functions."""
        for sig in self.db.get_all():
            # Add to bloom filter
            self._bloom.add(sig.sig_id)
            self._bloom.add(sig.name.lower())
            self._bloom.add(sig.layer.name)

            # Compile fast check if available
            if sig.fast_check:
                self._compile_fast_check(sig)

    def _compile_fast_check(self, sig: ThreatSignature):
        """Compile fast check expression to callable."""
        if not sig.fast_check:
            return

        try:
            # Parse simple expressions like "syn_ratio > 0.5"
            expr = sig.fast_check

            # Create a safe evaluator
            def evaluator(features: Dict[str, Any]) -> bool:
                try:
                    # Replace feature names with values
                    local_expr = expr
                    for name, value in features.items():
                        if name in local_expr:
                            if isinstance(value, bool):
                                local_expr = local_expr.replace(name, str(value))
                            elif isinstance(value, (int, float)):
                                local_expr = local_expr.replace(name, str(value))

                    # Simple expression evaluation (safe subset)
                    # Only allows: numbers, comparisons, and/or
                    if any(c in local_expr for c in ['import', 'exec', 'eval', '__']):
                        return True  # Don't reject on suspicious expressions

                    # Use simple parsing for safety
                    return self._safe_eval(local_expr, features)
                except Exception:
                    return True  # Don't reject on error

            self._fast_checks[sig.sig_id] = evaluator

        except Exception:
            pass

    def _safe_eval(self, expr: str, features: Dict[str, Any]) -> bool:
        """Safely evaluate simple comparison expressions."""
        try:
            # Handle common patterns
            for op in ['>=', '<=', '==', '!=', '>', '<']:
                if op in expr:
                    parts = expr.split(op)
                    if len(parts) == 2:
                        left = parts[0].strip()
                        right = parts[1].strip()

                        # Get left value
                        left_val = features.get(left, left)
                        if isinstance(left_val, str):
                            try:
                                left_val = float(left_val)
                            except ValueError:
                                pass

                        # Get right value
                        try:
                            right_val = float(right)
                        except ValueError:
                            right_val = features.get(right, right)

                        # Compare
                        if op == '>=':
                            return left_val >= right_val
                        elif op == '<=':
                            return left_val <= right_val
                        elif op == '==':
                            return left_val == right_val
                        elif op == '!=':
                            return left_val != right_val
                        elif op == '>':
                            return left_val > right_val
                        elif op == '<':
                            return left_val < right_val
        except Exception:
            pass

        return True  # Default to not rejecting

    def register_callback(self, callback: Callable[[DetectionEvent], None]):
        """Register a callback for detection events."""
        self._callbacks.append(callback)

    def match_features(
        self,
        features: Dict[str, Any],
        layer: Optional[OSILayer] = None,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
        source_ip: Optional[str] = None,
        source_mac: Optional[str] = None,
        destination_ip: Optional[str] = None
    ) -> List[MatchResult]:
        """
        Match features against all applicable signatures.

        Args:
            features: Dictionary of network/traffic features
            layer: Optional OSI layer to filter signatures
            protocol: Optional protocol to filter (tcp, udp, icmp)
            port: Optional port number to filter
            source_ip: Source IP for detection event
            source_mac: Source MAC for detection event
            destination_ip: Destination IP for detection event

        Returns:
            List of MatchResults for all matching signatures
        """
        start_time = time.perf_counter_ns()
        results: List[MatchResult] = []

        # Get cache key
        cache_key = self._get_cache_key(features, layer, protocol, port)

        # Check cache
        with self._cache_lock:
            if cache_key in self._cache:
                self.stats['cache_hits'] += 1
                return self._cache[cache_key]

        # Get applicable signatures
        signatures = self._get_applicable_signatures(layer, protocol, port)

        for sig in signatures:
            if not sig.enabled:
                continue

            # Fast check (if available and enabled)
            if self.enable_fast_check and sig.sig_id in self._fast_checks:
                if not self._fast_checks[sig.sig_id](features):
                    self.stats['fast_check_rejections'] += 1
                    continue

            # Full pattern matching
            self.stats['full_pattern_checks'] += 1
            result = self._match_signature(sig, features)

            if result.matched:
                results.append(result)
                self.stats['total_matches'] += 1
                self.stats['detections'][sig.sig_id] += 1

                # Create detection event
                event = DetectionEvent(
                    signature=sig,
                    confidence=result.confidence,
                    source_ip=source_ip,
                    source_mac=source_mac,
                    destination_ip=destination_ip,
                    destination_port=port,
                    protocol=protocol,
                    features={p: features.get(p) for p in result.matched_patterns},
                    auto_blocked=sig.auto_block
                )

                # Notify callbacks
                for callback in self._callbacks:
                    try:
                        callback(event)
                    except Exception:
                        pass

        # Calculate match time
        match_time_us = (time.perf_counter_ns() - start_time) // 1000

        # Update average
        total = self.stats['full_pattern_checks']
        if total > 0:
            self.stats['avg_match_time_us'] = (
                (self.stats['avg_match_time_us'] * (total - 1) + match_time_us) / total
            )

        # Cache all results
        if results:
            self._add_to_cache(cache_key, results)

        return results

    def match_single_signature(
        self,
        sig_id: str,
        features: Dict[str, Any]
    ) -> MatchResult:
        """
        Match features against a single specific signature.

        Args:
            sig_id: Signature ID to match
            features: Dictionary of network/traffic features

        Returns:
            MatchResult
        """
        start_time = time.perf_counter_ns()

        sig = self.db.get_signature(sig_id)
        if not sig:
            return MatchResult(
                matched=False,
                signature=None,
                confidence=0.0,
                matched_patterns=[],
                match_time_us=0
            )

        result = self._match_signature(sig, features)
        result.match_time_us = (time.perf_counter_ns() - start_time) // 1000

        return result

    def _match_signature(
        self,
        sig: ThreatSignature,
        features: Dict[str, Any]
    ) -> MatchResult:
        """
        Match features against a single signature's patterns.
        """
        if not sig.patterns:
            return MatchResult(
                matched=False,
                signature=sig,
                confidence=0.0,
                matched_patterns=[],
                match_time_us=0
            )

        matched_patterns = []
        total_weight = 0.0
        matched_weight = 0.0

        for pattern in sig.patterns:
            total_weight += pattern.weight

            actual_value = features.get(pattern.feature_name)
            if actual_value is not None and pattern.matches(actual_value):
                matched_patterns.append(pattern.feature_name)
                matched_weight += pattern.weight

        # Calculate confidence
        if total_weight > 0:
            confidence = matched_weight / total_weight
        else:
            confidence = 0.0

        # Check threshold
        matched = confidence >= sig.match_threshold

        return MatchResult(
            matched=matched,
            signature=sig if matched else None,
            confidence=confidence,
            matched_patterns=matched_patterns,
            match_time_us=0
        )

    def _get_applicable_signatures(
        self,
        layer: Optional[OSILayer],
        protocol: Optional[str],
        port: Optional[int]
    ) -> List[ThreatSignature]:
        """Get signatures that could apply to the given context.

        Protocol-agnostic signatures (empty protocols list) are always
        included regardless of the protocol/port filter. This prevents
        skipping signatures that apply to all protocols.
        """
        signatures: Set[str] = set()

        if layer:
            signatures.update(s.sig_id for s in self.db.get_by_layer(layer))
        else:
            signatures.update(self.db.signatures.keys())

        if protocol:
            # Include sigs matching the protocol + sigs with no protocol (agnostic)
            proto_sigs = set(s.sig_id for s in self.db.get_by_protocol(protocol))
            agnostic_sigs = set(
                sid for sid, sig in self.db.signatures.items()
                if not sig.protocols
            )
            signatures &= (proto_sigs | agnostic_sigs)

        if port:
            # Include sigs matching the port + sigs with no port filter (agnostic)
            port_sigs = set(s.sig_id for s in self.db.get_by_port(port))
            agnostic_sigs = set(
                sid for sid, sig in self.db.signatures.items()
                if not sig.ports
            )
            signatures &= (port_sigs | agnostic_sigs)

        return [self.db.signatures[sid] for sid in signatures]

    def _get_cache_key(
        self,
        features: Dict[str, Any],
        layer: Optional[OSILayer],
        protocol: Optional[str],
        port: Optional[int]
    ) -> str:
        """Generate cache key for features."""
        # Create a simple hash of feature values
        feature_str = str(sorted(features.items()))
        context_str = f"{layer}:{protocol}:{port}"
        return hashlib.md5(
            f"{feature_str}:{context_str}".encode(), usedforsecurity=False
        ).hexdigest()[:16]

    def _add_to_cache(self, key: str, results: List[MatchResult]):
        """Add results to cache with LRU eviction."""
        with self._cache_lock:
            if key in self._cache:
                return

            # Evict oldest if full
            if len(self._cache) >= self.cache_size:
                oldest = self._cache_order.popleft()
                del self._cache[oldest]

            self._cache[key] = list(results)
            self._cache_order.append(key)

    def clear_cache(self):
        """Clear the match cache."""
        with self._cache_lock:
            self._cache.clear()
            self._cache_order.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Get matcher statistics."""
        return {
            **self.stats,
            'cache_size': len(self._cache),
            'fast_checks_compiled': len(self._fast_checks),
            'top_detections': dict(
                sorted(self.stats['detections'].items(), key=lambda x: x[1], reverse=True)[:10]
            )
        }

    def reset_stats(self):
        """Reset statistics."""
        self.stats = {
            'total_matches': 0,
            'cache_hits': 0,
            'bloom_rejections': 0,
            'fast_check_rejections': 0,
            'full_pattern_checks': 0,
            'avg_match_time_us': 0.0,
            'detections': defaultdict(int),
        }


class QuickMatcher:
    """
    Ultra-lightweight matcher for real-time packet inspection.

    Designed for <0.01ms per packet with minimal memory footprint.
    Only checks critical signatures (auto_block=True).
    """

    def __init__(self, database: SignatureDatabase):
        self.db = database

        # Pre-compute critical checks by layer
        self.critical_checks: Dict[OSILayer, List[ThreatSignature]] = {
            layer: [] for layer in OSILayer
        }

        for sig in database.get_all():
            if sig.auto_block and sig.enabled:
                self.critical_checks[sig.layer].append(sig)

    def quick_check(
        self,
        layer: OSILayer,
        features: Dict[str, Any]
    ) -> Optional[ThreatSignature]:
        """
        Ultra-fast check for critical signatures.

        Returns first matching critical signature or None.
        """
        for sig in self.critical_checks.get(layer, []):
            if self._quick_match(sig, features):
                return sig
        return None

    def _quick_match(
        self,
        sig: ThreatSignature,
        features: Dict[str, Any]
    ) -> bool:
        """Quick pattern match (only checks first 2 patterns)."""
        patterns = sig.patterns[:2]  # Only check first 2 patterns for speed
        matches = 0

        for pattern in patterns:
            value = features.get(pattern.feature_name)
            if value is not None and pattern.matches(value):
                matches += 1

        return matches >= len(patterns) * 0.5
