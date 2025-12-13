"""
Signature Updater - Federated Threat Intelligence

Provides automatic signature updates through:
1. HookProbe mesh federated learning
2. Community threat feeds
3. Local learning from detection patterns

Privacy-preserving: Only shares anonymized attack patterns,
never raw traffic data. GDPR compliant.

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import json
import hashlib
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Any, Set
from collections import defaultdict
import urllib.request
import urllib.error

from .database import (
    SignatureDatabase, ThreatSignature, FeaturePattern,
    OSILayer, Severity, AttackCategory
)


@dataclass
class SignatureUpdate:
    """
    A signature update to share or receive.
    """
    action: str                            # 'add', 'update', 'disable', 'delete'
    signature: Optional[ThreatSignature]
    sig_id: str
    version: str
    source_node: str                       # Anonymized node ID
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    votes: int = 1                         # Community validation votes
    confidence: float = 0.5                # Update confidence

    def to_dict(self) -> dict:
        d = asdict(self)
        if self.signature:
            d['signature'] = self.signature.to_dict()
        return d

    @classmethod
    def from_dict(cls, d: dict) -> 'SignatureUpdate':
        d = d.copy()
        if d.get('signature'):
            d['signature'] = ThreatSignature.from_dict(d['signature'])
        return cls(**d)


@dataclass
class LearnedPattern:
    """
    A pattern learned from local detections.
    """
    feature_name: str
    operator: str
    value: Any
    occurrence_count: int = 0
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    associated_layer: Optional[OSILayer] = None
    associated_severity: Optional[Severity] = None

    def to_feature_pattern(self) -> FeaturePattern:
        return FeaturePattern(
            feature_name=self.feature_name,
            operator=self.operator,
            value=self.value,
            weight=min(2.0, 1.0 + self.occurrence_count * 0.1)
        )


class SignatureUpdater:
    """
    Manages signature updates from multiple sources:
    - HookProbe mesh (federated learning)
    - Community threat feeds
    - Local learning from detections

    Privacy-preserving design:
    - Never shares raw traffic or user data
    - Only shares anonymized attack patterns
    - Requires consensus before applying updates
    """

    # Official HookProbe threat feed (placeholder URL)
    OFFICIAL_FEED_URL = "https://threats.hookprobe.com/v1/signatures"

    # Community feeds
    COMMUNITY_FEEDS = [
        "https://raw.githubusercontent.com/hookprobe/threat-signatures/main/signatures.json",
    ]

    def __init__(
        self,
        database: SignatureDatabase,
        data_dir: str = "/opt/hookprobe/data/signatures",
        mesh_enabled: bool = True,
        community_feeds_enabled: bool = True,
        local_learning_enabled: bool = True,
        update_interval_hours: int = 24
    ):
        self.db = database
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.mesh_enabled = mesh_enabled
        self.community_feeds_enabled = community_feeds_enabled
        self.local_learning_enabled = local_learning_enabled
        self.update_interval = timedelta(hours=update_interval_hours)

        # Node identity (anonymized)
        self.node_id = self._generate_node_id()

        # Pending updates (require consensus)
        self.pending_updates: Dict[str, SignatureUpdate] = {}
        self.pending_lock = threading.Lock()

        # Local learning state
        self.learned_patterns: Dict[str, LearnedPattern] = {}
        self.detection_history: List[Dict[str, Any]] = []
        self.max_history = 10000

        # Statistics
        self.stats = {
            'updates_received': 0,
            'updates_applied': 0,
            'updates_rejected': 0,
            'patterns_learned': 0,
            'last_update_check': None,
            'last_feed_update': None,
            'mesh_peers_seen': 0,
        }

        # Background thread
        self._stop_event = threading.Event()
        self._update_thread: Optional[threading.Thread] = None

        # Load saved state
        self._load_state()

    def _generate_node_id(self) -> str:
        """Generate anonymized node ID (GDPR compliant)."""
        try:
            import socket
            hostname = socket.gethostname()
        except Exception:
            hostname = "unknown"

        # Hash for anonymization
        raw = f"{hostname}:{datetime.now().strftime('%Y%m')}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _load_state(self):
        """Load updater state from disk."""
        state_file = self.data_dir / "updater_state.json"
        if state_file.exists():
            try:
                with open(state_file) as f:
                    state = json.load(f)
                    self.stats.update(state.get('stats', {}))

                    # Load learned patterns
                    for name, data in state.get('learned_patterns', {}).items():
                        if isinstance(data.get('associated_layer'), str):
                            data['associated_layer'] = OSILayer[data['associated_layer']]
                        if isinstance(data.get('associated_severity'), str):
                            data['associated_severity'] = Severity[data['associated_severity']]
                        self.learned_patterns[name] = LearnedPattern(**data)

            except Exception as e:
                print(f"Warning: Failed to load updater state: {e}")

    def _save_state(self):
        """Save updater state to disk."""
        state_file = self.data_dir / "updater_state.json"
        try:
            learned = {}
            for name, pattern in self.learned_patterns.items():
                d = asdict(pattern)
                if d.get('associated_layer'):
                    d['associated_layer'] = d['associated_layer'].name
                if d.get('associated_severity'):
                    d['associated_severity'] = d['associated_severity'].name
                learned[name] = d

            with open(state_file, 'w') as f:
                json.dump({
                    'stats': self.stats,
                    'learned_patterns': learned,
                    'saved': datetime.now().isoformat()
                }, f, indent=2)
        except Exception as e:
            print(f"Warning: Failed to save updater state: {e}")

    def start_background_updates(self):
        """Start background update thread."""
        if self._update_thread and self._update_thread.is_alive():
            return

        self._stop_event.clear()
        self._update_thread = threading.Thread(
            target=self._background_update_loop,
            daemon=True,
            name="SignatureUpdater"
        )
        self._update_thread.start()

    def stop_background_updates(self):
        """Stop background update thread."""
        self._stop_event.set()
        if self._update_thread:
            self._update_thread.join(timeout=5)

    def _background_update_loop(self):
        """Background loop for periodic updates."""
        while not self._stop_event.wait(timeout=3600):  # Check every hour
            try:
                self.check_for_updates()
            except Exception as e:
                print(f"Warning: Signature update failed: {e}")

    def check_for_updates(self):
        """Check all sources for signature updates."""
        self.stats['last_update_check'] = datetime.now().isoformat()

        # Check community feeds
        if self.community_feeds_enabled:
            self._check_community_feeds()

        # Save state
        self._save_state()

    def _check_community_feeds(self):
        """Fetch updates from community feeds."""
        for feed_url in self.COMMUNITY_FEEDS:
            try:
                req = urllib.request.Request(
                    feed_url,
                    headers={'User-Agent': 'HookProbe-Guardian/5.0'}
                )
                with urllib.request.urlopen(req, timeout=30) as response:
                    data = json.loads(response.read().decode('utf-8'))

                    for sig_data in data.get('signatures', []):
                        try:
                            sig = ThreatSignature.from_dict(sig_data)
                            sig.source = "community"

                            # Apply if new or newer version
                            existing = self.db.get_signature(sig.sig_id)
                            if not existing or sig.version > existing.version:
                                self.db.add_signature(sig)
                                self.stats['updates_applied'] += 1

                        except Exception:
                            self.stats['updates_rejected'] += 1

                self.stats['last_feed_update'] = datetime.now().isoformat()

            except (urllib.error.URLError, json.JSONDecodeError, Exception) as e:
                print(f"Warning: Failed to fetch feed {feed_url}: {e}")

    def record_detection(
        self,
        features: Dict[str, Any],
        layer: OSILayer,
        severity: Severity,
        matched_sig_id: Optional[str] = None
    ):
        """
        Record a detection for local learning.

        This is the input to the local learning system.
        Patterns that appear frequently may become new signatures.
        """
        if not self.local_learning_enabled:
            return

        # Store in history
        self.detection_history.append({
            'timestamp': datetime.now().isoformat(),
            'features': features,
            'layer': layer.name,
            'severity': severity.name,
            'matched_sig': matched_sig_id
        })

        # Trim history
        if len(self.detection_history) > self.max_history:
            self.detection_history = self.detection_history[-self.max_history//2:]

        # Update learned patterns
        self._update_learned_patterns(features, layer, severity)

    def _update_learned_patterns(
        self,
        features: Dict[str, Any],
        layer: OSILayer,
        severity: Severity
    ):
        """Update learned patterns from detection features."""
        for name, value in features.items():
            if value is None:
                continue

            # Create pattern key
            key = f"{layer.name}:{name}"

            # Determine operator based on value type
            if isinstance(value, bool):
                operator = 'eq'
            elif isinstance(value, (int, float)):
                # For high values, use 'ge' (greater than or equal)
                operator = 'ge'
            else:
                operator = 'eq'

            if key in self.learned_patterns:
                pattern = self.learned_patterns[key]
                pattern.occurrence_count += 1
                pattern.last_seen = datetime.now().isoformat()
            else:
                self.learned_patterns[key] = LearnedPattern(
                    feature_name=name,
                    operator=operator,
                    value=value,
                    occurrence_count=1,
                    associated_layer=layer,
                    associated_severity=severity
                )
                self.stats['patterns_learned'] += 1

    def generate_learned_signature(
        self,
        min_occurrences: int = 10,
        layer: Optional[OSILayer] = None
    ) -> Optional[ThreatSignature]:
        """
        Generate a new signature from learned patterns.

        Only creates signatures from patterns seen multiple times.
        """
        # Filter patterns by occurrence count and layer
        eligible = []
        for pattern in self.learned_patterns.values():
            if pattern.occurrence_count >= min_occurrences:
                if layer is None or pattern.associated_layer == layer:
                    eligible.append(pattern)

        if len(eligible) < 2:
            return None

        # Group by layer
        by_layer: Dict[OSILayer, List[LearnedPattern]] = defaultdict(list)
        for p in eligible:
            if p.associated_layer:
                by_layer[p.associated_layer].append(p)

        # Generate signature for most common layer
        if not by_layer:
            return None

        target_layer = max(by_layer.keys(), key=lambda l: len(by_layer[l]))
        patterns = by_layer[target_layer][:5]  # Max 5 patterns

        # Determine severity from patterns
        severities = [p.associated_severity for p in patterns if p.associated_severity]
        severity = max(severities, key=lambda s: s.value) if severities else Severity.MEDIUM

        # Generate signature ID
        sig_id = f"HP-LEARNED-{datetime.now().strftime('%Y%m%d')}-{len(self.db.signatures):04d}"

        return ThreatSignature(
            sig_id=sig_id,
            name=f"Learned Pattern ({target_layer.name})",
            description=f"Auto-generated signature from {sum(p.occurrence_count for p in patterns)} detections",
            layer=target_layer,
            severity=severity,
            category=AttackCategory.DISCOVERY,  # Default category
            patterns=[p.to_feature_pattern() for p in patterns],
            match_threshold=0.6,
            recommended_action="Alert",
            auto_block=False,
            source="learned"
        )

    def propose_mesh_update(
        self,
        signature: ThreatSignature,
        action: str = "add"
    ) -> SignatureUpdate:
        """
        Propose a signature update to the mesh network.

        Updates require consensus from multiple nodes before being applied.
        """
        update = SignatureUpdate(
            action=action,
            signature=signature if action != "delete" else None,
            sig_id=signature.sig_id,
            version=signature.version,
            source_node=self.node_id,
            votes=1,
            confidence=0.5
        )

        with self.pending_lock:
            self.pending_updates[signature.sig_id] = update

        return update

    def receive_mesh_update(self, update_dict: Dict[str, Any]) -> bool:
        """
        Receive a signature update from mesh peer.

        Returns True if update was accepted for voting.
        """
        try:
            update = SignatureUpdate.from_dict(update_dict)
            self.stats['updates_received'] += 1
            self.stats['mesh_peers_seen'] += 1

            with self.pending_lock:
                if update.sig_id in self.pending_updates:
                    # Add vote to existing proposal
                    existing = self.pending_updates[update.sig_id]
                    existing.votes += 1
                    existing.confidence = min(1.0, existing.confidence + 0.1)

                    # Apply if enough votes (consensus)
                    if existing.votes >= 3 and existing.confidence >= 0.7:
                        return self._apply_update(existing)
                else:
                    # New proposal
                    self.pending_updates[update.sig_id] = update

            return True

        except Exception as e:
            print(f"Warning: Failed to process mesh update: {e}")
            self.stats['updates_rejected'] += 1
            return False

    def _apply_update(self, update: SignatureUpdate) -> bool:
        """Apply a validated update to the database."""
        try:
            if update.action == "add" and update.signature:
                update.signature.source = "mesh"
                self.db.add_signature(update.signature)
                self.stats['updates_applied'] += 1
                return True

            elif update.action == "update" and update.signature:
                update.signature.source = "mesh"
                self.db.add_signature(update.signature)
                self.stats['updates_applied'] += 1
                return True

            elif update.action == "disable":
                sig = self.db.get_signature(update.sig_id)
                if sig:
                    sig.enabled = False
                    self.stats['updates_applied'] += 1
                    return True

            elif update.action == "delete":
                if update.sig_id in self.db.signatures:
                    del self.db.signatures[update.sig_id]
                    self.stats['updates_applied'] += 1
                    return True

        except Exception as e:
            print(f"Warning: Failed to apply update: {e}")
            self.stats['updates_rejected'] += 1

        return False

    def get_pending_updates(self) -> List[Dict[str, Any]]:
        """Get all pending updates awaiting consensus."""
        with self.pending_lock:
            return [u.to_dict() for u in self.pending_updates.values()]

    def get_stats(self) -> Dict[str, Any]:
        """Get updater statistics."""
        return {
            **self.stats,
            'pending_updates': len(self.pending_updates),
            'learned_patterns': len(self.learned_patterns),
            'detection_history_size': len(self.detection_history),
        }

    def export_learned_patterns(self, filepath: str):
        """Export learned patterns to JSON."""
        data = {
            'exported': datetime.now().isoformat(),
            'node_id': self.node_id,
            'patterns': [
                asdict(p) for p in self.learned_patterns.values()
            ]
        }

        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
