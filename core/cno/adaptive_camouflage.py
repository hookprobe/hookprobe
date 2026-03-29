"""
Adaptive Camouflage — Network Deception System

Changes the network's external appearance based on the organism's
emotional state. Each emotion level activates progressively more
sophisticated deception techniques.

Level 0 (SERENE):   No camouflage
Level 1 (VIGILANT): Enhanced logging only
Level 2 (ANXIOUS):  TTL jitter, TCP window randomization
Level 3 (FEARFUL):  Full camo + honeypot deployment + timing perturbation
Level 4 (ANGRY):    Active counter-intel: tarpits, canary tokens, attacker fingerprinting

The camouflage system operates at two speeds:
    - BPF-level (Brainstem): TTL/window rewriting at wire speed via xdp_camo.c
    - Userspace (Cerebellum): Honeypot management, banner mutation, tarpits

Author: HookProbe Team
License: Proprietary
Version: 1.0.0
"""

import logging
import os
import random
import struct
import time
import threading
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.request import Request, urlopen

from .types import BPFMapWrite, EmotionState

logger = logging.getLogger(__name__)

# Configuration
CAMO_EVAL_INTERVAL_S = 10.0       # Re-evaluate camouflage every 10s
TTL_JITTER_RANGE = 16             # ±16 TTL variation
WINDOW_SIZES = [                   # Pool of realistic TCP window sizes
    5840, 8192, 14600, 16384,      # Linux defaults
    29200, 32768, 65535,           # Common maximums
    64240,                         # macOS
]
TARPIT_DELAY_MS = 5000            # Slow responses by 5 seconds
HONEYPOT_PORTS = [                 # Ports to expose as fake services
    21, 23, 445, 1433, 3306,       # FTP, Telnet, SMB, MSSQL, MySQL
    3389, 5432, 5900, 6379, 8080,  # RDP, PostgreSQL, VNC, Redis, HTTP
]

# Service banners for banner mutation
FAKE_BANNERS = {
    22: [
        'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6',
        'SSH-2.0-OpenSSH_9.3p1 Debian-1',
        'SSH-2.0-dropbear_2022.83',
    ],
    80: [
        'Apache/2.4.57 (Ubuntu)',
        'nginx/1.24.0',
        'Microsoft-IIS/10.0',
    ],
    443: [
        'Apache/2.4.57 (Ubuntu)',
        'nginx/1.24.0',
        'cloudflare',
    ],
    21: [
        'vsFTPd 3.0.5',
        'ProFTPD 1.3.8',
        'Pure-FTPd',
    ],
}

# Canary token templates
CANARY_FILENAMES = [
    'credentials.txt', 'passwords.xlsx', 'aws_keys.json',
    'database_backup.sql', 'private_key.pem', 'config.yaml',
    'admin_panel.html', 'internal_docs.pdf',
]


class AdaptiveCamouflage:
    """Network deception system driven by the Emotion Engine.

    Receives camouflage profiles from the Emotion Engine and activates
    the appropriate deception techniques.
    """

    def __init__(self, bpf_write_callback: Optional[Callable] = None):
        """Initialize camouflage system.

        Args:
            bpf_write_callback: Callback(BPFMapWrite) to queue BPF writes
                via the SynapticController.
        """
        self._bpf_write = bpf_write_callback
        self._current_level = 0
        self._active_techniques: Set[str] = set()
        self._emotion = EmotionState.SERENE

        # Honeypot state
        self._deployed_honeypots: Dict[int, str] = {}  # port → container_id
        self._canary_tokens: List[Dict[str, Any]] = []

        # Tarpit state
        self._tarpit_active = False
        self._tarpit_ips: Set[str] = set()  # IPs being tarpitted

        # Thread control
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Stats
        self._stats = {
            'level_changes': 0,
            'ttl_jitter_activations': 0,
            'window_randomizations': 0,
            'banner_mutations': 0,
            'honeypots_deployed': 0,
            'honeypots_removed': 0,
            'tarpits_activated': 0,
            'canary_tokens_deployed': 0,
            'attacker_fingerprints': 0,
        }

        logger.info("AdaptiveCamouflage initialized")

    # ------------------------------------------------------------------
    # Profile Application
    # ------------------------------------------------------------------

    def apply_profile(self, emotion: EmotionState,
                      profile: Dict[str, Any]) -> None:
        """Apply a camouflage profile from the Emotion Engine.

        Args:
            emotion: Current emotional state
            profile: Dict with 'level', 'techniques', 'description'
        """
        new_level = profile.get('level', 0)
        new_techniques = set(profile.get('techniques', []))

        with self._lock:
            if new_level == self._current_level and new_techniques == self._active_techniques:
                return  # No change

            old_level = self._current_level
            self._current_level = new_level
            self._emotion = emotion

            # Determine what to activate and deactivate
            to_activate = new_techniques - self._active_techniques
            to_deactivate = self._active_techniques - new_techniques
            self._active_techniques = new_techniques

        if new_level != old_level:
            self._stats['level_changes'] += 1
            logger.info(
                "CAMO LEVEL: %d → %d (%s) | activate=%s, deactivate=%s",
                old_level, new_level, emotion.value,
                list(to_activate), list(to_deactivate),
            )

        # Activate new techniques
        for technique in to_activate:
            self._activate_technique(technique)

        # Deactivate removed techniques
        for technique in to_deactivate:
            self._deactivate_technique(technique)

    # ------------------------------------------------------------------
    # Technique Activation
    # ------------------------------------------------------------------

    def _activate_technique(self, technique: str) -> None:
        """Activate a specific camouflage technique."""
        handler = {
            'enhanced_logging': self._activate_enhanced_logging,
            'ttl_jitter': self._activate_ttl_jitter,
            'window_randomize': self._activate_window_randomize,
            'banner_mutation': self._activate_banner_mutation,
            'honeypot_deploy': self._activate_honeypots,
            'timing_perturbation': self._activate_timing_perturbation,
            'tarpit_activation': self._activate_tarpit,
            'canary_tokens': self._activate_canary_tokens,
            'attacker_fingerprint': self._activate_fingerprinting,
        }.get(technique)

        if handler:
            try:
                handler()
            except Exception as e:
                logger.error("Failed to activate %s: %s", technique, e)

    def _deactivate_technique(self, technique: str) -> None:
        """Deactivate a specific camouflage technique."""
        handler = {
            'ttl_jitter': self._deactivate_ttl_jitter,
            'window_randomize': self._deactivate_window_randomize,
            'honeypot_deploy': self._deactivate_honeypots,
            'tarpit_activation': self._deactivate_tarpit,
        }.get(technique)

        if handler:
            try:
                handler()
            except Exception as e:
                logger.error("Failed to deactivate %s: %s", technique, e)

    # ------------------------------------------------------------------
    # Level 1: Enhanced Logging
    # ------------------------------------------------------------------

    def _activate_enhanced_logging(self) -> None:
        """Enable verbose logging for all network activity."""
        logger.info("CAMO: Enhanced logging activated")
        # In production: enable detailed ClickHouse logging for all flows

    # ------------------------------------------------------------------
    # Level 2: TTL Jitter (BPF-level)
    # ------------------------------------------------------------------

    def _activate_ttl_jitter(self) -> None:
        """Push TTL jitter config to BPF camo_config map.

        Format: camo_config[0] = {enabled: u8, ttl_jitter: u8, window_pool_idx: u8}
        """
        self._stats['ttl_jitter_activations'] += 1
        logger.info("CAMO: TTL jitter activated (±%d)", TTL_JITTER_RANGE)

        if self._bpf_write:
            # Key: index 0 in camo_config ARRAY
            key = struct.pack('<I', 0)
            # Value: enabled=1, ttl_jitter=16, window_idx=0
            value = struct.pack('<BBB', 1, TTL_JITTER_RANGE, 0)
            self._bpf_write(BPFMapWrite(
                map_name='camo_config',
                key=key,
                value=value,
                reason='ttl_jitter_activated',
            ))

    def _deactivate_ttl_jitter(self) -> None:
        """Disable TTL jitter in BPF map."""
        logger.info("CAMO: TTL jitter deactivated")
        if self._bpf_write:
            key = struct.pack('<I', 0)
            value = struct.pack('<BBB', 0, 0, 0)  # disabled
            self._bpf_write(BPFMapWrite(
                map_name='camo_config',
                key=key,
                value=value,
                reason='ttl_jitter_deactivated',
            ))

    # ------------------------------------------------------------------
    # Level 2: TCP Window Randomization
    # ------------------------------------------------------------------

    def _activate_window_randomize(self) -> None:
        """Select a random TCP window size from the pool."""
        self._stats['window_randomizations'] += 1
        window = random.choice(WINDOW_SIZES)
        logger.info("CAMO: TCP window set to %d", window)

        if self._bpf_write:
            # Write to camo_config[1] = {window_size: u16}
            key = struct.pack('<I', 1)
            value = struct.pack('<H', window)
            self._bpf_write(BPFMapWrite(
                map_name='camo_config',
                key=key,
                value=value,
                reason=f'window_randomize={window}',
            ))

    def _deactivate_window_randomize(self) -> None:
        """Reset TCP window to default."""
        logger.info("CAMO: TCP window reset to default")
        if self._bpf_write:
            key = struct.pack('<I', 1)
            value = struct.pack('<H', 0)  # 0 = use kernel default
            self._bpf_write(BPFMapWrite(
                map_name='camo_config',
                key=key,
                value=value,
                reason='window_randomize_disabled',
            ))

    # ------------------------------------------------------------------
    # Level 3: Service Banner Mutation
    # ------------------------------------------------------------------

    def _activate_banner_mutation(self) -> None:
        """Randomize service banners to confuse OS fingerprinting.

        In production: modifies nginx/SSH configs and reloads.
        Phase 1: Log only.
        """
        self._stats['banner_mutations'] += 1
        selected = {}
        for port, banners in FAKE_BANNERS.items():
            selected[port] = random.choice(banners)

        logger.info("CAMO: Banner mutation activated: %s", selected)
        # Phase 2: Actually modify service configs

    # ------------------------------------------------------------------
    # Level 3: Honeypot Deployment
    # ------------------------------------------------------------------

    def _activate_honeypots(self) -> None:
        """Deploy lightweight honeypot listeners on common attack ports.

        In production: uses rootless Podman API to spin up decoy containers.
        Phase 1: Log intent only.
        """
        # Select 3-5 random ports to honeypot
        ports = random.sample(HONEYPOT_PORTS, min(5, len(HONEYPOT_PORTS)))

        for port in ports:
            if port not in self._deployed_honeypots:
                self._deployed_honeypots[port] = f"honeypot-{port}-{int(time.time())}"
                self._stats['honeypots_deployed'] += 1

        logger.info("CAMO: Honeypots deployed on ports %s", list(self._deployed_honeypots.keys()))
        # Phase 2: Actually deploy lightweight listeners

    def _deactivate_honeypots(self) -> None:
        """Remove all deployed honeypots."""
        count = len(self._deployed_honeypots)
        self._deployed_honeypots.clear()
        self._stats['honeypots_removed'] += count
        logger.info("CAMO: %d honeypots removed", count)

    # ------------------------------------------------------------------
    # Level 3: Timing Perturbation
    # ------------------------------------------------------------------

    def _activate_timing_perturbation(self) -> None:
        """Add random delay to responses to defeat timing analysis.

        In production: hooks into response pipeline to add jitter.
        Phase 1: Log only.
        """
        logger.info("CAMO: Timing perturbation activated (±%dms jitter)",
                     TARPIT_DELAY_MS // 10)

    # ------------------------------------------------------------------
    # Level 4: Tarpit Activation
    # ------------------------------------------------------------------

    def _activate_tarpit(self) -> None:
        """Activate TCP tarpit for detected attackers.

        Tarpits accept connections but send data at 1 byte per second,
        wasting attacker resources.
        """
        self._tarpit_active = True
        self._stats['tarpits_activated'] += 1
        logger.info("CAMO: Tarpit activated (%dms delay per byte)", TARPIT_DELAY_MS)
        # Phase 2: Deploy actual tarpit (e.g., endlessh for SSH)

    def _deactivate_tarpit(self) -> None:
        """Deactivate tarpit."""
        self._tarpit_active = False
        self._tarpit_ips.clear()
        logger.info("CAMO: Tarpit deactivated")

    # ------------------------------------------------------------------
    # Level 4: Canary Tokens
    # ------------------------------------------------------------------

    def _activate_canary_tokens(self) -> None:
        """Deploy canary tokens — files that trigger alerts when accessed.

        In production: creates fake files (credentials.txt, passwords.xlsx)
        in honeypot filesystem that trigger alerts when opened/downloaded.
        """
        tokens = random.sample(CANARY_FILENAMES, min(3, len(CANARY_FILENAMES)))
        for filename in tokens:
            token = {
                'filename': filename,
                'deployed_at': time.time(),
                'triggered': False,
                'trigger_count': 0,
            }
            self._canary_tokens.append(token)
            self._stats['canary_tokens_deployed'] += 1

        logger.info("CAMO: Canary tokens deployed: %s", [t['filename'] for t in self._canary_tokens])

    # ------------------------------------------------------------------
    # Level 4: Attacker Fingerprinting
    # ------------------------------------------------------------------

    def _activate_fingerprinting(self) -> None:
        """Enable detailed attacker fingerprinting.

        Captures: JA3/JA3S hashes, User-Agent strings, SSH client versions,
        TCP stack parameters, timing patterns, tool signatures.
        """
        self._stats['attacker_fingerprints'] += 1
        logger.info("CAMO: Attacker fingerprinting activated")
        # Phase 2: Enable detailed ClickHouse logging of attacker attributes

    # ------------------------------------------------------------------
    # Tarpit IP Management
    # ------------------------------------------------------------------

    def add_tarpit_ip(self, ip: str) -> None:
        """Add an IP to the tarpit list."""
        if self._tarpit_active:
            self._tarpit_ips.add(ip)
            logger.debug("CAMO: IP %s added to tarpit", ip)

    def is_tarpitted(self, ip: str) -> bool:
        """Check if an IP is currently being tarpitted."""
        return ip in self._tarpit_ips

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def get_status(self) -> Dict[str, Any]:
        """Return current camouflage status."""
        return {
            'level': self._current_level,
            'emotion': self._emotion.value,
            'active_techniques': sorted(self._active_techniques),
            'honeypots': list(self._deployed_honeypots.keys()),
            'canary_tokens': len(self._canary_tokens),
            'tarpit_active': self._tarpit_active,
            'tarpit_ips': len(self._tarpit_ips),
            'stats': dict(self._stats),
        }
