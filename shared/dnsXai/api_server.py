#!/usr/bin/env python3
"""
dnsXai HTTP API Server

Exposes REST endpoints for the Fortress web UI to communicate with the dnsXai engine.
Runs alongside the DNS server on port 8080.

Endpoints:
    GET  /health              - Health check
    GET  /api/stats           - Get protection statistics
    GET  /api/status          - Get protection status
    POST /api/level           - Set protection level (0-5)
    POST /api/pause           - Pause/resume protection
    GET  /api/whitelist       - Get whitelist entries
    POST /api/whitelist       - Add to whitelist
    DELETE /api/whitelist     - Remove from whitelist
    GET  /api/blocked         - Get recently blocked domains
    GET  /api/ml/status       - Get ML model status
    POST /api/ml/train        - Trigger ML training
    GET  /api/ml/training-data - Get training data samples (queries log)

Author: HookProbe Security
License: AGPL-3.0
"""

import json
import logging
import math
import os
import random
import threading
import time
from collections import Counter, deque
from datetime import datetime, timedelta
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from typing import Dict, Any, Optional, Tuple, List, Set

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [API] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================
# CONFIGURATION
# ============================================================
DATA_DIR = Path(os.environ.get('DNSXAI_DATA_DIR', '/opt/hookprobe/shared/dnsXai/data'))
# USERDATA_DIR is bind-mounted from host and persists across reinstalls
USERDATA_DIR = Path(os.environ.get('DNSXAI_USERDATA_DIR', '/opt/hookprobe/shared/dnsXai/userdata'))
LOG_DIR = Path(os.environ.get('LOG_DIR', '/var/log/hookprobe'))
CONFIG_FILE = DATA_DIR / 'config.json'
STATS_FILE = DATA_DIR / 'stats.json'
WHITELIST_FILE = DATA_DIR / 'whitelist.txt'
USERDATA_WHITELIST_FILE = USERDATA_DIR / 'whitelist.txt'
BLOCKED_LOG = LOG_DIR / 'dnsxai-blocked.log'
QUERIES_LOG = LOG_DIR / 'dnsxai-queries.log'
TRAINING_LOG = LOG_DIR / 'dnsxai-training.log'

# Ensure directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
USERDATA_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# STATS TRACKER (Thread-safe)
# ============================================================
class StatsTracker:
    """Thread-safe statistics tracking for dnsXai."""

    def __init__(self):
        self._lock = threading.Lock()
        self._stats = {
            'total_queries': 0,
            'blocked_queries': 0,
            'allowed_queries': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'ml_classifications': 0,
            'ml_blocks': 0,
            'uptime_start': datetime.now().isoformat(),
            'last_updated': datetime.now().isoformat(),
        }
        self._hourly_queries = deque(maxlen=24)  # Last 24 hours
        self._blocked_domains = deque(maxlen=1000)  # Recent blocked domains
        self._protection_level = int(os.environ.get('DNSXAI_PROTECTION_LEVEL', '3'))
        self._paused = False
        self._pause_until = None
        self._load_stats()

    def _load_stats(self):
        """Load persisted stats from file."""
        try:
            if STATS_FILE.exists():
                with open(STATS_FILE, 'r') as f:
                    saved = json.load(f)
                    self._stats.update(saved.get('counters', {}))
                    self._protection_level = saved.get('protection_level', 3)
                    logger.info(f"Loaded stats: {self._stats['total_queries']} total queries")
        except Exception as e:
            logger.warning(f"Could not load stats: {e}")

    def _save_stats(self):
        """Persist stats to file."""
        try:
            with open(STATS_FILE, 'w') as f:
                json.dump({
                    'counters': self._stats,
                    'protection_level': self._protection_level,
                    'saved_at': datetime.now().isoformat()
                }, f, indent=2)
        except Exception as e:
            logger.warning(f"Could not save stats: {e}")

    def record_query(self, domain: str, blocked: bool, reason: str = '', ml_classified: bool = False):
        """Record a DNS query."""
        with self._lock:
            self._stats['total_queries'] += 1
            self._stats['last_updated'] = datetime.now().isoformat()

            if blocked:
                self._stats['blocked_queries'] += 1
                self._blocked_domains.append({
                    'domain': domain,
                    'reason': reason,
                    'timestamp': datetime.now().isoformat(),
                    'ml_classified': ml_classified
                })
                # Log to file for training data
                self._log_blocked(domain, reason, ml_classified)
            else:
                self._stats['allowed_queries'] += 1

            if ml_classified:
                self._stats['ml_classifications'] += 1
                if blocked:
                    self._stats['ml_blocks'] += 1

            # Periodic save (every 100 queries)
            if self._stats['total_queries'] % 100 == 0:
                self._save_stats()

    def _log_blocked(self, domain: str, reason: str, ml_classified: bool):
        """Log blocked domain for training data."""
        try:
            with open(BLOCKED_LOG, 'a') as f:
                f.write(f"{datetime.now().isoformat()}\t{domain}\t{reason}\t{ml_classified}\n")
        except Exception as e:
            logger.warning(f"Could not write to blocked log: {e}")

    def record_cache_hit(self):
        with self._lock:
            self._stats['cache_hits'] += 1

    def record_cache_miss(self):
        with self._lock:
            self._stats['cache_misses'] += 1

    def get_stats(self) -> Dict[str, Any]:
        """Get current statistics from log files written by DNS resolver."""
        # Check pause expiry first (this auto-resumes if time expired)
        currently_paused = self.is_paused()

        # Read actual stats from log files (written by engine.py resolver)
        total_queries = 0
        blocked_queries = 0
        allowed_queries = 0
        ml_blocks = 0

        try:
            if QUERIES_LOG.exists():
                with open(QUERIES_LOG, 'r') as f:
                    for line in f:
                        parts = line.strip().split('\t')
                        if len(parts) >= 2:
                            total_queries += 1
                            if parts[1] == 'BLOCKED':
                                blocked_queries += 1
                                # Check if ML classified (method contains 'ml')
                                if len(parts) >= 5 and 'ml' in parts[4].lower():
                                    ml_blocks += 1
                            else:
                                allowed_queries += 1
        except Exception as e:
            logger.warning(f"Could not read queries log for stats: {e}")

        # Calculate block rate
        block_rate = 0.0
        if total_queries > 0:
            block_rate = (blocked_queries / total_queries) * 100

        # Get blocklist size
        blocklist_size = 0
        blocklist_file = DATA_DIR / 'blocklist.txt'
        try:
            if blocklist_file.exists():
                with open(blocklist_file, 'r') as f:
                    blocklist_size = sum(1 for line in f if line.strip() and not line.startswith('#'))
        except Exception:
            pass

        with self._lock:
            return {
                'protection_enabled': not currently_paused,
                'protection_level': self._protection_level,
                'paused': currently_paused,
                'pause_until': self._pause_until if currently_paused else None,
                'total_queries': total_queries,
                'blocked_queries': blocked_queries,
                'allowed_queries': allowed_queries,
                'block_rate': round(block_rate, 2),
                'blocklist_size': blocklist_size,
                'cache_hits': self._stats['cache_hits'],
                'cache_misses': self._stats['cache_misses'],
                'ml_classifications': self._stats['ml_classifications'],
                'ml_blocks': ml_blocks,
                'uptime_start': self._stats['uptime_start'],
                'last_updated': datetime.now().isoformat(),
            }

    def get_blocked_domains(self, limit: int = 100) -> list:
        """Get recently blocked domains from log file (deduplicated, whitelist filtered)."""
        blocked = []
        seen_domains = set()

        try:
            if BLOCKED_LOG.exists():
                with open(BLOCKED_LOG, 'r') as f:
                    lines = f.readlines()
                    # Process from newest to oldest (reversed) to get most recent entries
                    for line in reversed(lines):
                        if len(blocked) >= limit:
                            break
                        parts = line.strip().split('\t')
                        if len(parts) >= 4:
                            domain = parts[1].lower()
                            # Skip duplicates
                            if domain in seen_domains:
                                continue
                            # Skip whitelisted domains
                            if whitelist_manager.contains(domain):
                                continue
                            seen_domains.add(domain)
                            blocked.append({
                                'domain': domain,
                                'reason': parts[2],
                                'timestamp': parts[0],
                                'ml_classified': 'ml' in parts[2].lower()
                            })
        except Exception as e:
            logger.warning(f"Could not read blocked log: {e}")
        return blocked

    def remove_from_blocked_log(self, domain: str) -> bool:
        """Remove all entries for a domain from the blocked log."""
        if not BLOCKED_LOG.exists():
            return False

        try:
            with self._lock:
                with open(BLOCKED_LOG, 'r') as f:
                    lines = f.readlines()

                # Filter out lines matching the domain
                original_count = len(lines)
                filtered_lines = [
                    line for line in lines
                    if len(line.strip().split('\t')) < 2 or
                       line.strip().split('\t')[1].lower() != domain.lower()
                ]

                if len(filtered_lines) == original_count:
                    return False  # Domain not found

                # Write back filtered lines
                with open(BLOCKED_LOG, 'w') as f:
                    f.writelines(filtered_lines)

                logger.info(f"Removed {original_count - len(filtered_lines)} entries for {domain} from blocked log")
                return True
        except Exception as e:
            logger.error(f"Failed to remove from blocked log: {e}")
            return False

    def set_protection_level(self, level: int) -> bool:
        """Set protection level (0-5)."""
        if not 0 <= level <= 5:
            return False
        with self._lock:
            self._protection_level = level
            self._save_stats()
            logger.info(f"Protection level set to {level}")
            return True

    def pause(self, minutes: int = 0) -> bool:
        """Pause protection."""
        with self._lock:
            self._paused = True
            if minutes > 0:
                self._pause_until = (datetime.now() + timedelta(minutes=minutes)).isoformat()
            else:
                self._pause_until = None
            logger.info(f"Protection paused for {minutes} minutes" if minutes else "Protection paused indefinitely")
            return True

    def resume(self) -> bool:
        """Resume protection."""
        with self._lock:
            self._paused = False
            self._pause_until = None
            logger.info("Protection resumed")
            return True

    def is_paused(self) -> bool:
        """Check if protection is paused."""
        with self._lock:
            if self._paused and self._pause_until:
                if datetime.now() > datetime.fromisoformat(self._pause_until):
                    self._paused = False
                    self._pause_until = None
                    return False
            return self._paused


# Global stats tracker instance
stats_tracker = StatsTracker()


# ============================================================
# WHITELIST MANAGER
# ============================================================
class WhitelistManager:
    """Manage dnsXai whitelist with persistent storage.

    Whitelist is saved to both:
    - DATA_DIR (container volume, fast access)
    - USERDATA_DIR (host bind-mount, survives reinstalls)
    """

    def __init__(self, whitelist_file: Path = WHITELIST_FILE,
                 userdata_whitelist_file: Path = USERDATA_WHITELIST_FILE):
        self.whitelist_file = whitelist_file
        self.userdata_whitelist_file = userdata_whitelist_file
        self._whitelist = set()
        self._load()

    def _load(self):
        """Load whitelist from file (prefer userdata if exists)."""
        try:
            # Prefer userdata whitelist (persistent across reinstalls)
            load_from = self.whitelist_file
            if self.userdata_whitelist_file.exists():
                load_from = self.userdata_whitelist_file
                logger.info("Loading whitelist from persistent userdata")

            if load_from.exists():
                with open(load_from, 'r') as f:
                    self._whitelist = {
                        line.strip().lower()
                        for line in f
                        if line.strip() and not line.startswith('#')
                    }
                logger.info(f"Loaded {len(self._whitelist)} whitelist entries")
        except Exception as e:
            logger.warning(f"Could not load whitelist: {e}")

    def _save(self):
        """Save whitelist to both data and userdata directories."""
        content = self._generate_whitelist_content()

        # Save to data directory (container volume)
        try:
            with open(self.whitelist_file, 'w') as f:
                f.write(content)
        except Exception as e:
            logger.error(f"Could not save whitelist to data dir: {e}")

        # Save to userdata directory (persistent across reinstalls)
        try:
            self.userdata_whitelist_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.userdata_whitelist_file, 'w') as f:
                f.write(content)
            logger.info(f"Whitelist saved to persistent storage ({len(self._whitelist)} entries)")
        except Exception as e:
            logger.error(f"Could not save whitelist to userdata dir: {e}")

    def _generate_whitelist_content(self) -> str:
        """Generate whitelist file content."""
        lines = [
            "# dnsXai Whitelist",
            f"# Updated: {datetime.now().isoformat()}",
            "# One domain per line",
            "# This file persists across Fortress reinstalls",
            ""
        ]
        lines.extend(sorted(self._whitelist))
        lines.append("")  # Trailing newline
        return "\n".join(lines)

    def get_all(self) -> list:
        """Get all whitelist entries."""
        return sorted(self._whitelist)

    def validate_domain(self, domain: str) -> Tuple[bool, str]:
        """Validate domain format. Returns (is_valid, error_message)."""
        import re

        if not domain:
            return False, "Domain cannot be empty"

        domain = domain.strip().lower()

        # Check length
        if len(domain) > 253:
            return False, "Domain too long (max 253 characters)"

        if len(domain) < 2:
            return False, "Domain too short"

        # Check for invalid characters
        # Valid: a-z, 0-9, hyphen, dot
        if not re.match(r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$', domain):
            return False, "Invalid characters (only a-z, 0-9, hyphen, dot allowed)"

        # Check for consecutive dots
        if '..' in domain:
            return False, "Invalid format: consecutive dots"

        # Check for leading/trailing hyphens in labels
        labels = domain.split('.')
        for label in labels:
            if not label:
                return False, "Invalid format: empty label"
            if len(label) > 63:
                return False, f"Label '{label}' too long (max 63 characters)"
            if label.startswith('-') or label.endswith('-'):
                return False, f"Label '{label}' cannot start or end with hyphen"

        # Must have at least one dot for a proper domain (or be a TLD which is ok)
        # Single-label domains are allowed for flexibility

        return True, ""

    def add(self, domain: str) -> Tuple[bool, str]:
        """Add domain to whitelist. Returns (success, message)."""
        domain = domain.strip().lower()

        # Validate domain format
        is_valid, error = self.validate_domain(domain)
        if not is_valid:
            return False, error

        # Check if already exists
        if domain in self._whitelist:
            return False, f"Domain '{domain}' is already whitelisted"

        # Add to whitelist
        self._whitelist.add(domain)
        self._save()
        logger.info(f"Added to whitelist: {domain}")
        return True, f"Domain '{domain}' added to whitelist"

    def remove(self, domain: str) -> bool:
        """Remove domain from whitelist."""
        domain = domain.strip().lower()
        if domain in self._whitelist:
            self._whitelist.discard(domain)
            self._save()
            logger.info(f"Removed from whitelist: {domain}")
            return True
        return False

    def contains(self, domain: str) -> bool:
        """Check if domain is whitelisted."""
        domain = domain.strip().lower()
        # Check exact match and parent domains
        parts = domain.split('.')
        for i in range(len(parts)):
            if '.'.join(parts[i:]) in self._whitelist:
                return True
        return False


# Global whitelist manager
whitelist_manager = WhitelistManager()


# ============================================================
# ML TRAINING MANAGER
# ============================================================
class SimpleDomainFeatureExtractor:
    """
    Smart pattern-based domain classifier.

    Uses weighted keyword matching learned from blocklists.
    Much faster and more accurate than neural network inference.
    """

    # High-confidence tracker/telemetry keywords - learned from major blocklists
    # Format: keyword -> confidence_score (0.0 to 1.0)
    TRACKER_KEYWORDS = {
        # Telemetry & Analytics (very high confidence)
        'telemetry': 0.95, 'analytics': 0.90, 'metric': 0.85, 'metrics': 0.85,
        'tracking': 0.95, 'tracker': 0.95, 'pixel': 0.90, 'beacon': 0.90,
        'collect': 0.75, 'ingest': 0.70, 'usage': 0.50, 'event': 0.45,
        # Advertising (high confidence)
        'adserv': 0.95, 'adtrack': 0.95, 'doubleclick': 0.95, 'adsense': 0.95,
        'pagead': 0.90, 'googleads': 0.95, 'advert': 0.85, 'banner': 0.65,
        'sponsor': 0.65, 'promo': 0.55, 'affiliate': 0.70, 'adtech': 0.90,
        # Click & Redirect tracking
        'clicktrack': 0.90, 'clickstream': 0.85, 'redirect': 0.45,
        # User tracking
        'fingerprint': 0.90, 'userid': 0.65, 'visitor': 0.55,
        # Stats & Logging
        'statistic': 0.75, 'stats': 0.70, 'stat': 0.60,
    }

    # Tracker subdomains (first part of domain)
    TRACKER_PREFIXES = {'track', 'pixel', 'stat', 'stats', 'log', 'logs', 'event',
                        'events', 'data', 'collect', 'beacon', 'telemetry',
                        'analytics', 'metric', 'metrics', 'click', 'img', 't', 'tr'}

    # Known tracker domain patterns (second-level domain)
    TRACKER_BASES = {'tracker', 'analytics', 'metrics', 'telemetry', 'stats',
                     'tracking', 'pixel', 'beacon', 'collect', 'adtech'}

    # CRITICAL: System connectivity check domains - NEVER block these
    # Blocking these breaks network detection and captive portal login
    SYSTEM_CONNECTIVITY_DOMAINS = {
        # Microsoft NCSI (Network Connectivity Status Indicator)
        'msftconnecttest.com', 'msftncsi.com', 'dns.msftncsi.com',
        'www.msftconnecttest.com', 'ipv6.msftconnecttest.com',
        # Apple Captive Network Assistant
        'captive.apple.com', 'www.apple.com',
        # Google connectivity check
        'connectivitycheck.gstatic.com', 'clients3.google.com',
        'connectivitycheck.android.com', 'play.googleapis.com',
        # Mozilla/Firefox captive portal detection
        'detectportal.firefox.com',
        # Ubuntu/Debian connectivity check
        'connectivity-check.ubuntu.com', 'nmcheck.gnome.org',
        # Chromebook
        'clients1.google.com',
        # Generic connectivity
        'captive.g.aaplimg.com',
    }

    # Known security/proxy service domains (legitimate web security)
    SECURITY_SERVICE_DOMAINS = {
        'webdefence.global.blackspider.com',  # Symantec Web Security
        'pac.webdefence.global.blackspider.com',  # Proxy auto-config
        'wss.webdefence.global.blackspider.com',
        'zscaler.com', 'zscaler.net', 'zscloud.net',  # Zscaler
        'forcepoint.net',  # Forcepoint web security
        'bluecoat.com',  # Symantec BlueCoat
    }

    # Legitimate CDN/infrastructure domains - context-sensitive (not auto-block)
    LEGITIMATE_INFRASTRUCTURE = {
        'microsoft.com', 'apple.com', 'google.com', 'akamai.com',
        'cloudflare.com', 'amazonaws.com', 'azureedge.net', 'cloudfront.net',
        'gstatic.com', 'googleapis.com', 'icloud.com', 'office.com',
    }

    # Package repositories and software distribution - CRITICAL: NEVER block
    SOFTWARE_DISTRIBUTION_DOMAINS = {
        # Linux distributions
        'raspberrypi.com', 'raspberrypi.org', 'archive.raspberrypi.com',
        'archive.raspberrypi.org', 'downloads.raspberrypi.com',
        'ubuntu.com', 'archive.ubuntu.com', 'security.ubuntu.com',
        'debian.org', 'deb.debian.org', 'security.debian.org',
        'fedoraproject.org', 'centos.org', 'archlinux.org',
        # Package managers
        'pypi.org', 'files.pythonhosted.org', 'npmjs.org', 'npmjs.com',
        'rubygems.org', 'crates.io', 'golang.org', 'maven.apache.org',
        # Container registries
        'docker.io', 'docker.com', 'ghcr.io', 'gcr.io', 'quay.io',
        # Version control
        'github.com', 'raw.githubusercontent.com', 'gitlab.com', 'bitbucket.org',
        # Common software
        'kernel.org', 'apache.org', 'gnu.org', 'mozilla.org',
    }

    def __init__(self):
        import re
        # Compile single regex for all keywords - O(1) lookup
        self._keyword_pattern = re.compile(
            r'\b(' + '|'.join(re.escape(k) for k in sorted(self.TRACKER_KEYWORDS.keys(), key=len, reverse=True)) + r')',
            re.IGNORECASE
        )

    def _is_protected_domain(self, domain: str) -> bool:
        """Check if domain is protected (system connectivity, security, CDN, software repos)."""
        domain_lower = domain.lower()

        # Check exact match first
        if domain_lower in self.SYSTEM_CONNECTIVITY_DOMAINS:
            return True
        if domain_lower in self.SECURITY_SERVICE_DOMAINS:
            return True
        if domain_lower in self.SOFTWARE_DISTRIBUTION_DOMAINS:
            return True

        # Check parent domains
        parts = domain_lower.split('.')
        for i in range(len(parts)):
            parent = '.'.join(parts[i:])
            if parent in self.SYSTEM_CONNECTIVITY_DOMAINS:
                return True
            if parent in self.SECURITY_SERVICE_DOMAINS:
                return True
            if parent in self.LEGITIMATE_INFRASTRUCTURE:
                return True
            if parent in self.SOFTWARE_DISTRIBUTION_DOMAINS:
                return True

        return False

    def quick_classify(self, domain: str) -> Tuple[bool, float, str]:
        """
        Fast O(n) classification using pattern matching.
        Returns: (should_block, confidence, reason)

        This is the SMART classifier - uses learned patterns instead of
        expensive ML inference.
        """
        domain_lower = domain.lower().strip('.')
        parts = domain_lower.split('.')

        # 0. CRITICAL: Never block system connectivity/security domains
        if self._is_protected_domain(domain_lower):
            return False, 0.0, "protected"

        # 1. Keyword scan - single regex pass, return highest confidence match
        matches = self._keyword_pattern.findall(domain_lower)
        if matches:
            best_match = max(matches, key=lambda m: self.TRACKER_KEYWORDS.get(m.lower(), 0))
            confidence = self.TRACKER_KEYWORDS.get(best_match.lower(), 0.7)
            if confidence >= 0.6:  # Only block if confidence is high enough
                return True, confidence, f"keyword:{best_match}"

        # 2. Prefix check - e.g., track.example.com, telemetry.n8n.io
        if len(parts) >= 2 and parts[0] in self.TRACKER_PREFIXES:
            return True, 0.80, f"prefix:{parts[0]}"

        # 3. Base domain check - e.g., example.analytics.com
        if len(parts) >= 2 and parts[-2] in self.TRACKER_BASES:
            return True, 0.75, f"base:{parts[-2]}"

        # 4. No match - allow domain
        return False, 0.0, "clean"

    def extract_features(self, domain: str) -> Dict[str, float]:
        """Extract features from a domain name for training."""
        domain = domain.lower().strip('.')
        parts = domain.split('.')

        features = {}
        features['length'] = len(domain)
        features['num_parts'] = len(parts)
        features['avg_part_length'] = sum(len(p) for p in parts) / max(len(parts), 1)
        features['max_part_length'] = max((len(p) for p in parts), default=0)
        features['digit_ratio'] = sum(c.isdigit() for c in domain) / max(len(domain), 1)
        features['hyphen_ratio'] = domain.count('-') / max(len(domain), 1)
        features['vowel_ratio'] = sum(c in 'aeiou' for c in domain) / max(len(domain), 1)

        # Entropy
        if domain:
            freq = Counter(domain)
            features['entropy'] = -sum((c/len(domain)) * math.log2(c/len(domain))
                                       for c in freq.values())
        else:
            features['entropy'] = 0.0

        # Smart keyword scoring
        should_block, confidence, reason = self.quick_classify(domain)
        features['keyword_score'] = confidence
        features['is_tracker'] = 1.0 if should_block else 0.0
        features['prefix_match'] = 1.0 if parts[0] in self.TRACKER_PREFIXES else 0.0

        # Subdomain depth
        features['subdomain_depth'] = max(0, len(parts) - 2)

        return features


class MLTrainingManager:
    """Manage ML model training with real blocklist-based learning."""

    # Legitimate infrastructure domains to use as negative examples
    LEGITIMATE_DOMAINS = [
        'google.com', 'apple.com', 'microsoft.com', 'amazon.com', 'facebook.com',
        'github.com', 'stackoverflow.com', 'wikipedia.org', 'reddit.com', 'twitter.com',
        'youtube.com', 'linkedin.com', 'netflix.com', 'spotify.com', 'cloudflare.com',
        'akamai.com', 'fastly.com', 'aws.amazon.com', 'azure.microsoft.com',
        'mail.google.com', 'drive.google.com', 'docs.google.com', 'icloud.com',
        'dropbox.com', 'slack.com', 'zoom.us', 'teams.microsoft.com', 'outlook.com',
    ]

    def __init__(self):
        self.model_file = DATA_DIR / 'ml_model.json'
        self.training_in_progress = False
        self.last_training = None
        self.training_history = []
        self.feature_extractor = SimpleDomainFeatureExtractor()
        self._load_state()

    def _load_state(self):
        """Load training state."""
        try:
            state_file = DATA_DIR / 'ml_state.json'
            if state_file.exists():
                with open(state_file, 'r') as f:
                    state = json.load(f)
                    self.last_training = state.get('last_training')
                    self.training_history = state.get('history', [])[-10:]
        except Exception as e:
            logger.warning(f"Could not load ML state: {e}")

    def _save_state(self):
        """Save training state."""
        try:
            state_file = DATA_DIR / 'ml_state.json'
            with open(state_file, 'w') as f:
                json.dump({
                    'last_training': self.last_training,
                    'history': self.training_history[-10:]
                }, f, indent=2)
        except Exception as e:
            logger.warning(f"Could not save ML state: {e}")

    def _load_blocklist_domains(self, limit: int = 5000) -> Set[str]:
        """Load domains from blocklist file."""
        domains = set()
        blocklist_file = DATA_DIR / 'blocklist.txt'
        try:
            if blocklist_file.exists():
                with open(blocklist_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            domains.add(line.lower())
                            if len(domains) >= limit:
                                break
        except Exception as e:
            logger.warning(f"Could not load blocklist: {e}")
        return domains

    def _load_whitelist_domains(self) -> Set[str]:
        """Load domains from whitelist."""
        domains = set()
        try:
            if WHITELIST_FILE.exists():
                with open(WHITELIST_FILE, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            domains.add(line.lower())
        except Exception as e:
            logger.warning(f"Could not load whitelist: {e}")
        return domains

    def _load_blocked_log_domains(self, limit: int = 1000) -> Set[str]:
        """Load recently blocked domains from log."""
        domains = set()
        try:
            if BLOCKED_LOG.exists():
                with open(BLOCKED_LOG, 'r') as f:
                    for line in f:
                        parts = line.strip().split('\t')
                        if len(parts) >= 2:
                            domains.add(parts[1].lower())
                            if len(domains) >= limit:
                                break
        except Exception as e:
            logger.warning(f"Could not load blocked log: {e}")
        return domains

    def _learn_patterns_from_domains(
        self,
        blocked_domains: List[str],
        legitimate_domains: List[str]
    ) -> Dict[str, float]:
        """
        SMART PATTERN LEARNING: Extract common n-grams from blocklist.

        This learns new patterns automatically by analyzing:
        1. Common substrings in blocked domains
        2. Filtering out patterns that also appear in legitimate domains
        3. Computing confidence scores based on frequency ratio

        Returns: Dict of pattern -> confidence_score
        """
        # Extract all n-grams from blocked domains
        blocked_ngrams = Counter()
        for domain in blocked_domains:
            domain_lower = domain.lower().strip('.')
            parts = domain_lower.split('.')
            # Extract word-level tokens from each part
            for part in parts[:-1]:  # Skip TLD
                if len(part) >= 4:  # Minimum pattern length
                    blocked_ngrams[part] += 1
                # Also extract substrings for compound words
                for i in range(len(part) - 3):
                    substr = part[i:i+4]
                    if substr.isalpha():
                        blocked_ngrams[substr] += 1

        # Extract n-grams from legitimate domains
        legit_ngrams = Counter()
        for domain in legitimate_domains:
            domain_lower = domain.lower().strip('.')
            parts = domain_lower.split('.')
            for part in parts[:-1]:
                if len(part) >= 4:
                    legit_ngrams[part] += 1
                for i in range(len(part) - 3):
                    substr = part[i:i+4]
                    if substr.isalpha():
                        legit_ngrams[substr] += 1

        # Compute pattern scores
        learned_patterns = {}
        min_blocked_count = max(5, len(blocked_domains) // 200)  # At least 0.5% occurrence

        for pattern, blocked_count in blocked_ngrams.items():
            if blocked_count < min_blocked_count:
                continue  # Too rare

            legit_count = legit_ngrams.get(pattern, 0)

            # Skip patterns common in legitimate domains
            if legit_count > blocked_count * 0.1:
                continue

            # Compute confidence: higher if pattern is unique to blocked domains
            if legit_count == 0:
                confidence = min(0.95, 0.5 + (blocked_count / len(blocked_domains)) * 10)
            else:
                ratio = blocked_count / max(legit_count, 1)
                confidence = min(0.85, 0.3 + ratio * 0.1)

            if confidence >= 0.5:
                learned_patterns[pattern] = round(confidence, 2)

        # Sort by confidence and limit to top patterns
        sorted_patterns = sorted(learned_patterns.items(), key=lambda x: -x[1])[:100]
        return dict(sorted_patterns)

    def get_status(self) -> Dict[str, Any]:
        """Get ML training status."""
        model_exists = self.model_file.exists()

        # Count samples from various sources
        blocklist_count = 0
        blocked_log_count = 0

        try:
            blocklist_file = DATA_DIR / 'blocklist.txt'
            if blocklist_file.exists():
                with open(blocklist_file, 'r') as f:
                    blocklist_count = sum(1 for line in f if line.strip() and not line.startswith('#'))
        except:
            pass

        try:
            if BLOCKED_LOG.exists():
                with open(BLOCKED_LOG, 'r') as f:
                    blocked_log_count = sum(1 for _ in f)
        except:
            pass

        total_samples = blocklist_count + blocked_log_count

        return {
            'model_trained': model_exists,
            'model_file': str(self.model_file) if model_exists else None,
            'training_in_progress': self.training_in_progress,
            'last_training': self.last_training,
            'training_samples': total_samples,
            'blocklist_samples': blocklist_count,
            'blocked_log_samples': blocked_log_count,
            'training_history': self.training_history[-5:],
            'ready_for_training': total_samples >= 100,
        }

    def start_training(self) -> Dict[str, Any]:
        """Start real ML training in background."""
        if self.training_in_progress:
            return {'success': False, 'error': 'Training already in progress'}

        status = self.get_status()
        if not status['ready_for_training']:
            return {
                'success': False,
                'error': f"Need at least 100 training samples (have {status['training_samples']})"
            }

        self.training_in_progress = True

        def train():
            try:
                logger.info("Starting ML training from blocklists...")
                start_time = datetime.now()

                # 1. Load positive examples (blocked domains)
                logger.info("Loading blocked domains from blocklist...")
                blocked_domains = self._load_blocklist_domains(limit=5000)
                blocked_from_log = self._load_blocked_log_domains(limit=1000)
                blocked_domains.update(blocked_from_log)
                logger.info(f"Loaded {len(blocked_domains)} blocked domain samples")

                # 2. Load negative examples (whitelisted + legitimate)
                logger.info("Loading legitimate domains...")
                whitelist = self._load_whitelist_domains()
                legitimate = set(self.LEGITIMATE_DOMAINS)
                legitimate.update(whitelist)
                logger.info(f"Loaded {len(legitimate)} legitimate domain samples")

                # 3. SMART PATTERN LEARNING - Extract common patterns from blocklist
                logger.info("Learning patterns from blocklist...")
                learned_patterns = self._learn_patterns_from_domains(
                    list(blocked_domains)[:3000],
                    list(legitimate)
                )
                logger.info(f"Learned {len(learned_patterns)} new patterns")

                # 4. Extract features from both sets
                logger.info("Extracting features...")
                blocked_features = []
                for domain in list(blocked_domains)[:2000]:
                    try:
                        features = self.feature_extractor.extract_features(domain)
                        blocked_features.append(features)
                    except:
                        pass

                legitimate_features = []
                for domain in legitimate:
                    try:
                        features = self.feature_extractor.extract_features(domain)
                        legitimate_features.append(features)
                    except:
                        pass

                logger.info(f"Extracted features: {len(blocked_features)} blocked, {len(legitimate_features)} legitimate")

                # 5. Compute feature statistics for decision boundaries
                if blocked_features and legitimate_features:
                    feature_names = list(blocked_features[0].keys())
                    feature_stats = {}

                    for name in feature_names:
                        blocked_vals = [f[name] for f in blocked_features if name in f]
                        legit_vals = [f[name] for f in legitimate_features if name in f]

                        if blocked_vals and legit_vals:
                            blocked_mean = sum(blocked_vals) / len(blocked_vals)
                            legit_mean = sum(legit_vals) / len(legit_vals)
                            blocked_std = math.sqrt(sum((x - blocked_mean)**2 for x in blocked_vals) / max(len(blocked_vals), 1))
                            legit_std = math.sqrt(sum((x - legit_mean)**2 for x in legit_vals) / max(len(legit_vals), 1))

                            feature_stats[name] = {
                                'blocked_mean': blocked_mean,
                                'blocked_std': blocked_std,
                                'legitimate_mean': legit_mean,
                                'legitimate_std': legit_std,
                                'threshold': (blocked_mean + legit_mean) / 2,
                                'weight': abs(blocked_mean - legit_mean) / max(blocked_std + legit_std, 0.01)
                            }

                    # 6. Save trained model with learned patterns
                    end_time = datetime.now()
                    duration = (end_time - start_time).total_seconds()

                    model = {
                        'version': '3.0',
                        'trained_at': end_time.isoformat(),
                        'blocked_samples': len(blocked_domains),
                        'legitimate_samples': len(legitimate),
                        'feature_stats': feature_stats,
                        'learned_patterns': learned_patterns,  # NEW: Learned from blocklist
                        'training_duration_seconds': duration
                    }

                    with open(self.model_file, 'w') as f:
                        json.dump(model, f, indent=2)

                    self.last_training = end_time.isoformat()
                    self.training_history.append({
                        'timestamp': end_time.isoformat(),
                        'duration_seconds': duration,
                        'blocked_samples': len(blocked_domains),
                        'legitimate_samples': len(legitimate),
                        'learned_patterns': len(learned_patterns),
                        'success': True
                    })

                    self._save_state()
                    logger.info(f"ML training completed in {duration:.1f}s - {len(learned_patterns)} patterns learned")
                else:
                    raise ValueError("Not enough features extracted for training")

            except Exception as e:
                logger.error(f"ML training failed: {e}")
                self.training_history.append({
                    'timestamp': datetime.now().isoformat(),
                    'success': False,
                    'error': str(e)
                })
                self._save_state()
            finally:
                self.training_in_progress = False

        thread = threading.Thread(target=train, daemon=True)
        thread.start()

        return {'success': True, 'message': 'Training started - learning from blocklists'}


# Global ML manager
ml_manager = MLTrainingManager()


# ============================================================
# HTTP REQUEST HANDLER
# ============================================================
class APIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for dnsXai API."""

    def log_message(self, format, *args):
        """Override to use our logger."""
        logger.info("%s - %s", self.client_address[0], format % args)

    def _send_json(self, data: Any, status: int = 200):
        """Send JSON response."""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _send_error(self, message: str, status: int = 400):
        """Send error response."""
        self._send_json({'error': message}, status)

    def _parse_body(self) -> Dict:
        """Parse request body as JSON."""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                body = self.rfile.read(content_length)
                return json.loads(body)
        except:
            pass
        return {}

    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        """Handle GET requests."""
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')

        routes = {
            '/health': self._health,
            '/api/stats': self._get_stats,
            '/api/status': self._get_status,
            '/api/whitelist': self._get_whitelist,
            '/api/whitelist/status': self._get_whitelist_status,
            '/api/blocked': self._get_blocked,
            '/api/ml/status': self._get_ml_status,
            '/api/ml/training-data': self._get_training_data,
            '/api/test/classify': self._test_classify,
        }

        handler = routes.get(path)
        if handler:
            handler()
        else:
            self._send_error('Not found', 404)

    def do_POST(self):
        """Handle POST requests."""
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')

        routes = {
            '/api/level': self._set_level,
            '/api/pause': self._pause,
            '/api/resume': self._resume,
            '/api/whitelist': self._add_whitelist,
            '/api/ml/train': self._start_training,
        }

        handler = routes.get(path)
        if handler:
            handler()
        else:
            self._send_error('Not found', 404)

    def do_DELETE(self):
        """Handle DELETE requests."""
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')

        if path == '/api/whitelist':
            self._remove_whitelist()
        elif path == '/api/blocked':
            self._remove_blocked()
        else:
            self._send_error('Not found', 404)

    # ---- Route Handlers ----

    def _health(self):
        """Health check endpoint."""
        self._send_json({
            'status': 'healthy',
            'service': 'dnsxai',
            'timestamp': datetime.now().isoformat()
        })

    def _get_stats(self):
        """Get protection statistics."""
        self._send_json(stats_tracker.get_stats())

    def _get_status(self):
        """Get protection status."""
        stats = stats_tracker.get_stats()
        self._send_json({
            'enabled': stats['protection_enabled'],
            'level': stats['protection_level'],
            'paused': stats['paused'],
            'pause_until': stats['pause_until']
        })

    def _set_level(self):
        """Set protection level."""
        data = self._parse_body()
        level = data.get('level')

        if level is None:
            self._send_error('Missing level parameter')
            return

        try:
            level = int(level)
            if stats_tracker.set_protection_level(level):
                self._send_json({'success': True, 'level': level})
            else:
                self._send_error('Invalid level (must be 0-5)')
        except ValueError:
            self._send_error('Invalid level value')

    def _pause(self):
        """Pause protection."""
        data = self._parse_body()
        minutes = int(data.get('minutes', 0))

        if stats_tracker.pause(minutes):
            self._send_json({'success': True, 'paused': True, 'minutes': minutes})
        else:
            self._send_error('Failed to pause')

    def _resume(self):
        """Resume protection."""
        if stats_tracker.resume():
            self._send_json({'success': True, 'paused': False})
        else:
            self._send_error('Failed to resume')

    def _get_whitelist(self):
        """Get whitelist entries."""
        self._send_json({
            'whitelist': whitelist_manager.get_all(),
            'count': len(whitelist_manager.get_all())
        })

    def _add_whitelist(self):
        """Add domain to whitelist with validation."""
        data = self._parse_body()
        domain = data.get('domain', '').strip()

        if not domain:
            self._send_json({'success': False, 'error': 'Missing domain parameter'}, 400)
            return

        success, message = whitelist_manager.add(domain)
        if success:
            self._send_json({'success': True, 'domain': domain.lower(), 'message': message})
        else:
            self._send_json({'success': False, 'error': message}, 400)

    def _remove_whitelist(self):
        """Remove domain from whitelist."""
        data = self._parse_body()
        domain = data.get('domain', '').strip()

        if not domain:
            self._send_error('Missing domain parameter')
            return

        if whitelist_manager.remove(domain):
            self._send_json({'success': True, 'domain': domain})
        else:
            self._send_json({'success': False, 'message': 'Domain not in whitelist'})

    def _get_blocked(self):
        """Get recently blocked domains."""
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        limit = int(params.get('limit', ['100'])[0])

        self._send_json({
            'blocked': stats_tracker.get_blocked_domains(limit),
            'count': len(stats_tracker.get_blocked_domains(limit))
        })

    def _remove_blocked(self):
        """Remove domain entries from blocked log."""
        data = self._parse_body()
        domain = data.get('domain', '').strip().lower()

        if not domain:
            self._send_error('Missing domain parameter')
            return

        if stats_tracker.remove_from_blocked_log(domain):
            self._send_json({'success': True, 'domain': domain})
        else:
            self._send_json({'success': False, 'error': 'Domain not found in blocked log'})

    def _get_ml_status(self):
        """Get ML training status."""
        self._send_json(ml_manager.get_status())

    def _get_training_data(self):
        """Get training data samples from logs."""
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        limit = int(params.get('limit', ['100'])[0])
        log_type = params.get('type', ['all'])[0]  # 'blocked', 'queries', 'all'

        result = {
            'blocked': [],
            'queries': [],
            'blocked_count': 0,
            'queries_count': 0,
            'log_files': {
                'blocked': str(BLOCKED_LOG),
                'queries': str(QUERIES_LOG)
            }
        }

        # Read blocked domains log
        if log_type in ('blocked', 'all'):
            try:
                if BLOCKED_LOG.exists():
                    with open(BLOCKED_LOG, 'r') as f:
                        lines = f.readlines()
                        result['blocked_count'] = len(lines)
                        for line in lines[-limit:]:
                            parts = line.strip().split('\t')
                            if len(parts) >= 4:
                                result['blocked'].append({
                                    'timestamp': parts[0],
                                    'domain': parts[1],
                                    'reason': parts[2],
                                    'ml_classified': parts[3] == 'True'
                                })
            except Exception as e:
                logger.warning(f"Could not read blocked log: {e}")

        # Read queries log
        if log_type in ('queries', 'all'):
            try:
                if QUERIES_LOG.exists():
                    with open(QUERIES_LOG, 'r') as f:
                        lines = f.readlines()
                        result['queries_count'] = len(lines)
                        for line in lines[-limit:]:
                            parts = line.strip().split('\t')
                            if len(parts) >= 7:
                                result['queries'].append({
                                    'timestamp': parts[0],
                                    'action': parts[1],
                                    'domain': parts[2],
                                    'qtype': parts[3],
                                    'method': parts[4],
                                    'category': parts[5],
                                    'confidence': float(parts[6]) if parts[6] else 0.0
                                })
            except Exception as e:
                logger.warning(f"Could not read queries log: {e}")

        self._send_json(result)

    def _start_training(self):
        """Start ML training."""
        result = ml_manager.start_training()
        status = 200 if result.get('success') else 400
        self._send_json(result, status)

    def _test_classify(self):
        """Test classify a domain without blocking (for debugging)."""
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        domain = params.get('domain', [''])[0].strip().lower()

        if not domain:
            self._send_error('Missing domain parameter')
            return

        # Use the smart classifier to test
        extractor = SimpleDomainFeatureExtractor()

        # Check if protected
        is_protected = extractor._is_protected_domain(domain)

        # Check if whitelisted
        is_whitelisted = whitelist_manager.contains(domain)

        # Quick classify
        would_block, confidence, reason = extractor.quick_classify(domain)

        # Extract features for debugging
        features = extractor.extract_features(domain)

        self._send_json({
            'domain': domain,
            'is_protected': is_protected,
            'is_whitelisted': is_whitelisted,
            'would_block': would_block and not is_protected and not is_whitelisted,
            'confidence': confidence,
            'reason': reason,
            'effective_action': 'ALLOW' if (is_protected or is_whitelisted or not would_block) else 'BLOCK',
            'features': features,
            'notes': self._get_classification_notes(domain, is_protected, is_whitelisted)
        })

    def _get_classification_notes(self, domain: str, is_protected: bool, is_whitelisted: bool) -> list:
        """Get helpful notes about domain classification."""
        notes = []

        if is_protected:
            notes.append("Domain is protected infrastructure (never blocked)")

        if is_whitelisted:
            notes.append("Domain is in user whitelist")

        # Check parent domains
        parts = domain.split('.')
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if whitelist_manager.contains(parent):
                notes.append(f"Parent domain '{parent}' is whitelisted")
                break

        extractor = SimpleDomainFeatureExtractor()
        if domain in extractor.SOFTWARE_DISTRIBUTION_DOMAINS:
            notes.append("Domain is a software distribution service")
        elif domain in extractor.SYSTEM_CONNECTIVITY_DOMAINS:
            notes.append("Domain is used for system connectivity checks")

        return notes

    def _get_whitelist_status(self):
        """Get detailed whitelist status."""
        self._send_json({
            'whitelist': whitelist_manager.get_all(),
            'count': len(whitelist_manager.get_all()),
            'file_location': str(USERDATA_WHITELIST_FILE) if USERDATA_WHITELIST_FILE.exists() else str(WHITELIST_FILE),
            'note': 'DNS engine auto-reloads whitelist every 5 seconds when file changes'
        })


def run_api_server(host: str = '0.0.0.0', port: int = 8080):
    """Run the HTTP API server."""
    server = HTTPServer((host, port), APIHandler)
    logger.info(f"dnsXai API server listening on {host}:{port}")
    server.serve_forever()


# ============================================================
# INTEGRATION FUNCTIONS
# ============================================================
def record_dns_query(domain: str, blocked: bool, reason: str = '', ml_classified: bool = False):
    """Record a DNS query from the engine."""
    stats_tracker.record_query(domain, blocked, reason, ml_classified)


def is_whitelisted(domain: str) -> bool:
    """Check if domain is whitelisted."""
    return whitelist_manager.contains(domain)


def is_protection_paused() -> bool:
    """Check if protection is paused."""
    return stats_tracker.is_paused()


def get_protection_level() -> int:
    """Get current protection level."""
    return stats_tracker.get_stats()['protection_level']


# ============================================================
# MAIN
# ============================================================
if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='dnsXai HTTP API Server')
    parser.add_argument('--host', default='0.0.0.0', help='Listen address')
    parser.add_argument('--port', type=int, default=8080, help='Listen port')
    args = parser.parse_args()

    run_api_server(args.host, args.port)
