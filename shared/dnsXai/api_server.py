#!/usr/bin/env python3
"""
dnsXai HTTP API Server

Exposes REST endpoints for the Fortress web UI to communicate with the dnsXai engine.
Runs alongside the DNS server on port 8080.

Endpoints:
    GET  /health         - Health check
    GET  /api/stats      - Get protection statistics
    GET  /api/status     - Get protection status
    POST /api/level      - Set protection level (0-5)
    POST /api/pause      - Pause/resume protection
    GET  /api/whitelist  - Get whitelist entries
    POST /api/whitelist  - Add to whitelist
    DELETE /api/whitelist - Remove from whitelist
    GET  /api/blocked    - Get recently blocked domains
    GET  /api/ml/status  - Get ML model status
    POST /api/ml/train   - Trigger ML training

Author: HookProbe Security
License: AGPL-3.0
"""

import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from collections import deque
from typing import Dict, Any, Optional

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
LOG_DIR = Path(os.environ.get('LOG_DIR', '/var/log/hookprobe'))
CONFIG_FILE = DATA_DIR / 'config.json'
STATS_FILE = DATA_DIR / 'stats.json'
WHITELIST_FILE = DATA_DIR / 'whitelist.txt'
BLOCKED_LOG = LOG_DIR / 'dnsxai-blocked.log'
TRAINING_LOG = LOG_DIR / 'dnsxai-training.log'

# Ensure directories exist
DATA_DIR.mkdir(parents=True, exist_ok=True)
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
        """Get current statistics."""
        with self._lock:
            block_rate = 0.0
            if self._stats['total_queries'] > 0:
                block_rate = (self._stats['blocked_queries'] / self._stats['total_queries']) * 100

            return {
                'protection_enabled': not self._paused,
                'protection_level': self._protection_level,
                'paused': self._paused,
                'pause_until': self._pause_until,
                'total_queries': self._stats['total_queries'],
                'blocked_queries': self._stats['blocked_queries'],
                'allowed_queries': self._stats['allowed_queries'],
                'block_rate': round(block_rate, 2),
                'cache_hits': self._stats['cache_hits'],
                'cache_misses': self._stats['cache_misses'],
                'ml_classifications': self._stats['ml_classifications'],
                'ml_blocks': self._stats['ml_blocks'],
                'uptime_start': self._stats['uptime_start'],
                'last_updated': self._stats['last_updated'],
            }

    def get_blocked_domains(self, limit: int = 100) -> list:
        """Get recently blocked domains."""
        with self._lock:
            return list(self._blocked_domains)[-limit:]

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
    """Manage dnsXai whitelist."""

    def __init__(self, whitelist_file: Path = WHITELIST_FILE):
        self.whitelist_file = whitelist_file
        self._whitelist = set()
        self._load()

    def _load(self):
        """Load whitelist from file."""
        try:
            if self.whitelist_file.exists():
                with open(self.whitelist_file, 'r') as f:
                    self._whitelist = {
                        line.strip().lower()
                        for line in f
                        if line.strip() and not line.startswith('#')
                    }
                logger.info(f"Loaded {len(self._whitelist)} whitelist entries")
        except Exception as e:
            logger.warning(f"Could not load whitelist: {e}")

    def _save(self):
        """Save whitelist to file."""
        try:
            with open(self.whitelist_file, 'w') as f:
                f.write("# dnsXai Whitelist\n")
                f.write(f"# Updated: {datetime.now().isoformat()}\n")
                f.write("# One domain per line\n\n")
                for domain in sorted(self._whitelist):
                    f.write(f"{domain}\n")
        except Exception as e:
            logger.error(f"Could not save whitelist: {e}")

    def get_all(self) -> list:
        """Get all whitelist entries."""
        return sorted(self._whitelist)

    def add(self, domain: str) -> bool:
        """Add domain to whitelist."""
        domain = domain.strip().lower()
        if domain and domain not in self._whitelist:
            self._whitelist.add(domain)
            self._save()
            logger.info(f"Added to whitelist: {domain}")
            return True
        return False

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
class MLTrainingManager:
    """Manage ML model training."""

    def __init__(self):
        self.model_file = DATA_DIR / 'ml_model.json'
        self.training_in_progress = False
        self.last_training = None
        self.training_history = []
        self._load_state()

    def _load_state(self):
        """Load training state."""
        try:
            state_file = DATA_DIR / 'ml_state.json'
            if state_file.exists():
                with open(state_file, 'r') as f:
                    state = json.load(f)
                    self.last_training = state.get('last_training')
                    self.training_history = state.get('history', [])[-10:]  # Keep last 10
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

    def get_status(self) -> Dict[str, Any]:
        """Get ML training status."""
        model_exists = self.model_file.exists()
        blocked_samples = 0

        try:
            if BLOCKED_LOG.exists():
                with open(BLOCKED_LOG, 'r') as f:
                    blocked_samples = sum(1 for _ in f)
        except:
            pass

        return {
            'model_trained': model_exists,
            'model_file': str(self.model_file) if model_exists else None,
            'training_in_progress': self.training_in_progress,
            'last_training': self.last_training,
            'training_samples': blocked_samples,
            'training_history': self.training_history[-5:],
            'ready_for_training': blocked_samples >= 100,  # Need at least 100 samples
        }

    def start_training(self) -> Dict[str, Any]:
        """Start ML training in background."""
        if self.training_in_progress:
            return {'success': False, 'error': 'Training already in progress'}

        # Check if we have enough data
        status = self.get_status()
        if not status['ready_for_training']:
            return {
                'success': False,
                'error': f"Need at least 100 training samples (have {status['training_samples']})"
            }

        self.training_in_progress = True

        # Run training in background thread
        def train():
            try:
                logger.info("Starting ML training...")
                start_time = datetime.now()

                # Simulate training (replace with actual ML training)
                # In a real implementation, this would:
                # 1. Load blocked domains from log
                # 2. Extract features
                # 3. Train classifier
                # 4. Save model
                time.sleep(5)  # Simulate training time

                # Record training completion
                end_time = datetime.now()
                duration = (end_time - start_time).total_seconds()

                self.last_training = end_time.isoformat()
                self.training_history.append({
                    'timestamp': end_time.isoformat(),
                    'duration_seconds': duration,
                    'samples': status['training_samples'],
                    'success': True
                })

                # Save dummy model for now
                with open(self.model_file, 'w') as f:
                    json.dump({
                        'version': '1.0',
                        'trained_at': self.last_training,
                        'samples': status['training_samples']
                    }, f)

                self._save_state()
                logger.info(f"ML training completed in {duration:.1f}s")

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

        return {'success': True, 'message': 'Training started in background'}


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
            '/api/blocked': self._get_blocked,
            '/api/ml/status': self._get_ml_status,
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
        """Add domain to whitelist."""
        data = self._parse_body()
        domain = data.get('domain', '').strip()

        if not domain:
            self._send_error('Missing domain parameter')
            return

        if whitelist_manager.add(domain):
            self._send_json({'success': True, 'domain': domain})
        else:
            self._send_json({'success': False, 'message': 'Domain already in whitelist or invalid'})

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

    def _get_ml_status(self):
        """Get ML training status."""
        self._send_json(ml_manager.get_status())

    def _start_training(self):
        """Start ML training."""
        result = ml_manager.start_training()
        status = 200 if result.get('success') else 400
        self._send_json(result, status)


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
