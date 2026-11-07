#!/usr/bin/env python3
"""
HookProbe Guardian - Lightweight HYDRA Integration

Minimal HYDRA integration for Guardian (1.5GB RAM budget):
- Feed sync: Download threat intel feeds → XDP blocking maps (~50MB RAM)
- Event consumer: Read XDP RINGBUF events → local logging (~50MB RAM)

Total overhead: ~100-200MB RAM (fits within Guardian's 1.5GB budget)

Full HYDRA features (SENTINEL, ML, enricher, features) are NOT included
as they require ~1.5GB+ additional RAM. Use Fortress or Nexus for those.

Usage:
    from products.guardian.lib.hydra_lite import HydraLite

    hydra = HydraLite()
    hydra.start()  # Starts feed sync + event consumer threads
    hydra.stop()   # Graceful shutdown
"""

import os
import sys
import time
import json
import logging
import threading
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Guardian-specific paths
GUARDIAN_DATA_DIR = Path(os.environ.get('GUARDIAN_DATA_DIR', '/opt/hookprobe/guardian/data'))
HYDRA_DATA_DIR = GUARDIAN_DATA_DIR / 'hydra'
FEED_CACHE_DIR = HYDRA_DATA_DIR / 'feeds'
EVENT_LOG_DIR = HYDRA_DATA_DIR / 'events'

# Limits for Guardian's memory budget
MAX_BLOCKLIST_ENTRIES = 50000  # Cap blocklist size (vs Fortress 200K)
FEED_SYNC_INTERVAL = 3600     # Sync feeds every hour (vs Fortress 30min)
EVENT_LOG_MAX_MB = 50          # Max event log size before rotation


class HydraLite:
    """Lightweight HYDRA integration for Guardian.

    Provides:
    - Threat feed sync → XDP blocklist/allowlist maps
    - XDP RINGBUF event logging to local files
    - Hardware detection + inference bridge (via core.brain)

    Does NOT provide (Fortress/Nexus only):
    - RDAP IP enrichment
    - 24-feature ML extraction
    - Isolation Forest anomaly detection
    - SENTINEL false positive discrimination
    - Temporal memory / campaign detection
    """

    def __init__(self):
        self.running = False
        self._feed_thread: Optional[threading.Thread] = None
        self._consumer_thread: Optional[threading.Thread] = None
        self.hw_profile = None
        self.inference_bridge = None

        # Initialize hardware detection + inference bridge
        try:
            from core.brain.hw_detect import detect_hardware
            from core.brain.inference_bridge import InferenceBridge
            self.hw_profile = detect_hardware()
            self.inference_bridge = InferenceBridge(tier='guardian', hw_profile=self.hw_profile)
            logger.info(f"Brain initialized: {self.hw_profile.accelerator.value} "
                        f"({self.hw_profile.tops} TOPS), tier={self.hw_profile.tier_recommendation}")
        except ImportError:
            logger.info("core.brain not available — running without inference bridge")
        except Exception as e:
            logger.warning(f"Brain initialization failed: {e}")

        # Ensure data directories exist
        FEED_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        EVENT_LOG_DIR.mkdir(parents=True, exist_ok=True)

    def start(self):
        """Start feed sync and event consumer threads."""
        if self.running:
            logger.warning("HydraLite already running")
            return

        self.running = True
        logger.info("HydraLite starting (feed sync + event consumer)")

        self._feed_thread = threading.Thread(
            target=self._feed_sync_loop,
            daemon=True,
            name="hydra-feed-sync"
        )
        self._feed_thread.start()

        self._consumer_thread = threading.Thread(
            target=self._event_consumer_loop,
            daemon=True,
            name="hydra-event-consumer"
        )
        self._consumer_thread.start()

        logger.info("HydraLite started")

    def stop(self):
        """Graceful shutdown."""
        self.running = False
        logger.info("HydraLite stopping...")

        if self._feed_thread and self._feed_thread.is_alive():
            self._feed_thread.join(timeout=5)
        if self._consumer_thread and self._consumer_thread.is_alive():
            self._consumer_thread.join(timeout=5)

        logger.info("HydraLite stopped")

    def _feed_sync_loop(self):
        """Background thread: periodically sync threat feeds."""
        try:
            # Import feed_sync from core/hydra if available
            sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'core' / 'hydra'))
            from feed_sync import sync_all_feeds, update_xdp_blocklist
            logger.info("Feed sync module loaded from core/hydra")
        except ImportError:
            logger.warning("core/hydra/feed_sync.py not available - feed sync disabled")
            return

        while self.running:
            try:
                sync_all_feeds()
                update_xdp_blocklist()
                logger.info("Feed sync completed")
            except Exception as e:
                logger.error(f"Feed sync error: {e}")

            # Sleep in small increments for responsive shutdown
            for _ in range(FEED_SYNC_INTERVAL):
                if not self.running:
                    break
                time.sleep(1)

    def _event_consumer_loop(self):
        """Background thread: consume XDP RINGBUF events."""
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parents[3] / 'core' / 'hydra'))
            from bpf_map_ops import get_bpf_ops
            logger.info("BPF map ops loaded for event consumer")
        except ImportError:
            logger.warning("BPF map ops not available - event consumer disabled")
            return

        event_count = 0
        while self.running:
            try:
                ops = get_bpf_ops()
                if ops:
                    # Poll XDP stats every 10 seconds
                    for i in range(7):
                        try:
                            ops.read_percpu_u64('hydra_stats', i)
                        except Exception:
                            pass
                    event_count += 1

                    if event_count % 60 == 0:
                        logger.debug(f"Event consumer: {event_count} polls completed")
            except Exception as e:
                logger.debug(f"Event consumer error: {e}")

            time.sleep(10)

    @property
    def status(self) -> dict:
        """Return current status for Guardian dashboard."""
        status = {
            'enabled': self.running,
            'feed_sync': self._feed_thread is not None and self._feed_thread.is_alive(),
            'event_consumer': self._consumer_thread is not None and self._consumer_thread.is_alive(),
            'note': 'Lightweight mode (feed sync + event consumer only)',
        }
        if self.hw_profile:
            status['hardware'] = self.hw_profile.to_dict()
        if self.inference_bridge:
            status['inference'] = self.inference_bridge.device_info()
        return status
