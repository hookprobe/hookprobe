#!/usr/bin/env python3
"""
HookProbe Guardian - HYDRA-Lite Daemon Wrapper

Runs HydraLite as a long-lived systemd service.
Handles SIGTERM/SIGINT for graceful shutdown.
"""

import signal
import sys
import logging
import threading

# Add Guardian lib to path for imports
sys.path.insert(0, '/opt/hookprobe/guardian/lib')

from hydra_lite import HydraLite

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger('hydra-lite-daemon')

stop_event = threading.Event()


def shutdown_handler(signum, frame):
    """Handle SIGTERM/SIGINT for graceful shutdown."""
    logger.info("Received signal %d, shutting down...", signum)
    stop_event.set()


def main():
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    logger.info("Starting HYDRA-Lite daemon")
    hydra = HydraLite()
    hydra.start()
    logger.info("HYDRA-Lite running (feed sync + event consumer)")

    # Block until shutdown signal
    stop_event.wait()

    logger.info("Stopping HYDRA-Lite...")
    hydra.stop()
    logger.info("HYDRA-Lite stopped cleanly")


if __name__ == '__main__':
    main()
