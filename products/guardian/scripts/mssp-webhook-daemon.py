#!/usr/bin/env python3
"""
HookProbe Guardian - MSSP Webhook Receiver Daemon

Runs the MSSP webhook receiver as a long-lived systemd service.
Receives push recommendations from MSSP and processes them
through the recommendation handler pipeline.

Listens on 127.0.0.1:8199 (localhost only).
"""

import signal
import sys
import logging
import threading

# Add shared modules to path
sys.path.insert(0, '/opt/hookprobe/shared')
sys.path.insert(0, '/opt/hookprobe/guardian/lib')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger('mssp-webhook-daemon')

stop_event = threading.Event()


def shutdown_handler(signum, frame):
    """Handle SIGTERM/SIGINT for graceful shutdown."""
    logger.info("Received signal %d, shutting down...", signum)
    stop_event.set()


def main():
    signal.signal(signal.SIGTERM, shutdown_handler)
    signal.signal(signal.SIGINT, shutdown_handler)

    logger.info("Starting MSSP Webhook Receiver daemon")

    # Initialize recommendation handler
    handler = None
    try:
        from mssp.recommendation_handler import RecommendationHandler
        handler = RecommendationHandler()
        logger.info("Recommendation handler initialized")
    except Exception as e:
        logger.warning("Recommendation handler unavailable: %s", e)

    # Initialize and start webhook receiver
    try:
        from mssp.webhook_receiver import MSSPWebhookReceiver
        receiver = MSSPWebhookReceiver(host='127.0.0.1', port=8199)
        if handler:
            receiver.on_recommendation(lambda action: handler.handle(action))
        receiver.start()
        logger.info("MSSP Webhook Receiver listening on 127.0.0.1:8199")
    except Exception as e:
        logger.error("Failed to start webhook receiver: %s", e)
        sys.exit(1)

    # Block until shutdown signal
    stop_event.wait()

    logger.info("Stopping MSSP Webhook Receiver...")
    try:
        receiver.stop()
    except Exception:
        pass
    logger.info("MSSP Webhook Receiver stopped cleanly")


if __name__ == '__main__':
    main()
