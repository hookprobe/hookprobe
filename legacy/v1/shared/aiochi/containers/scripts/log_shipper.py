#!/usr/bin/env python3
"""
AIOCHI Supplementary Log Shipper

NAPSE writes all IDS events (connections, DNS, alerts, HTTP, TLS, DHCP) directly
to ClickHouse via its clickhouse_shipper.py module. This service handles any
supplementary log data not covered by the NAPSE event bus pipeline.

Currently this runs as a minimal health-check-able process that monitors the
ClickHouse connection. Extend with additional log sources as needed.
"""

import os
import sys
import time
import logging

# NOTE: Using __import__ to avoid 'from X import Y' syntax which confuses buildah heredoc parsing
Event = __import__('threading').Event

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO').upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('aiochi-logshipper')

# Configuration from environment
CLICKHOUSE_HOST = os.getenv('CLICKHOUSE_HOST', '172.20.210.10')
CLICKHOUSE_PORT = int(os.getenv('CLICKHOUSE_PORT', 8123))
CLICKHOUSE_DB = os.getenv('CLICKHOUSE_DB', 'aiochi')
CLICKHOUSE_USER = os.getenv('CLICKHOUSE_USER', 'aiochi')
CLICKHOUSE_PASSWORD = os.getenv('CLICKHOUSE_PASSWORD', 'aiochi_secure_password')

HEALTH_CHECK_INTERVAL = int(os.getenv('HEALTH_CHECK_INTERVAL', 60))


class LogShipper:
    """Supplementary log shipper for data not handled by NAPSE's clickhouse_shipper."""

    def __init__(self):
        self.client = None
        self.stop_event = Event()
        self._connect()

    def _connect(self):
        """Connect to ClickHouse."""
        try:
            import clickhouse_connect
            self.client = clickhouse_connect.get_client(
                host=CLICKHOUSE_HOST,
                port=CLICKHOUSE_PORT,
                database=CLICKHOUSE_DB,
                username=CLICKHOUSE_USER,
                password=CLICKHOUSE_PASSWORD
            )
            logger.info(f"Connected to ClickHouse at {CLICKHOUSE_HOST}:{CLICKHOUSE_PORT}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to ClickHouse: {e}")
            return False

    def _health_check(self):
        """Verify ClickHouse connection is alive."""
        try:
            if self.client:
                self.client.command("SELECT 1")
                return True
        except Exception as e:
            logger.warning(f"ClickHouse health check failed: {e}")
            self._connect()
        return False

    def run(self):
        """Run the supplementary log shipper."""
        logger.info("Starting AIOCHI Supplementary Log Shipper...")
        logger.info("NAPSE handles primary IDS event shipping via clickhouse_shipper.py")
        logger.info("This service monitors ClickHouse health and ships supplementary data")

        try:
            while not self.stop_event.is_set():
                self._health_check()
                self.stop_event.wait(HEALTH_CHECK_INTERVAL)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self.stop_event.set()


if __name__ == '__main__':
    shipper = LogShipper()
    shipper.run()
