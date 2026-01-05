#!/usr/bin/env python3
"""
AIOCHI Log Shipper
Ships Suricata and Zeek logs to ClickHouse for analytics.
"""

import json
import os
import sys
import time
import logging
import clickhouse_connect

# NOTE: Using __import__ to avoid 'from X import Y' syntax which confuses buildah heredoc parsing
datetime = __import__('datetime').datetime
Path = __import__('pathlib').Path
Dict = __import__('typing').Dict
List = __import__('typing').List
Any = __import__('typing').Any
Optional = __import__('typing').Optional
deque = __import__('collections').deque
Thread = __import__('threading').Thread
Event = __import__('threading').Event

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('aiochi-logshipper')

# Configuration from environment
CLICKHOUSE_HOST = os.getenv('CLICKHOUSE_HOST', '172.20.210.10')
CLICKHOUSE_PORT = int(os.getenv('CLICKHOUSE_PORT', 8123))
CLICKHOUSE_DB = os.getenv('CLICKHOUSE_DB', 'aiochi')
CLICKHOUSE_USER = os.getenv('CLICKHOUSE_USER', 'aiochi')
CLICKHOUSE_PASSWORD = os.getenv('CLICKHOUSE_PASSWORD', 'aiochi_secure_password')

SURICATA_LOG_PATH = os.getenv('SURICATA_LOG_PATH', '/var/log/suricata/eve.json')
ZEEK_LOG_PATH = os.getenv('ZEEK_LOG_PATH', '/opt/zeek/logs/current')

BATCH_SIZE = int(os.getenv('BATCH_SIZE', 100))
FLUSH_INTERVAL = int(os.getenv('FLUSH_INTERVAL', 5))


class LogShipper:
    """Ships logs from Suricata/Zeek to ClickHouse."""

    def __init__(self):
        self.client = None
        self.suricata_buffer = deque(maxlen=10000)
        self.zeek_conn_buffer = deque(maxlen=10000)
        self.zeek_dns_buffer = deque(maxlen=10000)
        self.stop_event = Event()
        self._connect()

    def _connect(self):
        """Connect to ClickHouse."""
        try:
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

    def parse_suricata_event(self, line):
        """Parse a Suricata EVE JSON log line."""
        try:
            event = json.loads(line.strip())
            if event.get('event_type') != 'alert':
                return None

            return {
                'timestamp': datetime.fromisoformat(event.get('timestamp', '').replace('Z', '+00:00')),
                'src_ip': event.get('src_ip', ''),
                'src_port': event.get('src_port', 0),
                'dest_ip': event.get('dest_ip', ''),
                'dest_port': event.get('dest_port', 0),
                'proto': event.get('proto', ''),
                'alert_action': event.get('alert', {}).get('action', ''),
                'alert_gid': event.get('alert', {}).get('gid', 0),
                'alert_signature_id': event.get('alert', {}).get('signature_id', 0),
                'alert_rev': event.get('alert', {}).get('rev', 0),
                'alert_signature': event.get('alert', {}).get('signature', ''),
                'alert_category': event.get('alert', {}).get('category', ''),
                'alert_severity': event.get('alert', {}).get('severity', 0),
            }
        except Exception as e:
            logger.debug(f"Failed to parse Suricata event: {e}")
            return None

    def parse_zeek_conn(self, line):
        """Parse a Zeek conn.log line (JSON format)."""
        try:
            event = json.loads(line.strip())
            return {
                'timestamp': datetime.fromtimestamp(float(event.get('ts', 0))),
                'uid': event.get('uid', ''),
                'src_ip': event.get('id.orig_h', ''),
                'src_port': event.get('id.orig_p', 0),
                'dest_ip': event.get('id.resp_h', ''),
                'dest_port': event.get('id.resp_p', 0),
                'proto': event.get('proto', ''),
                'service': event.get('service', ''),
                'duration': float(event.get('duration', 0) or 0),
                'orig_bytes': int(event.get('orig_bytes', 0) or 0),
                'resp_bytes': int(event.get('resp_bytes', 0) or 0),
                'conn_state': event.get('conn_state', ''),
                'orig_pkts': int(event.get('orig_pkts', 0) or 0),
                'resp_pkts': int(event.get('resp_pkts', 0) or 0),
            }
        except Exception as e:
            logger.debug(f"Failed to parse Zeek conn: {e}")
            return None

    def parse_zeek_dns(self, line):
        """Parse a Zeek dns.log line (JSON format)."""
        try:
            event = json.loads(line.strip())
            return {
                'timestamp': datetime.fromtimestamp(float(event.get('ts', 0))),
                'uid': event.get('uid', ''),
                'src_ip': event.get('id.orig_h', ''),
                'src_port': event.get('id.orig_p', 0),
                'dest_ip': event.get('id.resp_h', ''),
                'dest_port': event.get('id.resp_p', 0),
                'query': event.get('query', ''),
                'qclass_name': event.get('qclass_name', ''),
                'qtype_name': event.get('qtype_name', ''),
                'rcode_name': event.get('rcode_name', ''),
                'answers': ','.join(event.get('answers', []) or []),
                'ttls': ','.join(str(t) for t in (event.get('TTLs', []) or [])),
            }
        except Exception as e:
            logger.debug(f"Failed to parse Zeek dns: {e}")
            return None

    def flush_suricata(self):
        """Flush Suricata buffer to ClickHouse."""
        if not self.suricata_buffer or not self.client:
            return

        try:
            rows = list(self.suricata_buffer)
            self.suricata_buffer.clear()

            self.client.insert(
                'suricata_alerts',
                [list(r.values()) for r in rows],
                column_names=list(rows[0].keys())
            )
            logger.info(f"Flushed {len(rows)} Suricata alerts to ClickHouse")
        except Exception as e:
            logger.error(f"Failed to flush Suricata buffer: {e}")
            # Re-add rows on failure
            self.suricata_buffer.extend(rows)

    def flush_zeek_conn(self):
        """Flush Zeek conn buffer to ClickHouse."""
        if not self.zeek_conn_buffer or not self.client:
            return

        try:
            rows = list(self.zeek_conn_buffer)
            self.zeek_conn_buffer.clear()

            self.client.insert(
                'zeek_connections',
                [list(r.values()) for r in rows],
                column_names=list(rows[0].keys())
            )
            logger.info(f"Flushed {len(rows)} Zeek connections to ClickHouse")
        except Exception as e:
            logger.error(f"Failed to flush Zeek conn buffer: {e}")
            self.zeek_conn_buffer.extend(rows)

    def flush_zeek_dns(self):
        """Flush Zeek DNS buffer to ClickHouse."""
        if not self.zeek_dns_buffer or not self.client:
            return

        try:
            rows = list(self.zeek_dns_buffer)
            self.zeek_dns_buffer.clear()

            self.client.insert(
                'zeek_dns',
                [list(r.values()) for r in rows],
                column_names=list(rows[0].keys())
            )
            logger.info(f"Flushed {len(rows)} Zeek DNS queries to ClickHouse")
        except Exception as e:
            logger.error(f"Failed to flush Zeek DNS buffer: {e}")
            self.zeek_dns_buffer.extend(rows)

    def watch_suricata(self):
        """Watch Suricata EVE log file."""
        logger.info(f"Watching Suricata log: {SURICATA_LOG_PATH}")

        while not self.stop_event.is_set():
            try:
                if not Path(SURICATA_LOG_PATH).exists():
                    time.sleep(5)
                    continue

                with open(SURICATA_LOG_PATH, 'r') as f:
                    # Seek to end initially
                    f.seek(0, 2)

                    while not self.stop_event.is_set():
                        line = f.readline()
                        if not line:
                            time.sleep(0.1)
                            continue

                        event = self.parse_suricata_event(line)
                        if event:
                            self.suricata_buffer.append(event)

                            if len(self.suricata_buffer) >= BATCH_SIZE:
                                self.flush_suricata()

            except Exception as e:
                logger.error(f"Suricata watcher error: {e}")
                time.sleep(5)

    def watch_zeek(self):
        """Watch Zeek log directory."""
        logger.info(f"Watching Zeek logs: {ZEEK_LOG_PATH}")

        while not self.stop_event.is_set():
            try:
                zeek_dir = Path(ZEEK_LOG_PATH)
                if not zeek_dir.exists():
                    time.sleep(5)
                    continue

                conn_log = zeek_dir / 'conn.log'
                dns_log = zeek_dir / 'dns.log'

                # Watch conn.log
                if conn_log.exists():
                    with open(conn_log, 'r') as f:
                        f.seek(0, 2)
                        for _ in range(100):  # Read up to 100 lines per iteration
                            line = f.readline()
                            if not line:
                                break
                            if line.startswith('#'):
                                continue
                            event = self.parse_zeek_conn(line)
                            if event:
                                self.zeek_conn_buffer.append(event)

                # Watch dns.log
                if dns_log.exists():
                    with open(dns_log, 'r') as f:
                        f.seek(0, 2)
                        for _ in range(100):
                            line = f.readline()
                            if not line:
                                break
                            if line.startswith('#'):
                                continue
                            event = self.parse_zeek_dns(line)
                            if event:
                                self.zeek_dns_buffer.append(event)

                time.sleep(1)

            except Exception as e:
                logger.error(f"Zeek watcher error: {e}")
                time.sleep(5)

    def flush_loop(self):
        """Periodic flush loop."""
        while not self.stop_event.is_set():
            time.sleep(FLUSH_INTERVAL)
            self.flush_suricata()
            self.flush_zeek_conn()
            self.flush_zeek_dns()

    def run(self):
        """Run the log shipper."""
        logger.info("Starting AIOCHI Log Shipper...")

        # Start watcher threads
        threads = [
            Thread(target=self.watch_suricata, daemon=True),
            Thread(target=self.watch_zeek, daemon=True),
            Thread(target=self.flush_loop, daemon=True),
        ]

        for t in threads:
            t.start()

        # Wait for stop signal
        try:
            while not self.stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self.stop_event.set()

            # Final flush
            self.flush_suricata()
            self.flush_zeek_conn()
            self.flush_zeek_dns()


if __name__ == '__main__':
    shipper = LogShipper()
    shipper.run()
