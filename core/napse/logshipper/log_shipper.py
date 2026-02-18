#!/usr/bin/env python3
"""
HookProbe IDS Log Shipper v3.0

Watches Napse v2 output logs and inserts into:
  1. Local ClickHouse for fast queries
  2. MSSP API for centralized monitoring and IPS

Napse v2 (Mojo) outputs two JSONL log files:
  - intents.json: Intent classifications from HMM inference
  - flows.json:   Reconstructed flow summaries

Aegis (Zig/eBPF) writes XDP stats directly to ClickHouse.
This shipper handles only Napse output logs.

Usage:
  python log_shipper.py

Environment Variables:
  CLICKHOUSE_HOST     - ClickHouse hostname (default: localhost)
  CLICKHOUSE_PORT     - ClickHouse HTTP port (default: 8123)
  CLICKHOUSE_DB       - Database name (default: hookprobe_ids)
  CLICKHOUSE_USER     - Username (default: ids)
  CLICKHOUSE_PASSWORD - Password (required)
  NAPSE_INTENT_LOG    - Path to intents.json (default: /var/log/napse/intents.json)
  NAPSE_FLOW_LOG      - Path to flows.json (default: /var/log/napse/flows.json)
  LOG_LEVEL           - Logging level (default: INFO)
  MSSP_API_URL        - MSSP API base URL (optional, for centralized monitoring)
  MSSP_API_TOKEN      - MSSP API token (required if MSSP_API_URL set)
  FORWARD_TO_MSSP     - Enable MSSP forwarding (default: false)
"""

import json
import logging
import os
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

import clickhouse_connect
from dateutil import parser as date_parser
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# Configuration from environment
CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT = int(os.getenv("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_DB = os.getenv("CLICKHOUSE_DB", "hookprobe_ids")
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER", "ids")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "")
NAPSE_INTENT_LOG = os.getenv("NAPSE_INTENT_LOG", "/var/log/napse/intents.json")
NAPSE_FLOW_LOG = os.getenv("NAPSE_FLOW_LOG", "/var/log/napse/flows.json")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# MSSP API configuration for centralized monitoring
MSSP_API_URL = os.getenv("MSSP_API_URL", "")  # e.g., https://mssp.hookprobe.com/api/v1
MSSP_API_TOKEN = os.getenv("MSSP_API_TOKEN", "")
FORWARD_TO_MSSP = os.getenv("FORWARD_TO_MSSP", "false").lower() in ("true", "1", "yes")

# Batch settings
BATCH_SIZE = 1000
BATCH_TIMEOUT = 5  # seconds

# Logging setup
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper()),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class ClickHouseClient:
    """ClickHouse client wrapper with connection retry."""

    def __init__(self):
        self.client = None
        self.connect()

    def connect(self, max_retries: int = 10, retry_delay: int = 5):
        """Connect to ClickHouse with retry logic."""
        for attempt in range(max_retries):
            try:
                self.client = clickhouse_connect.get_client(
                    host=CLICKHOUSE_HOST,
                    port=CLICKHOUSE_PORT,
                    database=CLICKHOUSE_DB,
                    username=CLICKHOUSE_USER,
                    password=CLICKHOUSE_PASSWORD,
                )
                logger.info(f"Connected to ClickHouse at {CLICKHOUSE_HOST}:{CLICKHOUSE_PORT}")
                return
            except Exception as e:
                logger.warning(f"Connection attempt {attempt + 1}/{max_retries} failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
        raise ConnectionError("Failed to connect to ClickHouse after retries")

    def insert_batch(self, table: str, data: List[Dict], columns: List[str]):
        """Insert a batch of records into ClickHouse."""
        if not data:
            return

        try:
            rows = [[row.get(col) for col in columns] for row in data]
            self.client.insert(table, rows, column_names=columns)
            logger.debug(f"Inserted {len(data)} rows into {table}")
        except Exception as e:
            logger.error(f"Failed to insert into {table}: {e}")
            # Reconnect and retry once
            self.connect(max_retries=3)
            try:
                rows = [[row.get(col) for col in columns] for row in data]
                self.client.insert(table, rows, column_names=columns)
            except Exception as e2:
                logger.error(f"Retry failed: {e2}")


class MSSPClient:
    """
    MSSP API Client for forwarding events to centralized monitoring.

    Sends batched events to the MSSP Alert Ingestion API for:
    - Hybrid classification (signature + ML)
    - Autonomous IPS quarantine
    - Dashboard visualization
    """

    def __init__(self, api_url: str, api_token: str):
        self.api_url = api_url.rstrip('/')
        self.api_token = api_token
        self.ingest_endpoint = f"{self.api_url}/security/alerts/ingest/"
        self.enabled = bool(api_url and api_token)

        if self.enabled:
            logger.info(f"MSSP forwarding enabled: {self.api_url}")
        else:
            logger.info("MSSP forwarding disabled (no URL or token)")

    def forward_napse_intents(self, events: List[Dict]) -> bool:
        """Forward Napse intent events to MSSP API."""
        if not self.enabled or not events:
            return True

        payload = {
            "source": "Napse",
            "log_type": "intent",
            "events": events
        }
        return self._send_to_mssp(payload)

    def forward_napse_flows(self, events: List[Dict]) -> bool:
        """Forward Napse flow events to MSSP API."""
        if not self.enabled or not events:
            return True

        payload = {
            "source": "Napse",
            "log_type": "flow",
            "events": events
        }
        return self._send_to_mssp(payload)

    def _send_to_mssp(self, payload: Dict) -> bool:
        """Send payload to MSSP API."""
        try:
            data = json.dumps(payload).encode('utf-8')
            request = Request(
                self.ingest_endpoint,
                data=data,
                headers={
                    'Content-Type': 'application/json',
                    'Authorization': f'Token {self.api_token}',
                },
                method='POST'
            )

            with urlopen(request, timeout=30) as response:
                result = json.loads(response.read().decode('utf-8'))
                logger.debug(
                    f"MSSP ingestion: processed={result.get('processed', 0)}, "
                    f"quarantined={result.get('quarantined', 0)}"
                )
                return True

        except HTTPError as e:
            logger.error(f"MSSP API error: {e.code} - {e.reason}")
            return False
        except URLError as e:
            logger.error(f"MSSP connection error: {e.reason}")
            return False
        except Exception as e:
            logger.error(f"MSSP forwarding error: {e}")
            return False


def parse_timestamp(ts) -> datetime:
    """Parse various timestamp formats including Unix epoch. Never returns None."""
    if ts is None:
        return datetime.utcnow()
    try:
        # Handle Unix epoch (float or int) - common in Napse JSONL output
        if isinstance(ts, (int, float)):
            return datetime.utcfromtimestamp(ts)
        # Handle string timestamps
        if isinstance(ts, str):
            # Try ISO format first
            return date_parser.parse(ts)
        return datetime.utcnow()
    except Exception:
        return datetime.utcnow()


def parse_ip(ip: str) -> str:
    """Ensure IP is valid, return 0.0.0.0 for invalid."""
    if not ip or ip == "-":
        return "0.0.0.0"
    return ip


def parse_int(val: Any, default: int = 0) -> int:
    """Safely parse integer."""
    try:
        return int(val) if val is not None else default
    except (ValueError, TypeError):
        return default


def parse_float(val: Any, default: float = 0.0) -> float:
    """Safely parse float."""
    try:
        return float(val) if val is not None else default
    except (ValueError, TypeError):
        return default


def detect_vrf(src_ip: str, dst_ip: str) -> str:
    """Detect VRF based on IP address."""
    for ip in [src_ip, dst_ip]:
        if ip and ip.startswith("172.30."):
            return "hp-public"
        elif ip and ip.startswith("172.31."):
            return "hp-mssp"
        elif ip and ip.startswith("172.32."):
            return "hp-ids"
    return "unknown"


class NapseIntentHandler(FileSystemEventHandler):
    """
    Handles Napse v2 intent classification log (intents.json).

    Napse writes JSONL records with HMM-based intent classifications:
    {
        "timestamp": "2026-02-16T12:00:00.000Z",
        "tenant_id": 0,
        "src_ip": "192.168.1.100",
        "src_port": 54321,
        "dst_ip": "10.0.0.1",
        "dst_port": 443,
        "proto": 6,
        "intent_class": "scan",
        "confidence": 0.92,
        "severity": 2,
        "hmm_state": "reconnaissance",
        "prior_probability": 0.3,
        "posterior_probability": 0.92,
        "entropy": 4.7,
        "community_id": "1:abc123...",
        "features_summary": "port_scan:54321->443"
    }
    """

    # ClickHouse columns for napse_intents table (must match init.sql schema)
    COLUMNS = [
        "timestamp", "tenant_id", "src_ip", "dst_ip", "src_port", "dst_port",
        "proto", "intent_class", "confidence", "severity", "hmm_state",
        "prior_probability", "posterior_probability", "entropy", "community_id",
        "features_summary", "vrf"
    ]

    def __init__(self, client: ClickHouseClient, log_path: str, mssp_client: Optional[MSSPClient] = None):
        self.client = client
        self.mssp_client = mssp_client
        self.log_path = Path(log_path)
        self.position = 0
        self.intent_batch: List[Dict] = []
        self.raw_events: List[Dict] = []  # Raw events for MSSP forwarding
        self.last_flush = time.time()

        # Initialize position to end of file
        if self.log_path.exists():
            self.position = self.log_path.stat().st_size

    def on_modified(self, event):
        """Handle file modification."""
        if event.src_path == str(self.log_path):
            self.process_new_lines()

    def process_new_lines(self):
        """Read and process new lines from the intent log."""
        try:
            with open(self.log_path, "r") as f:
                f.seek(self.position)
                for line in f:
                    self.process_line(line.strip())
                self.position = f.tell()
        except Exception as e:
            logger.error(f"Error processing Napse intent log: {e}")

        # Check if we should flush batches
        self.maybe_flush()

    def process_line(self, line: str):
        """Parse a single JSONL intent line."""
        if not line:
            return

        try:
            event = json.loads(line)
            self.process_intent(event)

            # Store raw event for MSSP forwarding (intents for classification)
            if self.mssp_client and self.mssp_client.enabled:
                self.raw_events.append(event)

        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON in intents.json: {line[:100]}...")
        except Exception as e:
            logger.error(f"Error processing intent event: {e}")

    def process_intent(self, event: Dict):
        """Process a Napse intent classification event."""
        record = {
            "timestamp": parse_timestamp(event.get("timestamp")),
            "tenant_id": parse_int(event.get("tenant_id"), 0),
            "src_ip": parse_ip(event.get("src_ip")),
            "dst_ip": parse_ip(event.get("dst_ip", event.get("dest_ip"))),
            "src_port": parse_int(event.get("src_port")),
            "dst_port": parse_int(event.get("dst_port", event.get("dest_port"))),
            "proto": parse_int(event.get("proto")),
            "intent_class": event.get("intent_class", ""),
            "confidence": parse_float(event.get("confidence")),
            "severity": parse_int(event.get("severity")),
            "hmm_state": event.get("hmm_state", ""),
            "prior_probability": parse_float(event.get("prior_probability")),
            "posterior_probability": parse_float(event.get("posterior_probability")),
            "entropy": parse_float(event.get("entropy")),
            "community_id": event.get("community_id", ""),
            "features_summary": event.get("features_summary", ""),
            "vrf": detect_vrf(
                event.get("src_ip"),
                event.get("dst_ip", event.get("dest_ip"))
            ),
        }
        self.intent_batch.append(record)

    def maybe_flush(self):
        """Flush batches if size or timeout reached."""
        now = time.time()
        should_flush = (
            len(self.intent_batch) >= BATCH_SIZE
            or (now - self.last_flush) >= BATCH_TIMEOUT
        )

        if should_flush:
            self.flush()

    def flush(self):
        """Flush intent batch to ClickHouse and MSSP."""
        # Flush to ClickHouse (local storage)
        if self.intent_batch:
            self.client.insert_batch("napse_intents", self.intent_batch, self.COLUMNS)
            logger.info(f"Flushed {len(self.intent_batch)} Napse intents to ClickHouse")
            self.intent_batch = []

        # Forward to MSSP API (centralized monitoring + IPS)
        if self.raw_events and self.mssp_client:
            if self.mssp_client.forward_napse_intents(self.raw_events):
                logger.info(f"Forwarded {len(self.raw_events)} Napse intents to MSSP")
            self.raw_events = []

        self.last_flush = time.time()


class NapseFlowHandler(FileSystemEventHandler):
    """
    Handles Napse v2 flow summary log (flows.json).

    Napse writes JSONL records with reconstructed flow summaries:
    {
        "timestamp": "2026-02-16T12:00:00.000Z",
        "tenant_id": 0,
        "community_id": "1:abc123...",
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "src_port": 54321,
        "dst_port": 443,
        "proto": 6,
        "service": "https",
        "duration": 1.5,
        "bytes_orig": 1024,
        "bytes_resp": 8192,
        "pkts_orig": 10,
        "pkts_resp": 12,
        "max_entropy": 5.2,
        "avg_entropy": 4.1,
        "intent_class": "benign",
        "confidence": 0.98,
        "hmm_final_state": "idle"
    }
    """

    # ClickHouse columns for napse_flows table (must match init.sql schema)
    COLUMNS = [
        "timestamp", "tenant_id", "community_id", "src_ip", "dst_ip",
        "src_port", "dst_port", "proto", "service", "duration", "bytes_orig",
        "bytes_resp", "pkts_orig", "pkts_resp", "max_entropy", "avg_entropy",
        "intent_class", "confidence", "hmm_final_state", "vrf"
    ]

    def __init__(self, client: ClickHouseClient, log_path: str, mssp_client: Optional[MSSPClient] = None):
        self.client = client
        self.mssp_client = mssp_client
        self.log_path = Path(log_path)
        self.position = 0
        self.flow_batch: List[Dict] = []
        self.raw_events: List[Dict] = []  # Raw events for MSSP forwarding
        self.last_flush = time.time()

        # Initialize position to end of file
        if self.log_path.exists():
            self.position = self.log_path.stat().st_size

    def on_modified(self, event):
        """Handle file modification."""
        if event.src_path == str(self.log_path):
            self.process_new_lines()

    def process_new_lines(self):
        """Read and process new lines from the flow log."""
        try:
            with open(self.log_path, "r") as f:
                f.seek(self.position)
                for line in f:
                    self.process_line(line.strip())
                self.position = f.tell()
        except Exception as e:
            logger.error(f"Error processing Napse flow log: {e}")

        # Check if we should flush batches
        self.maybe_flush()

    def process_line(self, line: str):
        """Parse a single JSONL flow line."""
        if not line:
            return

        try:
            event = json.loads(line)
            self.process_flow(event)

            # Store raw event for MSSP forwarding
            if self.mssp_client and self.mssp_client.enabled:
                self.raw_events.append(event)

        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON in flows.json: {line[:100]}...")
        except Exception as e:
            logger.error(f"Error processing flow event: {e}")

    def process_flow(self, event: Dict):
        """Process a Napse flow summary event."""
        # Convert duration_ms to seconds if provided in milliseconds
        duration = parse_float(event.get("duration", event.get("duration_ms", 0)))
        if event.get("duration_ms") is not None and event.get("duration") is None:
            duration = duration / 1000.0

        record = {
            "timestamp": parse_timestamp(event.get("timestamp")),
            "tenant_id": parse_int(event.get("tenant_id"), 0),
            "community_id": event.get("community_id", ""),
            "src_ip": parse_ip(event.get("src_ip")),
            "dst_ip": parse_ip(event.get("dst_ip", event.get("dest_ip"))),
            "src_port": parse_int(event.get("src_port")),
            "dst_port": parse_int(event.get("dst_port", event.get("dest_port"))),
            "proto": parse_int(event.get("proto")),
            "service": event.get("service", ""),
            "duration": duration,
            "bytes_orig": parse_int(event.get("bytes_orig", event.get("bytes_sent"))),
            "bytes_resp": parse_int(event.get("bytes_resp", event.get("bytes_recv"))),
            "pkts_orig": parse_int(event.get("pkts_orig", event.get("pkts_sent"))),
            "pkts_resp": parse_int(event.get("pkts_resp", event.get("pkts_recv"))),
            "max_entropy": parse_float(event.get("max_entropy")),
            "avg_entropy": parse_float(event.get("avg_entropy")),
            "intent_class": event.get("intent_class", ""),
            "confidence": parse_float(event.get("confidence")),
            "hmm_final_state": event.get("hmm_final_state", ""),
            "vrf": detect_vrf(
                event.get("src_ip"),
                event.get("dst_ip", event.get("dest_ip"))
            ),
        }
        self.flow_batch.append(record)

    def maybe_flush(self):
        """Flush batches if size or timeout reached."""
        now = time.time()
        should_flush = (
            len(self.flow_batch) >= BATCH_SIZE
            or (now - self.last_flush) >= BATCH_TIMEOUT
        )

        if should_flush:
            self.flush()

    def flush(self):
        """Flush flow batch to ClickHouse and MSSP."""
        # Flush to ClickHouse (local storage)
        if self.flow_batch:
            self.client.insert_batch("napse_flows", self.flow_batch, self.COLUMNS)
            logger.info(f"Flushed {len(self.flow_batch)} Napse flows to ClickHouse")
            self.flow_batch = []

        # Forward to MSSP API (centralized monitoring + IPS)
        if self.raw_events and self.mssp_client:
            if self.mssp_client.forward_napse_flows(self.raw_events):
                logger.info(f"Forwarded {len(self.raw_events)} Napse flows to MSSP")
            self.raw_events = []

        self.last_flush = time.time()


def main():
    """Main entry point."""
    logger.info("Starting HookProbe IDS Log Shipper v3.0")
    logger.info(f"ClickHouse: {CLICKHOUSE_HOST}:{CLICKHOUSE_PORT}/{CLICKHOUSE_DB}")
    logger.info(f"Napse intent log: {NAPSE_INTENT_LOG}")
    logger.info(f"Napse flow log: {NAPSE_FLOW_LOG}")

    # Connect to ClickHouse
    client = ClickHouseClient()

    # Create MSSP client for centralized monitoring
    mssp_client = None
    if FORWARD_TO_MSSP:
        mssp_client = MSSPClient(MSSP_API_URL, MSSP_API_TOKEN)

    # Set up handlers for Napse v2 output logs
    intent_handler = NapseIntentHandler(client, NAPSE_INTENT_LOG, mssp_client)
    flow_handler = NapseFlowHandler(client, NAPSE_FLOW_LOG, mssp_client)

    # Set up file observers
    observer = Observer()

    # Watch Napse intent log directory
    intent_log_dir = str(Path(NAPSE_INTENT_LOG).parent)
    flow_log_dir = str(Path(NAPSE_FLOW_LOG).parent)

    if os.path.exists(intent_log_dir):
        observer.schedule(intent_handler, intent_log_dir, recursive=False)
        logger.info(f"Watching Napse intent log: {NAPSE_INTENT_LOG}")

    # Only add a second schedule if the flow log is in a different directory
    if flow_log_dir != intent_log_dir and os.path.exists(flow_log_dir):
        observer.schedule(flow_handler, flow_log_dir, recursive=False)
        logger.info(f"Watching Napse flow log: {NAPSE_FLOW_LOG}")
    elif os.path.exists(flow_log_dir):
        # Same directory - the intent handler's observer covers it,
        # but we still need the flow handler scheduled
        observer.schedule(flow_handler, flow_log_dir, recursive=False)
        logger.info(f"Watching Napse flow log: {NAPSE_FLOW_LOG}")

    # Start observer
    observer.start()

    # Handle shutdown
    def shutdown(signum, frame):
        logger.info("Shutting down...")
        intent_handler.flush()
        flow_handler.flush()
        observer.stop()
        observer.join()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    # Main loop
    try:
        while True:
            time.sleep(1)
            # Periodic flush
            intent_handler.maybe_flush()
            flow_handler.maybe_flush()
    except KeyboardInterrupt:
        shutdown(None, None)


if __name__ == "__main__":
    main()
