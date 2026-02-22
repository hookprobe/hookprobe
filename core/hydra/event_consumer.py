#!/usr/bin/env python3
"""
HookProbe HYDRA Event Consumer
================================

Reads XDP RINGBUF events emitted by xdp_hydra.c and processes them:
  1. Batch inserts to ClickHouse hydra_events table
  2. Updates ip_reputation in PostgreSQL
  3. Emits Discord alerts for high-severity events

Uses BCC (BPF Compiler Collection) to read RINGBUF from the running
XDP program. Falls back to polling mode if BCC is not available.

Usage:
    python3 event_consumer.py [--interface dummy-mirror]

Architecture:
    XDP RINGBUF -> BCC ring_buffer_consume -> batch buffer -> ClickHouse
                                                          -> PostgreSQL (reputation)
                                                          -> Discord (alerts)
"""

import os
import sys
import time
import json
import struct
import signal
import logging
import socket
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [CONSUMER] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

CH_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CH_PORT = os.environ.get('CLICKHOUSE_PORT', '8123')
CH_DB = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
CH_USER = os.environ.get('CLICKHOUSE_USER', 'ids')
CH_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')

XDP_INTERFACE = os.environ.get('XDP_INTERFACE', 'dummy-mirror')
DISCORD_WEBHOOK = os.environ.get('DISCORD_WEBHOOK_URL', '')

# Batch settings
FLUSH_INTERVAL = 10  # Seconds between flushes
MAX_BATCH_SIZE = 1000  # Max events per batch

# Alert thresholds
ALERT_DROP_THRESHOLD = 100  # Alert after N drops from same source in 60s

# Event type constants (must match xdp_hydra.c)
HYDRA_EVENT_DROP = 1
HYDRA_EVENT_RATE_ALERT = 2
HYDRA_EVENT_PASS = 3
HYDRA_EVENT_SCORE_DROP = 4

# Reason constants
HYDRA_REASON_BLOCKLIST = 1
HYDRA_REASON_RATE = 2
HYDRA_REASON_SCORE = 3

EVENT_TYPE_NAMES = {
    HYDRA_EVENT_DROP: 'drop',
    HYDRA_EVENT_RATE_ALERT: 'alert',
    HYDRA_EVENT_PASS: 'pass',
    HYDRA_EVENT_SCORE_DROP: 'score_drop',
}

REASON_NAMES = {
    HYDRA_REASON_BLOCKLIST: 'blocklist',
    HYDRA_REASON_RATE: 'rate_exceeded',
    HYDRA_REASON_SCORE: 'score_threshold',
}

# ============================================================================
# GLOBAL STATE
# ============================================================================

running = True
event_buffer: List[dict] = []
drop_counts: Dict[str, int] = defaultdict(int)  # Per-IP drop counter for alerting
last_flush = time.monotonic()

def signal_handler(sig, frame):
    global running
    logger.info(f"Received signal {sig}, shutting down...")
    running = False

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

# ============================================================================
# EVENT STRUCT PARSING
# ============================================================================

# struct hydra_event {
#     __u64 timestamp_ns;    // 8 bytes
#     __u32 src_ip;          // 4 bytes
#     __u32 dst_ip;          // 4 bytes
#     __u16 src_port;        // 2 bytes
#     __u16 dst_port;        // 2 bytes
#     __u8  proto;           // 1 byte
#     __u8  event_type;      // 1 byte
#     __u8  reason;          // 1 byte
#     __u8  tcp_flags;       // 1 byte
#     __u32 rate_pps;        // 4 bytes
# };
# Total: 28 bytes

EVENT_STRUCT_FMT = '<QIIHH BBBB I'  # little-endian
EVENT_STRUCT_SIZE = struct.calcsize(EVENT_STRUCT_FMT)

def parse_event(data: bytes) -> Optional[dict]:
    """Parse raw RINGBUF event bytes into a dict."""
    if len(data) < EVENT_STRUCT_SIZE:
        return None

    try:
        fields = struct.unpack(EVENT_STRUCT_FMT, data[:EVENT_STRUCT_SIZE])
        timestamp_ns, src_ip, dst_ip, src_port, dst_port, \
            proto, event_type, reason, tcp_flags, rate_pps = fields

        # Convert IPs: stored as __be32 in kernel, read as LE u32
        # Pack back to LE bytes to get original network-order bytes
        src_str = str(ipaddress.IPv4Address(struct.pack('<I', src_ip)))
        dst_str = str(ipaddress.IPv4Address(struct.pack('<I', dst_ip)))

        return {
            'timestamp_ns': timestamp_ns,
            'src_ip': src_str,
            'dst_ip': dst_str,
            'src_port': src_port,
            'dst_port': dst_port,
            'proto': proto,
            'event_type': EVENT_TYPE_NAMES.get(event_type, f'unknown_{event_type}'),
            'reason': REASON_NAMES.get(reason, f'unknown_{reason}'),
            'tcp_flags': tcp_flags,
            'rate_pps': rate_pps,
        }
    except Exception as e:
        logger.debug(f"Event parse error: {e}")
        return None

# ============================================================================
# CLICKHOUSE WRITER
# ============================================================================

def ch_query(query: str, data: str = '') -> Optional[str]:
    """Execute a ClickHouse query via HTTP API."""
    if not CH_PASSWORD:
        return None

    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        params = urlencode({
            'query': query,
            'user': CH_USER,
            'password': CH_PASSWORD,
        })
        full_url = f"{url}?{params}"

        req = Request(full_url)
        if data:
            req.data = data.encode('utf-8')
            req.add_header('Content-Type', 'text/plain')

        with urlopen(req, timeout=10) as resp:
            return resp.read().decode('utf-8')

    except HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')[:500]
        logger.error(f"ClickHouse query error: {e} - {body}")
        return None
    except Exception as e:
        logger.error(f"ClickHouse query error: {e}")
        return None


def flush_events():
    """Flush event buffer to ClickHouse."""
    global event_buffer, last_flush

    if not event_buffer:
        last_flush = time.monotonic()
        return

    events = event_buffer[:MAX_BATCH_SIZE]
    event_buffer = event_buffer[MAX_BATCH_SIZE:]

    now = datetime.now(timezone.utc)

    # Build batch insert using POST body for data (avoids URL length limits)
    rows = []
    for evt in events:
        ts = now.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        rows.append(
            f"('{ts}', "
            f"IPv4StringToNum('{evt['src_ip']}'), "
            f"IPv4StringToNum('{evt['dst_ip']}'), "
            f"{evt['src_port']}, {evt['dst_port']}, "
            f"{evt['proto']}, "
            f"'{evt['event_type']}', '{evt['reason']}', '', "
            f"{evt['tcp_flags']})"
        )

    if rows:
        query = (
            f"INSERT INTO {CH_DB}.hydra_events "
            "(timestamp, src_ip, dst_ip, src_port, dst_port, "
            "proto, action, reason, feed_source, tcp_flags) VALUES"
        )
        data = ", ".join(rows)
        result = ch_query(query, data)
        if result is not None:
            logger.info(f"Flushed {len(rows)} events to ClickHouse")
        else:
            logger.warning(f"Failed to flush {len(rows)} events")

    # Check for alertable conditions
    check_alerts()

    # Reset counters periodically
    drop_counts.clear()
    last_flush = time.monotonic()


def check_alerts():
    """Check if any IPs exceed alert thresholds and send Discord alerts."""
    if not DISCORD_WEBHOOK:
        return

    for ip, count in drop_counts.items():
        if count >= ALERT_DROP_THRESHOLD:
            send_discord_alert(ip, count)


def send_discord_alert(src_ip: str, drop_count: int):
    """Send a Discord webhook alert for high-rate blocked IP."""
    try:
        payload = {
            'embeds': [{
                'title': 'HYDRA XDP Block Alert',
                'description': (
                    f'**Source IP**: `{src_ip}`\n'
                    f'**Drops**: {drop_count} in last {FLUSH_INTERVAL}s\n'
                    f'**Action**: Blocked by XDP blocklist'
                ),
                'color': 0xFF6B6B,  # Red
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'footer': {'text': 'HookProbe HYDRA Defense'},
            }]
        }

        data = json.dumps(payload).encode('utf-8')
        req = Request(DISCORD_WEBHOOK, data=data, headers={
            'Content-Type': 'application/json',
            'User-Agent': 'HookProbe-HYDRA/1.0',
        })
        urlopen(req, timeout=5)

    except Exception as e:
        logger.debug(f"Discord alert error: {e}")


# ============================================================================
# RINGBUF CONSUMER (via mmap — primary mode)
# ============================================================================

import ctypes
import ctypes.util
import mmap

# RINGBUF record header flags
BPF_RINGBUF_BUSY_BIT = 1 << 31
BPF_RINGBUF_DISCARD_BIT = 1 << 30
BPF_RINGBUF_HDR_SZ = 8  # u32 len + u32 padding


def run_ringbuf_consumer():
    """Read XDP events directly from BPF RINGBUF via mmap.

    RINGBUF layout:
    - Consumer page (1 page): consumer_pos at offset 0 (writable)
    - Data pages (N pages): producer_pos at offset 0 (read-only), then ring data
    """

    try:
        from bpf_map_ops import get_bpf_ops
        ops = get_bpf_ops()
    except Exception as e:
        logger.warning(f"Cannot init BPF ops: {e}")
        return False

    events_id = ops.find_map_by_name('events')
    if events_id is None:
        logger.warning("Cannot find 'events' RINGBUF map")
        return False

    info = ops._get_map_info_by_id(events_id)
    if not info:
        logger.warning("Cannot get info for events map")
        return False

    ringbuf_size = info['max_entries']  # Size in bytes
    page_size = os.sysconf('SC_PAGE_SIZE')
    logger.info(f"RINGBUF: id={events_id}, size={ringbuf_size}, page_size={page_size}")

    # Get FD for the ringbuf map (keep it open for the lifetime of the consumer)
    try:
        fd = ops._get_map_fd(events_id)
    except Exception as e:
        logger.warning(f"Cannot get FD for RINGBUF: {e}")
        return False

    try:
        # mmap consumer page (read-write)
        consumer_page = mmap.mmap(fd, page_size, mmap.MAP_SHARED,
                                  mmap.PROT_READ | mmap.PROT_WRITE, offset=0)

        # mmap data pages: producer page + double-mapped ring (for wrap-around reads)
        data_pages = mmap.mmap(fd, page_size + 2 * ringbuf_size, mmap.MAP_SHARED,
                               mmap.PROT_READ, offset=page_size)
    except Exception as e:
        logger.warning(f"Cannot mmap RINGBUF: {e}")
        os.close(fd)
        return False

    logger.info("RINGBUF consumer started (mmap mode)")

    mask = ringbuf_size - 1  # Ring buffer size is always power of 2
    # Ring data starts at page_size offset in data_pages (after producer page)
    data_start = page_size
    events_consumed = 0

    while running:
        try:
            # Read consumer_pos (unsigned long at offset 0 of consumer page)
            consumer_page.seek(0)
            consumer_pos = struct.unpack('<Q', consumer_page.read(8))[0]

            # Read producer_pos (unsigned long at offset 0 of data pages)
            data_pages.seek(0)
            producer_pos = struct.unpack('<Q', data_pages.read(8))[0]

            # Process available records
            batch_count = 0
            while consumer_pos < producer_pos and batch_count < 1000:
                # Read record header in the ring data area
                hdr_offset = data_start + (consumer_pos & mask)
                data_pages.seek(hdr_offset)
                hdr = struct.unpack('<I', data_pages.read(4))[0]

                # Check flags
                if hdr & BPF_RINGBUF_BUSY_BIT:
                    break  # Record still being written

                length = hdr & ~(BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT)
                is_discard = bool(hdr & BPF_RINGBUF_DISCARD_BIT)

                # Aligned total size (header + data, 8-byte aligned)
                total_size = BPF_RINGBUF_HDR_SZ + ((length + 7) & ~7)

                if not is_discard and length >= EVENT_STRUCT_SIZE:
                    # Read event data (after 8-byte header)
                    data_offset = data_start + ((consumer_pos + BPF_RINGBUF_HDR_SZ) & mask)
                    data_pages.seek(data_offset)
                    event_data = data_pages.read(min(length, EVENT_STRUCT_SIZE))

                    evt = parse_event(event_data)
                    if evt:
                        event_buffer.append(evt)
                        events_consumed += 1

                        # Track drops for alerting
                        if evt['event_type'] in ('drop', 'score_drop'):
                            drop_counts[evt['src_ip']] += 1

                consumer_pos += total_size
                batch_count += 1

            # Update consumer_pos (tell kernel we consumed up to here)
            if batch_count > 0:
                consumer_page.seek(0)
                consumer_page.write(struct.pack('<Q', consumer_pos))

            # Periodic flush
            if time.monotonic() - last_flush >= FLUSH_INTERVAL:
                flush_events()
                if events_consumed > 0 and int(time.monotonic()) % 60 < FLUSH_INTERVAL:
                    logger.info(f"RINGBUF: {events_consumed} events consumed total")

        except Exception as e:
            logger.debug(f"RINGBUF read error: {e}")

        time.sleep(0.1)  # 100ms poll interval

    # Cleanup
    consumer_page.close()
    data_pages.close()
    os.close(fd)
    logger.info(f"RINGBUF consumer stopped. Total events: {events_consumed}")
    return True


# ============================================================================
# POLL MODE CONSUMER (fallback — reads BPF maps for stats-based events)
# ============================================================================

def run_poll_consumer():
    """Poll XDP stats maps and high_rate_ips for event generation.

    Generates synthetic events from BPF map deltas when RINGBUF isn't available.
    """

    logger.info("Starting poll-mode consumer (reads XDP stats maps)...")

    try:
        from bpf_map_ops import get_bpf_ops
        ops = get_bpf_ops()
    except Exception:
        ops = None
        logger.warning("BPF map ops not available, consumer will only log heartbeats")

    # Track previous stats for delta computation
    prev_stats = [0] * 7
    STAT_LABELS = ['TOTAL', 'PASSED', 'DROPPED', 'ALLOWLISTED', 'BLOCKLISTED', 'RATE_DROPS', 'SCORE_DROPS']
    poll_count = 0

    while running:
        try:
            if ops:
                # Read hydra_stats PERCPU_ARRAY
                curr_stats = []
                for i in range(7):
                    curr_stats.append(ops.read_percpu_u64('hydra_stats', i))

                # Compute deltas
                deltas = [curr_stats[i] - prev_stats[i] for i in range(7)]

                # Log XDP stats periodically
                if poll_count % 6 == 0:  # Every 60s (poll_count increments every 10s)
                    logger.info(
                        f"XDP stats: total={curr_stats[0]} passed={curr_stats[1]} "
                        f"dropped={curr_stats[2]} blocklisted={curr_stats[4]} "
                        f"score_drops={curr_stats[6]} "
                        f"(+{deltas[0]} +{deltas[2]}drop +{deltas[4]}bl +{deltas[6]}sc)"
                    )

                # Generate events for blocklist hits, rate drops, score drops
                now = datetime.now(timezone.utc)
                ts = now.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

                # If there are new blocklist hits, read high_rate_ips for details
                if deltas[4] > 0 or deltas[5] > 0 or deltas[6] > 0:
                    # Read high_rate_ips for source IPs
                    hr_id = ops.find_map_by_name('high_rate_ips')
                    if hr_id:
                        entries = ops.map_dump(hr_id)
                        for key_bytes, val_bytes in entries:
                            if len(key_bytes) >= 4:
                                src_ip = str(ipaddress.IPv4Address(key_bytes[:4]))
                                rate = struct.unpack('<Q', val_bytes[:8])[0] if len(val_bytes) >= 8 else 0
                                event_buffer.append({
                                    'timestamp_ns': 0,
                                    'src_ip': src_ip,
                                    'dst_ip': '0.0.0.0',
                                    'src_port': 0,
                                    'dst_port': 0,
                                    'proto': 0,
                                    'event_type': 'alert',
                                    'reason': 'rate_exceeded',
                                    'tcp_flags': 0,
                                    'rate_pps': rate,
                                })
                                drop_counts[src_ip] += 1

                prev_stats = curr_stats

        except Exception as e:
            logger.debug(f"Poll error: {e}")

        # Flush events
        if time.monotonic() - last_flush >= FLUSH_INTERVAL:
            flush_events()

        poll_count += 1
        time.sleep(10)


# ============================================================================
# MAIN
# ============================================================================

def main():
    logger.info("HYDRA Event Consumer starting...")
    logger.info(f"XDP interface: {XDP_INTERFACE}")
    logger.info(f"Flush interval: {FLUSH_INTERVAL}s")
    logger.info(f"Discord alerts: {'enabled' if DISCORD_WEBHOOK else 'disabled'}")

    if not CH_PASSWORD:
        logger.warning("CLICKHOUSE_PASSWORD not set, ClickHouse logging disabled")

    # Try RINGBUF mmap first, fall back to poll mode
    if not run_ringbuf_consumer():
        run_poll_consumer()

    # Final flush
    flush_events()
    logger.info("HYDRA Event Consumer shutting down")


if __name__ == '__main__':
    main()
