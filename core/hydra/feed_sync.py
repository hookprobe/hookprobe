#!/usr/bin/env python3
"""
HookProbe HYDRA Feed Sync Daemon
=================================

Downloads threat intelligence feeds and pushes CIDRs to the XDP
blocklist/allowlist BPF maps via bpf_map_ops (raw syscalls). Also logs sync status to ClickHouse.

Feeds (free/open):
  - Spamhaus DROP + EDROP (hijacked/spam CIDRs)
  - FireHOL Level 1 (aggregated blocklist)
  - Emerging Threats compromised IPs
  - Feodo Tracker (banking trojan C2s)

Usage:
    python3 feed_sync.py [--interval 3600] [--xdp-interface dummy-mirror]

Architecture:
    Internet feeds -> parse CIDRs -> deduplicate -> BPF map update
    Also: -> ClickHouse hydra_feed_sync (status log)
          -> PostgreSQL threat_feeds (config/metadata)
"""

import os
import sys
import time
import json
import re
import signal
import logging
import hashlib
import ipaddress
import subprocess
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [FEED_SYNC] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

# ClickHouse connection
CH_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CH_PORT = os.environ.get('CLICKHOUSE_PORT', '8123')
CH_DB = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
CH_USER = os.environ.get('CLICKHOUSE_USER', 'ids')
CH_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')

# XDP interface where hydra program is loaded
XDP_INTERFACE = os.environ.get('XDP_INTERFACE', 'dummy-mirror')

# Sync interval in seconds (default: 60 minutes)
SYNC_INTERVAL = int(os.environ.get('SYNC_INTERVAL', '3600'))

# Trusted CIDRs (always in allowlist, never blocked)
TRUSTED_CIDRS = [
    # Owner's ISP (Vodafone Romania)
    '213.233.111.0/24',
    '46.97.153.0/24',
    # Anthropic (Claude Code SSH)
    '160.79.104.0/23',
    # Mitel Networks
    '209.249.57.0/24',
    # Cloudflare
    '173.245.48.0/20',
    '103.21.244.0/22',
    '103.22.200.0/22',
    '103.31.4.0/22',
    '141.101.64.0/18',
    '108.162.192.0/18',
    '190.93.240.0/20',
    '188.114.96.0/20',
    '197.234.240.0/22',
    '198.41.128.0/17',
    '162.158.0.0/15',
    '104.16.0.0/13',
    '104.24.0.0/14',
    '172.64.0.0/13',
    '131.0.72.0/22',
    # OCI metadata + internal
    '169.254.0.0/16',
    # RFC1918 private
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
    # Loopback
    '127.0.0.0/8',
    # Ubuntu archive servers
    '91.189.88.0/21',
    '185.125.188.0/22',
    # Google DNS
    '8.8.8.0/24',
    '8.8.4.0/24',
]

# Feed definitions
FEEDS = [
    {
        'name': 'spamhaus_drop',
        'url': 'https://www.spamhaus.org/drop/drop.txt',
        'format': 'spamhaus',
        'description': 'Spamhaus DROP - hijacked netblocks',
    },
    {
        'name': 'spamhaus_edrop',
        'url': 'https://www.spamhaus.org/drop/edrop.txt',
        'format': 'spamhaus',
        'description': 'Spamhaus EDROP - extended hijacked netblocks',
    },
    {
        'name': 'firehol_level1',
        'url': 'https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset',
        'format': 'netset',
        'description': 'FireHOL Level 1 - aggregated blocklist',
    },
    {
        'name': 'emerging_threats',
        'url': 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
        'format': 'plaintext',
        'description': 'Emerging Threats compromised IPs',
    },
    {
        'name': 'feodo_tracker',
        'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
        'format': 'comment_hash',
        'description': 'Feodo Tracker C2 IPs (banking trojans)',
    },
    {
        'name': 'greensnow',
        'url': 'https://blocklist.greensnow.co/greensnow.txt',
        'format': 'plaintext',
        'description': 'GreenSnow blocklist (active attackers)',
    },
    {
        'name': 'urlhaus_c2',
        'url': 'https://urlhaus.abuse.ch/downloads/text_online/',
        'format': 'urlhaus',
        'description': 'URLhaus malware distribution IPs',
    },
    {
        'name': 'sslbl_botnet_c2',
        'url': 'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
        'format': 'comment_hash',
        'description': 'SSL Blacklist - botnet C2 servers',
    },
    {
        'name': 'cins_army',
        'url': 'https://cinsscore.com/list/ci-badguys.txt',
        'format': 'plaintext',
        'description': 'CI Army - sentinels active threat intelligence',
    },
    {
        'name': 'blocklist_de',
        'url': 'https://lists.blocklist.de/lists/all.txt',
        'format': 'plaintext',
        'description': 'blocklist.de - IPs attacking Honeypots/DNSBL/SSH',
    },
]

# ============================================================================
# GLOBAL STATE
# ============================================================================

running = True
prev_blocklist: Set[str] = set()  # Previous blocklist for diff tracking

def signal_handler(sig, frame):
    global running
    logger.info(f"Received signal {sig}, shutting down...")
    running = False

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

# ============================================================================
# FEED PARSERS
# ============================================================================

def _extract_ip_from_url(url: str) -> Optional[str]:
    """Extract IP address from a URL (e.g., http://1.2.3.4:8080/path)."""
    try:
        # Strip protocol
        host = url.split('://', 1)[-1].split('/')[0].split(':')[0]
        ipaddress.ip_address(host)
        return host
    except ValueError:
        return None


def parse_feed(content: str, fmt: str) -> Set[str]:
    """Parse feed content into a set of CIDR strings."""
    cidrs = set()

    for line in content.splitlines():
        line = line.strip()

        # Skip empty lines and comments
        if not line:
            continue

        if fmt == 'spamhaus':
            # Format: "CIDR ; SBLnnnnn"
            if line.startswith(';'):
                continue
            parts = line.split(';')
            cidr = parts[0].strip()
        elif fmt == 'netset':
            # Format: one CIDR per line, # comments
            if line.startswith('#'):
                continue
            cidr = line
        elif fmt == 'comment_hash':
            # Format: one IP per line, # comments
            if line.startswith('#'):
                continue
            cidr = line
        elif fmt == 'plaintext':
            # Format: one IP/CIDR per line, # comments
            if line.startswith('#'):
                continue
            cidr = line
        elif fmt == 'urlhaus':
            # Format: URLs with IP hosts (extract IP from URL)
            if line.startswith('#'):
                continue
            ip = _extract_ip_from_url(line)
            if ip:
                cidr = ip
            else:
                continue
        else:
            continue

        # Validate and normalize
        try:
            if '/' in cidr:
                net = ipaddress.ip_network(cidr, strict=False)
            else:
                net = ipaddress.ip_network(f"{cidr}/32", strict=False)

            # Only IPv4 for now (XDP program uses IPv4)
            if isinstance(net, ipaddress.IPv4Network):
                # Skip private/reserved ranges
                if not net.is_private and not net.is_reserved and not net.is_loopback:
                    cidrs.add(str(net))
        except ValueError:
            continue

    return cidrs


def download_feed(feed: dict) -> Tuple[Set[str], Optional[str]]:
    """Download and parse a single feed. Returns (cidrs, error_message)."""
    try:
        req = Request(feed['url'], headers={
            'User-Agent': 'HookProbe-HYDRA/1.0 (threat-feed-sync)'
        })
        with urlopen(req, timeout=30) as resp:
            content = resp.read().decode('utf-8', errors='replace')

        cidrs = parse_feed(content, feed['format'])
        return cidrs, None

    except (URLError, HTTPError) as e:
        return set(), str(e)
    except Exception as e:
        return set(), f"Unexpected error: {e}"


# ============================================================================
# BPF MAP MANAGEMENT (via raw syscalls, no bpftool dependency)
# ============================================================================

from bpf_map_ops import get_bpf_ops

def find_map_id(map_name: str) -> Optional[int]:
    """Find BPF map ID by name using raw BPF syscalls."""
    try:
        return get_bpf_ops().find_map_by_name(map_name)
    except Exception as e:
        logger.debug(f"find_map_id error: {e}")
        return None


def update_xdp_map_batch(map_name: str, cidrs: Set[str], value: int = 1) -> int:
    """Update an LPM_TRIE BPF map with a batch of CIDRs.

    Returns count of entries added.
    """
    try:
        ops = get_bpf_ops()
        success, errors = ops.update_lpm_trie_batch(map_name, cidrs, value)
        if errors > 0:
            logger.warning(f"Map '{map_name}': {success} added, {errors} errors")
        return success
    except Exception as e:
        logger.warning(f"Cannot update BPF map '{map_name}': {e}")
        return 0


def update_allowlist() -> int:
    """Push trusted CIDRs to the XDP allowlist map."""
    return update_xdp_map_batch('allowlist', set(TRUSTED_CIDRS), value=1)


# ============================================================================
# CLICKHOUSE LOGGING
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

    except Exception as e:
        logger.error(f"ClickHouse query error: {e}")
        return None


def log_feed_sync(feed_name: str, feed_url: str, entries_count: int,
                   new_entries: int, removed_entries: int,
                   status: str, duration_ms: int, error_msg: str = ''):
    """Log feed sync result to ClickHouse."""
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

    # Escape single quotes in error message
    error_msg_safe = error_msg.replace("'", "\\'").replace("\\", "\\\\")[:500]
    feed_url_safe = feed_url.replace("'", "\\'")

    query = f"""INSERT INTO {CH_DB}.hydra_feed_sync
        (timestamp, feed_name, feed_url, entries_count, new_entries,
         removed_entries, status, sync_duration_ms, error_message)
        VALUES ('{now}', '{feed_name}', '{feed_url_safe}', {entries_count},
                {new_entries}, {removed_entries}, '{status}',
                {duration_ms}, '{error_msg_safe}')"""

    ch_query(query)


# ============================================================================
# MAIN SYNC LOOP
# ============================================================================

def sync_all_feeds() -> dict:
    """Download all feeds and update XDP maps. Returns summary stats."""
    global prev_blocklist

    all_cidrs: Set[str] = set()
    feed_results = []

    # Download and parse each feed
    for feed in FEEDS:
        start_time = time.monotonic()
        cidrs, error = download_feed(feed)
        duration_ms = int((time.monotonic() - start_time) * 1000)

        if error:
            logger.warning(f"Feed '{feed['name']}' failed: {error}")
            log_feed_sync(
                feed['name'], feed['url'], 0, 0, 0,
                'error', duration_ms, error
            )
            feed_results.append({
                'name': feed['name'],
                'status': 'error',
                'entries': 0,
                'error': error,
            })
        else:
            new_entries = len(cidrs - prev_blocklist) if prev_blocklist else len(cidrs)
            removed_entries = len(prev_blocklist - cidrs) if prev_blocklist else 0

            logger.info(f"Feed '{feed['name']}': {len(cidrs)} CIDRs "
                       f"(+{new_entries} new, -{removed_entries} removed)")
            log_feed_sync(
                feed['name'], feed['url'], len(cidrs), new_entries,
                removed_entries, 'success', duration_ms
            )
            feed_results.append({
                'name': feed['name'],
                'status': 'success',
                'entries': len(cidrs),
            })
            all_cidrs.update(cidrs)

    # Remove trusted CIDRs from blocklist (safety check)
    trusted_nets = set()
    for cidr in TRUSTED_CIDRS:
        try:
            trusted_nets.add(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            pass

    safe_cidrs = set()
    for cidr in all_cidrs:
        try:
            block_net = ipaddress.ip_network(cidr, strict=False)
            overlap = False
            for trusted in trusted_nets:
                if block_net.overlaps(trusted):
                    logger.warning("Skipping blocklist CIDR %s — overlaps a trusted network", cidr)
                    overlap = True
                    break
            if not overlap:
                safe_cidrs.add(cidr)
        except ValueError:
            pass

    # Update XDP maps
    blocklist_count = update_xdp_map_batch('blocklist', safe_cidrs, value=1)
    allowlist_count = update_allowlist()

    prev_blocklist = safe_cidrs

    summary = {
        'total_cidrs': len(safe_cidrs),
        'blocklist_loaded': blocklist_count,
        'allowlist_loaded': allowlist_count,
        'feeds': feed_results,
    }

    logger.info(f"Sync complete: {len(safe_cidrs)} blocklist CIDRs, "
               f"{allowlist_count} allowlist entries, "
               f"{blocklist_count} pushed to XDP")

    return summary


def main():
    logger.info("HYDRA Feed Sync starting...")
    logger.info(f"XDP interface: {XDP_INTERFACE}")
    logger.info(f"Sync interval: {SYNC_INTERVAL}s")
    logger.info(f"Trusted CIDRs: {len(TRUSTED_CIDRS)}")
    logger.info(f"Feeds configured: {len(FEEDS)}")

    if not CH_PASSWORD:
        logger.warning("CLICKHOUSE_PASSWORD not set, ClickHouse logging disabled")

    # Initial sync
    sync_all_feeds()

    # Periodic sync loop
    while running:
        for _ in range(SYNC_INTERVAL):
            if not running:
                break
            time.sleep(1)

        if running:
            try:
                sync_all_feeds()
            except Exception as e:
                logger.error(f"Sync cycle error: {e}")

    logger.info("HYDRA Feed Sync shutting down")


if __name__ == '__main__':
    main()
