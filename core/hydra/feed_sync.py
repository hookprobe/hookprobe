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
import threading
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

# Phase Q — Agency adoption for the LPM-trie batch updates that mutate
# XDP allowlist/blocklist BPF maps. Bypassing this would let a poisoned
# feed silently allowlist attacker CIDRs or blocklist legitimate ones.
from core.agency_shim import ActionKind as _AK_Q, agency_gated as _gated_Q

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
from core.common.clickhouse import ch_query_with_body as ch_query

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
    # Public DNS resolvers (upstream resolvers — the node queries these, so it
    # sees response traffic). These RESOLVER anycast ranges are NOT covered by
    # the Cloudflare CDN ranges above; without them the resolver IPs get
    # XDP-blocked once SENTINEL false-flags them. Keep in sync with
    # core/hydra/trusted_networks.py.
    '1.1.1.0/24',        # Cloudflare DNS
    '1.0.0.0/24',        # Cloudflare DNS
    '9.9.9.0/24',        # Quad9
    '149.112.112.0/24',  # Quad9 secondary
    '208.67.222.0/24',   # OpenDNS
    '208.67.220.0/24',   # OpenDNS
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


# Phase Q — Agency-gated batch update. We gate at the BATCH boundary
# (one decision per call) rather than per-CIDR — the per-CIDR
# alternative would be N gatekeeper roundtrips per blocklist refresh
# (typically 50K entries) which would be a startup-killer. Subject is
# the map name + entry count so audit shows the blast.
# blocklist/allowlist live as SEPARATE per-program LPM_TRIE instances: the
# mirror path (xdp_hydra: blocklist/allowlist, used for DETECTION) and the WAN
# path (xdp_synwall: sw_blocklist/sw_allowlist, used for ENFORCEMENT). They are
# not pinned-shared. The feed previously populated ONLY the mirror map, so
# xdp_synwall's maps were empty — arming enforce mode on the WAN would have
# dropped nothing. Push to BOTH so enforcement is ready when the mode is armed.
# Populating sw_* is a no-op while xdp_synwall stays in monitor mode → safe now.
_WAN_MAP_TWIN = {'blocklist': 'sw_blocklist', 'allowlist': 'sw_allowlist'}


@_gated_Q(
    kind=_AK_Q.UPDATE_ALLOWLIST,
    proposer="hydra.feed_sync",
    subject_fn=lambda map_name, cidrs, value=1: f"map:{map_name}:n={len(cidrs)}",
)
def update_xdp_map_batch(map_name: str, cidrs: Set[str], value: int = 1) -> int:
    """Update an LPM_TRIE BPF map with a batch of CIDRs (+ its WAN twin).

    Returns count of entries added to the primary (mirror-path) map.
    """
    try:
        ops = get_bpf_ops()
        success, errors = ops.update_lpm_trie_batch(map_name, cidrs, value)
        if errors > 0:
            logger.warning(f"Map '{map_name}': {success} added, {errors} errors")

        # Mirror the same CIDRs to the WAN-path enforcement map. Best-effort:
        # absent/empty when xdp_synwall isn't loaded, which must NOT break the
        # primary push.
        twin = _WAN_MAP_TWIN.get(map_name)
        if twin and cidrs:
            try:
                tw_ok, tw_err = ops.update_lpm_trie_batch(twin, cidrs, value)
                if tw_ok:
                    logger.debug(f"Mirrored {tw_ok} CIDRs to WAN map '{twin}'")
                elif tw_err:
                    logger.debug(f"WAN map '{twin}': {tw_err} errors (xdp_synwall loaded?)")
            except Exception as e:
                logger.debug(f"WAN map '{twin}' update skipped: {e}")

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

def log_feed_sync(feed_name: str, feed_url: str, entries_count: int,
                   new_entries: int, removed_entries: int,
                   status: str, duration_ms: int, error_msg: str = ''):
    """Log feed sync result to ClickHouse."""
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

    def _ch_escape(s: str) -> str:
        """Escape for ClickHouse SQL: backslash FIRST, then quote."""
        return s.replace('\\', '\\\\').replace("'", "\\'")

    # Escape all external strings before SQL interpolation
    feed_name_safe = _ch_escape(feed_name)[:100]
    feed_url_safe = _ch_escape(feed_url)[:500]
    status_safe = _ch_escape(status)[:20]
    error_msg_safe = _ch_escape(error_msg)[:500]

    query = f"""INSERT INTO {CH_DB}.hydra_feed_sync
        (timestamp, feed_name, feed_url, entries_count, new_entries,
         removed_entries, status, sync_duration_ms, error_message)
        VALUES ('{now}', '{feed_name_safe}', '{feed_url_safe}', {entries_count},
                {new_entries}, {removed_entries}, '{status_safe}',
                {duration_ms}, '{error_msg_safe}')"""

    ch_query(query)


# ============================================================================
# NEURAL-KERNEL: Cognitive Defense Block Sync
# ============================================================================

# Autonomous block producers whose hydra_blocks entries this function pushes
# to the XDP LPM_TRIE blocklist. Previously only 'neural_kernel' was synced,
# so the anomaly_detector ('ml') and AEGIS ('aegis') block paths wrote rows
# that nothing ever enforced — a silent dead-end in the autonomous loop.
COGNITIVE_BLOCK_SOURCES = ('neural_kernel', 'ml', 'aegis', 'cno_organism')


def sync_cognitive_blocks() -> Tuple[Set[str], int]:
    """Read active autonomous-defense blocks from ClickHouse and convert to CIDRs.

    Producers write blocks to hydra_blocks with a source tag (neural_kernel,
    ml, aegis, cno_organism). This function reads all of them and converts
    them to /32 CIDRs for XDP LPM_TRIE enforcement.

    Also cleans up expired blocks (auto_expired=1 or past TTL).

    Returns (active_cidrs, expired_count).
    """
    if not CH_PASSWORD:
        return set(), 0

    cognitive_cidrs: Set[str] = set()
    expired_count = 0
    sources_sql = ', '.join(f"'{s}'" for s in COGNITIVE_BLOCK_SOURCES)

    try:
        # Read active autonomous blocks (not yet expired) across all sources.
        # NB: this module's ch_query() does NOT append a format, so the result
        # defaults to TabSeparated. We parse rows as JSON below, so the query
        # must request JSONEachRow explicitly — without it every row fails to
        # parse and the sync silently returns zero cognitive blocks (the bug
        # that kept ml/aegis/neural_kernel blocks from ever reaching XDP via
        # feed_sync; the CNO's direct BPF writes were the only path working).
        query = f"""
            SELECT
                IPv4NumToString(src_ip) AS ip,
                source,
                duration_seconds,
                toUnixTimestamp(timestamp) AS created_ts
            FROM {CH_DB}.hydra_blocks
            WHERE source IN ({sources_sql})
              AND auto_expired = 0
              AND timestamp >= now() - INTERVAL 24 HOUR
            FORMAT JSONEachRow
        """
        result = ch_query(query)
        if result:
            now_unix = time.time()
            for line in result.strip().split('\n'):
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    ip = row.get('ip', '')
                    src = str(row.get('source', '')) or 'neural_kernel'
                    duration = int(row.get('duration_seconds', 3600))
                    created = float(row.get('created_ts', 0))

                    if not ip or src not in COGNITIVE_BLOCK_SOURCES:
                        continue

                    # Check TTL expiry. duration <= 0 means PERMANENT
                    # (types.py:199 / LLM "permanent" hardblocks) — never
                    # auto-expire it. The previous code treated 0 as
                    # already-expired, so the organism's most confident blocks
                    # were marked auto_expired=1 the same cycle and never
                    # reached XDP. The 24h read window above bounds re-pushing.
                    if duration > 0 and created > 0 and (now_unix - created) > duration:
                        # TTL expired — mark as expired (match the row's source)
                        expire_query = (
                            f"ALTER TABLE {CH_DB}.hydra_blocks "
                            f"UPDATE auto_expired = 1 "
                            f"WHERE src_ip = IPv4StringToNum('{ip}') "
                            f"AND source = '{src}' AND auto_expired = 0"
                        )
                        ch_query(expire_query)  # this module's ch_query has no fmt kwarg
                        expired_count += 1
                    else:
                        # Still active — add to blocklist
                        cognitive_cidrs.add(f"{ip}/32")
                except (json.JSONDecodeError, KeyError, ValueError):
                    continue

        if cognitive_cidrs:
            logger.info(f"Cognitive blocks: {len(cognitive_cidrs)} active, {expired_count} expired")

    except Exception as e:
        logger.error(f"Cognitive block sync error: {e}")

    return cognitive_cidrs, expired_count


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

    # Merge autonomous-defense blocks (ml/aegis/neural_kernel/cno_organism).
    # Apply the SAME trusted-network overlap filter as the external feeds, so
    # an autonomous block on an internal/trusted IP (e.g. an anomaly-detector
    # false positive on an RFC1918 host) never reaches the XDP blocklist.
    cognitive_cidrs, cognitive_expired = sync_cognitive_blocks()
    cognitive_safe = 0
    for cidr in cognitive_cidrs:
        try:
            block_net = ipaddress.ip_network(cidr, strict=False)
            if any(block_net.overlaps(t) for t in trusted_nets):
                logger.warning("Skipping cognitive block %s — overlaps a trusted network", cidr)
                continue
            safe_cidrs.add(cidr)
            cognitive_safe += 1
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
        'cognitive_blocks': cognitive_safe,
        'cognitive_found': len(cognitive_cidrs),
        'cognitive_expired': cognitive_expired,
        'feeds': feed_results,
    }

    logger.info(f"Sync complete: {len(safe_cidrs)} blocklist CIDRs "
               f"({cognitive_safe}/{len(cognitive_cidrs)} cognitive pushed), "
               f"{allowlist_count} allowlist entries, "
               f"{blocklist_count} pushed to XDP"
               + (f", {cognitive_expired} expired" if cognitive_expired else ""))

    return summary


def _start_peer_transport_consumer():
    """Ch 4a/b §P2 — bridge the IoCs table to XDP within ~5s.

    Runs the peer-transport consumer in a daemon thread inside the
    feed container (which has CAP_BPF + SYS_ADMIN). The producer
    (qsecbit, in another container) INSERTs to iocs; this loop polls
    the table every 5s and pushes any new IPs to the XDP blocklist
    map. Closes the gap where self-detected IoCs sat in the table
    forever without ever reaching the kernel filter.
    """
    try:
        # Add /app to sys.path so the cno.peer_transport import resolves
        # inside the fts-hydra container. Containerfile.hydra bakes the cno
        # package at /app/cno (and core at /app/core); WORKDIR is /app.
        import sys as _sys
        if "/app" not in _sys.path:
            _sys.path.insert(0, "/app")
        from cno.peer_transport import get_peer_transport
        # Reuse the small JSON-parser query helper from this module.
        def _ch_query_json(sql):
            raw = ch_query(sql)
            if not raw:
                return []
            return [
                __import__("json").loads(line)
                for line in raw.strip().splitlines() if line
            ]
        transport = get_peer_transport(ch_insert=lambda *_a, **_kw: True)
        threading.Thread(
            target=transport.watch_iocs_loop,
            args=(_ch_query_json,),
            kwargs={"poll_interval_s": float(os.environ.get("PEER_POLL_S", "5.0"))},
            daemon=True,
            name="peer-iocs-watcher",
        ).start()
        logger.info("peer_transport iocs-watcher thread started")
    except Exception as e:
        logger.warning("peer_transport startup failed: %s", e)


def _build_trusted_nets() -> Set:
    """Build the set of trusted ip_network objects from TRUSTED_CIDRS."""
    nets = set()
    for cidr in TRUSTED_CIDRS:
        try:
            nets.add(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            pass
    return nets


def cognitive_sync_once() -> int:
    """Ch 28 Q1 — fast path: push autonomous-defense (cognitive) blocks to XDP
    without waiting for the hourly full feed sync.

    The ML/anomaly/AEGIS/CNO detectors write blocks to hydra_blocks, but those
    only reached the XDP blocklist once per SYNC_INTERVAL (default 3600s) via
    sync_all_feeds(). That gave a worst-case ~1h detect→enforce tail for every
    block that did not go through the CNO's own direct BPF write. This applies
    the SAME trusted-overlap safety filter as the full sync, then pushes just
    the cognitive CIDRs (LPM_TRIE updates are additive, so feed CIDRs already in
    the map are untouched). Returns count pushed to XDP.
    """
    cognitive_cidrs, _expired = sync_cognitive_blocks()
    if not cognitive_cidrs:
        return 0
    trusted_nets = _build_trusted_nets()
    safe = set()
    for cidr in cognitive_cidrs:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            if any(net.overlaps(t) for t in trusted_nets):
                logger.warning("Skipping cognitive block %s — overlaps a trusted network", cidr)
                continue
            safe.add(cidr)
        except ValueError:
            pass
    if not safe:
        return 0
    return update_xdp_map_batch('blocklist', safe, value=1)


def _start_cognitive_sync_consumer():
    """Run cognitive_sync_once() on a fast loop in a daemon thread.

    Mirrors _start_peer_transport_consumer(): the feed container holds
    CAP_BPF + SYS_ADMIN, so it can write the XDP map. Interval is bounded
    to a 15s floor to avoid hammering ClickHouse.
    """
    interval = max(15, int(os.environ.get('COGNITIVE_SYNC_INTERVAL', '60')))

    def _loop():
        while running:
            for _ in range(interval):
                if not running:
                    return
                time.sleep(1)
            try:
                n = cognitive_sync_once()
                if n:
                    logger.info("cognitive fast-sync: %d block(s) pushed to XDP", n)
            except Exception as e:
                logger.warning("cognitive fast-sync error: %s", e)

    threading.Thread(target=_loop, daemon=True, name="cognitive-fast-sync").start()
    logger.info("cognitive fast-sync thread started (interval=%ds)", interval)


def main():
    logger.info("HYDRA Feed Sync starting...")
    logger.info(f"XDP interface: {XDP_INTERFACE}")
    logger.info(f"Sync interval: {SYNC_INTERVAL}s")
    logger.info(f"Trusted CIDRs: {len(TRUSTED_CIDRS)}")
    logger.info(f"Feeds configured: {len(FEEDS)}")

    if not CH_PASSWORD:
        logger.warning("CLICKHOUSE_PASSWORD not set, ClickHouse logging disabled")

    # Ch 4a/b §P2 — start the iocs→XDP consumer thread before kicking
    # off the feed sync. This lets node-A IoCs reach the kernel filter
    # in seconds rather than waiting for the next hourly feed cycle.
    _start_peer_transport_consumer()

    # Ch 28 Q1 — fast cognitive-block sync (every COGNITIVE_SYNC_INTERVAL,
    # default 60s) so ML/anomaly/AEGIS/CNO blocks reach XDP in ≤60s instead
    # of waiting up to a full SYNC_INTERVAL (3600s).
    _start_cognitive_sync_consumer()

    # Initial sync
    sync_all_feeds()

    # Persist XDP enforce mode across reboots. sw_config[0] is in-kernel BPF
    # state lost on reboot; setup-vrf reloads xdp_synwall in its MONITOR default,
    # so without this the enforce posture silently reverts to observe. Gated by
    # SYNWALL_ENFORCE (set in the IDS compose) so the posture is explicit and
    # revertible. Armed AFTER the initial sync so sw_blocklist/sw_allowlist are
    # populated first — never enforce against empty maps (would drop nothing and
    # could drop trusted traffic before the allowlist lands).
    if os.environ.get('SYNWALL_ENFORCE', '0') == '1':
        try:
            ok = get_bpf_ops().update_config('sw_config', 0, 1)
            logger.info("XDP enforce mode ARMED on xdp_synwall (sw_config[0]=1): %s", ok)
        except Exception as e:
            logger.warning("Failed to arm XDP enforce mode: %s", e)

    # Per-service readiness (Ch 22 §6.2) — expose /healthz so the watchdog and
    # dashboards see real readiness, not just process-alive.
    try:
        from core.common.health import HealthReporter, start_health_server
        _health = HealthReporter(service="hydra-feed", stale_threshold_s=7200)
        _health.set_model_loaded(True)  # no ML model to gate readiness on
        start_health_server(_health, port=int(os.environ.get("HEALTH_PORT", "9304")))
    except Exception as _e:
        _health = None
        logger.warning("health server start failed: %s", _e)

    # Periodic sync loop
    while running:
        if _health:
            _health.bump_ingest()
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
