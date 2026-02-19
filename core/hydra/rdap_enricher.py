#!/usr/bin/env python3
"""
HookProbe HYDRA RDAP Enricher
================================

Background daemon that queries RIPE RDAP for IP ownership data, classifies
IPs (datacenter/ISP/CDN/VPN/Tor), computes weighted threat scores, and
syncs results to the XDP ip_scores BPF map for kernel-level filtering.

Data flow:
  ClickHouse hydra_events  ──┐
  BPF ip_state map dump ─────┼─> deduplicate -> RDAP query -> classify
                              │   -> score -> ClickHouse rdap_cache
                              │   -> PostgreSQL ip_reputation
                              │   -> XDP ip_scores BPF map

Also runs adaptive sampling controller thread that adjusts XDP sampling
rate based on CPU load.

Usage:
    python3 rdap_enricher.py
"""

import os
import sys
import time
import json
import struct
import signal
import logging
import socket
import subprocess
import threading
import ipaddress
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Set, Tuple
from collections import OrderedDict
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [ENRICHER] %(levelname)s: %(message)s'
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

PG_HOST = os.environ.get('POSTGRES_HOST', '172.30.0.30')
PG_PORT = os.environ.get('POSTGRES_PORT', '5432')
PG_DB = os.environ.get('POSTGRES_DB', 'hookprobe')
PG_USER = os.environ.get('POSTGRES_USER', 'hookprobe')
PG_PASSWORD = os.environ.get('POSTGRES_PASSWORD', '')

XDP_INTERFACE = os.environ.get('XDP_INTERFACE', 'dummy-mirror')
SCORE_DROP_THRESHOLD = int(os.environ.get('SCORE_DROP_THRESHOLD', '100'))
RDAP_RATE_LIMIT = int(os.environ.get('RDAP_RATE_LIMIT', '10'))  # queries/sec
ENRICHER_INTERVAL = int(os.environ.get('ENRICHER_INTERVAL', '30'))  # seconds

# RDAP endpoints (RIPE covers all via redirect, but we try regional first)
RDAP_BASE_URL = 'https://rdap.db.ripe.net/ip/'

# ============================================================================
# CLASSIFICATION KEYWORDS
# ============================================================================

DATACENTER_KEYWORDS = [
    'hosting', 'cloud', 'server', 'vps', 'dedicated', 'colocation', 'colo',
    'hetzner', 'ovh', 'digitalocean', 'linode', 'vultr', 'contabo',
    'aws', 'amazon', 'google cloud', 'gcp', 'azure', 'microsoft',
    'oracle', 'alibaba', 'tencent', 'scaleway', 'upcloud', 'kamatera',
    'leaseweb', 'rackspace', 'equinix', 'packet', 'choopa',
    'serverius', 'i3d', 'worldstream', 'hostinger', 'ionos',
]

VPN_KEYWORDS = [
    'vpn', 'proxy', 'tunnel', 'anonymiz', 'privacy',
    'mullvad', 'nordvpn', 'expressvpn', 'surfshark', 'cyberghost',
    'pia', 'private internet', 'protonvpn', 'ipvanish', 'torguard',
    'windscribe', 'hide.me', 'purevpn',
]

CDN_KEYWORDS = [
    'cloudflare', 'akamai', 'fastly', 'cdn', 'imperva', 'incapsula',
    'stackpath', 'keycdn', 'bunny', 'cloudfront',
]

TOR_KEYWORDS = [
    'tor', 'exit', 'relay', 'chaoscomputer', 'torservers',
    'dfri', 'noreply', 'nos-oignons',
]

EDU_KEYWORDS = ['university', 'education', 'academic', 'research', '.edu']
GOV_KEYWORDS = ['government', 'federal', 'military', '.gov', '.mil']

# Networks to skip (never query RDAP for these)
SKIP_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('224.0.0.0/4'),      # Multicast
    ipaddress.ip_network('255.255.255.255/32'),
]

# Scoring weights
SCORE_DATACENTER = 30
SCORE_VPN = 20
SCORE_TOR = 40
SCORE_THREAT_FEED = 50
SCORE_RATE_ALERT = 15
SCORE_PER_BLOCK = 10
SCORE_BLOCK_CAP = 50
SCORE_CDN = -20
SCORE_EDU = -10
SCORE_GOV = -10

# Tag bitfield (matches xdp_hydra.c struct ip_score_val)
TAG_VPN = 0x01
TAG_DATACENTER = 0x02
TAG_TOR = 0x04
TAG_PROXY = 0x08

# ============================================================================
# GLOBAL STATE
# ============================================================================

shutdown_event = threading.Event()

def signal_handler(sig, frame):
    logger.info(f"Received signal {sig}, shutting down...")
    shutdown_event.set()

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


class LRUCache:
    """Simple LRU cache with TTL."""

    def __init__(self, maxsize: int = 50000, ttl_seconds: int = 86400):
        self._cache: OrderedDict = OrderedDict()
        self._maxsize = maxsize
        self._ttl = ttl_seconds

    def get(self, key: str) -> Optional[dict]:
        if key in self._cache:
            entry = self._cache[key]
            if time.monotonic() - entry['ts'] < self._ttl:
                self._cache.move_to_end(key)
                return entry['data']
            else:
                del self._cache[key]
        return None

    def put(self, key: str, data: dict):
        self._cache[key] = {'data': data, 'ts': time.monotonic()}
        self._cache.move_to_end(key)
        while len(self._cache) > self._maxsize:
            self._cache.popitem(last=False)

    def __len__(self):
        return len(self._cache)


# Local RDAP cache
rdap_cache = LRUCache(maxsize=50000, ttl_seconds=86400)

# ============================================================================
# CLICKHOUSE CLIENT
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
        logger.error(f"ClickHouse error: {e} - {body}")
        return None
    except Exception as e:
        logger.error(f"ClickHouse error: {e}")
        return None

# ============================================================================
# POSTGRESQL CLIENT
# ============================================================================

_pg_conn = None
_pg_disabled = False  # Set True after repeated failures to avoid log spam

def get_pg_conn():
    """Get or create PostgreSQL connection."""
    global _pg_conn, _pg_disabled
    if _pg_disabled:
        return None
    if _pg_conn is None or _pg_conn.closed:
        try:
            import psycopg2
            _pg_conn = psycopg2.connect(
                host=PG_HOST, port=PG_PORT, dbname=PG_DB,
                user=PG_USER, password=PG_PASSWORD,
                connect_timeout=3
            )
            _pg_conn.autocommit = True
            logger.info("Connected to PostgreSQL")
        except Exception as e:
            logger.warning(f"PostgreSQL unreachable ({PG_HOST}:{PG_PORT}), disabling PG writes")
            _pg_conn = None
            _pg_disabled = True
    return _pg_conn

def pg_upsert_reputation(ip: str, asn: int, asn_name: str,
                          country: str, score: int, tags: List[str],
                          ip_type: str):
    """Upsert IP reputation data into PostgreSQL."""
    conn = get_pg_conn()
    if not conn:
        return
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO ip_reputation (ip_address, asn, asn_name, country_code, score, tags, last_seen)
                VALUES (%s, %s, %s, %s, %s, %s, NOW())
                ON CONFLICT (ip_address) DO UPDATE SET
                    asn = EXCLUDED.asn,
                    asn_name = EXCLUDED.asn_name,
                    country_code = EXCLUDED.country_code,
                    score = EXCLUDED.score,
                    tags = EXCLUDED.tags,
                    last_seen = NOW(),
                    updated_at = NOW()
            """, (ip, asn, asn_name[:255], country[:2], score, tags))
    except Exception as e:
        logger.error(f"PostgreSQL upsert error for {ip}: {e}")
        # Reset connection on error
        global _pg_conn
        try:
            _pg_conn.close()
        except Exception:
            pass
        _pg_conn = None

# ============================================================================
# BPF MAP INTERACTION (via raw syscalls, no bpftool dependency)
# ============================================================================

from bpf_map_ops import get_bpf_ops

def push_ip_score(ip_str: str, score: int, tags: int) -> bool:
    """Push a single IP score to the XDP ip_scores BPF map."""
    try:
        return get_bpf_ops().update_ip_score('ip_scores', ip_str, score, tags)
    except Exception as e:
        logger.debug(f"push_ip_score error for {ip_str}: {e}")
        return False

# ============================================================================
# RDAP QUERY
# ============================================================================

_rdap_query_times: List[float] = []

def _enforce_rdap_rate_limit():
    """Enforce RIPE RDAP rate limit (max RDAP_RATE_LIMIT queries/sec)."""
    now = time.monotonic()
    # Remove old timestamps
    while _rdap_query_times and now - _rdap_query_times[0] > 1.0:
        _rdap_query_times.pop(0)

    if len(_rdap_query_times) >= RDAP_RATE_LIMIT:
        sleep_time = 1.0 - (now - _rdap_query_times[0])
        if sleep_time > 0:
            time.sleep(sleep_time)

    _rdap_query_times.append(time.monotonic())


def query_rdap(ip: str) -> Optional[dict]:
    """Query RIPE RDAP for IP ownership data."""
    _enforce_rdap_rate_limit()

    try:
        url = f"{RDAP_BASE_URL}{ip}"
        req = Request(url, headers={
            'Accept': 'application/rdap+json',
            'User-Agent': 'HookProbe-HYDRA/1.0 (security research)',
        })
        with urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return data
    except HTTPError as e:
        if e.code == 404:
            logger.debug(f"RDAP 404 for {ip}")
        elif e.code == 429:
            logger.warning("RDAP rate limited, backing off 30s")
            time.sleep(30)
        else:
            logger.debug(f"RDAP HTTP {e.code} for {ip}")
        return None
    except Exception as e:
        logger.debug(f"RDAP query error for {ip}: {e}")
        return None

# ============================================================================
# IP CLASSIFICATION
# ============================================================================

def _extract_names(rdap: dict) -> str:
    """Extract all name/handle strings from RDAP response for classification."""
    parts = []
    parts.append(rdap.get('name', ''))
    parts.append(rdap.get('handle', ''))
    parts.append(rdap.get('type', ''))

    # Entity names
    for entity in rdap.get('entities', []):
        parts.append(entity.get('handle', ''))
        vcards = entity.get('vcardArray', [])
        if len(vcards) > 1:
            for field in vcards[1]:
                if len(field) >= 4 and field[0] == 'fn':
                    parts.append(str(field[3]))

    # Remarks
    for remark in rdap.get('remarks', []):
        parts.append(remark.get('title', ''))
        for desc in remark.get('description', []):
            parts.append(desc)

    return ' '.join(parts).lower()


def _parse_cidr_prefix(rdap: dict) -> Optional[int]:
    """Extract CIDR prefix length from RDAP response."""
    # cidr0_cidrs field
    cidrs = rdap.get('cidr0_cidrs', [])
    if cidrs:
        return cidrs[0].get('length')

    # startAddress + endAddress fallback
    start = rdap.get('startAddress')
    end = rdap.get('endAddress')
    if start and end:
        try:
            net = ipaddress.summarize_address_range(
                ipaddress.IPv4Address(start),
                ipaddress.IPv4Address(end)
            )
            first_net = next(iter(net), None)
            if first_net:
                return first_net.prefixlen
        except Exception:
            pass
    return None


def _extract_asn(rdap: dict) -> Tuple[int, str]:
    """Extract ASN and AS name from RDAP response."""
    # Look in entities for autnum references
    for entity in rdap.get('entities', []):
        handle = entity.get('handle', '')
        # ASN handles are like 'AS12345'
        if handle.upper().startswith('AS') and handle[2:].isdigit():
            return int(handle[2:]), ''

    # Check arin_originas0_originautnums extension
    autnums = rdap.get('arin_originas0_originautnums', [])
    if autnums:
        return autnums[0], ''

    return 0, ''


def _extract_country(rdap: dict) -> str:
    """Extract country code from RDAP response."""
    country = rdap.get('country', '')
    if country and len(country) == 2:
        return country.upper()

    # Check entity addresses
    for entity in rdap.get('entities', []):
        vcards = entity.get('vcardArray', [])
        if len(vcards) > 1:
            for field in vcards[1]:
                if len(field) >= 4 and field[0] == 'adr':
                    # ADR field: last element is usually country
                    addr = field[3] if isinstance(field[3], list) else [field[3]]
                    if addr and isinstance(addr[-1], str) and len(addr[-1]) == 2:
                        return addr[-1].upper()
    return ''


def _extract_abuse_contact(rdap: dict) -> str:
    """Extract abuse contact email from RDAP response."""
    for entity in rdap.get('entities', []):
        roles = entity.get('roles', [])
        if 'abuse' in roles:
            vcards = entity.get('vcardArray', [])
            if len(vcards) > 1:
                for field in vcards[1]:
                    if len(field) >= 4 and field[0] == 'email':
                        return str(field[3])
    return ''


def classify_ip(rdap: dict) -> Tuple[str, int]:
    """Classify IP based on RDAP response.

    Returns (type_str, tags_bitfield).
    """
    names = _extract_names(rdap)
    tags = 0

    # Check order: tor > vpn > cdn > datacenter > edu/gov > isp > unknown
    if any(kw in names for kw in TOR_KEYWORDS):
        tags |= TAG_TOR
        return 'tor', tags

    if any(kw in names for kw in VPN_KEYWORDS):
        tags |= TAG_VPN
        return 'vpn', tags

    if any(kw in names for kw in CDN_KEYWORDS):
        return 'cdn', tags

    if any(kw in names for kw in DATACENTER_KEYWORDS):
        tags |= TAG_DATACENTER
        return 'datacenter', tags

    if any(kw in names for kw in EDU_KEYWORDS):
        return 'edu', tags

    if any(kw in names for kw in GOV_KEYWORDS):
        return 'gov', tags

    # Heuristic: small netblocks (>= /24) tend to be hosting
    prefix = _parse_cidr_prefix(rdap)
    if prefix is not None and prefix >= 24:
        tags |= TAG_DATACENTER
        return 'datacenter', tags

    # Large netblocks (<= /16) tend to be ISPs
    if prefix is not None and prefix <= 16:
        return 'isp', tags

    return 'unknown', tags


def compute_score(ip_type: str, blocked_count: int = 0,
                  rate_alerts: int = 0, in_feed: bool = False) -> int:
    """Compute weighted threat score for an IP."""
    score = 0

    # Type-based scoring
    if ip_type == 'datacenter':
        score += SCORE_DATACENTER
    elif ip_type == 'vpn':
        score += SCORE_VPN
    elif ip_type == 'tor':
        score += SCORE_TOR
    elif ip_type == 'cdn':
        score += SCORE_CDN
    elif ip_type == 'edu':
        score += SCORE_EDU
    elif ip_type == 'gov':
        score += SCORE_GOV

    # Behavioral scoring
    if in_feed:
        score += SCORE_THREAT_FEED
    if rate_alerts > 0:
        score += SCORE_RATE_ALERT
    if blocked_count > 0:
        score += min(blocked_count * SCORE_PER_BLOCK, SCORE_BLOCK_CAP)

    return max(score, 0)  # Floor at 0

# ============================================================================
# DATA SOURCES
# ============================================================================

def get_new_ips_from_clickhouse() -> Set[str]:
    """Get unique source IPs from recent hydra_events not yet in rdap_cache."""
    result = ch_query(
        f"SELECT DISTINCT IPv4NumToString(src_ip) AS ip "
        f"FROM {CH_DB}.hydra_events "
        f"WHERE timestamp >= now() - INTERVAL 5 MINUTE "
        f"AND src_ip NOT IN ("
        f"  SELECT ip FROM {CH_DB}.rdap_cache "
        f"  WHERE queried_at >= now() - INTERVAL 24 HOUR"
        f") "
        f"LIMIT 200 "
        f"FORMAT TabSeparated"
    )
    if not result:
        return set()
    return {line.strip() for line in result.strip().split('\n') if line.strip()}


def get_behavioral_signals(ip: str) -> Tuple[int, int, bool]:
    """Get blocked_count, rate_alerts, and threat_feed presence for an IP."""
    blocked_count = 0
    rate_alerts = 0
    in_feed = False

    # Count blocks in last hour
    result = ch_query(
        f"SELECT count() FROM {CH_DB}.hydra_events "
        f"WHERE src_ip = IPv4StringToNum('{ip}') "
        f"AND action = 'drop' "
        f"AND timestamp >= now() - INTERVAL 1 HOUR "
        f"FORMAT TabSeparated"
    )
    if result and result.strip().isdigit():
        blocked_count = int(result.strip())

    # Count rate alerts in last hour
    result = ch_query(
        f"SELECT count() FROM {CH_DB}.hydra_events "
        f"WHERE src_ip = IPv4StringToNum('{ip}') "
        f"AND action = 'alert' "
        f"AND timestamp >= now() - INTERVAL 1 HOUR "
        f"FORMAT TabSeparated"
    )
    if result and result.strip().isdigit():
        rate_alerts = int(result.strip())

    # Check blocklist (feed presence) via BPF syscall
    try:
        in_feed = get_bpf_ops().lookup_lpm_trie('blocklist', ip)
    except Exception:
        pass

    return blocked_count, rate_alerts, in_feed


def should_skip_ip(ip_str: str) -> bool:
    """Check if IP should be skipped (private, loopback, etc)."""
    try:
        addr = ipaddress.IPv4Address(ip_str)
        for net in SKIP_NETWORKS:
            if addr in net:
                return True
    except Exception:
        return True
    return False

# ============================================================================
# ENRICHMENT PIPELINE
# ============================================================================

def enrich_ip(ip: str) -> Optional[dict]:
    """Full enrichment pipeline for a single IP."""
    if should_skip_ip(ip):
        return None

    # Check local cache
    cached = rdap_cache.get(ip)
    if cached:
        return cached

    # Query RDAP
    rdap_data = query_rdap(ip)
    if not rdap_data:
        # Store a minimal entry to avoid re-querying
        minimal = {
            'ip': ip, 'rdap_type': 'unknown', 'asn': 0, 'asn_name': '',
            'country': '', 'abuse_contact': '', 'cidr_prefix': 0,
            'weighted_score': 0, 'tags': 0,
        }
        rdap_cache.put(ip, minimal)
        return minimal

    # Classify
    ip_type, tags = classify_ip(rdap_data)
    asn, asn_name = _extract_asn(rdap_data)
    country = _extract_country(rdap_data)
    abuse_contact = _extract_abuse_contact(rdap_data)
    cidr_prefix = _parse_cidr_prefix(rdap_data) or 0

    # Get behavioral signals
    blocked_count, rate_alerts, in_feed = get_behavioral_signals(ip)

    # Compute score
    score = compute_score(ip_type, blocked_count, rate_alerts, in_feed)

    result = {
        'ip': ip,
        'rdap_type': ip_type,
        'rdap_name': rdap_data.get('name', '')[:255],
        'rdap_handle': rdap_data.get('handle', '')[:255],
        'asn': asn,
        'asn_name': (asn_name or rdap_data.get('name', ''))[:255],
        'country': country[:2],
        'abuse_contact': abuse_contact[:255],
        'cidr_prefix': cidr_prefix,
        'weighted_score': score,
        'tags': tags,
    }

    # Cache locally
    rdap_cache.put(ip, result)

    # Write to ClickHouse rdap_cache
    raw_json = json.dumps(rdap_data)[:4000]  # Truncate for storage
    # Escape single quotes for ClickHouse
    rdap_name_esc = result['rdap_name'].replace("'", "\\'")
    rdap_handle_esc = result['rdap_handle'].replace("'", "\\'")
    asn_name_esc = result['asn_name'].replace("'", "\\'")
    abuse_esc = result['abuse_contact'].replace("'", "\\'")
    raw_json_esc = raw_json.replace("'", "\\'")

    ch_query(
        f"INSERT INTO {CH_DB}.rdap_cache "
        f"(ip, rdap_name, rdap_handle, rdap_type, country, asn, asn_name, "
        f"abuse_contact, cidr_prefix, weighted_score, raw_json) VALUES",
        f"(IPv4StringToNum('{ip}'), '{rdap_name_esc}', '{rdap_handle_esc}', "
        f"'{ip_type}', '{country}', {asn}, '{asn_name_esc}', "
        f"'{abuse_esc}', {cidr_prefix}, {score}, '{raw_json_esc}')"
    )

    # Upsert to PostgreSQL ip_reputation
    pg_tags = [ip_type]
    if tags & TAG_VPN:
        pg_tags.append('vpn')
    if tags & TAG_DATACENTER:
        pg_tags.append('datacenter')
    if tags & TAG_TOR:
        pg_tags.append('tor')
    pg_upsert_reputation(ip, asn, result['asn_name'], country, score, pg_tags, ip_type)

    # Push to XDP ip_scores map
    if score > 0:
        if push_ip_score(ip, score, tags):
            logger.debug(f"Pushed {ip} score={score} tags={tags:#04x} to XDP")
        else:
            logger.debug(f"Failed to push {ip} to XDP map")

    return result

# ============================================================================
# ADAPTIVE SAMPLING CONTROLLER
# ============================================================================

def sampling_controller():
    """Adjust XDP sampling rate based on CPU load. Runs in background thread."""
    logger.info("Adaptive sampling controller started")

    while not shutdown_event.is_set():
        try:
            load_1m = os.getloadavg()[0]
            cpu_count = os.cpu_count() or 1
            load_pct = (load_1m / cpu_count) * 100

            # Graduated sampling: higher load = skip more packets for IAT/rate
            if load_pct < 50:
                sample_rate = 1    # 100% - process every packet
            elif load_pct < 70:
                sample_rate = 2    # 50%
            elif load_pct < 85:
                sample_rate = 4    # 25%
            else:
                sample_rate = 8    # 12.5%

            try:
                # CONFIG_SAMPLE_RATE = key index 2
                ok = get_bpf_ops().update_config('hydra_config', 2, sample_rate)
                if not ok:
                    logger.debug("Sampling rate update failed")
            except Exception as e:
                logger.debug(f"Sampling rate update error: {e}")

            if int(time.monotonic()) % 60 < 10:
                logger.debug(f"CPU load: {load_pct:.0f}%, sampling: 1/{sample_rate}")

        except Exception as e:
            logger.debug(f"Sampling controller error: {e}")

        shutdown_event.wait(10)  # Check every 10 seconds

    logger.info("Adaptive sampling controller stopped")

# ============================================================================
# MAIN LOOP
# ============================================================================

def enrichment_cycle():
    """Run one enrichment cycle: discover new IPs, enrich, push scores."""
    new_ips = get_new_ips_from_clickhouse()
    if not new_ips:
        return 0

    # Filter out already-cached and private IPs
    to_enrich = [ip for ip in new_ips if not should_skip_ip(ip) and rdap_cache.get(ip) is None]

    if not to_enrich:
        return 0

    logger.info(f"Enriching {len(to_enrich)} new IPs (of {len(new_ips)} discovered)")

    enriched = 0
    for ip in to_enrich:
        if shutdown_event.is_set():
            break

        result = enrich_ip(ip)
        if result:
            enriched += 1
            level = logging.WARNING if result['weighted_score'] >= SCORE_DROP_THRESHOLD else logging.DEBUG
            logger.log(level,
                f"Enriched {ip}: type={result['rdap_type']} "
                f"score={result['weighted_score']} "
                f"asn={result['asn']} country={result['country']}")

    return enriched


def main():
    logger.info("HYDRA RDAP Enricher starting...")
    logger.info(f"Score drop threshold: {SCORE_DROP_THRESHOLD}")
    logger.info(f"RDAP rate limit: {RDAP_RATE_LIMIT} queries/sec")
    logger.info(f"Enrichment interval: {ENRICHER_INTERVAL}s")
    logger.info(f"XDP interface: {XDP_INTERFACE}")

    if not CH_PASSWORD:
        logger.warning("CLICKHOUSE_PASSWORD not set, ClickHouse features disabled")
    if not PG_PASSWORD:
        logger.warning("POSTGRES_PASSWORD not set, PostgreSQL features disabled")

    # Start adaptive sampling controller in background thread
    sampling_thread = threading.Thread(target=sampling_controller, daemon=True)
    sampling_thread.start()

    # Main enrichment loop
    cycle_count = 0
    total_enriched = 0

    while not shutdown_event.is_set():
        try:
            enriched = enrichment_cycle()
            total_enriched += enriched
            cycle_count += 1

            if cycle_count % 10 == 0:
                logger.info(
                    f"Stats: {total_enriched} IPs enriched, "
                    f"{len(rdap_cache)} in cache, "
                    f"{cycle_count} cycles"
                )

        except Exception as e:
            logger.error(f"Enrichment cycle error: {e}")

        shutdown_event.wait(ENRICHER_INTERVAL)

    logger.info(f"HYDRA RDAP Enricher shutting down. Total enriched: {total_enriched}")


if __name__ == '__main__':
    main()
