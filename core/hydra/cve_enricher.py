#!/usr/bin/env python3
"""
HookProbe SENTINEL CVE Enricher
=================================

Stage 2 of the SENTINEL engine: downloads CVE data from NVD and CISA KEV,
stores in local SQLite, and provides CVE relevance scoring per
(IP, port, intent_class) tuple.

Data sources:
  - NVD CVE API 2.0: Full CVE database with CVSS scores and CPE matching
  - CISA KEV: Known Exploited Vulnerabilities (actively exploited in the wild)

Port-to-Service-to-CPE mapping:
  Port 22/TCP  -> openssh, dropbear
  Port 80/TCP  -> apache, nginx, lighttpd
  Port 443/TCP -> openssl, apache, nginx
  Port 3306/TCP -> mysql, mariadb
  Port 5432/TCP -> postgresql
  Port 3389/TCP -> ms-rdp, xrdp
  Port 53/TCP+UDP -> bind, dnsmasq, unbound
  Port 25/TCP  -> postfix, exim, sendmail
  Port 21/TCP  -> vsftpd, proftpd

Storage:
  SQLite database on hydra_models volume (~100MB indexed)

Output:
  - ClickHouse: sentinel_cve_context table
  - In-memory port->CVE index for fast lookups

Usage:
    python3 cve_enricher.py [--mode sync|score] [--db-path /app/models/cve.db]
"""

import os
import sys
import time
import json
import math
import signal
import sqlite3
import logging
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Set
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import urlencode

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [CVE_ENRICHER] %(levelname)s: %(message)s'
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

# SQLite path for CVE database
CVE_DB_PATH = os.environ.get('CVE_DB_PATH', '/app/models/cve.db')

# NVD API configuration
NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
NVD_API_KEY = os.environ.get('NVD_API_KEY', '')  # Optional, increases rate limit
NVD_RATE_LIMIT = 0.6 if NVD_API_KEY else 6.0  # seconds between requests

# CISA KEV feed
CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

# Sync intervals
FULL_SYNC_INTERVAL = int(os.environ.get('CVE_FULL_SYNC_HOURS', '168'))  # weekly
INCREMENTAL_SYNC_INTERVAL = int(os.environ.get('CVE_INCR_SYNC_HOURS', '24'))  # daily
SCORING_INTERVAL = int(os.environ.get('CVE_SCORING_INTERVAL', '300'))  # 5 minutes

running = True


def signal_handler(sig, frame):
    global running
    logger.info(f"Received signal {sig}, shutting down...")
    running = False


signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)


# ============================================================================
# PORT -> SERVICE -> CPE MAPPING
# ============================================================================

# Map port numbers to service keywords for CPE matching
PORT_SERVICE_MAP: Dict[int, List[dict]] = {
    22: [
        {'vendor': 'openbsd', 'product': 'openssh', 'service': 'ssh'},
        {'vendor': 'dropbear_ssh_project', 'product': 'dropbear_ssh', 'service': 'ssh'},
    ],
    80: [
        {'vendor': 'apache', 'product': 'http_server', 'service': 'http'},
        {'vendor': 'nginx', 'product': 'nginx', 'service': 'http'},
        {'vendor': 'lighttpd', 'product': 'lighttpd', 'service': 'http'},
    ],
    443: [
        {'vendor': 'openssl', 'product': 'openssl', 'service': 'https'},
        {'vendor': 'apache', 'product': 'http_server', 'service': 'https'},
        {'vendor': 'nginx', 'product': 'nginx', 'service': 'https'},
    ],
    3306: [
        {'vendor': 'oracle', 'product': 'mysql', 'service': 'mysql'},
        {'vendor': 'mariadb', 'product': 'mariadb', 'service': 'mysql'},
    ],
    5432: [
        {'vendor': 'postgresql', 'product': 'postgresql', 'service': 'postgresql'},
    ],
    3389: [
        {'vendor': 'microsoft', 'product': 'remote_desktop_services', 'service': 'rdp'},
    ],
    53: [
        {'vendor': 'isc', 'product': 'bind', 'service': 'dns'},
        {'vendor': 'thekelleys', 'product': 'dnsmasq', 'service': 'dns'},
        {'vendor': 'nlnetlabs', 'product': 'unbound', 'service': 'dns'},
    ],
    25: [
        {'vendor': 'postfix', 'product': 'postfix', 'service': 'smtp'},
        {'vendor': 'exim', 'product': 'exim', 'service': 'smtp'},
    ],
    21: [
        {'vendor': 'vsftpd_project', 'product': 'vsftpd', 'service': 'ftp'},
        {'vendor': 'proftpd', 'product': 'proftpd', 'service': 'ftp'},
    ],
    8080: [
        {'vendor': 'apache', 'product': 'tomcat', 'service': 'http-proxy'},
    ],
    6379: [
        {'vendor': 'redis', 'product': 'redis', 'service': 'redis'},
    ],
    27017: [
        {'vendor': 'mongodb', 'product': 'mongodb', 'service': 'mongodb'},
    ],
    9200: [
        {'vendor': 'elastic', 'product': 'elasticsearch', 'service': 'elasticsearch'},
    ],
    8443: [
        {'vendor': 'apache', 'product': 'http_server', 'service': 'https-alt'},
        {'vendor': 'nginx', 'product': 'nginx', 'service': 'https-alt'},
    ],
}

# Intent class to attack vector mapping (for relevance scoring)
INTENT_ATTACK_VECTORS = {
    'brute_force': 'NETWORK',
    'port_scan': 'NETWORK',
    'syn_flood': 'NETWORK',
    'ddos': 'NETWORK',
    'exploit': 'NETWORK',
    'data_exfiltration': 'NETWORK',
    'c2_communication': 'NETWORK',
    'reconnaissance': 'NETWORK',
    'web_attack': 'NETWORK',
}


# ============================================================================
# CLICKHOUSE CLIENT
# ============================================================================

def ch_escape(value: str) -> str:
    """Escape a string for safe use in ClickHouse SQL VALUES."""
    return value.replace('\\', '\\\\').replace("'", "\\'")


def ch_query(query: str, fmt: str = 'JSONEachRow') -> Optional[str]:
    """Execute a ClickHouse query via HTTP API with auth in headers."""
    if not CH_PASSWORD:
        return None

    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        full_query = query + (f" FORMAT {fmt}" if fmt else "")

        req = Request(url, data=full_query.encode('utf-8'))
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        with urlopen(req, timeout=30) as resp:
            return resp.read().decode('utf-8')

    except Exception as e:
        logger.error(f"ClickHouse query error: {e}")
        return None


def ch_insert(query: str, data: str = '') -> bool:
    """Execute a ClickHouse INSERT with auth in headers."""
    if not CH_PASSWORD:
        return False

    try:
        url = f"http://{CH_HOST}:{CH_PORT}/"
        params = urlencode({'query': query})
        full_url = f"{url}?{params}"

        req = Request(full_url)
        req.add_header('X-ClickHouse-User', CH_USER)
        req.add_header('X-ClickHouse-Key', CH_PASSWORD)
        if data:
            req.data = data.encode('utf-8')
            req.add_header('Content-Type', 'text/plain')

        with urlopen(req, timeout=30) as resp:
            resp.read()
        return True

    except Exception as e:
        logger.error(f"ClickHouse insert error: {e}")
        return False


# ============================================================================
# SQLITE CVE DATABASE
# ============================================================================

def init_cve_db(db_path: str) -> sqlite3.Connection:
    """Initialize the SQLite CVE database."""
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cves (
            cve_id TEXT PRIMARY KEY,
            description TEXT DEFAULT '',
            cvss_score REAL DEFAULT 0.0,
            cvss_vector TEXT DEFAULT '',
            attack_vector TEXT DEFAULT '',
            attack_complexity TEXT DEFAULT '',
            privileges_required TEXT DEFAULT '',
            user_interaction TEXT DEFAULT '',
            scope TEXT DEFAULT '',
            confidentiality_impact TEXT DEFAULT '',
            integrity_impact TEXT DEFAULT '',
            availability_impact TEXT DEFAULT '',
            published_date TEXT DEFAULT '',
            last_modified TEXT DEFAULT '',
            is_kev INTEGER DEFAULT 0,
            kev_date_added TEXT DEFAULT '',
            kev_due_date TEXT DEFAULT '',
            raw_json TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS cve_cpes (
            cve_id TEXT NOT NULL,
            vendor TEXT NOT NULL,
            product TEXT NOT NULL,
            version_start TEXT DEFAULT '',
            version_end TEXT DEFAULT '',
            vulnerable INTEGER DEFAULT 1,
            FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
        );

        CREATE INDEX IF NOT EXISTS idx_cve_cpes_product
            ON cve_cpes(vendor, product);
        CREATE INDEX IF NOT EXISTS idx_cve_cpes_cve
            ON cve_cpes(cve_id);
        CREATE INDEX IF NOT EXISTS idx_cves_cvss
            ON cves(cvss_score DESC);
        CREATE INDEX IF NOT EXISTS idx_cves_kev
            ON cves(is_kev) WHERE is_kev = 1;
        CREATE INDEX IF NOT EXISTS idx_cves_attack_vector
            ON cves(attack_vector);

        CREATE TABLE IF NOT EXISTS sync_state (
            key TEXT PRIMARY KEY,
            value TEXT DEFAULT ''
        );
    """)

    conn.commit()
    return conn


# ============================================================================
# NVD API CLIENT
# ============================================================================

def nvd_fetch(params: dict) -> Optional[dict]:
    """Fetch from NVD API 2.0 with rate limiting."""
    try:
        query_str = urlencode(params)
        url = f"{NVD_API_BASE}?{query_str}"

        req = Request(url, headers={
            'User-Agent': 'HookProbe-SENTINEL/1.0 (cve-enricher)',
        })
        if NVD_API_KEY:
            req.add_header('apiKey', NVD_API_KEY)

        with urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return data

    except HTTPError as e:
        if e.code in (403, 429):
            logger.warning(f"NVD API rate limited ({e.code}), backing off 30s...")
            time.sleep(30)
        elif e.code == 404:
            return None
        else:
            logger.error(f"NVD API error: {e}")
        return None
    except Exception as e:
        logger.error(f"NVD fetch error: {e}")
        return None


def parse_nvd_cve(cve_item: dict) -> Optional[dict]:
    """Parse a single CVE item from NVD API response."""
    try:
        cve = cve_item.get('cve', {})
        cve_id = cve.get('id', '')
        if not cve_id.startswith('CVE-'):
            return None

        # Get description
        descriptions = cve.get('descriptions', [])
        desc = ''
        for d in descriptions:
            if d.get('lang', '') == 'en':
                desc = d.get('value', '')
                break

        # Get CVSS v3.1 metrics (prefer v3.1 over v3.0 over v2)
        metrics = cve.get('metrics', {})
        cvss_score = 0.0
        cvss_vector = ''
        attack_vector = ''
        attack_complexity = ''
        privileges_required = ''
        user_interaction = ''
        scope = ''
        conf_impact = ''
        int_impact = ''
        avail_impact = ''

        for metric_key in ['cvssMetricV31', 'cvssMetricV30']:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                primary = None
                for m in metric_list:
                    if m.get('type') == 'Primary':
                        primary = m
                        break
                if not primary:
                    primary = metric_list[0]

                cvss_data = primary.get('cvssData', {})
                cvss_score = float(cvss_data.get('baseScore', 0.0))
                cvss_vector = cvss_data.get('vectorString', '')
                attack_vector = cvss_data.get('attackVector', '')
                attack_complexity = cvss_data.get('attackComplexity', '')
                privileges_required = cvss_data.get('privilegesRequired', '')
                user_interaction = cvss_data.get('userInteraction', '')
                scope = cvss_data.get('scope', '')
                conf_impact = cvss_data.get('confidentialityImpact', '')
                int_impact = cvss_data.get('integrityImpact', '')
                avail_impact = cvss_data.get('availabilityImpact', '')
                break

        # Fall back to v2 if no v3
        if cvss_score == 0.0:
            v2_metrics = metrics.get('cvssMetricV2', [])
            if v2_metrics:
                cvss_data = v2_metrics[0].get('cvssData', {})
                cvss_score = float(cvss_data.get('baseScore', 0.0))
                attack_vector = cvss_data.get('accessVector', '')

        # Get published/modified dates
        published = cve.get('published', '')[:19]
        modified = cve.get('lastModified', '')[:19]

        # Parse CPE configurations
        cpes = []
        configurations = cve.get('configurations', [])
        for config in configurations:
            for node in config.get('nodes', []):
                for match in node.get('cpeMatch', []):
                    criteria = match.get('criteria', '')
                    vulnerable = match.get('vulnerable', True)

                    # Parse CPE 2.3 string: cpe:2.3:a:vendor:product:version:...
                    parts = criteria.split(':')
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                        version = parts[5] if len(parts) > 5 else '*'

                        ver_start = match.get('versionStartIncluding', '')
                        ver_end = match.get('versionEndExcluding',
                                            match.get('versionEndIncluding', ''))

                        cpes.append({
                            'vendor': vendor,
                            'product': product,
                            'version_start': ver_start,
                            'version_end': ver_end,
                            'vulnerable': 1 if vulnerable else 0,
                        })

        return {
            'cve_id': cve_id,
            'description': desc[:2000],
            'cvss_score': cvss_score,
            'cvss_vector': cvss_vector,
            'attack_vector': attack_vector,
            'attack_complexity': attack_complexity,
            'privileges_required': privileges_required,
            'user_interaction': user_interaction,
            'scope': scope,
            'confidentiality_impact': conf_impact,
            'integrity_impact': int_impact,
            'availability_impact': avail_impact,
            'published_date': published,
            'last_modified': modified,
            'cpes': cpes,
        }

    except Exception as e:
        logger.debug(f"CVE parse error: {e}")
        return None


def sync_cves_for_product(conn: sqlite3.Connection, vendor: str,
                          product: str, last_modified: str = '') -> int:
    """
    Sync CVEs for a specific vendor:product from NVD.

    Uses cpeName search to find all CVEs affecting this product.
    Returns count of CVEs synced.
    """
    synced = 0
    start_index = 0
    results_per_page = 50

    # Use keywordSearch for broad matching (cpeName wildcards don't work well)
    keyword = product.replace('_', ' ')

    while running:
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': results_per_page,
            'startIndex': start_index,
        }
        if last_modified:
            params['lastModStartDate'] = last_modified
            params['lastModEndDate'] = datetime.now(timezone.utc).strftime(
                '%Y-%m-%dT%H:%M:%S.000')

        data = nvd_fetch(params)
        if not data:
            break

        vulnerabilities = data.get('vulnerabilities', [])
        if not vulnerabilities:
            break

        for item in vulnerabilities:
            parsed = parse_nvd_cve(item)
            if not parsed:
                continue

            # Upsert CVE
            conn.execute("""
                INSERT OR REPLACE INTO cves
                (cve_id, description, cvss_score, cvss_vector, attack_vector,
                 attack_complexity, privileges_required, user_interaction,
                 scope, confidentiality_impact, integrity_impact,
                 availability_impact, published_date, last_modified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                parsed['cve_id'], parsed['description'],
                parsed['cvss_score'], parsed['cvss_vector'],
                parsed['attack_vector'], parsed['attack_complexity'],
                parsed['privileges_required'], parsed['user_interaction'],
                parsed['scope'], parsed['confidentiality_impact'],
                parsed['integrity_impact'], parsed['availability_impact'],
                parsed['published_date'], parsed['last_modified'],
            ))

            # Insert CPE matches
            conn.execute("DELETE FROM cve_cpes WHERE cve_id = ?",
                         (parsed['cve_id'],))
            for cpe in parsed['cpes']:
                conn.execute("""
                    INSERT INTO cve_cpes
                    (cve_id, vendor, product, version_start, version_end, vulnerable)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    parsed['cve_id'], cpe['vendor'], cpe['product'],
                    cpe['version_start'], cpe['version_end'], cpe['vulnerable'],
                ))

            synced += 1

        conn.commit()

        # Pagination
        total_results = data.get('totalResults', 0)
        start_index += results_per_page
        if start_index >= total_results:
            break

        # Rate limiting
        time.sleep(NVD_RATE_LIMIT)

    return synced


def sync_cisa_kev(conn: sqlite3.Connection) -> int:
    """Download and sync CISA Known Exploited Vulnerabilities catalog."""
    try:
        req = Request(CISA_KEV_URL, headers={
            'User-Agent': 'HookProbe-SENTINEL/1.0 (cve-enricher)',
        })
        with urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode('utf-8'))

        vulnerabilities = data.get('vulnerabilities', [])
        synced = 0

        for vuln in vulnerabilities:
            cve_id = vuln.get('cveID', '')
            if not cve_id.startswith('CVE-'):
                continue

            date_added = vuln.get('dateAdded', '')
            due_date = vuln.get('dueDate', '')

            # Update existing CVE records with KEV status
            conn.execute("""
                UPDATE cves SET is_kev = 1, kev_date_added = ?, kev_due_date = ?
                WHERE cve_id = ?
            """, (date_added, due_date, cve_id))

            # Also insert stub if CVE doesn't exist yet
            conn.execute("""
                INSERT OR IGNORE INTO cves
                (cve_id, description, is_kev, kev_date_added, kev_due_date)
                VALUES (?, ?, 1, ?, ?)
            """, (
                cve_id,
                vuln.get('shortDescription', vuln.get('vulnerabilityName', '')),
                date_added, due_date,
            ))
            synced += 1

        conn.commit()
        logger.info(f"CISA KEV synced: {synced} vulnerabilities")
        return synced

    except Exception as e:
        logger.error(f"CISA KEV sync error: {e}")
        return 0


def full_sync(conn: sqlite3.Connection) -> dict:
    """Full CVE sync for all port-mapped services."""
    logger.info("Starting full CVE sync...")
    total_synced = 0

    # Get unique vendor:product pairs from port map
    products: Set[Tuple[str, str]] = set()
    for port, services in PORT_SERVICE_MAP.items():
        for svc in services:
            products.add((svc['vendor'], svc['product']))

    for vendor, product in sorted(products):
        if not running:
            break

        logger.info(f"Syncing CVEs for {vendor}:{product}...")
        count = sync_cves_for_product(conn, vendor, product)
        logger.info(f"  {vendor}:{product}: {count} CVEs")
        total_synced += count

    # Sync CISA KEV
    if running:
        kev_count = sync_cisa_kev(conn)
        total_synced += kev_count

    # Update sync timestamp
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT OR REPLACE INTO sync_state (key, value) VALUES ('last_full_sync', ?)",
        (now,))
    conn.commit()

    # Get stats
    cve_count = conn.execute("SELECT count(*) FROM cves").fetchone()[0]
    kev_count = conn.execute(
        "SELECT count(*) FROM cves WHERE is_kev = 1").fetchone()[0]
    cpe_count = conn.execute("SELECT count(*) FROM cve_cpes").fetchone()[0]

    logger.info(f"Full sync complete: {total_synced} synced, "
                f"{cve_count} total CVEs, {kev_count} KEV, {cpe_count} CPE matches")

    return {
        'synced': total_synced,
        'total_cves': cve_count,
        'kev_count': kev_count,
        'cpe_matches': cpe_count,
    }


def incremental_sync(conn: sqlite3.Connection) -> int:
    """Incremental sync: only fetch CVEs modified since last sync."""
    row = conn.execute(
        "SELECT value FROM sync_state WHERE key = 'last_incr_sync'"
    ).fetchone()

    if row:
        last_modified = row[0]
    else:
        # Default to 7 days ago
        last_modified = (datetime.now(timezone.utc) - timedelta(days=7)).strftime(
            '%Y-%m-%dT%H:%M:%S.000')

    logger.info(f"Incremental CVE sync since {last_modified}")
    total = 0

    products: Set[Tuple[str, str]] = set()
    for port, services in PORT_SERVICE_MAP.items():
        for svc in services:
            products.add((svc['vendor'], svc['product']))

    for vendor, product in sorted(products):
        if not running:
            break
        count = sync_cves_for_product(conn, vendor, product, last_modified)
        if count > 0:
            logger.info(f"  {vendor}:{product}: {count} updated CVEs")
        total += count

    # Also refresh KEV
    if running:
        sync_cisa_kev(conn)

    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT OR REPLACE INTO sync_state (key, value) VALUES ('last_incr_sync', ?)",
        (now,))
    conn.commit()

    logger.info(f"Incremental sync complete: {total} CVEs updated")
    return total


# ============================================================================
# CVE RELEVANCE SCORING
# ============================================================================

# In-memory cache: port -> [(cve_id, cvss_score, attack_vector, is_kev), ...]
port_cve_cache: Dict[int, List[dict]] = {}


def build_port_cve_cache(conn: sqlite3.Connection) -> int:
    """Build in-memory port->CVE index from SQLite data."""
    global port_cve_cache
    port_cve_cache = {}
    total = 0

    for port, services in PORT_SERVICE_MAP.items():
        cves = []
        for svc in services:
            rows = conn.execute("""
                SELECT DISTINCT c.cve_id, c.cvss_score, c.attack_vector,
                       c.attack_complexity, c.is_kev, c.description
                FROM cves c
                JOIN cve_cpes cp ON c.cve_id = cp.cve_id
                WHERE cp.vendor = ? AND cp.product = ?
                  AND cp.vulnerable = 1
                  AND c.cvss_score > 0
                ORDER BY c.cvss_score DESC
                LIMIT 100
            """, (svc['vendor'], svc['product'])).fetchall()

            for row in rows:
                cves.append({
                    'cve_id': row[0],
                    'cvss_score': row[1],
                    'attack_vector': row[2],
                    'attack_complexity': row[3],
                    'is_kev': bool(row[4]),
                    'description': row[5][:200] if row[5] else '',
                })

        if cves:
            # Deduplicate by CVE ID, keep highest CVSS
            seen: Dict[str, dict] = {}
            for cve in cves:
                existing = seen.get(cve['cve_id'])
                if not existing or cve['cvss_score'] > existing['cvss_score']:
                    seen[cve['cve_id']] = cve
            port_cve_cache[port] = sorted(
                seen.values(), key=lambda x: x['cvss_score'], reverse=True)
            total += len(port_cve_cache[port])

    logger.info(f"Port-CVE cache built: {len(port_cve_cache)} ports, "
                f"{total} CVE entries")
    return total


def compute_cve_relevance(port: int, intent_class: str = '') -> dict:
    """
    Compute CVE relevance score for a (port, intent_class) pair.

    Returns:
        {
            'cve_relevance_score': float (0-1),
            'matched_cve_count': int,
            'max_cvss_score': float (0-10),
            'top_cve_ids': [str],
            'attack_vector': str,
            'attack_complexity': str,
            'has_kev': bool,
        }
    """
    cves = port_cve_cache.get(port, [])
    if not cves:
        return {
            'cve_relevance_score': 0.0,
            'matched_cve_count': 0,
            'max_cvss_score': 0.0,
            'top_cve_ids': [],
            'attack_vector': '',
            'attack_complexity': '',
            'has_kev': False,
        }

    # Filter for network-accessible CVEs only
    network_cves = [c for c in cves
                    if c.get('attack_vector', '') in ('NETWORK', 'ADJACENT_NETWORK', '')]

    if not network_cves:
        network_cves = cves  # Fallback to all if none are network

    max_cvss = max(c['cvss_score'] for c in network_cves)
    has_kev = any(c['is_kev'] for c in network_cves)
    top_cves = network_cves[:5]

    # Base relevance: normalized CVSS (0-10 -> 0-1)
    base_relevance = max_cvss / 10.0

    # KEV multiplier: actively exploited CVEs are much more relevant
    kev_boost = 0.2 if has_kev else 0.0

    # Count factor: more CVEs = broader attack surface
    count_factor = min(len(network_cves) / 50.0, 0.15)

    # Intent matching: brute_force on SSH with auth bypass CVEs = very relevant
    intent_boost = 0.0
    if intent_class in ('brute_force', 'exploit'):
        # Check for auth bypass / RCE CVEs
        for c in top_cves:
            desc_lower = (c.get('description', '') or '').lower()
            if any(kw in desc_lower for kw in
                   ['remote code execution', 'authentication bypass',
                    'privilege escalation', 'buffer overflow',
                    'command injection', 'sql injection']):
                intent_boost = 0.1
                break

    relevance = min(1.0, base_relevance + kev_boost + count_factor + intent_boost)

    return {
        'cve_relevance_score': round(relevance, 4),
        'matched_cve_count': len(network_cves),
        'max_cvss_score': max_cvss,
        'top_cve_ids': [c['cve_id'] for c in top_cves],
        'attack_vector': top_cves[0].get('attack_vector', '') if top_cves else '',
        'attack_complexity': top_cves[0].get('attack_complexity', '') if top_cves else '',
        'has_kev': has_kev,
    }


# ============================================================================
# SCORING CYCLE: Enrich recent verdicts with CVE context
# ============================================================================

def create_cve_context_table():
    """Create sentinel_cve_context table if it doesn't exist."""
    ch_query(f"""
        CREATE TABLE IF NOT EXISTS {CH_DB}.sentinel_cve_context (
            timestamp DateTime64(3),
            src_ip IPv4,
            dst_port UInt16,
            intent_class LowCardinality(String) DEFAULT '',
            matched_cve_count UInt16 DEFAULT 0,
            max_cvss_score Float32 DEFAULT 0,
            cve_relevance_score Float32 DEFAULT 0,
            top_cve_ids Array(String) DEFAULT [],
            attack_vector LowCardinality(String) DEFAULT '',
            attack_complexity LowCardinality(String) DEFAULT '',
            has_kev UInt8 DEFAULT 0
        ) ENGINE = MergeTree()
        PARTITION BY toYYYYMM(timestamp)
        ORDER BY (timestamp, src_ip, dst_port)
        TTL toDateTime(timestamp) + INTERVAL 30 DAY
    """, fmt='')


def scoring_cycle():
    """Score recent events with CVE context."""
    # Get recent unique (src_ip, dst_port) pairs from hydra_events
    query = f"""
        SELECT
            IPv4NumToString(src_ip) AS ip,
            dst_port,
            count() AS event_count
        FROM {CH_DB}.hydra_events
        WHERE timestamp >= now() - INTERVAL {SCORING_INTERVAL} SECOND
          AND dst_port > 0
        GROUP BY src_ip, dst_port
        HAVING event_count >= 3
    """

    result = ch_query(query)
    if not result:
        return 0

    rows = []
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

    for line in result.strip().split('\n'):
        if not line:
            continue
        try:
            row = json.loads(line)
            ip = row['ip']
            port = int(row['dst_port'])

            cve = compute_cve_relevance(port)
            if cve['matched_cve_count'] == 0:
                continue

            top_ids = "[" + ",".join(
                f"'{ch_escape(cid)[:20]}'" for cid in cve['top_cve_ids'][:5]
            ) + "]"
            av = ch_escape(cve['attack_vector'])[:20]
            ac = ch_escape(cve['attack_complexity'])[:20]

            rows.append(
                f"('{now}', IPv4StringToNum('{ip}'), {port}, '', "
                f"{cve['matched_cve_count']}, {cve['max_cvss_score']:.2f}, "
                f"{cve['cve_relevance_score']:.4f}, {top_ids}, "
                f"'{av}', '{ac}', {1 if cve['has_kev'] else 0})"
            )
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            continue

    if not rows:
        return 0

    query = (
        f"INSERT INTO {CH_DB}.sentinel_cve_context "
        "(timestamp, src_ip, dst_port, intent_class, matched_cve_count, "
        "max_cvss_score, cve_relevance_score, top_cve_ids, "
        "attack_vector, attack_complexity, has_kev) VALUES"
    )

    # Insert in batches
    total = 0
    for i in range(0, len(rows), 100):
        batch = rows[i:i + 100]
        if ch_insert(query, ", ".join(batch)):
            total += len(batch)

    return total


# ============================================================================
# PUBLIC API (for sentinel_engine.py import)
# ============================================================================

def get_cve_relevance(port: int, intent_class: str = '') -> dict:
    """Get CVE relevance for a port/intent pair."""
    return compute_cve_relevance(port, intent_class)


def get_cve_stats() -> dict:
    """Get overall CVE database statistics."""
    total_ports = len(port_cve_cache)
    total_cves = sum(len(v) for v in port_cve_cache.values())
    kev_count = sum(
        1 for cves in port_cve_cache.values()
        for c in cves if c.get('is_kev')
    )
    return {
        'cached_ports': total_ports,
        'total_cves': total_cves,
        'kev_count': kev_count,
    }


# ============================================================================
# MAIN LOOP
# ============================================================================

def main():
    logger.info("SENTINEL CVE Enricher starting...")
    logger.info(f"CVE database: {CVE_DB_PATH}")
    logger.info(f"NVD API key: {'configured' if NVD_API_KEY else 'not set (slower rate limit)'}")
    logger.info(f"Port mappings: {len(PORT_SERVICE_MAP)} ports")

    if not CH_PASSWORD:
        logger.error("CLICKHOUSE_PASSWORD not set, cannot proceed")
        sys.exit(1)

    # Initialize SQLite
    os.makedirs(os.path.dirname(CVE_DB_PATH) or '.', exist_ok=True)
    conn = init_cve_db(CVE_DB_PATH)

    # Check if we need a full sync
    row = conn.execute(
        "SELECT value FROM sync_state WHERE key = 'last_full_sync'"
    ).fetchone()

    needs_full_sync = True
    if row:
        try:
            last_sync = datetime.fromisoformat(row[0])
            age_hours = (datetime.now(timezone.utc) - last_sync).total_seconds() / 3600
            needs_full_sync = age_hours > FULL_SYNC_INTERVAL
            logger.info(f"Last full sync: {row[0]} ({age_hours:.1f}h ago)")
        except ValueError:
            pass

    # Create ClickHouse table
    create_cve_context_table()

    if needs_full_sync:
        full_sync(conn)
    else:
        incremental_sync(conn)

    # Build in-memory cache
    build_port_cve_cache(conn)

    # Initial scoring cycle
    scored = scoring_cycle()
    logger.info(f"Initial scoring: {scored} CVE context entries written")

    # Main loop
    last_incr_sync = time.monotonic()
    cycle_count = 0

    while running:
        # Wait for next scoring cycle
        for _ in range(SCORING_INTERVAL):
            if not running:
                break
            time.sleep(1)

        if not running:
            break

        cycle_count += 1

        try:
            # Scoring cycle
            scored = scoring_cycle()
            if scored > 0:
                logger.info(f"Cycle {cycle_count}: {scored} CVE context entries")

            # Check if we need an incremental sync
            elapsed_hours = (time.monotonic() - last_incr_sync) / 3600
            if elapsed_hours >= INCREMENTAL_SYNC_INTERVAL:
                incremental_sync(conn)
                build_port_cve_cache(conn)
                last_incr_sync = time.monotonic()

        except Exception as e:
            logger.error(f"Scoring cycle error: {e}", exc_info=True)

    conn.close()
    logger.info("SENTINEL CVE Enricher shutting down")


if __name__ == '__main__':
    main()
