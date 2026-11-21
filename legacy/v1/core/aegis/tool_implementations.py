"""AEGIS tool implementations — enforcement-critical actions.

Wires the highest-value GUARDIAN/MEDIC tools to real enforcement so the
orchestrator's decisions actually take effect instead of returning
NotImplementedError. The enforcement channel is the hydra_blocks ClickHouse
table, which feed_sync.py syncs to the XDP LPM_TRIE blocklist (source='aegis'
is included in COGNITIVE_BLOCK_SOURCES). This reuses the same proven path the
anomaly detector and CNO cognitive defense use.

Call register_default_implementations() once at startup (client.py wires this
after the ToolExecutor is constructed). Tools without an implementation here
continue to raise NotImplementedError, which is honest — they have no
enforcement primitive on this deployment yet.

All ClickHouse access is best-effort and fail-soft: on edge/router builds
without an IDS ClickHouse, these return a human-readable status string rather
than raising, so the orchestrator degrades gracefully.
"""

import ipaddress
import logging
import os
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .tool_executor import register_tool_implementation

logger = logging.getLogger(__name__)

CH_HOST = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
CH_PORT = os.environ.get('CLICKHOUSE_PORT', '8123')
CH_DB = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
CH_USER = os.environ.get('CLICKHOUSE_USER', 'ids')
CH_PASSWORD = os.environ.get('CLICKHOUSE_PASSWORD', '')

# Source tag for AEGIS-originated blocks. Must be present in feed_sync.py's
# COGNITIVE_BLOCK_SOURCES for the block to reach XDP.
AEGIS_BLOCK_SOURCE = 'aegis'


def _validate_ip(ip: str) -> str:
    """Return the canonical IPv4 string or raise ValueError."""
    addr = ipaddress.ip_address(ip)  # raises ValueError on bad input
    if addr.version != 4:
        raise ValueError(f"only IPv4 is enforceable here: {ip}")
    return str(addr)


def _ch_post(query: str, body: bytes = b"") -> str:
    """POST a query to ClickHouse with auth headers. Returns the response text."""
    url = f"http://{CH_HOST}:{CH_PORT}/?{urlencode({'query': query})}"
    req = Request(url, data=body if body else b"", method="POST")
    req.add_header('X-ClickHouse-User', CH_USER)
    req.add_header('X-ClickHouse-Key', CH_PASSWORD)
    with urlopen(req, timeout=10) as resp:
        return resp.read().decode('utf-8', errors='replace')


def _ch_available() -> bool:
    return bool(CH_PASSWORD)


def block_ip(ip: str, duration: int = 3600, reason: str = "") -> str:
    """Block a source IP by writing to hydra_blocks (synced to XDP by feed_sync)."""
    try:
        safe = _validate_ip(ip)
    except ValueError as e:
        return f"block_ip rejected: {e}"
    if not _ch_available():
        return f"block_ip unavailable: no ClickHouse configured (would block {safe})"

    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    reason_clean = (reason or "aegis_decision")[:200].replace("\\", "\\\\").replace("'", "\\'")
    duration = max(60, int(duration) if duration else 3600)
    insert = (
        f"INSERT INTO {CH_DB}.hydra_blocks "
        "(timestamp, src_ip, duration_seconds, reason, source, auto_expired, event_count) VALUES "
        f"('{now}', IPv4StringToNum('{safe}'), {duration}, "
        f"'aegis: {reason_clean}', '{AEGIS_BLOCK_SOURCE}', 0, 0)"
    )
    try:
        _ch_post(insert)
        logger.info("AEGIS block_ip %s for %ds (%s)", safe, duration, reason_clean)
        return f"blocked {safe} for {duration}s via XDP (reason: {reason_clean})"
    except HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')[:300]
        logger.error("block_ip failed: %s - %s", e.code, body)
        return f"block_ip failed: HTTP {e.code}"
    except Exception as e:
        logger.error("block_ip failed: %s", e)
        return f"block_ip failed: {e}"


def unblock_ip(ip: str) -> str:
    """Remove an AEGIS block: mark matching hydra_blocks rows auto_expired."""
    try:
        safe = _validate_ip(ip)
    except ValueError as e:
        return f"unblock_ip rejected: {e}"
    if not _ch_available():
        return f"unblock_ip unavailable: no ClickHouse configured (would unblock {safe})"

    alter = (
        f"ALTER TABLE {CH_DB}.hydra_blocks UPDATE auto_expired = 1 "
        f"WHERE src_ip = IPv4StringToNum('{safe}') "
        f"AND source = '{AEGIS_BLOCK_SOURCE}' AND auto_expired = 0"
    )
    try:
        _ch_post(alter)
        logger.info("AEGIS unblock_ip %s", safe)
        return f"unblocked {safe} (feed_sync will drop it from XDP next cycle)"
    except Exception as e:
        logger.error("unblock_ip failed: %s", e)
        return f"unblock_ip failed: {e}"


def rate_limit(ip: str, rate: str = "", reason: str = "") -> str:
    """Apply a short-TTL soft block as a rate-limit stand-in.

    The XDP fast-path has no per-IP token-bucket map exposed to userspace, so
    a true rate limit is not yet expressible. We approximate by a short (300s)
    block and label it clearly so it is auditable and not mistaken for a hard
    block. A real rate-limit map is tracked as a follow-up.
    """
    try:
        safe = _validate_ip(ip)
    except ValueError as e:
        return f"rate_limit rejected: {e}"
    note = f"rate_limit({rate or 'default'}): {reason or 'aegis_decision'}"
    return block_ip(safe, duration=300, reason=note)


def sentinel_query_verdict(ip: str) -> str:
    """Read the latest SENTINEL verdict + anomaly score for an IP (read-only)."""
    try:
        safe = _validate_ip(ip)
    except ValueError as e:
        return f"sentinel_query_verdict rejected: {e}"
    if not _ch_available():
        return "sentinel_query_verdict unavailable: no ClickHouse configured"

    query = (
        "SELECT verdict, round(sentinel_score, 4) AS score, round(confidence, 4) AS conf "
        f"FROM {CH_DB}.sentinel_evidence "
        f"WHERE src_ip = toIPv4('{safe}') "
        "ORDER BY timestamp DESC LIMIT 1 FORMAT JSONEachRow"
    )
    try:
        out = _ch_post(query).strip()
        if not out:
            return f"no SENTINEL evidence for {safe}"
        return f"SENTINEL verdict for {safe}: {out}"
    except Exception as e:
        logger.error("sentinel_query_verdict failed: %s", e)
        return f"sentinel_query_verdict failed: {e}"


def register_default_implementations() -> int:
    """Register the enforcement-critical tool implementations. Returns count."""
    impls = {
        "block_ip": block_ip,
        "unblock_ip": unblock_ip,
        "rate_limit": rate_limit,
        "sentinel_query_verdict": sentinel_query_verdict,
    }
    for name, fn in impls.items():
        register_tool_implementation(name, fn)
    logger.info("AEGIS: registered %d tool implementations (%s)",
                len(impls), ", ".join(impls))
    return len(impls)
