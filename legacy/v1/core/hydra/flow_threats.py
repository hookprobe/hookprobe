"""Flow-based inbound threat detection (low-and-slow recon the XDP path misses).

Why this exists (2026-11-09 audit):
  * hydra_events only ever held XDP drop/alert events — traffic ALREADY on a
    blocklist or above the 5000-pps rate threshold. SENTINEL scores only IPs
    in hydra_events, so in quiet periods it logged "no active IPs" every cycle
    while napse_flows held real inbound recon it never looked at.
  * Internet SSH probing here is low-and-slow (2-3 connections per IP per
    day across dozens of IPs) — the inspector's 60s windows can't see it.
  * Anyone can reach the origin directly on 80/443, bypassing Cloudflare.

This module aggregates the last hour of napse_flows (correctly oriented since
the packet_inspector direction fix) per external source that INITIATED flows
to this host, and emits hydra_events rows for three behaviours:

  slow_scan      >= SCAN_MIN_PORTS distinct dst ports in the window, or
                 >= SCAN_MIN_UNANSWERED unanswered flows over >= 3 ports
  ssh_probe      >= SSH_MIN_FLOWS inbound flows to tcp/22
  origin_direct  >= ORIGIN_MIN_FLOWS flows to 80/443 from a NON-Cloudflare
                 source (origin bypass of the CF WAF)

Events land in hydra_events (action='alert'), which SENTINEL, the anomaly
detector and the dashboard already consume — no new table, no new consumer.
Trusted sources (canonical + dynamic operator trust) are never reported.
Pure functions are separated from I/O so they are unit-testable.
"""
from __future__ import annotations

import ipaddress
import json
import os
import time
from typing import Callable, Dict, Iterable, List, Optional, Sequence

WINDOW_S = int(os.environ.get('FLOW_THREAT_WINDOW_S', '3600'))
SCAN_INTERVAL_S = int(os.environ.get('FLOW_THREAT_INTERVAL_S', '300'))
SCAN_MIN_PORTS = int(os.environ.get('FLOW_THREAT_SCAN_PORTS', '8'))
SCAN_MIN_UNANSWERED = int(os.environ.get('FLOW_THREAT_SCAN_UNANSWERED', '5'))
SSH_MIN_FLOWS = int(os.environ.get('FLOW_THREAT_SSH_FLOWS', '3'))
ORIGIN_MIN_FLOWS = int(os.environ.get('FLOW_THREAT_ORIGIN_FLOWS', '3'))
MAX_EVENTS_PER_IP = 20
# origin_direct is weaker evidence (mesh/HSG clients may legitimately use 443
# on the DNS-only mesh hostname), so it contributes only enough events to
# register in SENTINEL (HAVING event_count >= 3), never a high-volume signal.
MAX_EVENTS_BY_REASON = {'origin_direct': 3}

# Cloudflare published proxy ranges (https://www.cloudflare.com/ips-v4).
# Web traffic from these is the normal proxied path, not an origin bypass.
CLOUDFLARE_V4 = tuple(ipaddress.ip_network(c) for c in (
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
))

WEB_PORTS = (80, 443)
SSH_PORT = 22


def is_cloudflare(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in CLOUDFLARE_V4)


def _valid_ipv4(ip: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except ValueError:
        return False


def build_query(db: str, local_ips: Sequence[str], window_s: int = WINDOW_S) -> Optional[str]:
    """Per-source aggregate of inbound flows to this host. None if no local IPs."""
    locals_ok = [ip for ip in local_ips if _valid_ipv4(ip)]
    if not locals_ok:
        return None
    ip_list = ', '.join(f"IPv4StringToNum('{ip}')" for ip in sorted(locals_ok))
    return f"""
        SELECT
            IPv4NumToString(src_ip) AS ip,
            count() AS flows,
            uniq(dst_port) AS uniq_ports,
            groupUniqArray(50)(dst_port) AS ports,
            countIf(dst_port = {SSH_PORT} AND proto = 6) AS ssh_flows,
            countIf(dst_port IN {WEB_PORTS} AND proto = 6) AS web_flows,
            countIf(pkts_resp = 0) AS unanswered
        FROM {db}.napse_flows
        WHERE timestamp >= now() - INTERVAL {int(window_s)} SECOND
          AND dst_ip IN ({ip_list})
          AND src_ip NOT IN ({ip_list})
        GROUP BY src_ip
        HAVING flows >= 3
        FORMAT JSONEachRow
    """


def classify(row: dict) -> List[str]:
    """Return the threat reasons a per-source aggregate row triggers."""
    reasons: List[str] = []
    ip = str(row.get('ip', ''))
    uniq_ports = int(row.get('uniq_ports') or 0)
    unanswered = int(row.get('unanswered') or 0)
    if uniq_ports >= SCAN_MIN_PORTS or (unanswered >= SCAN_MIN_UNANSWERED and uniq_ports >= 3):
        reasons.append('slow_scan')
    if int(row.get('ssh_flows') or 0) >= SSH_MIN_FLOWS:
        reasons.append('ssh_probe')
    if int(row.get('web_flows') or 0) >= ORIGIN_MIN_FLOWS and not is_cloudflare(ip):
        reasons.append('origin_direct')
    return reasons


def events_for(row: dict, reason: str, local_ip: str) -> List[dict]:
    """Expand a flagged aggregate into hydra_events-shaped dicts.

    One event per observed flow (capped) so SENTINEL's per-IP features
    (event_count, unique ports, entropy) reflect the real activity.
    """
    ports = [int(p) for p in (row.get('ports') or []) if str(p).isdigit()] or [0]
    if reason == 'ssh_probe':
        ports = [SSH_PORT]
    elif reason == 'origin_direct':
        ports = [p for p in ports if p in WEB_PORTS] or [443]
    cap = MAX_EVENTS_BY_REASON.get(reason, MAX_EVENTS_PER_IP)
    n = max(1, min(int(row.get('flows') or 1), cap))
    return [{
        'timestamp_ns': 0,
        'src_ip': row['ip'],
        'dst_ip': local_ip,
        'src_port': 0,
        'dst_port': ports[i % len(ports)],
        'proto': 6,
        'event_type': 'alert',
        'reason': reason,
        'tcp_flags': 0x02,
    } for i in range(n)]


class FlowThreatDetector:
    """Periodic scanner with per-(ip, reason) suppression for one window."""

    def __init__(self, db: str, query_fn: Callable[[str], Optional[str]],
                 local_ips_fn: Callable[[], Iterable[str]],
                 is_trusted_fn: Optional[Callable[[str], bool]] = None,
                 clock: Callable[[], float] = time.monotonic):
        self.db = db
        self.query_fn = query_fn
        self.local_ips_fn = local_ips_fn
        self.is_trusted_fn = is_trusted_fn
        self.clock = clock
        self._last_emit: Dict[tuple, float] = {}
        self._last_scan = float('-inf')

    def due(self) -> bool:
        return self.clock() - self._last_scan >= SCAN_INTERVAL_S

    def scan(self) -> List[dict]:
        self._last_scan = self.clock()
        local_ips = [ip for ip in self.local_ips_fn() if _valid_ipv4(ip)]
        query = build_query(self.db, local_ips)
        if not query:
            return []
        raw = self.query_fn(query) or ''
        now = self.clock()
        # Expire suppression entries older than one window.
        self._last_emit = {k: t for k, t in self._last_emit.items() if now - t < WINDOW_S}
        out: List[dict] = []
        for line in raw.strip().split('\n'):
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            ip = str(row.get('ip', ''))
            if not _valid_ipv4(ip):
                continue
            if self.is_trusted_fn is not None and self.is_trusted_fn(ip):
                continue
            for reason in classify(row):
                key = (ip, reason)
                if key in self._last_emit:
                    continue
                self._last_emit[key] = now
                out.extend(events_for(row, reason, local_ips[0]))
        return out


def local_ipv4s() -> List[str]:
    """IPv4 addresses owned by this host (host-network container view)."""
    ips = set()
    try:
        with open('/proc/net/fib_trie') as fh:
            prev = None
            for line in fh:
                line = line.strip()
                if line.startswith('|--'):
                    prev = line[3:].strip()
                elif '/32 host LOCAL' in line and prev:
                    ips.add(prev)
    except OSError:
        pass
    return sorted(ip for ip in ips
                  if _valid_ipv4(ip) and not ip.startswith('127.')
                  and not ipaddress.ip_address(ip).is_link_local)
