"""Canonical trusted-network list shared across HYDRA/NAPSE services.

Before this module existed, each service (inspector/packet_inspector.py,
hydra/sentinel_engine.py, etc.) kept its own hand-maintained TRUSTED_NETWORKS
list. The lists drifted — inspector ignored Vodafone/Anthropic/Mitel while
SENTINEL would malicious-label the same IPs, producing contradictory
verdicts for the same traffic.

This module is the single source of truth for "trusted sources that should
not be classified as a threat by any threat-scoring component." Import it
from every threat-scoring service. Kernel-level allowlists (feed_sync's
TRUSTED_CIDRS, which also embeds Cloudflare ranges) serve a different
purpose and stay separate on purpose.
"""
from __future__ import annotations

import ipaddress
from typing import Iterable, List, Optional, Union

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

# Canonical trusted networks — union of inspector + sentinel lists.
# Order is by specificity (most specific first) only for readability;
# the membership check is O(n) over all entries.
TRUSTED_NETWORKS: List[IPNetwork] = [
    # Operator-specific — adjust if deployment environment changes.
    ipaddress.ip_network('160.79.104.0/23'),    # Anthropic (Claude Code SSH egress)
    ipaddress.ip_network('213.233.111.0/24'),   # Vodafone Romania (owner ISP — Bucharest)
    ipaddress.ip_network('46.97.153.0/24'),     # Vodafone Romania (owner ISP — Giurgiu)
    ipaddress.ip_network('84.232.173.0/24'),    # RCS&RDS / Digi Romania (owner ISP — *.rdsnet.ro)
    ipaddress.ip_network('213.233.110.0/24'),   # xnet.ro (owner ISP — *.xnet.ro broadband)
    ipaddress.ip_network('132.145.236.0/24'),   # Oracle Cloud (OCI mgmt jump host — accepted SSH)
    ipaddress.ip_network('209.249.57.0/24'),    # Mitel Networks
    # Cloud/infra
    ipaddress.ip_network('169.254.0.0/16'),     # Link-local / OCI metadata
    # Public DNS resolvers — the edge node uses these as upstream DNS, so the
    # inspector sees the high-volume RESPONSE traffic (src = resolver IP) and
    # threat-scorers (SENTINEL/anomaly) were flagging it as beaconing/exfil.
    # These anycast ranges serve only the public resolver, never originate
    # attacks, and must never be classified as a threat. NOTE: these are the
    # RESOLVER anycast ranges — distinct from Cloudflare's CDN ranges in
    # feed_sync.TRUSTED_CIDRS (104.16.0.0/13 etc.), which do NOT cover 1.1.1.1.
    ipaddress.ip_network('1.1.1.0/24'),          # Cloudflare DNS (1.1.1.1 / 1.0.0.1 secondary)
    ipaddress.ip_network('1.0.0.0/24'),          # Cloudflare DNS (1.0.0.1)
    ipaddress.ip_network('8.8.8.0/24'),          # Google Public DNS (8.8.8.8)
    ipaddress.ip_network('8.8.4.0/24'),          # Google Public DNS (8.8.4.4)
    ipaddress.ip_network('9.9.9.0/24'),          # Quad9 (9.9.9.9)
    ipaddress.ip_network('149.112.112.0/24'),    # Quad9 secondary
    ipaddress.ip_network('208.67.222.0/24'),     # OpenDNS (208.67.222.222)
    ipaddress.ip_network('208.67.220.0/24'),     # OpenDNS (208.67.220.220)
    # RFC-1918
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    # Loopback
    ipaddress.ip_network('127.0.0.0/8'),
]


# ---------------------------------------------------------------------------
# Dynamic operator trust
# ---------------------------------------------------------------------------
# The operator's ISP hands out dynamic IPs, so the static /24s above keep
# drifting (2026-11-08: neural-kernel cognitive_throttle blackholed the
# operator's home IP 86.120.11.18 on the mesh/VPN port 8144 for ~7h; it had
# SSH'd in the evening before but had no LIVE SSH session, so the live-SSH
# guard did not cover it). The host timer `operator-trust-sync` writes the
# source IPs of recent SUCCESSFUL SSH logins to this file (one IP/CIDR per
# line, '#' comments allowed); every threat scorer and the XDP allowlist
# treat them as trusted. Missing/unreadable file == no dynamic entries.
import os as _os
import time as _time

DYNAMIC_TRUST_FILE = _os.environ.get(
    'HOOKPROBE_DYNAMIC_TRUST_FILE', '/var/lib/hookprobe/trust/operator_ips.txt')
_DYN_RECHECK_S = 30.0
_dyn_cache = {'mtime': None, 'checked': 0.0, 'nets': ()}


def parse_trust_lines(lines: Iterable[str]) -> List[IPNetwork]:
    """Parse IP/CIDR lines; skip comments, blanks and invalid entries.

    Over-broad entries (< /16 IPv4, < /32 IPv6) are rejected so a corrupt
    file can never allowlist the internet.
    """
    nets: List[IPNetwork] = []
    for raw in lines:
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if net.version == 4 and net.prefixlen < 16:
            continue
        if net.version == 6 and net.prefixlen < 32:
            continue
        nets.append(net)
    return nets


def dynamic_trusted_networks() -> tuple:
    """Return the dynamic trust entries, re-reading the file on mtime change."""
    now = _time.monotonic()
    if now - _dyn_cache['checked'] < _DYN_RECHECK_S and _dyn_cache['mtime'] is not None:
        return _dyn_cache['nets']
    _dyn_cache['checked'] = now
    try:
        mtime = _os.stat(DYNAMIC_TRUST_FILE).st_mtime
    except OSError:
        _dyn_cache.update(mtime=0.0, nets=())
        return ()
    if mtime != _dyn_cache['mtime']:
        try:
            with open(DYNAMIC_TRUST_FILE) as fh:
                nets = tuple(parse_trust_lines(fh))
        except OSError:
            nets = ()
        _dyn_cache.update(mtime=mtime, nets=nets)
    return _dyn_cache['nets']


# CDN edge proxies (2026-11-09). Every public request reaches the origin
# through Cloudflare, so its edge IPs carry heavy, entirely normal traffic —
# the anomaly scorer was labelling them 'suspicious' (93% of all suspicious
# verdicts: 2,985/3,198 in 24h across 678 edge IPs). A CDN edge is never the
# attacker; the real client is attributed at L7 (nginx real-IP + AI-WAF).
# Treated as trusted for SCORING. The origin-bypass detector
# (flow_threats.is_cloudflare) and the kernel allowlist (feed_sync
# TRUSTED_CIDRS) keep their own copies on purpose.
# Source: https://www.cloudflare.com/ips-v4 + /ips-v6 (keep in sync with
# containers/proxy cloudflare-ips-sync.sh).
CDN_EDGE_NETWORKS: List[IPNetwork] = [ipaddress.ip_network(c) for c in (
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
    '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
    '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
)]


def is_cdn_edge(ip_str: str) -> bool:
    """True if ip is a CDN (Cloudflare) edge proxy address."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return False
    return any(addr in net for net in CDN_EDGE_NETWORKS if addr.version == net.version)


def all_trusted_networks() -> List[IPNetwork]:
    """Static canonical list + dynamic operator entries."""
    return list(TRUSTED_NETWORKS) + list(dynamic_trusted_networks())


def is_trusted(ip_str: str) -> bool:
    """Return True if the given IPv4/IPv6 string is inside any trusted network
    (static canonical list or dynamic operator trust file).

    Invalid/empty IPs return False (never trusted).
    """
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return False
    if any(addr in net for net in TRUSTED_NETWORKS):
        return True
    if is_cdn_edge(ip_str):
        return True
    return any(addr in net for net in dynamic_trusted_networks())


def filter_trusted(ips: Iterable[str]) -> List[str]:
    """Return the subset of the input IPs that are NOT trusted.

    Convenience helper for bulk filtering in hot paths.
    """
    return [ip for ip in ips if not is_trusted(ip)]


def network_for(ip_str: str) -> Optional[IPNetwork]:
    """Return the matching trusted network for an IP, or None if untrusted."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return None
    for net in TRUSTED_NETWORKS:
        if addr in net:
            return net
    return None
