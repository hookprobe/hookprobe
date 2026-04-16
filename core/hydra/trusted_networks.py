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
    ipaddress.ip_network('209.249.57.0/24'),    # Mitel Networks
    # Cloud/infra
    ipaddress.ip_network('169.254.0.0/16'),     # Link-local / OCI metadata
    # RFC-1918
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    # Loopback
    ipaddress.ip_network('127.0.0.0/8'),
]


def is_trusted(ip_str: str) -> bool:
    """Return True if the given IPv4/IPv6 string is inside any trusted network.

    Invalid/empty IPs return False (never trusted).
    """
    if not ip_str:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
    except (ValueError, TypeError):
        return False
    return any(addr in net for net in TRUSTED_NETWORKS)


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
