#!/usr/bin/env python3
"""
HookProbe Packet Inspector - Real-time traffic capture and intent classification.

Replaces Aegis (Zig/eBPF) + Napse (Mojo) with a production-ready Python implementation
that captures real packets from dummy-mirror and writes to ClickHouse.

Data flow:
  dummy-mirror (AF_PACKET) -> parse -> classify -> ClickHouse
    - napse_intents: threat intent classifications
    - napse_flows: flow summaries (5-tuple aggregated)
    - xdp_stats: periodic traffic statistics

Usage:
    python3 packet_inspector.py [--interface dummy-mirror] [--stats-interval 10]
"""

import os
import sys
import time
import math
import json
import re
import struct
import socket
import signal
import logging
import hashlib
import heapq
import argparse
import ipaddress
import base64
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, Tuple, Optional
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [INSPECTOR] %(levelname)s: %(message)s'
)
logger = logging.getLogger(__name__)

# Protocol numbers
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMP = 1

# Well-known ports
PORT_HTTP = 80
PORT_HTTPS = 443
PORT_DNS = 53
PORT_SSH = 22
PORT_VPN_PORTS = {500, 4500, 1194, 51820}  # IKE, NAT-T, OpenVPN, WireGuard
PORT_HTP = 9443  # HookProbe Transport Protocol
PORT_BRUTE = {22, 3389, 5432, 3306, 1433, 27017}  # SSH, RDP, PG, MySQL, MSSQL, Mongo
PORT_ADMIN = {22, 3389, 5985, 5986, 445, 135, 139}  # Admin/lateral movement ports

# Known DNS-over-HTTPS resolver IPs
DOH_RESOLVER_IPS = {
    '1.1.1.1', '1.0.0.1',           # Cloudflare
    '8.8.8.8', '8.8.4.4',           # Google
    '9.9.9.9', '149.112.112.112',   # Quad9
    '208.67.222.222', '208.67.220.220',  # OpenDNS
}

# Trusted networks - never classify as threats
# These are known legitimate sources that should not trigger alerts
TRUSTED_NETWORKS = [
    ipaddress.ip_network('160.79.104.0/23'),    # Anthropic (Claude Code SSH)
    ipaddress.ip_network('213.233.111.0/24'),    # Vodafone Romania (owner ISP - Bucharest)
    ipaddress.ip_network('46.97.153.0/24'),      # Vodafone Romania (owner ISP - Giurgiu)
    ipaddress.ip_network('209.249.57.0/24'),     # Mitel Networks
    ipaddress.ip_network('169.254.0.0/16'),      # Link-local / cloud metadata
    ipaddress.ip_network('10.0.0.0/8'),          # Private RFC1918
    ipaddress.ip_network('172.16.0.0/12'),       # Private RFC1918
    ipaddress.ip_network('192.168.0.0/16'),      # Private RFC1918
    ipaddress.ip_network('127.0.0.0/8'),         # Loopback
]

# Known infrastructure IPs (CDN, repos, cloud services) - never flag as threats
TRUSTED_IPS = set()

def _build_trusted_ips():
    """Build a set of known-good individual IPs at startup."""
    # These are resolved once; add more as needed
    known = [
        '91.189.92.21',     # Ubuntu archive (apt)
        '91.189.91.82',     # Ubuntu archive
        '185.125.190.36',   # Ubuntu cloud images
    ]
    for ip in known:
        try:
            TRUSTED_IPS.add(ipaddress.ip_address(ip))
        except ValueError:
            pass

_build_trusted_ips()

def is_trusted_source(ip_str: str) -> bool:
    """Check if an IP belongs to a trusted network or is a known infrastructure IP."""
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr in TRUSTED_IPS:
            return True
        return any(addr in net for net in TRUSTED_NETWORKS)
    except ValueError:
        return False

# Intent classes (must match ClickHouse schema)
INTENT_BENIGN = 'benign'
INTENT_SCAN = 'scan'
INTENT_BRUTEFORCE = 'bruteforce'
INTENT_C2_BEACON = 'c2_beacon'
INTENT_EXFILTRATION = 'exfiltration'
INTENT_DDOS = 'ddos'
INTENT_MALWARE = 'malware'
INTENT_LATERAL = 'lateral_movement'

# HMM kill chain states
HMM_IDLE = 'idle'
HMM_RECON = 'reconnaissance'
HMM_DELIVERY = 'delivery'
HMM_EXPLOITATION = 'exploitation'
HMM_C2 = 'command_control'

INTENT_TO_HMM = {
    INTENT_BENIGN: HMM_IDLE,
    INTENT_SCAN: HMM_RECON,
    INTENT_BRUTEFORCE: HMM_DELIVERY,
    INTENT_C2_BEACON: HMM_C2,
    INTENT_EXFILTRATION: HMM_C2,
    INTENT_DDOS: HMM_EXPLOITATION,
    INTENT_MALWARE: HMM_DELIVERY,
    INTENT_LATERAL: HMM_EXPLOITATION,
}

# Allowlists for batch insert validation (CRITICAL: prevents SQL injection)
ALLOWED_TABLES = frozenset({
    'napse_intents', 'napse_flows', 'xdp_stats',
})
_COLUMN_NAME_RE = re.compile(r'^[a-z_][a-z0-9_]{0,63}$')


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def parse_dns_query_name(payload: bytes) -> Optional[str]:
    """
    Parse DNS query name from UDP payload.
    Returns the fully qualified domain name or None on error.
    DNS wire format: [len]label[len]label...0x00
    Skips the 12-byte DNS header (ID + flags + counts).
    """
    if len(payload) < 13:  # 12-byte header + at least 1 byte
        return None

    # Check that it looks like a standard query (QR=0, OPCODE=0)
    flags = struct.unpack('!H', payload[2:4])[0]
    if flags & 0x8000:  # QR bit set = response, not query
        return None

    labels = []
    offset = 12  # Start after DNS header
    total_len = 0

    while offset < len(payload):
        label_len = payload[offset]
        if label_len == 0:
            break
        if label_len > 63:  # Compression pointer or invalid
            return None
        if offset + 1 + label_len > len(payload):
            return None
        total_len += label_len
        if total_len > 253:  # Max DNS name length
            return None
        labels.append(payload[offset + 1:offset + 1 + label_len].decode('ascii', errors='replace'))
        offset += 1 + label_len

    if not labels:
        return None

    return '.'.join(labels)


def label_entropy(name: str) -> float:
    """Compute Shannon entropy of a DNS label string (characters only)."""
    if not name:
        return 0.0
    # Remove dots, compute entropy of the raw characters
    chars = name.replace('.', '')
    if len(chars) < 4:
        return 0.0
    freq: Dict[str, int] = {}
    for c in chars:
        freq[c] = freq.get(c, 0) + 1
    n = len(chars)
    entropy = 0.0
    for count in freq.values():
        if count > 0:
            p = count / n
            entropy -= p * math.log2(p)
    return entropy


def extract_base_domain(fqdn: str) -> str:
    """Extract the base domain (last 2 labels) from an FQDN."""
    parts = fqdn.rstrip('.').split('.')
    if len(parts) <= 2:
        return fqdn
    return '.'.join(parts[-2:])


def community_id(proto: int, src_ip: str, dst_ip: str,
                 src_port: int, dst_port: int) -> str:
    """Generate a community ID hash for flow correlation."""
    # Simplified community ID (deterministic for same 5-tuple regardless of direction)
    if (src_ip, src_port) > (dst_ip, dst_port):
        key = f"{proto}:{dst_ip}:{dst_port}-{src_ip}:{src_port}"
    else:
        key = f"{proto}:{src_ip}:{src_port}-{dst_ip}:{dst_port}"
    return "1:" + hashlib.sha256(key.encode()).hexdigest()[:16]


def is_private_ip(ip_str: str) -> bool:
    """Check if IP is private/internal."""
    try:
        return ipaddress.ip_address(ip_str).is_private
    except ValueError:
        return False


def classify_port(port: int) -> str:
    """Classify a port into a service category."""
    if port == PORT_HTTP or port == 8080 or port == 8000:
        return 'http'
    elif port == PORT_HTTPS or port == 8443:
        return 'https'
    elif port == PORT_DNS:
        return 'dns'
    elif port == PORT_SSH:
        return 'ssh'
    elif port in PORT_VPN_PORTS:
        return 'vpn'
    elif port == PORT_HTP:
        return 'htp'
    else:
        return 'other'


class FlowEntry:
    """Track a single network flow."""
    __slots__ = ('src_ip', 'dst_ip', 'src_port', 'dst_port', 'proto',
                 'pkts_orig', 'pkts_resp', 'bytes_orig', 'bytes_resp',
                 'start_time', 'last_seen', 'entropy_sum', 'entropy_count',
                 'max_entropy', 'service', 'intent_class', 'confidence')

    def __init__(self, src_ip, dst_ip, src_port, dst_port, proto):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.proto = proto
        self.pkts_orig = 0
        self.pkts_resp = 0
        self.bytes_orig = 0
        self.bytes_resp = 0
        self.start_time = time.time()
        self.last_seen = self.start_time
        self.entropy_sum = 0.0
        self.entropy_count = 0
        self.max_entropy = 0.0
        self.service = classify_port(min(src_port, dst_port))
        self.intent_class = INTENT_BENIGN
        self.confidence = 0.5


class PacketInspector:
    """Main packet capture and classification engine."""

    def __init__(self, interface: str, stats_interval: int = 10,
                 flow_expiry: int = 300, flush_interval: int = 30):
        self.interface = interface
        self.stats_interval = stats_interval
        self.flow_expiry = flow_expiry
        self.flush_interval = flush_interval
        self.running = True

        # ClickHouse config
        self.ch_host = os.environ.get('CLICKHOUSE_HOST', '127.0.0.1')
        self.ch_port = os.environ.get('CLICKHOUSE_PORT', '8123')
        self.ch_db = os.environ.get('CLICKHOUSE_DB', 'hookprobe_ids')
        self.ch_user = os.environ.get('CLICKHOUSE_USER', 'ids')
        self.ch_password = os.environ.get('CLICKHOUSE_PASSWORD', '')

        if not self.ch_password:
            logger.error("CLICKHOUSE_PASSWORD environment variable is required")
            sys.exit(1)

        # Enforce localhost-only for cleartext HTTP to ClickHouse
        if self.ch_host not in ('127.0.0.1', 'localhost', '::1'):
            logger.error(
                f"CLICKHOUSE_HOST={self.ch_host} is not localhost. "
                "Cleartext HTTP with credentials to remote hosts is not allowed."
            )
            sys.exit(1)

        # Flow table: (src_ip, dst_ip, src_port, dst_port, proto) -> FlowEntry
        self.flows: Dict[Tuple, FlowEntry] = {}

        # Intent tracking for heuristic detection
        self.src_dst_ports: Dict[str, set] = defaultdict(set)  # src -> set of dst_ports
        self.src_port_counts: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))

        # DNS tunnel detection tracking (per source IP per 60s window)
        self.dns_queries_per_src: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))  # src -> base_domain -> set(subdomains)
        self.dns_query_lengths: Dict[str, list] = defaultdict(list)  # src -> list of query name lengths
        self.dns_high_entropy_count: Dict[str, int] = defaultdict(int)  # src -> count of high-entropy queries
        self.dns_txt_count: Dict[str, int] = defaultdict(int)  # src -> TXT query count
        self.src_pkt_rate: Dict[str, deque] = defaultdict(deque)  # src -> deque of timestamps

        # Traffic counters for xdp_stats
        self.stats = {
            'total_packets': 0, 'total_bytes': 0,
            'tcp_packets': 0, 'udp_packets': 0, 'icmp_packets': 0, 'other_packets': 0,
            'tcp_bytes': 0, 'udp_bytes': 0, 'icmp_bytes': 0, 'other_bytes': 0,
            'http_packets': 0, 'https_packets': 0, 'dns_packets': 0,
            'ssh_packets': 0, 'vpn_packets': 0, 'htp_packets': 0,
        }
        self.prev_stats = dict(self.stats)
        self.high_rate_ips: Dict[str, int] = {}

        # Timing
        self.last_stats_flush = time.time()
        self.last_flow_flush = time.time()
        self.last_intent_window_reset = time.time()

        # Pending inserts (batch for efficiency)
        self.pending_intents = []
        self.pending_flows = []

    def _ch_request(self, url: str, data: bytes, timeout: int = 5, retries: int = 3) -> Tuple[int, str]:
        """Make an HTTP POST to ClickHouse with Basic auth and retry on connection errors."""
        auth = base64.b64encode(f"{self.ch_user}:{self.ch_password}".encode()).decode()
        for attempt in range(retries):
            req = Request(url, data=data, method='POST')
            req.add_header('Authorization', f'Basic {auth}')
            try:
                resp = urlopen(req, timeout=timeout)
                return resp.status, resp.read().decode()
            except HTTPError as e:
                return e.code, e.read().decode()[:200]
            except (URLError, OSError) as e:
                if attempt < retries - 1:
                    time.sleep(0.5 * (2 ** attempt))
                    continue
                return 0, str(e)
        return 0, "Max retries exceeded"

    def _ch_insert(self, query: str, params: dict) -> bool:
        """Execute ClickHouse INSERT with parameterized values."""
        try:
            url_params = {'database': self.ch_db}
            for key, value in params.items():
                url_params[f'param_{key}'] = str(value)

            url = f"http://{self.ch_host}:{self.ch_port}/?{urlencode(url_params)}"
            status, body = self._ch_request(url, query.encode())
            if status != 200:
                logger.warning(f"ClickHouse insert failed ({status}): {body}")
                return False
            return True
        except Exception as e:
            logger.error(f"ClickHouse error: {e}")
            return False

    def _ch_batch_insert(self, table: str, columns: list, rows: list) -> bool:
        """Batch insert rows into ClickHouse using JSONEachRow format."""
        if not rows:
            return True

        # Validate table name against allowlist (prevents SQL injection)
        if table not in ALLOWED_TABLES:
            logger.error(f"Rejected batch insert: table '{table}' not in allowlist")
            return False
        # Validate column names against strict pattern
        for col in columns:
            if not _COLUMN_NAME_RE.match(col):
                logger.error(f"Rejected batch insert: invalid column name '{col}'")
                return False

        try:
            body_lines = []
            for row in rows:
                obj = {}
                for i, col in enumerate(columns):
                    obj[col] = row[i]
                body_lines.append(json.dumps(obj))
            body = '\n'.join(body_lines)

            url_params = {
                'database': self.ch_db,
                'query': f"INSERT INTO {table} ({', '.join(columns)}) FORMAT JSONEachRow"
            }

            url = f"http://{self.ch_host}:{self.ch_port}/?{urlencode(url_params)}"
            status, resp_body = self._ch_request(url, body.encode(), timeout=10)
            if status != 200:
                logger.warning(f"Batch insert to {table} failed ({status}): {resp_body}")
                return False
            return True
        except Exception as e:
            logger.error(f"Batch insert error: {e}")
            return False

    def parse_packet(self, raw: bytes) -> Optional[dict]:
        """Parse raw Ethernet frame into structured packet info."""
        if len(raw) < 14:
            return None

        # Ethernet header (14 bytes)
        eth_proto = struct.unpack('!H', raw[12:14])[0]

        # Only handle IPv4 (0x0800)
        if eth_proto != 0x0800:
            return None

        if len(raw) < 34:  # 14 eth + 20 min IP
            return None

        # IPv4 header
        ip_header = raw[14:34]
        ihl = (ip_header[0] & 0x0F) * 4
        if ihl < 20:  # Minimum valid IPv4 header is 20 bytes
            return None
        if len(raw) < 14 + ihl:  # Ensure full IP header is present
            return None
        total_length = struct.unpack('!H', ip_header[2:4])[0]
        proto = ip_header[9]
        src_ip = socket.inet_ntoa(ip_header[12:16])
        dst_ip = socket.inet_ntoa(ip_header[16:20])

        src_port = 0
        dst_port = 0
        tcp_flags = 0
        payload_start = 14 + ihl

        if proto == PROTO_TCP and len(raw) >= payload_start + 20:
            tcp_header = raw[payload_start:payload_start + 20]
            src_port = struct.unpack('!H', tcp_header[0:2])[0]
            dst_port = struct.unpack('!H', tcp_header[2:4])[0]
            data_offset = ((tcp_header[12] >> 4) & 0x0F) * 4
            if data_offset < 20 or data_offset > 60:
                return None
            tcp_flags = tcp_header[13]
            payload_start += data_offset
        elif proto == PROTO_UDP and len(raw) >= payload_start + 8:
            udp_header = raw[payload_start:payload_start + 8]
            src_port = struct.unpack('!H', udp_header[0:2])[0]
            dst_port = struct.unpack('!H', udp_header[2:4])[0]
            payload_start += 8
        elif proto == PROTO_ICMP:
            payload_start += 8  # ICMP header

        payload = raw[payload_start:] if payload_start < len(raw) else b''
        payload_len = len(payload)
        entropy = shannon_entropy(payload[:256]) if payload_len > 0 else 0.0

        return {
            'src_ip': src_ip, 'dst_ip': dst_ip,
            'src_port': src_port, 'dst_port': dst_port,
            'proto': proto, 'tcp_flags': tcp_flags,
            'total_length': total_length, 'payload_len': payload_len,
            'entropy': entropy,
            'payload': payload,
        }

    def update_stats(self, pkt: dict):
        """Update traffic counters."""
        self.stats['total_packets'] += 1
        self.stats['total_bytes'] += pkt['total_length']

        proto = pkt['proto']
        size = pkt['total_length']
        if proto == PROTO_TCP:
            self.stats['tcp_packets'] += 1
            self.stats['tcp_bytes'] += size
        elif proto == PROTO_UDP:
            self.stats['udp_packets'] += 1
            self.stats['udp_bytes'] += size
        elif proto == PROTO_ICMP:
            self.stats['icmp_packets'] += 1
            self.stats['icmp_bytes'] += size
        else:
            self.stats['other_packets'] += 1
            self.stats['other_bytes'] += size

        # Port category
        dst_port = pkt['dst_port']
        src_port = pkt['src_port']
        svc = classify_port(min(dst_port, src_port) if dst_port > 0 else dst_port)
        key = f'{svc}_packets'
        if key in self.stats:
            self.stats[key] += 1

    def update_flow(self, pkt: dict):
        """Update flow table with packet data."""
        src = pkt['src_ip']
        dst = pkt['dst_ip']
        sp = pkt['src_port']
        dp = pkt['dst_port']
        proto = pkt['proto']

        # Canonical flow key (lower IP first for bidirectional matching)
        if (src, sp) <= (dst, dp):
            key = (src, dst, sp, dp, proto)
            is_orig = True
        else:
            key = (dst, src, dp, sp, proto)
            is_orig = False

        now = time.time()

        if key not in self.flows:
            if is_orig:
                self.flows[key] = FlowEntry(src, dst, sp, dp, proto)
            else:
                self.flows[key] = FlowEntry(dst, src, dp, sp, proto)

        flow = self.flows[key]
        flow.last_seen = now

        if is_orig:
            flow.pkts_orig += 1
            flow.bytes_orig += pkt['total_length']
        else:
            flow.pkts_resp += 1
            flow.bytes_resp += pkt['total_length']

        if pkt['entropy'] > 0:
            flow.entropy_sum += pkt['entropy']
            flow.entropy_count += 1
            flow.max_entropy = max(flow.max_entropy, pkt['entropy'])

    def _classify_ddos_subtype(self, pkt: dict, pps: int) -> str:
        """Classify DDoS variant by traffic shape."""
        tcp_flags = pkt['tcp_flags']
        proto = pkt['proto']

        if proto == PROTO_TCP:
            # SYN flood: high SYN ratio, no ACK completion
            if (tcp_flags & 0x02) and not (tcp_flags & 0x10):
                return 'syn_flood'
            # ACK flood
            if (tcp_flags & 0x10) and not (tcp_flags & 0x02):
                return 'ack_flood'
            # RST flood
            if tcp_flags & 0x04:
                return 'rst_flood'
        elif proto == PROTO_UDP:
            return 'udp_flood'
        elif proto == PROTO_ICMP:
            return 'icmp_flood'

        if pkt.get('payload_len', 0) < 100:
            return 'small_packet_flood'
        return 'volumetric'

    def _classify_bruteforce_subtype(self, dst_port: int) -> str:
        """Classify brute force variant by target port."""
        if dst_port == 22:
            return 'ssh_bruteforce'
        if dst_port == 3389:
            return 'rdp_bruteforce'
        if dst_port in (80, 443, 8080, 8443):
            return 'http_auth_bruteforce'
        if dst_port in (5432, 3306, 1433, 27017):
            return 'db_bruteforce'
        if dst_port in (21, 990):
            return 'ftp_bruteforce'
        return 'generic_bruteforce'

    def classify_intent(self, pkt: dict) -> Optional[Tuple[str, float, int, str]]:
        """
        Classify packet intent using heuristics.
        Returns (intent_class, confidence, severity, attack_subtype) or None for benign.
        attack_subtype provides granular classification (e.g., 'syn_flood', 'ssh_bruteforce').

        Classification philosophy:
        - Trusted sources are NEVER flagged (allowlist check first)
        - DDoS requires DISTRIBUTED sources at HIGH intensity
        - Brute force requires SYN-only packets (new connections) to auth ports
        - Port scan requires probing non-standard ports, not just visiting services
        - Established TCP sessions (data transfer) are not attacks
        """
        src = pkt['src_ip']
        dst = pkt['dst_ip']
        dst_port = pkt['dst_port']
        src_port = pkt['src_port']
        proto = pkt['proto']
        tcp_flags = pkt['tcp_flags']
        now = time.time()

        # ---- ALLOWLIST CHECK (first, before any tracking) ----
        # Never classify trusted sources as threats
        if is_trusted_source(src):
            return None

        # Skip response traffic on ephemeral ports (>= 32768)
        # These are server responses, not attacks
        if src_port >= 32768 and dst_port < 1024:
            # This is likely a server responding to a client - skip
            pass  # Continue to classification for the client side
        elif dst_port >= 32768 and src_port < 1024:
            # Response packet from server to client on ephemeral port - benign
            return None

        # ---- UPDATE TRACKING STRUCTURES ----
        self.src_dst_ports[src].add(dst_port)
        if dst_port > 0:
            self.src_port_counts[src][dst_port] += 1
        self.src_pkt_rate[src].append(now)

        # Clean old rate entries (60-second sliding window)
        cutoff = now - 60
        rate_deque = self.src_pkt_rate[src]
        while rate_deque and rate_deque[0] <= cutoff:
            rate_deque.popleft()

        pps = len(rate_deque)

        # ---- DDoS DETECTION ----
        # Real DDoS = DISTRIBUTED denial of service
        # Requires: high packet rate AND multiple sources exhibiting the same behavior
        # A single source at high rate is just a busy connection, not DDoS
        if pps > 5000:  # 5000 pkts/60s = ~83 pps sustained (was 1000)
            self.high_rate_ips[src] = pps
            # Only classify as DDoS if we see 10+ distinct high-rate sources
            # (i.e., a coordinated attack from multiple IPs)
            if len(self.high_rate_ips) >= 10:
                # Sub-classify DDoS variant by traffic shape
                subtype = self._classify_ddos_subtype(pkt, pps)
                return (INTENT_DDOS, 0.9, 1, subtype)
            # Single high-rate source: just track it, don't alert
            # It could be a legitimate bulk transfer, API client, or SSH session

        # ---- PORT SCAN DETECTION ----
        # Real port scan = probing many UNUSUAL ports, not visiting well-known services
        # Exclude common service ports from the count
        COMMON_PORTS = {22, 53, 80, 123, 443, 3000, 5432, 8000, 8080, 8123, 8443, 9443}
        unique_ports = len(self.src_dst_ports[src])
        uncommon_ports = len(self.src_dst_ports[src] - COMMON_PORTS)
        if uncommon_ports > 25:  # Probing 25+ non-standard ports (was 10 total)
            return (INTENT_SCAN, min(0.5 + uncommon_ports * 0.01, 0.90), 3, 'port_scan')

        # ---- BRUTE FORCE DETECTION ----
        # Real brute force = many NEW connection attempts (SYN) to auth ports
        # NOT just packet count (an established SSH session generates thousands of packets)
        if proto == PROTO_TCP and (tcp_flags & 0x02) and not (tcp_flags & 0x10):
            # This is a SYN-only packet (new connection attempt, not SYN-ACK)
            for port in PORT_BRUTE:
                if dst_port == port:
                    # Track SYN-only count separately using a special key
                    syn_key = f"syn_{port}"
                    self.src_port_counts[src][10000 + port] = self.src_port_counts[src].get(10000 + port, 0) + 1
                    syn_count = self.src_port_counts[src].get(10000 + port, 0)
                    if syn_count > 50:  # 50+ SYN attempts to auth port in 60s (was 20 total pkts)
                        subtype = self._classify_bruteforce_subtype(dst_port)
                        return (INTENT_BRUTEFORCE, min(0.6 + syn_count * 0.005, 0.95), 2, subtype)

        # ---- EXFILTRATION DETECTION ----
        # Large payload + high entropy outbound from internal to external
        if (pkt['payload_len'] > 1000 and pkt['entropy'] > 7.5
                and is_private_ip(src) and not is_private_ip(dst)
                and dst_port not in {80, 443, 53}):  # Exclude normal web/DNS
            return (INTENT_EXFILTRATION, 0.7, 2, 'high_entropy_exfil')

        # ---- LATERAL MOVEMENT DETECTION ----
        # Internal -> internal SYN to admin ports
        if (is_private_ip(src) and is_private_ip(dst)
                and dst_port in PORT_ADMIN and proto == PROTO_TCP):
            if tcp_flags & 0x02 and not (tcp_flags & 0x10):  # SYN-only
                return (INTENT_LATERAL, 0.6, 3, 'lateral_movement')

        # ---- DNS TUNNELING DETECTION ----
        if dst_port == PORT_DNS and proto == PROTO_UDP:
            dns_count = self.src_port_counts[src].get(PORT_DNS, 0)

            # Parse the DNS query name from payload
            payload = pkt.get('payload', b'')
            qname = parse_dns_query_name(payload) if payload else None

            if qname:
                base_domain = extract_base_domain(qname)
                # Extract subdomain portion (everything before base domain)
                sub = qname[:-(len(base_domain) + 1)] if len(qname) > len(base_domain) else ''

                # Track unique subdomains per base domain
                if sub:
                    self.dns_queries_per_src[src][base_domain].add(sub)

                # Track query name length
                self.dns_query_lengths[src].append(len(qname))

                # Track high-entropy query names (base32/base64 encoding signature)
                name_ent = label_entropy(qname)
                if name_ent > 3.5 and len(qname) > 30:
                    self.dns_high_entropy_count[src] += 1

                # Check for TXT record queries (common tunnel type, qtype at offset after qname)
                # QTYPE is 2 bytes after the qname null terminator
                qname_end = 12  # DNS header
                while qname_end < len(payload) and payload[qname_end] != 0:
                    qname_end += 1 + payload[qname_end]
                qname_end += 1  # Skip null terminator
                if qname_end + 2 <= len(payload):
                    qtype = struct.unpack('!H', payload[qname_end:qname_end + 2])[0]
                    if qtype == 16:  # TXT record
                        self.dns_txt_count[src] += 1

                # DETECTION 1: Excessive unique subdomains to a single domain
                # Normal: a few subdomains (www, api, cdn). Tunnel: hundreds of unique labels
                for domain, subs in self.dns_queries_per_src[src].items():
                    if len(subs) > 50:  # 50+ unique subdomains to one domain in 60s
                        return (INTENT_EXFILTRATION, min(0.7 + len(subs) * 0.002, 0.95), 2, 'dns_tunnel')

                # DETECTION 2: High-entropy query names (base32/base64 encoded data)
                # Legitimate DNS: low entropy (www.example.com ≈ 2.5 bits)
                # DNS tunnel: high entropy (aGVsbG8gd29ybGQ.evil.com ≈ 4.5+ bits)
                if self.dns_high_entropy_count[src] > 10:
                    return (INTENT_C2_BEACON, min(0.65 + self.dns_high_entropy_count[src] * 0.005, 0.90), 2, 'dns_tunnel_entropy')

                # DETECTION 3: Long DNS query names (tunnel payloads)
                # Normal DNS queries are typically < 50 chars
                # DNS tunnels encode data in labels, making names 100-250 chars
                recent_lengths = self.dns_query_lengths[src]
                if len(recent_lengths) > 5:
                    avg_len = sum(recent_lengths) / len(recent_lengths)
                    if avg_len > 60:  # Average query name > 60 chars
                        return (INTENT_C2_BEACON, 0.7, 2, 'dns_tunnel_long_names')

                # DETECTION 4: Excessive TXT queries (common DNS tunnel channel)
                if self.dns_txt_count[src] > 20:
                    return (INTENT_C2_BEACON, 0.75, 2, 'dns_tunnel_txt')

            # DETECTION 5: Volume-based fallback (original check, works even without parsing)
            if dns_count > 200:  # 200+ DNS queries in 60s
                return (INTENT_SCAN, 0.65, 3, 'dns_scan')

        # ---- DNS-over-HTTPS (DoH) DETECTION ----
        # Large volumes of HTTPS traffic to known DoH resolvers may indicate
        # DNS tunnel bypass using encrypted DNS
        if proto == PROTO_TCP and dst_port == PORT_HTTPS and dst in DOH_RESOLVER_IPS:
            doh_count = self.src_port_counts[src].get(PORT_HTTPS, 0)
            if doh_count > 100:  # 100+ HTTPS packets to a DoH resolver in 60s
                return (INTENT_C2_BEACON, 0.55, 4, 'doh_bypass')

        return None  # Benign - this is the expected path for normal traffic

    def flush_stats(self):
        """Flush traffic statistics to xdp_stats table."""
        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

        delta_packets = self.stats['total_packets'] - self.prev_stats['total_packets']
        delta_bytes = self.stats['total_bytes'] - self.prev_stats['total_bytes']

        params = {
            'p_ts': now,
            'p_iface': self.interface,
            'p_total_pkts': self.stats['total_packets'],
            'p_total_bytes': self.stats['total_bytes'],
            'p_tcp_pkts': self.stats['tcp_packets'],
            'p_udp_pkts': self.stats['udp_packets'],
            'p_icmp_pkts': self.stats['icmp_packets'],
            'p_other_pkts': self.stats['other_packets'],
            'p_tcp_bytes': self.stats['tcp_bytes'],
            'p_udp_bytes': self.stats['udp_bytes'],
            'p_icmp_bytes': self.stats['icmp_bytes'],
            'p_other_bytes': self.stats['other_bytes'],
            'p_http_pkts': self.stats['http_packets'],
            'p_https_pkts': self.stats['https_packets'],
            'p_dns_pkts': self.stats['dns_packets'],
            'p_ssh_pkts': self.stats['ssh_packets'],
            'p_vpn_pkts': self.stats['vpn_packets'],
            'p_htp_pkts': self.stats.get('htp_packets', 0),
            'p_high_rate': len(self.high_rate_ips),
            'p_delta_pkts': delta_packets,
            'p_delta_bytes': delta_bytes,
        }

        query = """
            INSERT INTO xdp_stats (
                timestamp, interface, total_packets, total_bytes,
                tcp_packets, udp_packets, icmp_packets, other_packets,
                tcp_bytes, udp_bytes, icmp_bytes, other_bytes,
                http_packets, https_packets, dns_packets, ssh_packets,
                vpn_packets, htp_packets,
                high_rate_ip_count, delta_packets, delta_bytes
            ) VALUES (
                {p_ts:String}, {p_iface:String},
                {p_total_pkts:UInt64}, {p_total_bytes:UInt64},
                {p_tcp_pkts:UInt64}, {p_udp_pkts:UInt64},
                {p_icmp_pkts:UInt64}, {p_other_pkts:UInt64},
                {p_tcp_bytes:UInt64}, {p_udp_bytes:UInt64},
                {p_icmp_bytes:UInt64}, {p_other_bytes:UInt64},
                {p_http_pkts:UInt64}, {p_https_pkts:UInt64},
                {p_dns_pkts:UInt64}, {p_ssh_pkts:UInt64},
                {p_vpn_pkts:UInt64}, {p_htp_pkts:UInt64},
                {p_high_rate:UInt32}, {p_delta_pkts:UInt64}, {p_delta_bytes:UInt64}
            )
        """

        if self._ch_insert(query, params):
            logger.info(
                f"XDP stats: +{delta_packets} pkts, +{delta_bytes} bytes, "
                f"total={self.stats['total_packets']}, high_rate_ips={len(self.high_rate_ips)}"
            )

        self.prev_stats = dict(self.stats)

    def flush_intents(self):
        """Flush pending intent classifications to napse_intents."""
        if not self.pending_intents:
            return

        columns = [
            'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'proto', 'intent_class', 'confidence', 'severity',
            'hmm_state', 'entropy', 'community_id', 'features_summary'
        ]

        if self._ch_batch_insert('napse_intents', columns, self.pending_intents):
            logger.info(f"Flushed {len(self.pending_intents)} intents to ClickHouse")
        self.pending_intents = []

    def flush_expired_flows(self):
        """Flush expired flows to napse_flows and remove from table."""
        now = time.time()
        expired_keys = []
        rows = []

        for key, flow in self.flows.items():
            if now - flow.last_seen > self.flow_expiry:
                expired_keys.append(key)
                duration = flow.last_seen - flow.start_time
                avg_entropy = (flow.entropy_sum / flow.entropy_count
                               if flow.entropy_count > 0 else 0.0)
                cid = community_id(flow.proto, flow.src_ip, flow.dst_ip,
                                   flow.src_port, flow.dst_port)

                rows.append([
                    datetime.utcfromtimestamp(flow.start_time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                    cid,
                    flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port,
                    flow.proto, flow.service, round(duration, 3),
                    flow.bytes_orig, flow.bytes_resp,
                    flow.pkts_orig, flow.pkts_resp,
                    round(flow.max_entropy, 4), round(avg_entropy, 4),
                    flow.intent_class, round(flow.confidence, 4),
                    INTENT_TO_HMM.get(flow.intent_class, HMM_IDLE),
                ])

        if rows:
            columns = [
                'timestamp', 'community_id', 'src_ip', 'dst_ip',
                'src_port', 'dst_port', 'proto', 'service', 'duration',
                'bytes_orig', 'bytes_resp', 'pkts_orig', 'pkts_resp',
                'max_entropy', 'avg_entropy', 'intent_class', 'confidence',
                'hmm_final_state'
            ]
            if self._ch_batch_insert('napse_flows', columns, rows):
                logger.info(f"Flushed {len(rows)} expired flows to ClickHouse")

        for key in expired_keys:
            del self.flows[key]

        # Force-flush large flow table to prevent memory growth
        if len(self.flows) > 50000:
            evict_count = len(self.flows) - 30000
            oldest_keys = heapq.nsmallest(evict_count, self.flows, key=lambda k: self.flows[k].last_seen)
            for key in oldest_keys:
                del self.flows[key]
            logger.warning(f"Flow table pruned: removed {evict_count} entries, {len(self.flows)} remaining")

    def reset_intent_windows(self):
        """Reset per-source tracking windows every 60s."""
        self.src_dst_ports.clear()
        self.src_port_counts.clear()
        self.high_rate_ips.clear()
        self.dns_queries_per_src.clear()
        self.dns_query_lengths.clear()
        self.dns_high_entropy_count.clear()
        self.dns_txt_count.clear()
        # Prune src_pkt_rate: remove keys with no recent timestamps
        cutoff = time.time() - 60
        stale_keys = [k for k, v in self.src_pkt_rate.items() if not v or v[-1] < cutoff]
        for k in stale_keys:
            del self.src_pkt_rate[k]

    def run(self):
        """Main capture loop."""
        logger.info(f"Starting packet inspector on {self.interface}")
        logger.info(f"  ClickHouse: {self.ch_host}:{self.ch_port}/{self.ch_db}")
        logger.info(f"  Stats interval: {self.stats_interval}s")
        logger.info(f"  Flow expiry: {self.flow_expiry}s")

        # Verify ClickHouse connectivity
        try:
            url = f"http://{self.ch_host}:{self.ch_port}/ping"
            resp = urlopen(url, timeout=5)
            if resp.status == 200:
                logger.info("  ClickHouse: connected")
            else:
                logger.error(f"  ClickHouse ping failed: {resp.status}")
                sys.exit(1)
        except Exception as e:
            logger.error(f"  ClickHouse unreachable: {e}")
            sys.exit(1)

        # Open raw socket on interface
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
            sock.bind((self.interface, 0))
            sock.settimeout(1.0)  # 1s timeout for periodic maintenance
            logger.info(f"  Socket bound to {self.interface}")
        except PermissionError:
            logger.error("Permission denied. Run with CAP_NET_RAW or as root.")
            sys.exit(1)
        except OSError as e:
            logger.error(f"Cannot bind to {self.interface}: {e}")
            sys.exit(1)

        # Drop privileges: switch to nobody (65534) after binding raw socket
        try:
            if os.getuid() == 0:
                os.setgid(65534)
                os.setuid(65534)
                logger.info("  Privileges dropped to nobody (65534)")
        except OSError as e:
            logger.warning(f"  Could not drop privileges: {e}")

        logger.info("Capture started. Press Ctrl+C to stop.")

        pkt_count = 0
        intent_count = 0

        while self.running:
            try:
                raw = sock.recv(65535)
            except socket.timeout:
                raw = None
            except OSError:
                if not self.running:
                    break
                raise

            now = time.time()

            if raw:
                pkt = self.parse_packet(raw)
                if pkt:
                    pkt_count += 1
                    self.update_stats(pkt)
                    self.update_flow(pkt)

                    # Classify intent
                    result = self.classify_intent(pkt)
                    if result:
                        intent_class, confidence, severity, attack_subtype = result
                        cid = community_id(pkt['proto'], pkt['src_ip'], pkt['dst_ip'],
                                           pkt['src_port'], pkt['dst_port'])
                        ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
                        self.pending_intents.append([
                            ts, pkt['src_ip'], pkt['dst_ip'],
                            pkt['src_port'], pkt['dst_port'], pkt['proto'],
                            intent_class, round(confidence, 4), severity,
                            INTENT_TO_HMM.get(intent_class, HMM_IDLE),
                            round(pkt['entropy'], 4), cid, attack_subtype
                        ])
                        intent_count += 1

                        # Cap pending intents to prevent unbounded memory growth
                        if len(self.pending_intents) >= 10000:
                            self.flush_intents()

                        # Update flow intent (highest severity wins)
                        src, dst = pkt['src_ip'], pkt['dst_ip']
                        sp, dp = pkt['src_port'], pkt['dst_port']
                        if (src, sp) <= (dst, dp):
                            fkey = (src, dst, sp, dp, pkt['proto'])
                        else:
                            fkey = (dst, src, dp, sp, pkt['proto'])
                        if fkey in self.flows:
                            flow = self.flows[fkey]
                            # Lower severity number = more critical
                            if severity < 4:
                                flow.intent_class = intent_class
                                flow.confidence = max(flow.confidence, confidence)

            # Periodic maintenance
            if now - self.last_stats_flush >= self.stats_interval:
                self.flush_stats()
                self.last_stats_flush = now

            if now - self.last_flow_flush >= self.flush_interval:
                self.flush_intents()
                self.flush_expired_flows()
                self.last_flow_flush = now

            if now - self.last_intent_window_reset >= 60:
                self.reset_intent_windows()
                self.last_intent_window_reset = now
                if pkt_count > 0:
                    logger.info(
                        f"Window stats: {pkt_count} packets, {intent_count} intents, "
                        f"{len(self.flows)} active flows"
                    )

        # Final flush
        self.flush_stats()
        self.flush_intents()
        sock.close()
        logger.info(f"Stopped. Total: {pkt_count} packets, {intent_count} intents")


def main():
    parser = argparse.ArgumentParser(description='HookProbe Packet Inspector')
    parser.add_argument('--interface', default='dummy-mirror',
                        help='Capture interface (default: dummy-mirror)')
    parser.add_argument('--stats-interval', type=int, default=10,
                        help='XDP stats flush interval in seconds (default: 10)')
    parser.add_argument('--flow-expiry', type=int, default=300,
                        help='Flow idle expiry in seconds (default: 300)')
    parser.add_argument('--flush-interval', type=int, default=30,
                        help='Intent/flow flush interval in seconds (default: 30)')
    parser.add_argument('--log-level', default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])
    args = parser.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level))

    inspector = PacketInspector(
        interface=args.interface,
        stats_interval=args.stats_interval,
        flow_expiry=args.flow_expiry,
        flush_interval=args.flush_interval,
    )

    def handle_signal(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        inspector.running = False

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    inspector.run()


if __name__ == '__main__':
    main()
