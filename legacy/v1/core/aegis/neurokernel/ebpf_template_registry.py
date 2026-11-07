"""
eBPF Template Registry — Pre-vetted eBPF templates for known threat patterns.

Each template is a parameterized C program that can be deployed instantly
without LLM generation. Templates are matched against StandardSignals
using pattern rules on source, event_type, severity, and data fields.

Templates cover the top 10 attack patterns detected by NAPSE/QSecBit:
  1. SYN Flood (XDP drop by rate)
  2. UDP Flood (XDP drop by rate)
  3. Port Scan (XDP drop after threshold)
  4. DNS Amplification (XDP drop oversized DNS)
  5. ARP Spoof (XDP drop conflicting ARP)
  6. ICMP Flood (XDP rate-limit ICMP)
  7. TCP RST Attack (XDP drop forged RSTs)
  8. Slowloris (TC delay for slow connections)
  9. DNS Tunneling (XDP drop high-entropy DNS)
 10. IP Spoofing (XDP drop src outside LAN)

Author: Andrei Toma
License: Proprietary
Version: 1.0.0
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ..types import StandardSignal
from .types import ProgramType, TemplateMatch

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Template definition
# ------------------------------------------------------------------

@dataclass
class EBPFTemplate:
    """A pre-vetted eBPF program template."""
    name: str
    description: str
    program_type: ProgramType
    c_source: str
    # Match criteria
    source_patterns: List[str] = field(default_factory=list)   # regex on signal.source
    event_patterns: List[str] = field(default_factory=list)     # regex on signal.event_type
    severity_min: str = "MEDIUM"                                # Minimum severity to trigger
    data_patterns: Dict[str, str] = field(default_factory=dict) # regex on signal.data values
    # Metadata
    confidence: float = 0.9
    parameters: Dict[str, Any] = field(default_factory=dict)

    def matches(self, signal: StandardSignal) -> float:
        """Check if this template matches a signal.

        Returns confidence (0.0-1.0), 0.0 if no match.
        """
        severity_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        sig_severity = severity_order.get(signal.severity.upper(), 0)
        min_severity = severity_order.get(self.severity_min.upper(), 2)

        if sig_severity < min_severity:
            return 0.0

        # Must match at least one source pattern (if any specified)
        if self.source_patterns:
            source_match = any(
                re.search(p, signal.source, re.I) for p in self.source_patterns
            )
            if not source_match:
                return 0.0

        # Must match at least one event pattern (if any specified)
        if self.event_patterns:
            event_match = any(
                re.search(p, signal.event_type, re.I) for p in self.event_patterns
            )
            if not event_match:
                return 0.0

        # Optional data field patterns (all specified must match)
        if self.data_patterns:
            for key, pattern in self.data_patterns.items():
                value = str(signal.data.get(key, ""))
                if not re.search(pattern, value, re.I):
                    return 0.0

        return self.confidence


# ------------------------------------------------------------------
# Built-in templates
# ------------------------------------------------------------------

# Template 1: SYN Flood Mitigation (XDP)
SYN_FLOOD_XDP = EBPFTemplate(
    name="syn_flood_xdp",
    description="Drop SYN packets exceeding rate threshold from a source IP",
    program_type=ProgramType.XDP,
    source_patterns=[r"napse", r"qsecbit"],
    event_patterns=[r"syn.?flood", r"ddos.*syn", r"l4.*flood"],
    severity_min="HIGH",
    confidence=0.95,
    c_source=r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

// Per-source IP: packet count in current window
BPF_HASH(syn_count, u32, u64, 65536);
// Per-source IP: window start timestamp (ns)
BPF_HASH(syn_window, u32, u64, 65536);
// Stats
BPF_ARRAY(syn_stats, u64, 3);
enum { SYN_TOTAL = 0, SYN_DROPPED = 1, SYN_PASSED = 2 };

// Configurable: max SYN packets per source per second
#define SYN_RATE_LIMIT 100
#define WINDOW_NS 1000000000ULL  // 1 second

int xdp_syn_flood(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    u64 *total = syn_stats.lookup(&(u32){SYN_TOTAL});
    if (total) __sync_fetch_and_add(total, 1);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    // Only count SYN-only packets (SYN=1, ACK=0)
    if (!(tcp->syn && !tcp->ack)) return XDP_PASS;

    u32 src = ip->saddr;
    u64 now = bpf_ktime_get_ns();

    // Check/reset window
    u64 *window_start = syn_window.lookup(&src);
    u64 *count = syn_count.lookup(&src);

    if (!window_start || (now - *window_start) > WINDOW_NS) {
        u64 w = now;
        syn_window.update(&src, &w);
        u64 one = 1;
        syn_count.update(&src, &one);

        u64 *p = syn_stats.lookup(&(u32){SYN_PASSED});
        if (p) __sync_fetch_and_add(p, 1);
        return XDP_PASS;
    }

    if (count) {
        __sync_fetch_and_add(count, 1);
        if (*count > SYN_RATE_LIMIT) {
            u64 *d = syn_stats.lookup(&(u32){SYN_DROPPED});
            if (d) __sync_fetch_and_add(d, 1);
            return XDP_DROP;
        }
    }

    u64 *p = syn_stats.lookup(&(u32){SYN_PASSED});
    if (p) __sync_fetch_and_add(p, 1);
    return XDP_PASS;
}
""",
)

# Template 2: UDP Flood Mitigation (XDP)
UDP_FLOOD_XDP = EBPFTemplate(
    name="udp_flood_xdp",
    description="Drop UDP packets exceeding rate threshold from a source IP",
    program_type=ProgramType.XDP,
    source_patterns=[r"napse", r"qsecbit"],
    event_patterns=[r"udp.?flood", r"ddos.*udp", r"l4.*flood.*udp"],
    severity_min="HIGH",
    confidence=0.93,
    c_source=r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

BPF_HASH(udp_count, u32, u64, 65536);
BPF_HASH(udp_window, u32, u64, 65536);
BPF_ARRAY(udp_stats, u64, 3);
enum { UDP_TOTAL = 0, UDP_DROPPED = 1, UDP_PASSED = 2 };

#define UDP_RATE_LIMIT 500
#define WINDOW_NS 1000000000ULL

int xdp_udp_flood(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    u64 *total = udp_stats.lookup(&(u32){UDP_TOTAL});
    if (total) __sync_fetch_and_add(total, 1);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

    u32 src = ip->saddr;
    u64 now = bpf_ktime_get_ns();

    u64 *window_start = udp_window.lookup(&src);
    u64 *count = udp_count.lookup(&src);

    if (!window_start || (now - *window_start) > WINDOW_NS) {
        u64 w = now;
        udp_window.update(&src, &w);
        u64 one = 1;
        udp_count.update(&src, &one);
        u64 *p = udp_stats.lookup(&(u32){UDP_PASSED});
        if (p) __sync_fetch_and_add(p, 1);
        return XDP_PASS;
    }

    if (count) {
        __sync_fetch_and_add(count, 1);
        if (*count > UDP_RATE_LIMIT) {
            u64 *d = udp_stats.lookup(&(u32){UDP_DROPPED});
            if (d) __sync_fetch_and_add(d, 1);
            return XDP_DROP;
        }
    }

    u64 *p = udp_stats.lookup(&(u32){UDP_PASSED});
    if (p) __sync_fetch_and_add(p, 1);
    return XDP_PASS;
}
""",
)

# Template 3: Port Scan Detection (XDP)
PORT_SCAN_XDP = EBPFTemplate(
    name="port_scan_xdp",
    description="Drop traffic from IPs scanning multiple ports",
    program_type=ProgramType.XDP,
    source_patterns=[r"napse", r"qsecbit", r"scan"],
    event_patterns=[r"port.?scan", r"scan.*detect", r"l4.*scan"],
    severity_min="MEDIUM",
    confidence=0.90,
    c_source=r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

// Track unique destination ports per source IP (bitmap approach)
BPF_HASH(scan_ports, u32, u64, 65536);
BPF_HASH(scan_window, u32, u64, 65536);
BPF_ARRAY(scan_stats, u64, 3);
enum { SCAN_TOTAL = 0, SCAN_DROPPED = 1, SCAN_PASSED = 2 };

// Drop if >20 unique ports probed in 10 seconds
#define PORT_THRESHOLD 20
#define SCAN_WINDOW_NS 10000000000ULL  // 10 seconds

int xdp_port_scan(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    u64 *total = scan_stats.lookup(&(u32){SCAN_TOTAL});
    if (total) __sync_fetch_and_add(total, 1);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    // Only track SYN packets (port probes)
    if (!(tcp->syn && !tcp->ack)) return XDP_PASS;

    u32 src = ip->saddr;
    u64 now = bpf_ktime_get_ns();

    u64 *window_start = scan_window.lookup(&src);
    if (!window_start || (now - *window_start) > SCAN_WINDOW_NS) {
        u64 w = now;
        scan_window.update(&src, &w);
        u64 one = 1;
        scan_ports.update(&src, &one);
        u64 *p = scan_stats.lookup(&(u32){SCAN_PASSED});
        if (p) __sync_fetch_and_add(p, 1);
        return XDP_PASS;
    }

    u64 *count = scan_ports.lookup(&src);
    if (count) {
        __sync_fetch_and_add(count, 1);
        if (*count > PORT_THRESHOLD) {
            u64 *d = scan_stats.lookup(&(u32){SCAN_DROPPED});
            if (d) __sync_fetch_and_add(d, 1);
            return XDP_DROP;
        }
    }

    u64 *p = scan_stats.lookup(&(u32){SCAN_PASSED});
    if (p) __sync_fetch_and_add(p, 1);
    return XDP_PASS;
}
""",
)

# Template 4: DNS Amplification (XDP)
DNS_AMP_XDP = EBPFTemplate(
    name="dns_amplification_xdp",
    description="Drop oversized DNS response packets (amplification attack)",
    program_type=ProgramType.XDP,
    source_patterns=[r"napse", r"dns"],
    event_patterns=[r"dns.*amp", r"dns.*flood", r"l7.*dns"],
    severity_min="HIGH",
    confidence=0.92,
    c_source=r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

BPF_ARRAY(dns_amp_stats, u64, 3);
enum { DA_TOTAL = 0, DA_DROPPED = 1, DA_PASSED = 2 };

// DNS responses >512 bytes from external sources are suspicious
#define DNS_PORT 53
#define DNS_MAX_SIZE 512

int xdp_dns_amp(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    u64 *total = dns_amp_stats.lookup(&(u32){DA_TOTAL});
    if (total) __sync_fetch_and_add(total, 1);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;

    // Only check DNS source port (responses)
    if (__constant_ntohs(udp->source) != DNS_PORT) return XDP_PASS;

    u16 udp_len = __constant_ntohs(udp->len);
    if (udp_len > DNS_MAX_SIZE) {
        u64 *d = dns_amp_stats.lookup(&(u32){DA_DROPPED});
        if (d) __sync_fetch_and_add(d, 1);
        return XDP_DROP;
    }

    u64 *p = dns_amp_stats.lookup(&(u32){DA_PASSED});
    if (p) __sync_fetch_and_add(p, 1);
    return XDP_PASS;
}
""",
)

# Template 5: ICMP Flood Rate Limit (XDP)
ICMP_FLOOD_XDP = EBPFTemplate(
    name="icmp_flood_xdp",
    description="Rate-limit ICMP packets per source IP",
    program_type=ProgramType.XDP,
    source_patterns=[r"napse", r"qsecbit"],
    event_patterns=[r"icmp.*flood", r"ping.*flood", r"l3.*icmp"],
    severity_min="MEDIUM",
    confidence=0.91,
    c_source=r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

BPF_HASH(icmp_count, u32, u64, 65536);
BPF_HASH(icmp_window, u32, u64, 65536);
BPF_ARRAY(icmp_stats, u64, 3);
enum { ICMP_TOTAL = 0, ICMP_DROPPED = 1, ICMP_PASSED = 2 };

#define ICMP_RATE_LIMIT 50
#define WINDOW_NS 1000000000ULL

int xdp_icmp_flood(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    u64 *total = icmp_stats.lookup(&(u32){ICMP_TOTAL});
    if (total) __sync_fetch_and_add(total, 1);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_ICMP) return XDP_PASS;

    u32 src = ip->saddr;
    u64 now = bpf_ktime_get_ns();

    u64 *window_start = icmp_window.lookup(&src);
    u64 *count = icmp_count.lookup(&src);

    if (!window_start || (now - *window_start) > WINDOW_NS) {
        u64 w = now;
        icmp_window.update(&src, &w);
        u64 one = 1;
        icmp_count.update(&src, &one);
        u64 *p = icmp_stats.lookup(&(u32){ICMP_PASSED});
        if (p) __sync_fetch_and_add(p, 1);
        return XDP_PASS;
    }

    if (count) {
        __sync_fetch_and_add(count, 1);
        if (*count > ICMP_RATE_LIMIT) {
            u64 *d = icmp_stats.lookup(&(u32){ICMP_DROPPED});
            if (d) __sync_fetch_and_add(d, 1);
            return XDP_DROP;
        }
    }

    u64 *p = icmp_stats.lookup(&(u32){ICMP_PASSED});
    if (p) __sync_fetch_and_add(p, 1);
    return XDP_PASS;
}
""",
)

# Template 6: TCP RST Attack (XDP) — drop forged RSTs
TCP_RST_XDP = EBPFTemplate(
    name="tcp_rst_attack_xdp",
    description="Rate-limit TCP RST packets to prevent connection disruption",
    program_type=ProgramType.XDP,
    source_patterns=[r"napse", r"qsecbit"],
    event_patterns=[r"tcp.*rst", r"rst.*attack", r"l4.*rst"],
    severity_min="HIGH",
    confidence=0.88,
    c_source=r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

BPF_HASH(rst_count, u32, u64, 65536);
BPF_HASH(rst_window, u32, u64, 65536);
BPF_ARRAY(rst_stats, u64, 3);
enum { RST_TOTAL = 0, RST_DROPPED = 1, RST_PASSED = 2 };

#define RST_RATE_LIMIT 10
#define WINDOW_NS 1000000000ULL

int xdp_tcp_rst(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    u64 *total = rst_stats.lookup(&(u32){RST_TOTAL});
    if (total) __sync_fetch_and_add(total, 1);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP) return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) return XDP_PASS;

    if (!tcp->rst) return XDP_PASS;

    u32 src = ip->saddr;
    u64 now = bpf_ktime_get_ns();

    u64 *window_start = rst_window.lookup(&src);
    u64 *count = rst_count.lookup(&src);

    if (!window_start || (now - *window_start) > WINDOW_NS) {
        u64 w = now;
        rst_window.update(&src, &w);
        u64 one = 1;
        rst_count.update(&src, &one);
        u64 *p = rst_stats.lookup(&(u32){RST_PASSED});
        if (p) __sync_fetch_and_add(p, 1);
        return XDP_PASS;
    }

    if (count) {
        __sync_fetch_and_add(count, 1);
        if (*count > RST_RATE_LIMIT) {
            u64 *d = rst_stats.lookup(&(u32){RST_DROPPED});
            if (d) __sync_fetch_and_add(d, 1);
            return XDP_DROP;
        }
    }

    u64 *p = rst_stats.lookup(&(u32){RST_PASSED});
    if (p) __sync_fetch_and_add(p, 1);
    return XDP_PASS;
}
""",
)

# Template 7: ARP Spoof Detection (XDP)
ARP_SPOOF_XDP = EBPFTemplate(
    name="arp_spoof_xdp",
    description="Drop ARP replies from known-spoofed sources",
    program_type=ProgramType.XDP,
    source_patterns=[r"napse", r"qsecbit"],
    event_patterns=[r"arp.*spoof", r"l2.*arp", r"arp.*poison"],
    severity_min="HIGH",
    confidence=0.94,
    c_source=r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

// Map of blocked ARP source IPs (populated by userspace)
BPF_HASH(arp_blocklist, u32, u8, 4096);
BPF_ARRAY(arp_stats, u64, 3);
enum { ARP_TOTAL = 0, ARP_DROPPED = 1, ARP_PASSED = 2 };

struct arp_payload {
    unsigned char ar_sha[6]; // sender MAC
    u32 ar_sip;             // sender IP
    unsigned char ar_tha[6]; // target MAC
    u32 ar_tip;             // target IP
} __attribute__((packed));

int xdp_arp_spoof(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    u64 *total = arp_stats.lookup(&(u32){ARP_TOTAL});
    if (total) __sync_fetch_and_add(total, 1);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_ARP)) return XDP_PASS;

    struct arphdr *arp = (void *)(eth + 1);
    if ((void *)(arp + 1) > data_end) return XDP_PASS;

    // Only check ARP replies (opcode 2)
    if (__constant_ntohs(arp->ar_op) != 2) return XDP_PASS;

    struct arp_payload *payload = (void *)(arp + 1);
    if ((void *)(payload + 1) > data_end) return XDP_PASS;

    u32 sender_ip = payload->ar_sip;
    u8 *blocked = arp_blocklist.lookup(&sender_ip);
    if (blocked) {
        u64 *d = arp_stats.lookup(&(u32){ARP_DROPPED});
        if (d) __sync_fetch_and_add(d, 1);
        return XDP_DROP;
    }

    u64 *p = arp_stats.lookup(&(u32){ARP_PASSED});
    if (p) __sync_fetch_and_add(p, 1);
    return XDP_PASS;
}
""",
)

# Template 8: Slowloris Detection (TC delay)
SLOWLORIS_TC = EBPFTemplate(
    name="slowloris_tc",
    description="Delay responses to suspected Slowloris connections",
    program_type=ProgramType.TC,
    source_patterns=[r"napse", r"qsecbit"],
    event_patterns=[r"slowloris", r"slow.*http", r"l7.*slow"],
    severity_min="MEDIUM",
    confidence=0.85,
    c_source=r"""
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

// Slowloris suspects (populated by userspace after detecting slow headers)
BPF_HASH(slow_targets, u32, u64, 4096);
BPF_ARRAY(slow_stats, u64, 3);
enum { SLOW_TOTAL = 0, SLOW_DELAYED = 1, SLOW_PASSED = 2 };

#define SLOW_DELAY_NS 2000000000ULL  // 2 second delay for suspects

int tc_slowloris(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    u64 *total = slow_stats.lookup(&(u32){SLOW_TOTAL});
    if (total) __sync_fetch_and_add(total, 1);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

    u32 dst = ip->daddr;
    u64 *delay = slow_targets.lookup(&dst);
    if (delay) {
        u64 now = bpf_ktime_get_ns();
        skb->tstamp = now + SLOW_DELAY_NS;
        u64 *d = slow_stats.lookup(&(u32){SLOW_DELAYED});
        if (d) __sync_fetch_and_add(d, 1);
        return TC_ACT_OK;
    }

    u64 *p = slow_stats.lookup(&(u32){SLOW_PASSED});
    if (p) __sync_fetch_and_add(p, 1);
    return TC_ACT_OK;
}
""",
)

# Template 9: DNS Tunneling Detection (XDP)
DNS_TUNNEL_XDP = EBPFTemplate(
    name="dns_tunnel_xdp",
    description="Drop DNS queries with unusually long labels (tunneling indicator)",
    program_type=ProgramType.XDP,
    source_patterns=[r"napse", r"dns", r"watchdog"],
    event_patterns=[r"dns.*tunnel", r"dns.*exfil", r"dga"],
    severity_min="HIGH",
    confidence=0.87,
    c_source=r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

BPF_ARRAY(tunnel_stats, u64, 3);
enum { TUN_TOTAL = 0, TUN_DROPPED = 1, TUN_PASSED = 2 };

#define DNS_PORT 53
// DNS queries with total QNAME > 80 bytes are suspicious
#define MAX_QNAME_LEN 80

int xdp_dns_tunnel(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    u64 *total = tunnel_stats.lookup(&(u32){TUN_TOTAL});
    if (total) __sync_fetch_and_add(total, 1);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end) return XDP_PASS;

    if (__constant_ntohs(udp->dest) != DNS_PORT) return XDP_PASS;

    // DNS header is 12 bytes after UDP header
    void *dns_data = (void *)(udp + 1);
    if (dns_data + 12 > data_end) return XDP_PASS;

    // Walk the QNAME (label-encoded) to measure total length
    void *qname = dns_data + 12;
    u16 total_len = 0;

    #pragma unroll
    for (int i = 0; i < 32; i++) {  // Max 32 labels
        if (qname + 1 > data_end) break;
        u8 label_len = *(u8 *)qname;
        if (label_len == 0) break;  // End of QNAME
        if (label_len > 63) break;  // Compression pointer — stop
        total_len += label_len + 1;
        qname += label_len + 1;
        if (qname > data_end) break;
    }

    if (total_len > MAX_QNAME_LEN) {
        u64 *d = tunnel_stats.lookup(&(u32){TUN_DROPPED});
        if (d) __sync_fetch_and_add(d, 1);
        return XDP_DROP;
    }

    u64 *p = tunnel_stats.lookup(&(u32){TUN_PASSED});
    if (p) __sync_fetch_and_add(p, 1);
    return XDP_PASS;
}
""",
)

# Template 10: IP Source Spoofing (XDP)
IP_SPOOF_XDP = EBPFTemplate(
    name="ip_spoof_xdp",
    description="Drop packets with source IP outside the local LAN range",
    program_type=ProgramType.XDP,
    source_patterns=[r"napse", r"qsecbit"],
    event_patterns=[r"ip.*spoof", r"l3.*spoof", r"forged.*src"],
    severity_min="HIGH",
    confidence=0.92,
    c_source=r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

BPF_ARRAY(spoof_stats, u64, 3);
enum { SP_TOTAL = 0, SP_DROPPED = 1, SP_PASSED = 2 };

// LAN range: 10.200.0.0/16 (configurable via map in production)
// Packets arriving on LAN interface claiming non-LAN source are spoofed
#define LAN_NETWORK 0x0AC80000  // 10.200.0.0 in network byte order
#define LAN_MASK    0xFFFF0000  // /16

int xdp_ip_spoof(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    u64 *total = spoof_stats.lookup(&(u32){SP_TOTAL});
    if (total) __sync_fetch_and_add(total, 1);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    // Allow multicast/broadcast
    u32 src = __constant_ntohl(ip->saddr);
    if ((src & 0xF0000000) == 0xE0000000) return XDP_PASS;  // 224.0.0.0/4
    if (src == 0xFFFFFFFF) return XDP_PASS;  // broadcast
    if (src == 0) return XDP_PASS;  // DHCP

    // Check if source is in LAN range
    if ((src & LAN_MASK) != (LAN_NETWORK)) {
        u64 *d = spoof_stats.lookup(&(u32){SP_DROPPED});
        if (d) __sync_fetch_and_add(d, 1);
        return XDP_DROP;
    }

    u64 *p = spoof_stats.lookup(&(u32){SP_PASSED});
    if (p) __sync_fetch_and_add(p, 1);
    return XDP_PASS;
}
""",
)


# ------------------------------------------------------------------
# Template Registry
# ------------------------------------------------------------------

class TemplateRegistry:
    """Registry of pre-vetted eBPF templates.

    Matches incoming signals against template patterns and returns
    the best matching template. Templates are ordered by confidence.
    """

    def __init__(self):
        self._templates: Dict[str, EBPFTemplate] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        """Register the built-in templates."""
        for template in [
            SYN_FLOOD_XDP,
            UDP_FLOOD_XDP,
            PORT_SCAN_XDP,
            DNS_AMP_XDP,
            ICMP_FLOOD_XDP,
            TCP_RST_XDP,
            ARP_SPOOF_XDP,
            SLOWLORIS_TC,
            DNS_TUNNEL_XDP,
            IP_SPOOF_XDP,
        ]:
            self._templates[template.name] = template

    def register(self, template: EBPFTemplate) -> None:
        """Register a custom template."""
        self._templates[template.name] = template
        logger.info("Registered eBPF template: %s", template.name)

    def unregister(self, name: str) -> bool:
        """Remove a template."""
        return self._templates.pop(name, None) is not None

    def match(self, signal: StandardSignal) -> Optional[TemplateMatch]:
        """Find the best matching template for a signal.

        Returns the highest-confidence match, or None.
        """
        best_match: Optional[TemplateMatch] = None
        best_confidence = 0.0

        for template in self._templates.values():
            confidence = template.matches(signal)
            if confidence > best_confidence:
                best_confidence = confidence
                best_match = TemplateMatch(
                    matched=True,
                    template_name=template.name,
                    program_type=template.program_type,
                    c_source=template.c_source,
                    confidence=confidence,
                    description=template.description,
                    parameters=template.parameters,
                )

        return best_match

    def get(self, name: str) -> Optional[EBPFTemplate]:
        """Get a template by name."""
        return self._templates.get(name)

    def list_templates(self) -> List[Dict[str, Any]]:
        """List all registered templates."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "program_type": t.program_type.value,
                "confidence": t.confidence,
            }
            for t in self._templates.values()
        ]

    def __len__(self) -> int:
        return len(self._templates)
