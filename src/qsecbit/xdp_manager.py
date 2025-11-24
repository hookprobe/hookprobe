"""
XDP/eBPF DDoS Mitigation Manager

Author: Andrei Toma
License: MIT
Version: 5.0
"""

import socket
import struct
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional, List
from .nic_detector import NICDetector, NICCapability, XDPMode

# Optional BCC/eBPF integration
try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False


# eBPF/XDP Program for DDoS Mitigation
XDP_DDOS_PROGRAM = """
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

// Rate limiting map: source IP -> packet count
BPF_HASH(rate_limit, u32, u64, 65536);

// Blocked IPs map
BPF_HASH(blocked_ips, u32, u8, 65536);

// Statistics counters
BPF_ARRAY(stats, u64, 8);

// Statistics indices
enum {
    STAT_TOTAL_PACKETS = 0,
    STAT_DROPPED_BLOCKED = 1,
    STAT_DROPPED_RATE_LIMIT = 2,
    STAT_DROPPED_MALFORMED = 3,
    STAT_PASSED = 4,
    STAT_TCP_SYN_FLOOD = 5,
    STAT_UDP_FLOOD = 6,
    STAT_ICMP_FLOOD = 7,
};

// Configuration (packets per second per IP)
#define RATE_LIMIT_PPS 1000
#define RATE_WINDOW_NS 1000000000ULL  // 1 second

// XDP main function
int xdp_ddos_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Statistics
    u64 *total_packets = stats.lookup(&(u32){STAT_TOTAL_PACKETS});
    if (total_packets) {
        __sync_fetch_and_add(total_packets, 1);
    }

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        u64 *malformed = stats.lookup(&(u32){STAT_DROPPED_MALFORMED});
        if (malformed) __sync_fetch_and_add(malformed, 1);
        return XDP_DROP;
    }

    // Only process IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) {
        u64 *malformed = stats.lookup(&(u32){STAT_DROPPED_MALFORMED});
        if (malformed) __sync_fetch_and_add(malformed, 1);
        return XDP_DROP;
    }

    u32 src_ip = ip->saddr;

    // Check if IP is blocked
    u8 *blocked = blocked_ips.lookup(&src_ip);
    if (blocked && *blocked == 1) {
        u64 *dropped_blocked = stats.lookup(&(u32){STAT_DROPPED_BLOCKED});
        if (dropped_blocked) __sync_fetch_and_add(dropped_blocked, 1);
        return XDP_DROP;
    }

    // Rate limiting
    u64 now = bpf_ktime_get_ns();
    u64 *last_time = rate_limit.lookup(&src_ip);

    if (last_time) {
        u64 elapsed = now - *last_time;

        // Reset counter every second
        if (elapsed > RATE_WINDOW_NS) {
            rate_limit.update(&src_ip, &now);
        } else {
            // Count packets in current window
            u64 count = 1;
            u64 *pkt_count = rate_limit.lookup(&src_ip);
            if (pkt_count) {
                count = *pkt_count + 1;
            }

            if (count > RATE_LIMIT_PPS) {
                // Rate limit exceeded - drop packet
                u64 *dropped_rate = stats.lookup(&(u32){STAT_DROPPED_RATE_LIMIT});
                if (dropped_rate) __sync_fetch_and_add(dropped_rate, 1);
                return XDP_DROP;
            }

            rate_limit.update(&src_ip, &count);
        }
    } else {
        // First packet from this IP
        rate_limit.update(&src_ip, &now);
    }

    // Protocol-specific flood detection
    u8 protocol = ip->protocol;

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)(tcp + 1) > data_end) {
            return XDP_DROP;
        }

        // Detect SYN flood
        if (tcp->syn && !tcp->ack) {
            u64 *syn_flood = stats.lookup(&(u32){STAT_TCP_SYN_FLOOD});
            if (syn_flood) __sync_fetch_and_add(syn_flood, 1);

            // Could implement SYN cookie logic here
        }
    } else if (protocol == IPPROTO_UDP) {
        u64 *udp_flood = stats.lookup(&(u32){STAT_UDP_FLOOD});
        if (udp_flood) __sync_fetch_and_add(udp_flood, 1);

    } else if (protocol == IPPROTO_ICMP) {
        u64 *icmp_flood = stats.lookup(&(u32){STAT_ICMP_FLOOD});
        if (icmp_flood) __sync_fetch_and_add(icmp_flood, 1);
    }

    // Packet passed all filters
    u64 *passed = stats.lookup(&(u32){STAT_PASSED});
    if (passed) __sync_fetch_and_add(passed, 1);

    return XDP_PASS;
}
"""


@dataclass
class XDPStats:
    """XDP statistics"""
    total_packets: int = 0
    dropped_blocked: int = 0
    dropped_rate_limit: int = 0
    dropped_malformed: int = 0
    passed: int = 0
    tcp_syn_flood: int = 0
    udp_flood: int = 0
    icmp_flood: int = 0
    timestamp: datetime = field(default_factory=datetime.now)


class XDPManager:
    """Manage XDP/eBPF programs for DDoS mitigation"""

    def __init__(self, interface: Optional[str] = None, auto_detect: bool = True):
        """
        Initialize XDP manager

        Args:
            interface: Network interface to attach XDP (auto-detected if None)
            auto_detect: Automatically detect NIC capabilities
        """
        self.interface = interface
        self.capability: Optional[NICCapability] = None
        self.xdp_mode: XDPMode = XDPMode.DISABLED
        self.bpf: Optional[BPF] = None
        self.enabled = False
        self.stats_history: List[XDPStats] = []

        if not BCC_AVAILABLE:
            print("Warning: BCC not available. XDP/eBPF support disabled.")
            print("Install with: pip install bcc")
            return

        # Auto-detect interface if not provided
        if not self.interface and auto_detect:
            self.interface = NICDetector.get_primary_interface()
            if not self.interface:
                print("Warning: Could not detect primary network interface")
                return

        # Detect NIC capabilities
        if auto_detect and self.interface:
            self.capability = NICDetector.detect_capability(self.interface)
            self.xdp_mode = NICDetector.select_xdp_mode(self.capability)

            print(f"✓ NIC Detected: {self.capability.vendor} {self.capability.model}")
            print(f"  - Interface: {self.interface}")
            print(f"  - Driver: {self.capability.driver}")
            print(f"  - XDP Mode: {self.xdp_mode.value}")
            print(f"  - Max Throughput: {self.capability.max_throughput}")
            if self.capability.notes:
                print(f"  - Notes: {self.capability.notes}")

    def load_program(self, program_code: Optional[str] = None) -> bool:
        """
        Load XDP/eBPF program

        Args:
            program_code: eBPF C code (uses default DDoS program if None)

        Returns:
            True if loaded successfully
        """
        if not BCC_AVAILABLE:
            print("Error: BCC not available")
            return False

        if not self.interface:
            print("Error: No network interface specified")
            return False

        if self.xdp_mode == XDPMode.DISABLED:
            print("Error: XDP not supported on this NIC")
            return False

        try:
            # Use default DDoS mitigation program if not provided
            code = program_code or XDP_DDOS_PROGRAM

            # Compile and load BPF program
            self.bpf = BPF(text=code)

            # Get main function
            fn = self.bpf.load_func("xdp_ddos_filter", BPF.XDP)

            # Attach to interface
            flags = 0
            if self.xdp_mode == XDPMode.SKB:
                flags = 1 << 1  # XDP_FLAGS_SKB_MODE
            elif self.xdp_mode == XDPMode.DRV:
                flags = 1 << 2  # XDP_FLAGS_DRV_MODE

            self.bpf.attach_xdp(self.interface, fn, flags)

            self.enabled = True
            print(f"✓ XDP program loaded on {self.interface} ({self.xdp_mode.value})")
            return True

        except Exception as e:
            print(f"Error loading XDP program: {e}")
            return False

    def unload_program(self) -> bool:
        """Unload XDP program from interface"""
        if not self.bpf or not self.interface:
            return False

        try:
            self.bpf.remove_xdp(self.interface)
            self.enabled = False
            print(f"✓ XDP program unloaded from {self.interface}")
            return True
        except Exception as e:
            print(f"Error unloading XDP program: {e}")
            return False

    def get_stats(self) -> Optional[XDPStats]:
        """Get current XDP statistics"""
        if not self.enabled or not self.bpf:
            return None

        try:
            stats_map = self.bpf["stats"]

            stats = XDPStats(
                total_packets=stats_map[0].value if 0 in stats_map else 0,
                dropped_blocked=stats_map[1].value if 1 in stats_map else 0,
                dropped_rate_limit=stats_map[2].value if 2 in stats_map else 0,
                dropped_malformed=stats_map[3].value if 3 in stats_map else 0,
                passed=stats_map[4].value if 4 in stats_map else 0,
                tcp_syn_flood=stats_map[5].value if 5 in stats_map else 0,
                udp_flood=stats_map[6].value if 6 in stats_map else 0,
                icmp_flood=stats_map[7].value if 7 in stats_map else 0,
                timestamp=datetime.now()
            )

            self.stats_history.append(stats)
            if len(self.stats_history) > 1000:
                self.stats_history.pop(0)

            return stats

        except Exception as e:
            print(f"Error getting XDP stats: {e}")
            return None

    def block_ip(self, ip_address: str) -> bool:
        """Block an IP address at XDP layer"""
        if not self.enabled or not self.bpf:
            return False

        try:
            # Convert IP string to integer
            ip_int = struct.unpack("!I", socket.inet_aton(ip_address))[0]

            # Update blocked_ips map
            blocked_map = self.bpf["blocked_ips"]
            blocked_map[blocked_map.Key(ip_int)] = blocked_map.Leaf(1)

            print(f"✓ Blocked IP {ip_address} at XDP layer")
            return True

        except Exception as e:
            print(f"Error blocking IP {ip_address}: {e}")
            return False

    def unblock_ip(self, ip_address: str) -> bool:
        """Unblock an IP address"""
        if not self.enabled or not self.bpf:
            return False

        try:
            ip_int = struct.unpack("!I", socket.inet_aton(ip_address))[0]

            blocked_map = self.bpf["blocked_ips"]
            del blocked_map[blocked_map.Key(ip_int)]

            print(f"✓ Unblocked IP {ip_address}")
            return True

        except Exception as e:
            print(f"Error unblocking IP {ip_address}: {e}")
            return False

    def __del__(self):
        """Cleanup: unload XDP program on deletion"""
        if self.enabled:
            self.unload_program()
