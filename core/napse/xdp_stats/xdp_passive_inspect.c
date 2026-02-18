/*
 * HookProbe XDP Passive Inspection
 * =================================
 *
 * This XDP program provides kernel-level packet inspection WITHOUT
 * introducing any latency or packet loss. It uses XDP_PASS to allow
 * all packets through while collecting statistics.
 *
 * Key Features:
 *   - Zero latency: All packets pass through unchanged
 *   - Kernel-level metrics: Protocol/port statistics in BPF maps
 *   - Anomaly detection hooks: Rate tracking per source IP
 *   - Integration with userspace daemon for alerts
 *
 * Why XDP_PASS instead of XDP_TX/XDP_REDIRECT:
 *   - XDP_PASS: Packet continues to kernel stack (no latency)
 *   - XDP_TX: Reflects packet back (would break traffic)
 *   - XDP_REDIRECT: Moves packet to another interface (adds latency)
 *
 * Compile:
 *   clang -O2 -target bpf -c xdp_passive_inspect.c -o xdp_passive_inspect.o
 *
 * Load:
 *   ip link set dev dummy-mirror xdp obj xdp_passive_inspect.o sec xdp_pass
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* Protocol statistics keys */
#define PROTO_TCP    0
#define PROTO_UDP    1
#define PROTO_ICMP   2
#define PROTO_OTHER  3
#define PROTO_MAX    4

/* Port category keys */
#define PORT_HTTP    0
#define PORT_HTTPS   1
#define PORT_DNS     2
#define PORT_SSH     3
#define PORT_VPN     4  /* WireGuard 51820, OpenVPN 1194 */
#define PORT_HTP     5  /* HookProbe Transport Protocol 4719, 8144 */
#define PORT_OTHER   6
#define PORT_MAX     7

/* Rate limiting window (nanoseconds) */
#define RATE_WINDOW_NS 1000000000ULL  /* 1 second */

/* ==========================================================================
 * BPF MAPS - Shared with userspace daemon
 * ========================================================================== */

/* Protocol packet counters */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, PROTO_MAX);
    __type(key, __u32);
    __type(value, __u64);
} proto_stats SEC(".maps");

/* Protocol byte counters */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, PROTO_MAX);
    __type(key, __u32);
    __type(value, __u64);
} proto_bytes SEC(".maps");

/* Port category packet counters */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, PORT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} port_stats SEC(".maps");

/* Per-source IP packet rate (for anomaly detection) */
struct rate_info {
    __u64 packets;
    __u64 bytes;
    __u64 last_update;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);  /* Track up to 64K unique IPs */
    __type(key, __u32);          /* Source IPv4 address */
    __type(value, struct rate_info);
} src_ip_rate SEC(".maps");

/* High-rate source IPs (>1000 pps) - for alerting */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);  /* Packet rate */
} high_rate_ips SEC(".maps");

/* Total packet/byte counters */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);  /* 0=packets, 1=bytes */
    __type(key, __u32);
    __type(value, __u64);
} total_stats SEC(".maps");

/* ==========================================================================
 * HELPER FUNCTIONS
 * ========================================================================== */

static __always_inline void update_counter(__u64 *counter, __u64 value)
{
    if (counter)
        __sync_fetch_and_add(counter, value);
}

static __always_inline __u32 get_port_category(__u16 port)
{
    switch (port) {
    case 80:
    case 8080:
        return PORT_HTTP;
    case 443:
    case 8443:
        return PORT_HTTPS;
    case 53:
        return PORT_DNS;
    case 22:
        return PORT_SSH;
    case 51820:  /* WireGuard */
    case 1194:   /* OpenVPN */
        return PORT_VPN;
    case 4719:   /* HTP primary */
    case 8144:   /* HTP secondary */
    case 853:    /* DNS-over-TLS / HTP */
    case 3478:   /* STUN / HTP */
        return PORT_HTP;
    default:
        return PORT_OTHER;
    }
}

static __always_inline void update_rate_tracking(__u32 src_ip, __u64 pkt_len)
{
    __u64 now = bpf_ktime_get_ns();
    struct rate_info *info;
    struct rate_info new_info = {0};

    info = bpf_map_lookup_elem(&src_ip_rate, &src_ip);

    if (info) {
        /* Check if we're in a new window */
        if (now - info->last_update > RATE_WINDOW_NS) {
            /* Check if previous rate was high (>1000 pps) */
            if (info->packets > 1000) {
                bpf_map_update_elem(&high_rate_ips, &src_ip,
                                   &info->packets, BPF_ANY);
            }
            /* Reset counters */
            new_info.packets = 1;
            new_info.bytes = pkt_len;
            new_info.last_update = now;
            bpf_map_update_elem(&src_ip_rate, &src_ip, &new_info, BPF_ANY);
        } else {
            /* Increment counters (in-place update not allowed, so just track) */
            __sync_fetch_and_add(&info->packets, 1);
            __sync_fetch_and_add(&info->bytes, pkt_len);
        }
    } else {
        /* New source IP */
        new_info.packets = 1;
        new_info.bytes = pkt_len;
        new_info.last_update = now;
        bpf_map_update_elem(&src_ip_rate, &src_ip, &new_info, BPF_ANY);
    }
}

/* ==========================================================================
 * XDP PROGRAM - Passive Inspection
 * ========================================================================== */

SEC("xdp_pass")
int xdp_passive_inspect(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    __u32 key;
    __u64 *counter;
    __u64 pkt_len = data_end - data;

    /* Update total counters */
    key = 0;  /* packets */
    counter = bpf_map_lookup_elem(&total_stats, &key);
    update_counter(counter, 1);

    key = 1;  /* bytes */
    counter = bpf_map_lookup_elem(&total_stats, &key);
    update_counter(counter, pkt_len);

    /* Parse Ethernet header */
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* IPv4 processing */
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;

        /* Update protocol stats */
        switch (iph->protocol) {
        case IPPROTO_TCP:
            key = PROTO_TCP;
            break;
        case IPPROTO_UDP:
            key = PROTO_UDP;
            break;
        case IPPROTO_ICMP:
            key = PROTO_ICMP;
            break;
        default:
            key = PROTO_OTHER;
        }

        counter = bpf_map_lookup_elem(&proto_stats, &key);
        update_counter(counter, 1);

        counter = bpf_map_lookup_elem(&proto_bytes, &key);
        update_counter(counter, pkt_len);

        /* Track source IP rate */
        update_rate_tracking(iph->saddr, pkt_len);

        /* Parse transport layer for port stats */
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
            if ((void *)(tcph + 1) <= data_end) {
                __u16 dport = bpf_ntohs(tcph->dest);
                __u16 sport = bpf_ntohs(tcph->source);
                key = get_port_category(dport);
                if (key == PORT_OTHER)
                    key = get_port_category(sport);
                counter = bpf_map_lookup_elem(&port_stats, &key);
                update_counter(counter, 1);
            }
        } else if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = (void *)iph + (iph->ihl * 4);
            if ((void *)(udph + 1) <= data_end) {
                __u16 dport = bpf_ntohs(udph->dest);
                __u16 sport = bpf_ntohs(udph->source);
                key = get_port_category(dport);
                if (key == PORT_OTHER)
                    key = get_port_category(sport);
                counter = bpf_map_lookup_elem(&port_stats, &key);
                update_counter(counter, 1);
            }
        }
    }
    /* IPv6 processing */
    else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;

        /* Basic IPv6 protocol stats */
        switch (ip6h->nexthdr) {
        case IPPROTO_TCP:
            key = PROTO_TCP;
            break;
        case IPPROTO_UDP:
            key = PROTO_UDP;
            break;
        case IPPROTO_ICMPV6:
            key = PROTO_ICMP;
            break;
        default:
            key = PROTO_OTHER;
        }

        counter = bpf_map_lookup_elem(&proto_stats, &key);
        update_counter(counter, 1);

        counter = bpf_map_lookup_elem(&proto_bytes, &key);
        update_counter(counter, pkt_len);
    }

    /* ALWAYS return XDP_PASS - we're passive inspection only */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
