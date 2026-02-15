/**
 * NAPSE XDP Gate - Enhanced XDP/eBPF Program
 *
 * Extends the existing XDP_DDOS_PROGRAM from core/qsecbit/xdp_manager.py
 * with flow-aware promotion, smart packet steering, and AF_XDP support.
 *
 * Key additions over the base XDP program:
 *   1. Flow tracking in eBPF hash maps (5-tuple keyed)
 *   2. Verdict map for per-flow PASS/DROP/MIRROR/REDIRECT
 *   3. Smart promotion: only interesting packets go to userspace
 *   4. AF_XDP redirect for zero-copy delivery to Rust engine
 *
 * Author: HookProbe Team
 * License: Proprietary
 * Version: 1.0.0
 */

#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

/* ========================================================================
 * Configuration
 * ======================================================================== */

#define RATE_LIMIT_PPS      1000
#define RATE_WINDOW_NS      1000000000ULL    /* 1 second */
#define FLOW_TABLE_SIZE     65536
#define BLOCKED_IPS_SIZE    65536

/* Ports to always promote to userspace for deep inspection */
#define PORT_DNS            53
#define PORT_HTTP           80
#define PORT_HTTPS          443
#define PORT_SSH            22
#define PORT_DHCP_S         67
#define PORT_DHCP_C         68
#define PORT_MDNS           5353
#define PORT_SSDP           1900
#define PORT_NETBIOS        137
#define PORT_LLMNR          5355
#define PORT_SMTP           25
#define PORT_FTP            21
#define PORT_RDP            3389
#define PORT_MQTT           1883
#define PORT_MODBUS         502
#define PORT_DNP3           20000

/* ========================================================================
 * Data Structures
 * ======================================================================== */

/* 5-tuple flow key */
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  pad[3];
};

/* Flow state tracked in eBPF */
struct flow_state {
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u64 orig_bytes;
    __u64 resp_bytes;
    __u32 orig_pkts;
    __u32 resp_pkts;
    __u8  tcp_state;     /* Simplified TCP state */
    __u8  promoted;      /* Already sent to userspace? */
    __u8  verdict;       /* 0=PASS, 1=DROP, 2=REDIRECT */
    __u8  pad;
};

/* Lightweight metadata exported via ringbuf */
struct flow_metadata {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  tcp_flags;
    __u16 payload_len;
    __u32 orig_pkts;
    __u32 resp_pkts;
};

/* TCP states for conntrack-lite */
enum tcp_state {
    TCP_NEW = 0,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_TIME_WAIT,
    TCP_CLOSED,
};

/* Verdict codes */
enum verdict {
    VERDICT_PASS = 0,
    VERDICT_DROP = 1,
    VERDICT_REDIRECT = 2,    /* Send to AF_XDP for deep inspection */
};

/* Statistics indices */
enum {
    STAT_TOTAL_PACKETS = 0,
    STAT_DROPPED_BLOCKED = 1,
    STAT_DROPPED_RATE_LIMIT = 2,
    STAT_DROPPED_MALFORMED = 3,
    STAT_PASSED = 4,
    STAT_TCP_SYN_FLOOD = 5,
    STAT_UDP_FLOOD = 6,
    STAT_ICMP_FLOOD = 7,
    STAT_PROMOTED = 8,       /* Packets promoted to userspace */
    STAT_FLOWS_TRACKED = 9,  /* Active flows in table */
};

/* ========================================================================
 * eBPF Maps
 * ======================================================================== */

/* Rate limiting (from base XDP program) */
BPF_HASH(rate_limit_ts, __u32, __u64, BLOCKED_IPS_SIZE);
BPF_HASH(rate_limit_count, __u32, __u64, BLOCKED_IPS_SIZE);

/* Blocked IPs (from base XDP program) */
BPF_HASH(blocked_ips, __u32, __u8, BLOCKED_IPS_SIZE);

/* NAPSE additions: flow table and verdicts */
BPF_HASH(flow_table, struct flow_key, struct flow_state, FLOW_TABLE_SIZE);

/* Verdict overrides from userspace */
BPF_HASH(verdict_map, struct flow_key, __u8, FLOW_TABLE_SIZE);

/* Statistics */
BPF_ARRAY(stats, __u64, 12);

/* Ring buffer for metadata export (connection records at near-zero cost) */
BPF_RINGBUF_OUTPUT(metadata_rb, 1 << 20);  /* 1MB ring buffer */

/* AF_XDP socket map for zero-copy packet delivery */
BPF_XSKMAP(xsks_map, 4);  /* Up to 4 AF_XDP sockets */

/* ========================================================================
 * Helper: Increment stat counter
 * ======================================================================== */
static __always_inline void inc_stat(__u32 idx) {
    __u64 *val = stats.lookup(&idx);
    if (val) __sync_fetch_and_add(val, 1);
}

/* ========================================================================
 * Helper: Check if port should be promoted to userspace
 * ======================================================================== */
static __always_inline int is_interesting_port(__u16 port) {
    switch (port) {
        case PORT_DNS:
        case PORT_HTTP:
        case PORT_HTTPS:
        case PORT_SSH:
        case PORT_DHCP_S:
        case PORT_DHCP_C:
        case PORT_MDNS:
        case PORT_SSDP:
        case PORT_NETBIOS:
        case PORT_LLMNR:
        case PORT_SMTP:
        case PORT_FTP:
        case PORT_RDP:
        case PORT_MQTT:
        case PORT_MODBUS:
        case PORT_DNP3:
            return 1;
        default:
            return 0;
    }
}

/* ========================================================================
 * Main XDP Function
 * ======================================================================== */
int napse_xdp_gate(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    inc_stat(STAT_TOTAL_PACKETS);

    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        inc_stat(STAT_DROPPED_MALFORMED);
        return XDP_DROP;
    }

    /* Only process IPv4 */
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    /* Parse IP header */
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) {
        inc_stat(STAT_DROPPED_MALFORMED);
        return XDP_DROP;
    }

    __u32 src_ip = ip->saddr;

    /* Check blocked IPs */
    __u8 *blocked = blocked_ips.lookup(&src_ip);
    if (blocked && *blocked == 1) {
        inc_stat(STAT_DROPPED_BLOCKED);
        return XDP_DROP;
    }

    /* Rate limiting */
    __u64 now = bpf_ktime_get_ns();
    __u64 *last_time = rate_limit_ts.lookup(&src_ip);
    __u64 *pkt_count = rate_limit_count.lookup(&src_ip);

    if (last_time) {
        if (now - *last_time > RATE_WINDOW_NS) {
            __u64 init = 1;
            rate_limit_ts.update(&src_ip, &now);
            rate_limit_count.update(&src_ip, &init);
        } else {
            __u64 count = pkt_count ? (*pkt_count + 1) : 1;
            if (count > RATE_LIMIT_PPS) {
                inc_stat(STAT_DROPPED_RATE_LIMIT);
                return XDP_DROP;
            }
            rate_limit_count.update(&src_ip, &count);
        }
    } else {
        __u64 init = 1;
        rate_limit_ts.update(&src_ip, &now);
        rate_limit_count.update(&src_ip, &init);
    }

    /* Build flow key */
    struct flow_key key = {};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.proto = ip->protocol;

    __u16 src_port = 0, dst_port = 0;
    __u8 tcp_flags = 0;
    int should_promote = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;

        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
        src_port = __constant_ntohs(tcp->source);
        dst_port = __constant_ntohs(tcp->dest);
        tcp_flags = (tcp->syn << 1) | (tcp->ack << 4) | (tcp->fin << 0) | (tcp->rst << 2);

        /* SYN flood tracking */
        if (tcp->syn && !tcp->ack)
            inc_stat(STAT_TCP_SYN_FLOOD);

        /* Promote new connections (SYN) for protocol detection */
        if (tcp->syn && !tcp->ack)
            should_promote = 1;

    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP;

        key.src_port = udp->source;
        key.dst_port = udp->dest;
        src_port = __constant_ntohs(udp->source);
        dst_port = __constant_ntohs(udp->dest);

        inc_stat(STAT_UDP_FLOOD);

    } else if (ip->protocol == IPPROTO_ICMP) {
        inc_stat(STAT_ICMP_FLOOD);
    }

    /* Check if port is interesting (DNS, DHCP, mDNS, etc.) */
    if (is_interesting_port(src_port) || is_interesting_port(dst_port))
        should_promote = 1;

    /* Check verdict map (userspace can override per-flow) */
    __u8 *v = verdict_map.lookup(&key);
    if (v) {
        if (*v == VERDICT_DROP) {
            inc_stat(STAT_DROPPED_BLOCKED);
            return XDP_DROP;
        }
        if (*v == VERDICT_REDIRECT)
            should_promote = 1;
    }

    /* Update flow table */
    struct flow_state *flow = flow_table.lookup(&key);
    if (flow) {
        flow->last_seen_ns = now;
        flow->orig_pkts += 1;
        flow->orig_bytes += (data_end - data);
    } else {
        /* New flow */
        struct flow_state new_flow = {};
        new_flow.first_seen_ns = now;
        new_flow.last_seen_ns = now;
        new_flow.orig_pkts = 1;
        new_flow.orig_bytes = (data_end - data);
        new_flow.tcp_state = TCP_NEW;
        new_flow.verdict = VERDICT_PASS;
        flow_table.update(&key, &new_flow);
        inc_stat(STAT_FLOWS_TRACKED);

        /* Always promote first packet of new flow */
        should_promote = 1;
    }

    /* Promote to userspace via AF_XDP or export metadata via ringbuf */
    if (should_promote) {
        /* Try AF_XDP redirect first (zero-copy) */
        int ret = xsks_map.redirect_map(ctx->rx_queue_index, 0);
        if (ret == XDP_REDIRECT) {
            inc_stat(STAT_PROMOTED);
            return XDP_REDIRECT;
        }

        /* Fallback: export metadata via ringbuf */
        struct flow_metadata *md = metadata_rb.ringbuf_output(sizeof(*md), 0);
        if (md) {
            md->timestamp_ns = now;
            md->src_ip = ip->saddr;
            md->dst_ip = ip->daddr;
            md->src_port = src_port;
            md->dst_port = dst_port;
            md->proto = ip->protocol;
            md->tcp_flags = tcp_flags;
            md->payload_len = data_end - data - sizeof(*eth) - sizeof(*ip);
            md->orig_pkts = flow ? flow->orig_pkts : 1;
            md->resp_pkts = flow ? flow->resp_pkts : 0;
            metadata_rb.ringbuf_submit(md, 0);
            inc_stat(STAT_PROMOTED);
        }
    }

    inc_stat(STAT_PASSED);
    return XDP_PASS;
}
