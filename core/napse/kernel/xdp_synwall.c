/*
 * HookProbe HYDRA SynWall — Production Interface Protection
 * ==========================================================
 *
 * XDP program for enp0s6 (production interface) providing:
 *   1. RPF (Reverse Path Forwarding) anti-spoofing via bpf_fib_lookup()
 *   2. SYN flood rate limiting per source IP
 *   3. Allowlist/blocklist enforcement (shared with HYDRA)
 *   4. Connection tracking for fast-path established flows
 *   5. RINGBUF events for dropped/alerted packets
 *
 * Safety:
 *   - Defaults to MONITOR mode (log only, no drops)
 *   - Set config key 0 = 1 to enable ENFORCE mode
 *   - Allowlisted IPs bypass all checks
 *   - RPF failures only drop in enforce mode
 *
 * Compile:
 *   clang -O2 -g -target bpf -c xdp_synwall.c -o xdp_synwall.o
 *
 * Load:
 *   ip link set dev enp0s6 xdp obj xdp_synwall.o sec xdp_synwall
 *
 * Unload:
 *   ip link set dev enp0s6 xdp off
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ========================================================================
 * CONSTANTS
 * ======================================================================== */

/* SYN rate limit: max SYN packets per source IP per second */
#define SYN_RATE_LIMIT        50

/* Rate window in nanoseconds (1 second) */
#define RATE_WINDOW_NS        1000000000ULL

/* Connection tracking states */
#define CONN_SYN_SEEN         1  /* SYN received */
#define CONN_ESTABLISHED      2  /* 3-way handshake complete */
#define CONN_FIN_SEEN         3  /* FIN received */

/* Event types */
#define SYNWALL_EVENT_RPF_FAIL    1  /* RPF check failed (spoofed source) */
#define SYNWALL_EVENT_SYN_FLOOD   2  /* SYN rate exceeded */
#define SYNWALL_EVENT_BLOCKLIST   3  /* Blocklist match */
#define SYNWALL_EVENT_CONN_NEW    4  /* New connection tracked */
#define SYNWALL_EVENT_PASS        5  /* Packet passed */

/* Event reasons */
#define REASON_RPF_NO_ROUTE     1  /* No route for source IP */
#define REASON_RPF_IFACE_MISMATCH 2  /* Route exists but wrong interface */
#define REASON_SYN_RATE         3  /* SYN rate exceeded */
#define REASON_BLOCKLIST        4  /* Matched blocklist CIDR */

/* Config keys */
#define CONFIG_MODE          0  /* 0 = monitor, 1 = enforce */
#define CONFIG_SYN_RATE      1  /* SYN rate limit override */
#define CONFIG_MAX           2

/* Stats keys */
#define STAT_TOTAL           0
#define STAT_PASSED          1
#define STAT_DROPPED         2
#define STAT_RPF_FAIL        3
#define STAT_SYN_FLOOD       4
#define STAT_BLOCKLISTED     5
#define STAT_ALLOWLISTED     6
#define STAT_CONNTRACK_HIT   7
#define STAT_MAX             8

/* TCP flags */
#define TCP_SYN  0x02
#define TCP_ACK  0x10
#define TCP_FIN  0x01
#define TCP_RST  0x04
#define TCP_SYNACK (TCP_SYN | TCP_ACK)

/* ========================================================================
 * STRUCTURES
 * ======================================================================== */

/* LPM trie key (same format as xdp_hydra.c for shared maps) */
struct lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

/* Per-source IP SYN rate tracker */
struct syn_rate {
    __u64 syn_count;
    __u64 last_reset;
};

/* Connection tracking entry */
struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  pad[3];
};

struct conn_val {
    __u8  state;
    __u8  pad[3];
    __u32 packets;
    __u64 last_seen;
};

/* RINGBUF event */
struct synwall_event {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  event_type;
    __u8  reason;
    __u8  tcp_flags;
    __u32 syn_rate_pps;
};

/* ========================================================================
 * BPF MAPS
 * ======================================================================== */

/* Trusted CIDRs — shared allowlist format with xdp_hydra.c */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 10240);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u8);
} sw_allowlist SEC(".maps");

/* Threat feed blocklist — shared format with xdp_hydra.c */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1048576);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u8);
} sw_blocklist SEC(".maps");

/* Per-source IP SYN rate tracking */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);  /* 128K unique sources */
    __type(key, __u32);
    __type(value, struct syn_rate);
} syn_rate_map SEC(".maps");

/* Connection tracking table */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 524288);  /* 500K connections */
    __type(key, struct conn_key);
    __type(value, struct conn_val);
} conntrack SEC(".maps");

/* RINGBUF for events to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 262144);  /* 256KB */
} sw_events SEC(".maps");

/* Runtime configuration */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CONFIG_MAX);
    __type(key, __u32);
    __type(value, __u64);
} sw_config SEC(".maps");

/* Statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} sw_stats SEC(".maps");

/* ========================================================================
 * HELPER FUNCTIONS
 * ======================================================================== */

static __always_inline void inc_stat(__u32 key)
{
    __u64 *counter = bpf_map_lookup_elem(&sw_stats, &key);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

static __always_inline int get_mode(void)
{
    __u32 key = CONFIG_MODE;
    __u64 *val = bpf_map_lookup_elem(&sw_config, &key);
    if (val)
        return (__u32)*val;
    return 0;  /* default: monitor */
}

static __always_inline __u32 get_syn_rate_limit(void)
{
    __u32 key = CONFIG_SYN_RATE;
    __u64 *val = bpf_map_lookup_elem(&sw_config, &key);
    if (val && *val > 0)
        return (__u32)*val;
    return SYN_RATE_LIMIT;
}

static __always_inline void emit_event(__u32 src_ip, __u32 dst_ip,
                                        __u16 src_port, __u16 dst_port,
                                        __u8 proto, __u8 event_type,
                                        __u8 reason, __u8 tcp_flags,
                                        __u32 syn_rate_pps)
{
    struct synwall_event *evt;

    evt = bpf_ringbuf_reserve(&sw_events, sizeof(*evt), 0);
    if (!evt)
        return;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->src_ip = src_ip;
    evt->dst_ip = dst_ip;
    evt->src_port = src_port;
    evt->dst_port = dst_port;
    evt->proto = proto;
    evt->event_type = event_type;
    evt->reason = reason;
    evt->tcp_flags = tcp_flags;
    evt->syn_rate_pps = syn_rate_pps;

    bpf_ringbuf_submit(evt, 0);
}

/*
 * RPF (Reverse Path Forwarding) check using bpf_fib_lookup.
 *
 * Verifies that the source IP has a valid route back through the
 * incoming interface. Packets with spoofed source IPs will fail
 * because the FIB lookup returns a different egress interface
 * (or no route at all).
 *
 * Returns:
 *   0 = RPF pass (source is valid)
 *   1 = RPF fail: no route for source IP
 *   2 = RPF fail: route exists but via different interface
 */
static __always_inline int check_rpf(struct xdp_md *ctx,
                                      struct iphdr *iph,
                                      __u32 ingress_ifindex)
{
    struct bpf_fib_lookup fib_params;

    __builtin_memset(&fib_params, 0, sizeof(fib_params));
    fib_params.family = 2;  /* AF_INET */
    fib_params.l4_protocol = iph->protocol;
    fib_params.tot_len = bpf_ntohs(iph->tot_len);
    fib_params.ifindex = ingress_ifindex;

    /* For RPF: look up route TO the source IP */
    fib_params.ipv4_src = iph->daddr;  /* Our IP as source */
    fib_params.ipv4_dst = iph->saddr;  /* Packet's source as destination */

    int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), 0);

    if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
        /* Route found — check if it goes through the same interface */
        if (fib_params.ifindex != ingress_ifindex) {
            return 2;  /* Route exists but wrong interface */
        }
        return 0;  /* Valid: route goes through same interface */
    }

    if (rc == BPF_FIB_LKUP_RET_NOT_FWDED) {
        /*
         * Packet is destined for local delivery (our own IP).
         * This is normal for incoming traffic — RPF pass.
         */
        return 0;
    }

    /* No route, blackhole, unreachable, etc. */
    return 1;
}

/*
 * Check SYN rate for a source IP.
 * Returns current SYN rate (SYNs per second).
 * If rate exceeds limit, the caller should take action.
 */
static __always_inline __u32 check_syn_rate(__u32 src_ip)
{
    __u64 now = bpf_ktime_get_ns();
    struct syn_rate *rate;
    struct syn_rate new_rate = {0};

    rate = bpf_map_lookup_elem(&syn_rate_map, &src_ip);
    if (rate) {
        if (now - rate->last_reset > RATE_WINDOW_NS) {
            /* Window elapsed — reset counter */
            __u32 prev_rate = (__u32)rate->syn_count;
            new_rate.syn_count = 1;
            new_rate.last_reset = now;
            bpf_map_update_elem(&syn_rate_map, &src_ip, &new_rate, BPF_ANY);
            return prev_rate;
        } else {
            __sync_fetch_and_add(&rate->syn_count, 1);
            return (__u32)rate->syn_count;
        }
    } else {
        new_rate.syn_count = 1;
        new_rate.last_reset = now;
        bpf_map_update_elem(&syn_rate_map, &src_ip, &new_rate, BPF_ANY);
        return 1;
    }
}

/*
 * Connection tracking lookup/update.
 * Returns 1 if this is a known established connection (fast path).
 */
static __always_inline int conntrack_check(
    __u32 src_ip, __u32 dst_ip,
    __u16 src_port, __u16 dst_port,
    __u8 proto, __u8 tcp_flags)
{
    struct conn_key key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
        .proto = proto,
    };

    struct conn_val *val = bpf_map_lookup_elem(&conntrack, &key);
    if (val) {
        val->packets++;
        val->last_seen = bpf_ktime_get_ns();

        /* Update state based on TCP flags */
        if (proto == IPPROTO_TCP) {
            if (tcp_flags & TCP_FIN)
                val->state = CONN_FIN_SEEN;
            else if (tcp_flags & TCP_RST) {
                /* RST — remove connection */
                bpf_map_delete_elem(&conntrack, &key);
                return 0;
            }
        }

        return (val->state == CONN_ESTABLISHED) ? 1 : 0;
    }

    /* New connection — create entry for SYN or first packet */
    if (proto == IPPROTO_TCP) {
        if (tcp_flags & TCP_SYN) {
            struct conn_val new_val = {
                .state = CONN_SYN_SEEN,
                .packets = 1,
                .last_seen = bpf_ktime_get_ns(),
            };
            bpf_map_update_elem(&conntrack, &key, &new_val, BPF_ANY);
        } else if ((tcp_flags & TCP_ACK) && !(tcp_flags & TCP_SYN)) {
            /* ACK without SYN — likely established (missed handshake) */
            struct conn_val new_val = {
                .state = CONN_ESTABLISHED,
                .packets = 1,
                .last_seen = bpf_ktime_get_ns(),
            };
            bpf_map_update_elem(&conntrack, &key, &new_val, BPF_ANY);
            return 1;
        }
    } else {
        /* UDP/ICMP — track as established after first packet */
        struct conn_val new_val = {
            .state = CONN_ESTABLISHED,
            .packets = 1,
            .last_seen = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&conntrack, &key, &new_val, BPF_ANY);
        return 1;
    }

    /* Also check reverse direction (server response creates established) */
    struct conn_key rev_key = {
        .src_ip = dst_ip,
        .dst_ip = src_ip,
        .src_port = dst_port,
        .dst_port = src_port,
        .proto = proto,
    };
    struct conn_val *rev_val = bpf_map_lookup_elem(&conntrack, &rev_key);
    if (rev_val && rev_val->state == CONN_SYN_SEEN &&
        (tcp_flags & TCP_SYNACK) == TCP_SYNACK) {
        /* This is a SYN-ACK for an outgoing connection — mark established */
        rev_val->state = CONN_ESTABLISHED;
        rev_val->last_seen = bpf_ktime_get_ns();

        /* Also create forward entry */
        struct conn_val fwd_val = {
            .state = CONN_ESTABLISHED,
            .packets = 1,
            .last_seen = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&conntrack, &key, &fwd_val, BPF_ANY);
        return 1;
    }

    return 0;
}

/* ========================================================================
 * XDP PROGRAM — SynWall Production Interface Protection
 * ======================================================================== */

SEC("xdp_synwall")
int xdp_synwall_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    struct iphdr *iph;

    inc_stat(STAT_TOTAL);

    /* Parse Ethernet header */
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = iph->saddr;
    __u32 dst_ip = iph->daddr;
    __u16 src_port = 0;
    __u16 dst_port = 0;
    __u8  tcp_flags = 0;
    int enforce = get_mode();

    /* Parse transport headers */
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcph + 1) <= data_end) {
            src_port = bpf_ntohs(tcph->source);
            dst_port = bpf_ntohs(tcph->dest);
            tcp_flags = ((__u8 *)tcph)[13];
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (void *)iph + (iph->ihl * 4);
        if ((void *)(udph + 1) <= data_end) {
            src_port = bpf_ntohs(udph->source);
            dst_port = bpf_ntohs(udph->dest);
        }
    }

    /* ---- STEP 1: Allowlist (trusted IPs bypass everything) ---- */
    struct lpm_key lpm = { .prefixlen = 32, .addr = src_ip };
    __u8 *allowed = bpf_map_lookup_elem(&sw_allowlist, &lpm);
    if (allowed) {
        inc_stat(STAT_ALLOWLISTED);
        inc_stat(STAT_PASSED);
        return XDP_PASS;
    }

    /* ---- STEP 2: Connection tracking fast path ---- */
    if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
        int established = conntrack_check(src_ip, dst_ip,
                                           src_port, dst_port,
                                           iph->protocol, tcp_flags);
        if (established) {
            inc_stat(STAT_CONNTRACK_HIT);
            inc_stat(STAT_PASSED);
            return XDP_PASS;
        }
    }

    /* ---- STEP 3: Blocklist check ---- */
    __u8 *blocked = bpf_map_lookup_elem(&sw_blocklist, &lpm);
    if (blocked) {
        inc_stat(STAT_BLOCKLISTED);
        emit_event(src_ip, dst_ip, src_port, dst_port,
                   iph->protocol, SYNWALL_EVENT_BLOCKLIST,
                   REASON_BLOCKLIST, tcp_flags, 0);

        if (enforce) {
            inc_stat(STAT_DROPPED);
            return XDP_DROP;
        }
    }

    /* ---- STEP 4: RPF anti-spoofing ---- */
    int rpf_result = check_rpf(ctx, iph, ctx->ingress_ifindex);
    if (rpf_result != 0) {
        inc_stat(STAT_RPF_FAIL);
        __u8 reason = (rpf_result == 1)
            ? REASON_RPF_NO_ROUTE
            : REASON_RPF_IFACE_MISMATCH;
        emit_event(src_ip, dst_ip, src_port, dst_port,
                   iph->protocol, SYNWALL_EVENT_RPF_FAIL,
                   reason, tcp_flags, 0);

        if (enforce) {
            inc_stat(STAT_DROPPED);
            return XDP_DROP;
        }
    }

    /* ---- STEP 5: SYN rate limiting ---- */
    if (iph->protocol == IPPROTO_TCP && (tcp_flags & TCP_SYN) &&
        !(tcp_flags & TCP_ACK)) {
        __u32 syn_rate = check_syn_rate(src_ip);
        __u32 limit = get_syn_rate_limit();

        if (syn_rate > limit) {
            inc_stat(STAT_SYN_FLOOD);
            emit_event(src_ip, dst_ip, src_port, dst_port,
                       IPPROTO_TCP, SYNWALL_EVENT_SYN_FLOOD,
                       REASON_SYN_RATE, tcp_flags, syn_rate);

            if (enforce) {
                inc_stat(STAT_DROPPED);
                return XDP_DROP;
            }
        }
    }

    /* ---- All checks passed ---- */
    inc_stat(STAT_PASSED);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
