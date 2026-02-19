/*
 * HookProbe HYDRA XDP Active Filtering
 * =====================================
 *
 * Active XDP program that enforces blocklist/allowlist filtering at line rate.
 * Replaces xdp_passive_inspect.c with active blocking while preserving all
 * existing passive statistics collection.
 *
 * Architecture:
 *   1. Check allowlist (LPM_TRIE) -> trusted IPs always pass
 *   2. Check blocklist (LPM_TRIE) -> threat feed IPs get dropped
 *   3. Rate tracking per source IP (LRU_HASH)
 *   4. All passive stats collected regardless of action
 *   5. Drop/alert events emitted to RINGBUF for userspace consumer
 *
 * BPF Maps (userspace-managed):
 *   - allowlist: Trusted CIDRs (populated by feed_sync.py)
 *   - blocklist: Threat feed CIDRs (populated by feed_sync.py)
 *   - hydra_config: Runtime config (mode: monitor/enforce)
 *   - events: RINGBUF for drop/alert events -> event_consumer.py
 *
 * Compile:
 *   clang -O2 -g -target bpf -c xdp_hydra.c -o xdp_hydra.o
 *
 * Load:
 *   ip link set dev dummy-mirror xdp obj xdp_hydra.o sec xdp_hydra
 *
 * Unload:
 *   ip link set dev dummy-mirror xdp off
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
#define PORT_VPN     4
#define PORT_HTP     5
#define PORT_OTHER   6
#define PORT_MAX     7

/* Rate limiting window (nanoseconds) */
#define RATE_WINDOW_NS 1000000000ULL  /* 1 second */

/* Rate threshold for alerting (packets per second) */
#define RATE_ALERT_THRESHOLD 5000

/* HYDRA event types */
#define HYDRA_EVENT_DROP       1  /* Packet dropped by blocklist */
#define HYDRA_EVENT_RATE_ALERT 2  /* High rate detected */
#define HYDRA_EVENT_PASS       3  /* Packet passed (allowlisted) */
#define HYDRA_EVENT_SCORE_DROP 4  /* Dropped by weighted IP score */

/* HYDRA event reasons */
#define HYDRA_REASON_BLOCKLIST  1  /* Matched threat feed blocklist */
#define HYDRA_REASON_RATE       2  /* Exceeded rate threshold */
#define HYDRA_REASON_SCORE      3  /* Weighted score exceeded threshold */

/* Config keys */
#define CONFIG_MODE        0  /* 0 = monitor (log only), 1 = enforce (drop) */
#define CONFIG_RATE_THRESH 1  /* Rate threshold override */
#define CONFIG_SAMPLE_RATE 2  /* Adaptive sampling denominator (1=100%, 2=50%, 4=25%) */
#define CONFIG_MAX         3

/* Weighted IP score drop threshold */
#define SCORE_DROP_THRESHOLD 100

/* Stats keys for HYDRA counters */
#define STAT_TOTAL_PACKETS  0
#define STAT_TOTAL_BYTES    1
#define STAT_DROPPED        2
#define STAT_ALLOWLISTED    3
#define STAT_BLOCKLISTED    4
#define STAT_RATE_ALERTS    5
#define STAT_SCORE_DROPS    6
#define STAT_MAX            7

/* ========================================================================
 * STRUCTURES
 * ======================================================================== */

/* LPM trie key for IPv4 CIDR matching */
struct lpm_key {
    __u32 prefixlen;
    __u32 addr;
};

/* Per-source IP rate tracking */
struct rate_info {
    __u64 packets;
    __u64 bytes;
    __u64 last_update;
};

/* IAT (Inter-Arrival Time) histogram buckets — 16 log-scale bins.
 * Bucket boundaries (nanoseconds):
 *   0: [0, 1us)         4: [100us, 316us)     8:  [10ms, 31.6ms)   12: [1s, 3.16s)
 *   1: [1us, 3.16us)    5: [316us, 1ms)       9:  [31.6ms, 100ms)  13: [3.16s, 10s)
 *   2: [3.16us, 10us)   6: [1ms, 3.16ms)      10: [100ms, 316ms)   14: [10s, 31.6s)
 *   3: [10us, 100us)    7: [3.16ms, 10ms)     11: [316ms, 1s)      15: [31.6s, inf)
 */
#define IAT_BUCKETS     16

/* Per-source IP IAT state.
 * Histogram and min/max/sum collected in kernel.
 * Mean/variance/entropy computed by userspace feature_extractor.py. */
struct iat_state {
    __u64 last_arrival_ns;          /* Timestamp of last packet */
    __u64 count;                    /* Number of IAT samples */
    __u64 sum_ns;                   /* Sum of all IATs (for mean) */
    __u64 min_ns;                   /* Minimum IAT observed */
    __u64 max_ns;                   /* Maximum IAT observed */
    __u32 histogram[IAT_BUCKETS];   /* Log-scale histogram */
};

/* Per-IP weighted threat score (populated by rdap_enricher.py).
 * Tags bitfield: bit0=vpn, bit1=datacenter, bit2=tor, bit3=proxy */
struct ip_score_val {
    __u16 score;      /* Cumulative threat score (0-65535) */
    __u8  tags;       /* Classification bitfield */
    __u8  reserved;
};

/* RINGBUF event structure for userspace consumer */
struct hydra_event {
    __u64 timestamp_ns;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  event_type;   /* HYDRA_EVENT_* */
    __u8  reason;       /* HYDRA_REASON_* */
    __u8  tcp_flags;
    __u32 rate_pps;     /* Packets per second (for rate events) */
};

/* ========================================================================
 * BPF MAPS
 * ======================================================================== */

/* Trusted CIDRs - packets from these ranges always pass.
 * Populated by feed_sync.py with: Anthropic, Vodafone RO, Cloudflare,
 * OCI metadata, RFC1918, loopback, etc. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 10240);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u8);   /* 1 = trusted */
} allowlist SEC(".maps");

/* Threat feed CIDRs - packets from these ranges get dropped.
 * Populated by feed_sync.py from Spamhaus, FireHOL, ET, etc. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 1048576);  /* 1M entries */
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct lpm_key);
    __type(value, __u8);   /* feed source ID */
} blocklist SEC(".maps");

/* Per-source IP state tracking */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 524288);  /* 500K unique IPs */
    __type(key, __u32);           /* Source IPv4 address */
    __type(value, struct rate_info);
} ip_state SEC(".maps");

/* Per-source IP IAT state (inter-arrival time tracking).
 * Read by feature_extractor.py for ML feature extraction. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);  /* 64K unique IPs */
    __type(key, __u32);          /* Source IPv4 address */
    __type(value, struct iat_state);
} iat_map SEC(".maps");

/* Per-IP weighted threat scores (populated by rdap_enricher.py).
 * Scores derived from RDAP classification + behavioral signals.
 * Score >= SCORE_DROP_THRESHOLD triggers XDP_DROP in enforce mode. */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);  /* 128K IPs */
    __type(key, __u32);           /* Source IPv4 address */
    __type(value, struct ip_score_val);
} ip_scores SEC(".maps");

/* RINGBUF for drop/alert events to userspace consumer */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 262144);  /* 256KB */
} events SEC(".maps");

/* Runtime configuration (monitor vs enforce mode) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CONFIG_MAX);
    __type(key, __u32);
    __type(value, __u64);
} hydra_config SEC(".maps");

/* HYDRA statistics counters */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STAT_MAX);
    __type(key, __u32);
    __type(value, __u64);
} hydra_stats SEC(".maps");

/* ---- Legacy maps (backward compatibility with existing stats pipeline) ---- */

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

/* Per-source IP packet rate (legacy, kept for existing exporter) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct rate_info);
} src_ip_rate SEC(".maps");

/* High-rate source IPs (legacy, kept for existing exporter) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} high_rate_ips SEC(".maps");

/* Total packet/byte counters (legacy) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} total_stats SEC(".maps");

/* ========================================================================
 * HELPER FUNCTIONS
 * ======================================================================== */

static __always_inline void inc_stat(__u32 key, __u64 val)
{
    __u64 *counter = bpf_map_lookup_elem(&hydra_stats, &key);
    if (counter)
        __sync_fetch_and_add(counter, val);
}

static __always_inline void inc_legacy_stat(__u32 key, __u64 val, void *map)
{
    __u64 *counter = bpf_map_lookup_elem(map, &key);
    if (counter)
        __sync_fetch_and_add(counter, val);
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
    case 51820:
    case 1194:
        return PORT_VPN;
    case 4719:
    case 8144:
    case 853:
    case 3478:
        return PORT_HTP;
    default:
        return PORT_OTHER;
    }
}

static __always_inline int get_mode(void)
{
    __u32 key = CONFIG_MODE;
    __u64 *val = bpf_map_lookup_elem(&hydra_config, &key);
    if (val)
        return (__u32)*val;
    return 0;  /* default: monitor mode */
}

static __always_inline void emit_event(__u32 src_ip, __u32 dst_ip,
                                        __u16 src_port, __u16 dst_port,
                                        __u8 proto, __u8 event_type,
                                        __u8 reason, __u8 tcp_flags,
                                        __u32 rate_pps)
{
    struct hydra_event *evt;

    evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
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
    evt->rate_pps = rate_pps;

    bpf_ringbuf_submit(evt, 0);
}

/*
 * Map IAT (nanoseconds) to log-scale histogram bucket.
 * Uses integer comparison to approximate log10 bucketing.
 * 16 buckets covering sub-microsecond to multi-second ranges.
 */
static __always_inline __u32 iat_to_bucket(__u64 iat_ns)
{
    if (iat_ns < 1000ULL)          return 0;   /* < 1us */
    if (iat_ns < 3162ULL)          return 1;   /* < 3.16us */
    if (iat_ns < 10000ULL)         return 2;   /* < 10us */
    if (iat_ns < 100000ULL)        return 3;   /* < 100us */
    if (iat_ns < 316228ULL)        return 4;   /* < 316us */
    if (iat_ns < 1000000ULL)       return 5;   /* < 1ms */
    if (iat_ns < 3162278ULL)       return 6;   /* < 3.16ms */
    if (iat_ns < 10000000ULL)      return 7;   /* < 10ms */
    if (iat_ns < 31622776ULL)      return 8;   /* < 31.6ms */
    if (iat_ns < 100000000ULL)     return 9;   /* < 100ms */
    if (iat_ns < 316227766ULL)     return 10;  /* < 316ms */
    if (iat_ns < 1000000000ULL)    return 11;  /* < 1s */
    if (iat_ns < 3162277660ULL)    return 12;  /* < 3.16s */
    if (iat_ns < 10000000000ULL)   return 13;  /* < 10s */
    if (iat_ns < 31622776602ULL)   return 14;  /* < 31.6s */
    return 15;                                  /* >= 31.6s */
}

/*
 * Update IAT (inter-arrival time) statistics for a source IP.
 *
 * Collects histogram, min, max, sum in-kernel using unsigned
 * arithmetic only (BPF prohibits signed division).
 * Userspace feature_extractor.py computes mean, variance, entropy.
 */
static __always_inline void update_iat(__u32 src_ip)
{
    __u64 now = bpf_ktime_get_ns();
    struct iat_state *state;

    state = bpf_map_lookup_elem(&iat_map, &src_ip);
    if (state) {
        if (state->last_arrival_ns > 0 && now > state->last_arrival_ns) {
            __u64 iat_ns = now - state->last_arrival_ns;

            /* Update histogram */
            __u32 bucket = iat_to_bucket(iat_ns);
            if (bucket < IAT_BUCKETS)
                __sync_fetch_and_add(&state->histogram[bucket], 1);

            /* Update aggregate stats */
            state->count++;
            state->sum_ns += iat_ns;

            /* Update min/max */
            if (state->count == 1 || iat_ns < state->min_ns)
                state->min_ns = iat_ns;
            if (iat_ns > state->max_ns)
                state->max_ns = iat_ns;
        }
        state->last_arrival_ns = now;
    } else {
        /* First packet from this IP — initialize */
        struct iat_state new_state = {0};
        new_state.last_arrival_ns = now;
        bpf_map_update_elem(&iat_map, &src_ip, &new_state, BPF_ANY);
    }
}

/* Update rate tracking for a source IP and return current PPS */
static __always_inline __u64 update_rate(__u32 src_ip, __u64 pkt_len)
{
    __u64 now = bpf_ktime_get_ns();
    struct rate_info *info;
    struct rate_info new_info = {0};
    __u64 pps = 0;

    info = bpf_map_lookup_elem(&ip_state, &src_ip);
    if (info) {
        if (now - info->last_update > RATE_WINDOW_NS) {
            /* Window elapsed — record previous rate */
            pps = info->packets;

            /* Also update legacy high_rate_ips map */
            if (pps > 1000)
                bpf_map_update_elem(&high_rate_ips, &src_ip, &pps, BPF_ANY);

            /* Reset for new window */
            new_info.packets = 1;
            new_info.bytes = pkt_len;
            new_info.last_update = now;
            bpf_map_update_elem(&ip_state, &src_ip, &new_info, BPF_ANY);
        } else {
            __sync_fetch_and_add(&info->packets, 1);
            __sync_fetch_and_add(&info->bytes, pkt_len);
            pps = info->packets;
        }
    } else {
        new_info.packets = 1;
        new_info.bytes = pkt_len;
        new_info.last_update = now;
        bpf_map_update_elem(&ip_state, &src_ip, &new_info, BPF_ANY);
        pps = 1;
    }

    /* Also update legacy src_ip_rate map for existing exporter */
    struct rate_info *legacy = bpf_map_lookup_elem(&src_ip_rate, &src_ip);
    if (legacy) {
        if (now - legacy->last_update > RATE_WINDOW_NS) {
            struct rate_info li = { .packets = 1, .bytes = pkt_len, .last_update = now };
            bpf_map_update_elem(&src_ip_rate, &src_ip, &li, BPF_ANY);
        } else {
            __sync_fetch_and_add(&legacy->packets, 1);
            __sync_fetch_and_add(&legacy->bytes, pkt_len);
        }
    } else {
        struct rate_info li = { .packets = 1, .bytes = pkt_len, .last_update = now };
        bpf_map_update_elem(&src_ip_rate, &src_ip, &li, BPF_ANY);
    }

    return pps;
}

/* ========================================================================
 * XDP PROGRAM - HYDRA Active Filtering
 * ======================================================================== */

SEC("xdp_hydra")
int xdp_hydra_filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth;
    struct iphdr *iph;
    __u32 key;
    __u64 pkt_len = data_end - data;

    /* ---- Update total counters (legacy + hydra) ---- */
    key = 0;
    inc_legacy_stat(key, 1, &total_stats);
    key = 1;
    inc_legacy_stat(key, pkt_len, &total_stats);
    inc_stat(STAT_TOTAL_PACKETS, 1);
    inc_stat(STAT_TOTAL_BYTES, pkt_len);

    /* ---- Parse Ethernet header ---- */
    eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* ---- IPv4 processing ---- */
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;

        __u32 src_ip = iph->saddr;
        __u32 dst_ip = iph->daddr;
        __u16 src_port = 0;
        __u16 dst_port = 0;
        __u8  tcp_flags = 0;

        /* ---- Parse transport headers for port info ---- */
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (void *)iph + (iph->ihl * 4);
            if ((void *)(tcph + 1) <= data_end) {
                src_port = bpf_ntohs(tcph->source);
                dst_port = bpf_ntohs(tcph->dest);
                tcp_flags = ((__u8 *)tcph)[13]; /* TCP flags byte */
            }
        } else if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = (void *)iph + (iph->ihl * 4);
            if ((void *)(udph + 1) <= data_end) {
                src_port = bpf_ntohs(udph->source);
                dst_port = bpf_ntohs(udph->dest);
            }
        }

        /* ---- STEP 1: Check allowlist (trusted CIDRs pass immediately) ---- */
        struct lpm_key lpm = { .prefixlen = 32, .addr = src_ip };
        __u8 *allowed = bpf_map_lookup_elem(&allowlist, &lpm);
        if (allowed) {
            inc_stat(STAT_ALLOWLISTED, 1);
            goto collect_stats;
        }

        /* ---- STEP 2: Check blocklist (threat feed drops) ---- */
        __u8 *blocked = bpf_map_lookup_elem(&blocklist, &lpm);
        if (blocked) {
            inc_stat(STAT_BLOCKLISTED, 1);

            /* Emit RINGBUF event */
            emit_event(src_ip, dst_ip, src_port, dst_port,
                       iph->protocol, HYDRA_EVENT_DROP,
                       HYDRA_REASON_BLOCKLIST, tcp_flags, 0);

            /* In enforce mode: drop. In monitor mode: pass but log. */
            if (get_mode() == 1) {
                inc_stat(STAT_DROPPED, 1);
                return XDP_DROP;
            }
            /* Monitor mode: fall through to collect stats and pass */
        }

        /* ---- STEP 2.5: Check weighted IP score ---- */
        struct ip_score_val *ip_score = bpf_map_lookup_elem(&ip_scores, &src_ip);
        if (ip_score && ip_score->score >= SCORE_DROP_THRESHOLD) {
            inc_stat(STAT_SCORE_DROPS, 1);
            emit_event(src_ip, dst_ip, src_port, dst_port,
                       iph->protocol, HYDRA_EVENT_SCORE_DROP,
                       HYDRA_REASON_SCORE, tcp_flags, ip_score->score);

            if (get_mode() == 1) {
                inc_stat(STAT_DROPPED, 1);
                return XDP_DROP;
            }
            /* Monitor mode: fall through to collect stats */
        }

        /* ---- STEP 3: Rate tracking + IAT (with adaptive sampling) ---- */
        {
            __u32 sample_key = CONFIG_SAMPLE_RATE;
            __u64 *sample_val = bpf_map_lookup_elem(&hydra_config, &sample_key);
            __u32 sample_denom = sample_val ? (__u32)*sample_val : 1;

            /* When under CPU load, sample every Nth packet for IAT/rate */
            if (sample_denom <= 1 || (bpf_get_prandom_u32() % sample_denom) == 0) {
                __u64 pps = update_rate(src_ip, pkt_len);
                update_iat(src_ip);

                /* Check if rate exceeds alert threshold */
                if (pps > RATE_ALERT_THRESHOLD) {
                    inc_stat(STAT_RATE_ALERTS, 1);
                    emit_event(src_ip, dst_ip, src_port, dst_port,
                               iph->protocol, HYDRA_EVENT_RATE_ALERT,
                               HYDRA_REASON_RATE, tcp_flags, (__u32)pps);
                }
            }
        }

collect_stats:
        /* ---- Collect passive statistics (backward compatible) ---- */

        /* Protocol stats */
        switch (iph->protocol) {
        case IPPROTO_TCP:  key = PROTO_TCP; break;
        case IPPROTO_UDP:  key = PROTO_UDP; break;
        case IPPROTO_ICMP: key = PROTO_ICMP; break;
        default:           key = PROTO_OTHER;
        }
        inc_legacy_stat(key, 1, &proto_stats);
        inc_legacy_stat(key, pkt_len, &proto_bytes);

        /* Port stats */
        if (iph->protocol == IPPROTO_TCP || iph->protocol == IPPROTO_UDP) {
            __u32 port_key = get_port_category(dst_port);
            if (port_key == PORT_OTHER)
                port_key = get_port_category(src_port);
            inc_legacy_stat(port_key, 1, &port_stats);
        }

        return XDP_PASS;
    }

    /* ---- IPv6 processing (stats only, no filtering yet) ---- */
    if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;

        switch (ip6h->nexthdr) {
        case IPPROTO_TCP:  key = PROTO_TCP; break;
        case IPPROTO_UDP:  key = PROTO_UDP; break;
        case IPPROTO_ICMPV6: key = PROTO_ICMP; break;
        default:           key = PROTO_OTHER;
        }
        inc_legacy_stat(key, 1, &proto_stats);
        inc_legacy_stat(key, pkt_len, &proto_bytes);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
