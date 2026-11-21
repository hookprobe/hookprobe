// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_flow_ctrl.c — Fight-or-Flight Traffic Prioritization
 *
 * The autonomic nervous system's flow control — heart rate and respiration.
 * Reads organism stress level from BPF map and classifies traffic into
 * three priority tiers:
 *
 *   VITAL (0):      DNS, SSH admin, HTP mesh, ICMP echo — always pass
 *   NORMAL (1):     HTTP/S, established connections — pass unless FIGHT
 *   DEFERRABLE (2): Bulk transfer, streaming, updates — throttle in ALERT+
 *
 * Stress States (from StressGauge):
 *   0 = CALM:     All traffic passes normally
 *   1 = ALERT:    Deferrable traffic rate-limited (50% pass)
 *   2 = FIGHT:    Deferrable dropped, normal rate-limited (75% pass)
 *   3 = RECOVERY: Deferrable rate-limited (75% pass), normal passes
 *
 * Attach: TC ingress classifier (not XDP — needs to coexist with xdp_hydra)
 * Build: clang -O2 -g -target bpf -c xdp_flow_ctrl.c -o xdp_flow_ctrl.o
 *
 * Author: HookProbe Team
 * License: GPL-2.0
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ---------- Constants ---------- */

#define STRESS_CALM     0
#define STRESS_ALERT    1
#define STRESS_FIGHT    2
#define STRESS_RECOVERY 3

#define TIER_VITAL      0
#define TIER_NORMAL     1
#define TIER_DEFERRABLE 2

/* Well-known ports for classification */
#define PORT_DNS     53
#define PORT_SSH     22
#define PORT_HTTP    80
#define PORT_HTTPS   443
#define PORT_HTP     8144
#define PORT_STUN    3478
#define PORT_MESH    8766
#define PORT_NTP     123
#define PORT_SMTP    25
#define PORT_SMTP_S  587

/* ---------- BPF Maps ---------- */

/*
 * stress_level: Single-element array holding the current organism stress.
 * Written by stress_gauge.py via bpf_map_ops.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} stress_level SEC(".maps");

/*
 * flow_stats: Per-CPU counters for vital/normal/deferrable traffic.
 * Used for monitoring and dashboard metrics.
 *
 * Index 0: vital_passed
 * Index 1: normal_passed
 * Index 2: normal_throttled
 * Index 3: deferrable_passed
 * Index 4: deferrable_throttled
 * Index 5: deferrable_dropped
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 6);
    __type(key, __u32);
    __type(value, __u64);
} flow_stats SEC(".maps");

/*
 * rate_seed: Pseudo-random seed for probabilistic throttling.
 * Uses packet timestamp XOR source IP for cheap entropy.
 */

/* ---------- Helpers ---------- */

static __always_inline void inc_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&flow_stats, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline __u8 get_stress(void)
{
    __u32 key = 0;
    __u8 *val = bpf_map_lookup_elem(&stress_level, &key);
    return val ? *val : STRESS_CALM;
}

/*
 * classify_port: Determine traffic tier based on destination port.
 * Returns TIER_VITAL, TIER_NORMAL, or TIER_DEFERRABLE.
 */
static __always_inline __u8 classify_port(__u16 dport, __u16 sport, __u8 proto)
{
    /* ICMP is always vital (ping, traceroute, PMTU) */
    if (proto == IPPROTO_ICMP)
        return TIER_VITAL;

    /* DNS — vital for all network operations */
    if (dport == PORT_DNS || sport == PORT_DNS)
        return TIER_VITAL;

    /* SSH admin — vital for operator access */
    if (dport == PORT_SSH)
        return TIER_VITAL;

    /* HTP mesh — vital for organism inter-node communication */
    if (dport == PORT_HTP || sport == PORT_HTP ||
        dport == PORT_STUN || sport == PORT_STUN ||
        dport == PORT_MESH || sport == PORT_MESH)
        return TIER_VITAL;

    /* NTP — vital for time synchronization */
    if (dport == PORT_NTP || sport == PORT_NTP)
        return TIER_VITAL;

    /* HTTP/HTTPS — normal priority */
    if (dport == PORT_HTTP || dport == PORT_HTTPS ||
        sport == PORT_HTTP || sport == PORT_HTTPS)
        return TIER_NORMAL;

    /* SMTP — normal (email delivery) */
    if (dport == PORT_SMTP || dport == PORT_SMTP_S)
        return TIER_NORMAL;

    /* Ephemeral → well-known: likely client request = normal */
    if (sport > 1024 && dport < 1024)
        return TIER_NORMAL;

    /* Everything else: deferrable (bulk, streaming, P2P, etc.) */
    return TIER_DEFERRABLE;
}

/*
 * should_throttle: Probabilistic rate limiting.
 *
 * Uses packet timestamp + src_ip as cheap entropy to determine
 * if this packet should be throttled. pass_percent is 0-100.
 *
 * Returns 1 if packet should be throttled (dropped), 0 if pass.
 */
static __always_inline int should_throttle(__u32 src_ip, __u8 pass_percent)
{
    if (pass_percent >= 100)
        return 0;
    if (pass_percent == 0)
        return 1;

    /* Cheap PRNG: timestamp XOR source IP */
    __u64 ts = bpf_ktime_get_ns();
    __u32 entropy = (__u32)(ts ^ src_ip ^ (ts >> 17));
    __u8 roll = entropy % 100;

    return (roll >= pass_percent) ? 1 : 0;
}

/* ---------- Main TC Program ---------- */

SEC("tc")
int flow_control(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Parse Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    /* Only process IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    /* Parse IP header */
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return TC_ACT_OK;

    __u8 proto = iph->protocol;
    __u32 src_ip = iph->saddr;
    __u16 dport = 0, sport = 0;

    /* Extract ports for TCP/UDP */
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)iph + (iph->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        dport = bpf_ntohs(tcp->dest);
        sport = bpf_ntohs(tcp->source);
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)iph + (iph->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        dport = bpf_ntohs(udp->dest);
        sport = bpf_ntohs(udp->source);
    }

    /* Get current stress level */
    __u8 stress = get_stress();

    /* Classify traffic tier */
    __u8 tier = classify_port(dport, sport, proto);

    /* ---------- Decision Matrix ----------
     *
     *              CALM    ALERT     FIGHT     RECOVERY
     * VITAL:       PASS    PASS      PASS      PASS
     * NORMAL:      PASS    PASS      75% pass  PASS
     * DEFERRABLE:  PASS    50% pass  DROP      75% pass
     */

    switch (tier) {
    case TIER_VITAL:
        /* Always pass vital traffic regardless of stress */
        inc_stat(0);  /* vital_passed */
        return TC_ACT_OK;

    case TIER_NORMAL:
        if (stress == STRESS_FIGHT) {
            if (should_throttle(src_ip, 75)) {
                inc_stat(2);  /* normal_throttled */
                return TC_ACT_SHOT;
            }
        }
        inc_stat(1);  /* normal_passed */
        return TC_ACT_OK;

    case TIER_DEFERRABLE:
        if (stress == STRESS_FIGHT) {
            /* Drop all deferrable during active fight */
            inc_stat(5);  /* deferrable_dropped */
            return TC_ACT_SHOT;
        }
        if (stress == STRESS_ALERT) {
            if (should_throttle(src_ip, 50)) {
                inc_stat(4);  /* deferrable_throttled */
                return TC_ACT_SHOT;
            }
        }
        if (stress == STRESS_RECOVERY) {
            if (should_throttle(src_ip, 75)) {
                inc_stat(4);  /* deferrable_throttled */
                return TC_ACT_SHOT;
            }
        }
        inc_stat(3);  /* deferrable_passed */
        return TC_ACT_OK;
    }

    /* Default: pass */
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
