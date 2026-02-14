/**
 * NAPSE Conntrack-Lite - Lightweight TCP State Machine in eBPF
 *
 * Tracks TCP connection state transitions at the kernel level for
 * SYN flood detection without userspace involvement.
 *
 * This is a simplified version of the Linux conntrack subsystem,
 * optimized for NAPSE's detection needs:
 *   - SYN flood: many SYN_SENT without completing handshake
 *   - Half-open connections: stuck in SYN_RECV
 *   - Stealth scans: FIN/XMAS/NULL without ESTABLISHED
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

#define CT_TABLE_SIZE    65536
#define HALF_OPEN_LIMIT  100     /* Max half-open per source IP */
#define CT_TIMEOUT_NS    120000000000ULL  /* 120 seconds */

/* Simplified TCP states */
enum ct_state {
    CT_NONE = 0,
    CT_SYN_SENT,
    CT_SYN_RECV,
    CT_ESTABLISHED,
    CT_FIN_WAIT,
    CT_CLOSED,
};

/* Connection tracking entry */
struct ct_entry {
    __u64 first_seen_ns;
    __u64 last_seen_ns;
    __u8  state;
    __u8  pad[7];
};

/* Per-source-IP half-open counter */
struct half_open_count {
    __u32 count;
    __u64 last_reset_ns;
};

/* Flow key (simplified 4-tuple for directional tracking) */
struct ct_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

/* Maps */
BPF_HASH(ct_table, struct ct_key, struct ct_entry, CT_TABLE_SIZE);
BPF_HASH(half_open_map, __u32, struct half_open_count, 65536);

/* Statistics */
BPF_ARRAY(ct_stats, __u64, 4);

enum {
    CT_STAT_NEW = 0,
    CT_STAT_ESTABLISHED = 1,
    CT_STAT_CLOSED = 2,
    CT_STAT_SYN_FLOOD_BLOCKED = 3,
};

static __always_inline void ct_inc_stat(__u32 idx) {
    __u64 *val = ct_stats.lookup(&idx);
    if (val) __sync_fetch_and_add(val, 1);
}

/**
 * Process a TCP packet and update connection state.
 *
 * Called from the main XDP gate when a TCP packet is received.
 * Returns: 0 = allow, 1 = drop (SYN flood protection)
 */
static __always_inline int ct_process_tcp(
    __u32 src_ip, __u32 dst_ip,
    __u16 src_port, __u16 dst_port,
    __u8 syn, __u8 ack, __u8 fin, __u8 rst)
{
    __u64 now = bpf_ktime_get_ns();

    struct ct_key key = {
        .src_ip = src_ip,
        .dst_ip = dst_ip,
        .src_port = src_port,
        .dst_port = dst_port,
    };

    struct ct_entry *entry = ct_table.lookup(&key);

    if (!entry) {
        /* New connection */
        if (syn && !ack) {
            /* SYN: Check half-open limit for source IP */
            struct half_open_count *ho = half_open_map.lookup(&src_ip);
            if (ho) {
                /* Reset counter every second */
                if (now - ho->last_reset_ns > 1000000000ULL) {
                    ho->count = 0;
                    ho->last_reset_ns = now;
                }

                if (ho->count >= HALF_OPEN_LIMIT) {
                    ct_inc_stat(CT_STAT_SYN_FLOOD_BLOCKED);
                    return 1;  /* Drop: SYN flood */
                }
                ho->count += 1;
            } else {
                struct half_open_count new_ho = {
                    .count = 1,
                    .last_reset_ns = now,
                };
                half_open_map.update(&src_ip, &new_ho);
            }

            /* Create new CT entry */
            struct ct_entry new_entry = {
                .first_seen_ns = now,
                .last_seen_ns = now,
                .state = CT_SYN_SENT,
            };
            ct_table.update(&key, &new_entry);
            ct_inc_stat(CT_STAT_NEW);
        }
        return 0;
    }

    /* Update existing entry */
    entry->last_seen_ns = now;

    if (rst) {
        entry->state = CT_CLOSED;
        ct_inc_stat(CT_STAT_CLOSED);
        return 0;
    }

    switch (entry->state) {
    case CT_SYN_SENT:
        if (syn && ack) {
            entry->state = CT_SYN_RECV;
        }
        break;

    case CT_SYN_RECV:
        if (ack && !syn) {
            entry->state = CT_ESTABLISHED;
            ct_inc_stat(CT_STAT_ESTABLISHED);

            /* Decrement half-open counter */
            struct half_open_count *ho = half_open_map.lookup(&src_ip);
            if (ho && ho->count > 0) {
                ho->count -= 1;
            }
        }
        break;

    case CT_ESTABLISHED:
        if (fin) {
            entry->state = CT_FIN_WAIT;
        }
        break;

    case CT_FIN_WAIT:
        if (ack) {
            entry->state = CT_CLOSED;
            ct_inc_stat(CT_STAT_CLOSED);
        }
        break;
    }

    return 0;
}
