/* napse_detect.h — shared schema between the CO-RE BPF program (napse_detect.bpf.c) and the
 * userspace loader/consumer (napse-xdp-loader). Kept dependency-free (plain C types) so both the
 * bpf-target compile and the musl userspace compile include it. See docs/adr/0005. */
#ifndef NAPSE_DETECT_H
#define NAPSE_DETECT_H

/* The BPF compile gets __uN from vmlinux.h (included first). A C userspace consumer has no vmlinux.h,
 * so provide the fixed-width types from stdint there. (The Rust consumer re-declares the struct.) */
#ifndef __VMLINUX_H__
#include <stdint.h>
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#endif

/* ── Verdicts (hook-agnostic; wrappers map to XDP or TC_ACT verdicts) ────────── */
enum napse_verdict {
	NAPSE_PASS = 0,   /* established/known-good → fast-pass in kernel            */
	NAPSE_DROP = 1,   /* known-bad (blocklist / RPF fail / rate) → drop inline   */
	NAPSE_ESCALATE = 2, /* new/suspicious → pass but emit event for userspace IDS */
};

/* Why a packet was flagged (for the event + telemetry). */
enum napse_reason {
	R_NONE = 0,
	R_ESTABLISHED,     /* ct said established → fast path                        */
	R_NEW_FLOW,        /* ct miss / new → escalate to NAPSE                      */
	R_BLOCKLIST,       /* src/dst in the threat-feed LPM trie                    */
	R_ALLOWLIST,       /* src/dst trusted → always pass                          */
	R_RPF_FAIL,        /* reverse-path check failed (WAN spoof)                  */
	R_SYN_RATE,        /* SYN flood rate exceeded (WAN)                          */
	R_LAN_LATERAL,     /* LAN east-west to a new internal peer (lateral move)    */
	R_RESOURCE_SHED,   /* shed-v2 PSI token bucket exhausted (base-tier-build-ticket.md P2) */
};

/* Which side of the router the ingress NIC is on — selects the ruleset. Mirrors
 * inspect::InspectRole. The loader populates the per-ifindex map from the manifest. */
enum napse_role {
	ROLE_LAN = 0,      /* AP/LAN carrier — client behaviour policy               */
	ROLE_WAN = 1,      /* uplink — ingress-threat + egress-exfil policy           */
};

/* Runtime posture, in the config ARRAY map (index CFG_MODE). */
enum napse_mode {
	MODE_MONITOR = 0,  /* observe only: never DROP, only ESCALATE (fail-open)    */
	MODE_ENFORCE = 1,  /* inline drop enabled                                    */
};
#define CFG_MODE 0

/* ── Shed-v2 (base-tier-build-ticket.md Phase 2, ADR 0031 amendment §E) ──────────────────────
 * `shed_ctrl` is a tiny 3-element BPF_MAP_TYPE_ARRAY the OUT-OF-TREE userspace `hookprobe-psid`
 * daemon writes (it never loads this object itself — it opens the map by its PINNED path,
 * `/sys/fs/bpf/hookprobe/shed_ctrl`, the same "pin so a separate process can drive it" pattern
 * `blocklist`/`allowlist` already use for hydra-feedsync). Deliberately three PLAIN u64 array
 * slots (mirrors `napse_cfg`'s shape above) rather than a packed struct value, so neither side
 * needs to agree on struct layout/padding across the Rust/C boundary — only three integers. */
#define SHED_KEY_TIER          0   /* current pressure tier: 0 (bypass) .. 3 (severe)         */
#define SHED_KEY_RATE_PPS      1   /* r_base_pps for the CURRENT tier, plain pps (0 = unset)  */
#define SHED_KEY_HEARTBEAT_NS  2   /* CLOCK_MONOTONIC ns of psid's last write (staleness/fail-open) */
#define SHED_CTRL_MAP_ENTRIES  3

/* Pressure tiers (spec §3.2). Tier 0 is not "a very high rate" — the bucket is BYPASSED
 * entirely (observe-by-default holds, ADR 0023); tiers 1-3 progressively tighten. */
#define SHED_TIER_BYPASSED 0
#define SHED_TIER_MAX      3

/* Fail-open: a heartbeat older than this (or a missing/unreadable shed_ctrl entry) is treated
 * as tier 0 (PASS), never "hold the last tier" — psid dying must never turn into a stuck shed. */
#define SHED_HEARTBEAT_STALE_NS (30ULL * 1000000000ULL)

/* Per-source token-bucket state, keyed by saddr in the `shed_bucket` LRU_HASH (extends the same
 * "per-source LRU state" pattern `syn_rate` already uses). `tokens_scaled` is FIXED-POINT
 * integer — scaled by SHED_TOKEN_SCALE "micro-tokens" — NEVER float (eBPF has no FPU; the
 * naive `rate * dt_ns / 1e9` truncates to 0 at per-packet dt and would stick every source's
 * bucket at 0 forever under tier>=1, dropping every new flow including legitimate ones — the
 * base-tier-build-ticket.md must-fix #1 this schema exists to make impossible). */
struct shed_token {
	__u64 tokens_scaled;  /* current balance, in micro-tokens (SHED_TOKEN_SCALE per real token) */
	__u64 last_ns;        /* bpf_ktime_get_ns() of the last refill (exact — never rounded)       */
};
#define SHED_TOKEN_SCALE       1000000ULL  /* 1 real token == 1,000,000 scaled "micro-token" units */
/* Cap dt at 1s: bounds `rate_scaled * elapsed` (the fixed-point refill multiply in shed_admit())
 * to a value that provably never overflows u64 even at SHED_MAX_RATE_PPS (napse_detect.bpf.c) —
 * 10000 pps * SHED_TOKEN_SCALE * SHED_ELAPSED_CAP_NS == 1e19, comfortably under U64_MAX
 * (~1.8447e19); a 2s cap would overflow at that same ceiling (2e19 > U64_MAX) — keep these two
 * constants' relationship in mind if either is ever tuned. Also the de-facto 1s burst-depth cap
 * (`tokens` is clamped to `rate_scaled` == exactly 1s worth of tokens at the tier's rate). */
#define SHED_ELAPSED_CAP_NS    1000000000ULL

/* One SHED_V2 telemetry record, reserved from the SAME `events` ringbuf as `napse_event` but at
 * its OWN (smaller, distinct) size — the userspace ringbuf callback dispatches on `data.len()`
 * (32 == napse_event, this size == shed_event), so the existing 32-byte parser is untouched. */
struct shed_event {
	__u64 ts_ns;       /* bpf_ktime_get_ns()                                     */
	__u32 saddr;       /* v4, network order — the shed source                    */
	__u8  tier;        /* pressure tier in effect when this packet was shed      */
	__u8  disposition; /* enum napse_verdict — always NAPSE_DROP today, carried for schema stability */
	__u8  _pad[2];
	__u32 rate_pps;    /* r_base_pps in effect for `tier` (the "effective rate")  */
};
_Static_assert(sizeof(struct shed_event) == 24, "shed_event must remain 24 bytes");

/* One event exported to userspace via the ringbuf (the NAPSE flow stream). Fixed layout so the
 * userspace consumer can memcpy it and re-emit as the common event schema (/var/lib/hookprobe/flows). */
struct napse_event {
	__u64 ts_ns;       /* bpf_ktime_get_ns()                                     */
	__u32 saddr;       /* v4 (network order); v6 handled in a later revision      */
	__u32 daddr;
	__u16 sport;       /* host order                                             */
	__u16 dport;
	__u8  proto;       /* IPPROTO_TCP/UDP/ICMP                                    */
	__u8  role;        /* enum napse_role                                        */
	__u8  verdict;     /* enum napse_verdict                                     */
	__u8  reason;      /* enum napse_reason                                      */
	__u32 ifindex;     /* ingress interface                                      */
	__u32 pkt_len;     /* L3 length                                              */
};
/* Guard the fixed 32-byte layout: the userspace drainer memcpy/reads it by offset (event.rs), so a
 * field reorder that adds padding must fail the build, not silently desync. */
_Static_assert(sizeof(struct napse_event) == 32, "napse_event must remain 32 bytes");
/* shed_event (24) must stay distinct from napse_event (32) — that size gap IS the dispatch key
 * the userspace ringbuf callback uses; guard it can never accidentally collide. */
_Static_assert(sizeof(struct shed_event) != sizeof(struct napse_event), "shed_event and napse_event must remain distinguishable by size");

/* LPM-trie key for the block/allow lists (IPv4 CIDR). prefixlen is in BITS. */
struct lpm_v4_key {
	__u32 prefixlen;
	__u32 addr;        /* network order                                          */
};

#endif /* NAPSE_DETECT_H */
