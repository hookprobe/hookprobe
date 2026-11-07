// SPDX-License-Identifier: GPL-2.0
/* napse_detect.bpf.c — UNIFIED HookProbe detection core (CO-RE), attachable as BOTH native XDP and
 * TC-bpf (SCHED_CLS @ clsact). ONE detection logic, two thin wrappers; the loader picks the hook per
 * NIC (native XDP where the driver supports it, TC-bpf otherwise — incl. all Wi-Fi/mac80211). See
 * docs/adr/0005. Stateful via the nf_conntrack lookup kfuncs (kernel >= 5.19, nf_conntrack loaded).
 *
 * BUILD: compiled in CI (clang -target bpf -g -O2 + CO-RE), NOT on the device (immutable image).
 * Needs vmlinux.h (bpftool gen) + libbpf headers. Verifier-tuning happens against target kernels;
 * BTFGen blobs are shipped for BSP kernels lacking CONFIG_DEBUG_INFO_BTF. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "napse_detect.h"

/* vmlinux.h provides kernel STRUCTS but not these UAPI constants — define them (guarded). */
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif

char LICENSE[] SEC("license") = "GPL";

/* ── nf_conntrack lookup kfuncs (5.19+). Both hooks can query conntrack natively; established flows
 *    fast-pass in kernel instead of the old userspace /proc/net/nf_conntrack read. ─────────────── */
struct nf_conn;
struct bpf_ct_opts___local { s32 netns_id; s32 error; u8 l4proto; u8 dir; u8 reserved[2]; } __attribute__((preserve_access_index));
extern struct nf_conn *bpf_xdp_ct_lookup(struct xdp_md *, struct bpf_sock_tuple *, __u32,
					 struct bpf_ct_opts___local *, __u32) __ksym;
extern struct nf_conn *bpf_skb_ct_lookup(struct __sk_buff *, struct bpf_sock_tuple *, __u32,
					 struct bpf_ct_opts___local *, __u32) __ksym;
extern void bpf_ct_release(struct nf_conn *) __ksym;

/* ── Maps (shared by both wrappers) ─────────────────────────────────────────── */
struct { __uint(type, BPF_MAP_TYPE_LPM_TRIE); __uint(max_entries, 1048576);
	 __uint(map_flags, BPF_F_NO_PREALLOC); __type(key, struct lpm_v4_key); __type(value, __u8);
} blocklist SEC(".maps");                 /* threat-feed CIDRs (HYDRA hourly sync)      */
struct { __uint(type, BPF_MAP_TYPE_LPM_TRIE); __uint(max_entries, 65536);
	 __uint(map_flags, BPF_F_NO_PREALLOC); __type(key, struct lpm_v4_key); __type(value, __u8);
} allowlist SEC(".maps");                 /* trusted CIDRs (edge, PoP, LAN gw)          */
/* Fixed-window SYN counter per source: reset when the window elapses (a lifetime cumulative counter
 * would permanently block any client that ever sends SYN_RATE_LIMIT SYNs). */
struct syn_win { __u64 start_ns; __u64 count; };
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 262144);
	 __type(key, __u32); __type(value, struct syn_win);
} syn_rate SEC(".maps");                  /* per-src SYN rate window (WAN)              */
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);
	 __type(key, __u32); __type(value, __u8);
} role_by_ifindex SEC(".maps");           /* ifindex → enum napse_role (loader fills)   */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 4);
	 __type(key, __u32); __type(value, __u64);
} napse_cfg SEC(".maps");                 /* CFG_MODE → enum napse_mode (config: vmlinux typedef) */
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20);
} events SEC(".maps");                    /* flow events → userspace NAPSE              */

/* ── Shed-v2 (base-tier-build-ticket.md Phase 2) ─────────────────────────────────────────────
 * `shed_ctrl`: the PSI→tier control-plane bridge. Written ONLY by the separate `hookprobe-psid`
 * process via this map's PINNED path (never by this program) — see napse_detect.h's doc on
 * SHED_KEY_*. `shed_bucket`: the per-source fixed-point token bucket, extends the same
 * "per-source LRU state" pattern `syn_rate` above already uses. */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, SHED_CTRL_MAP_ENTRIES);
	 __type(key, __u32); __type(value, __u64);
} shed_ctrl SEC(".maps");                 /* tier / r_base_pps / heartbeat_ns (psid-owned) */
struct { __uint(type, BPF_MAP_TYPE_LRU_HASH); __uint(max_entries, 65536);
	 __type(key, __u32); __type(value, struct shed_token);
} shed_bucket SEC(".maps");               /* per-src fixed-point token bucket (shed-v2)  */

#define SYN_RATE_LIMIT 50                 /* SYN/window/src before a WAN drop           */
#define SYN_WINDOW_NS 1000000000ULL       /* 1s window                                  */

/* Shed-v2 safety ceiling: clamp any `r_base_pps` read from `shed_ctrl` (an externally-written,
 * hence not fully trusted, control-plane value) to a sane maximum BEFORE it enters the
 * fixed-point refill multiply below. This bounds `rate_scaled * SHED_ELAPSED_CAP_NS` well under
 * U64_MAX for every possible input (10000 * 1e6 * 1e9 == 1e19 < ~1.8447e19) — a garbage/corrupt
 * control value fails toward "generous rate" (effectively no shed), never toward a silent
 * integer-overflow wraparound that could shed a legitimate flow. No real tier config ever
 * approaches this ceiling (spec §3.2's tiers top out two orders of magnitude below it). */
#define SHED_MAX_RATE_PPS 10000U
#define NSEC_PER_SEC_U64 1000000000ULL

/* Durable guard: a compile-time proof (not just a comment) that `rate_scaled * elapsed` in
 * shed_admit() below can NEVER overflow u64 at these constants, checked as
 * `SHED_MAX_RATE_PPS * SHED_TOKEN_SCALE <= U64_MAX / SHED_ELAPSED_CAP_NS` (a division-based
 * formulation so the check itself can't silently wrap the way the direct product would). This
 * exists because the constants live in TWO files (SHED_TOKEN_SCALE/SHED_ELAPSED_CAP_NS in
 * napse_detect.h, SHED_MAX_RATE_PPS here) — a future edit to either one in isolation would
 * otherwise regress the exact overflow this whole safety-ceiling design exists to prevent
 * without a build failure to catch it (this repo caught precisely that during Phase 2's own
 * review: the header briefly carried a 2s elapsed cap while this ceiling's comment assumed 1s). */
_Static_assert((unsigned long long)SHED_MAX_RATE_PPS * SHED_TOKEN_SCALE <= (0xFFFFFFFFFFFFFFFFULL / SHED_ELAPSED_CAP_NS),
		"shed-v2 fixed-point refill would overflow u64 — lower SHED_MAX_RATE_PPS or SHED_ELAPSED_CAP_NS");

/* Parsed L3/L4 the core reasons over (hook-independent). */
struct pkt_meta { __u32 saddr, daddr; __u16 sport, dport; __u8 proto; __u8 is_syn; __u32 l3len; };

static __always_inline __u8 cfg_mode(void)
{
	__u32 k = CFG_MODE; __u64 *v = bpf_map_lookup_elem(&napse_cfg, &k);
	return v ? (__u8)*v : MODE_MONITOR;   /* default fail-open                          */
}

static __always_inline __u8 role_for(__u32 ifindex)
{
	__u8 *r = bpf_map_lookup_elem(&role_by_ifindex, &ifindex);
	return r ? *r : ROLE_LAN;             /* unknown iface defaults to LAN policy       */
}

static __always_inline int lpm_hit(void *map, __u32 addr)
{
	struct lpm_v4_key k = { .prefixlen = 32, .addr = addr };
	return bpf_map_lookup_elem(map, &k) != NULL;
}

/* Shared L2/L3/L4 parse over a [data,data_end) window — identical for XDP and TC (both give direct
 * packet access). Bounds-checked for the verifier. Returns 0 on a v4 TCP/UDP/ICMP packet, else -1. */
static __always_inline int parse(void *data, void *data_end, struct pkt_meta *m)
{
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) return -1;
	if (eth->h_proto != bpf_htons(ETH_P_IP)) return -1;   /* v6 in a later revision      */
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end) return -1;
	/* Clamp ihl to [5,15] in a local so the verifier tracks the 20..60 byte L4 offset bound (helps
	 * the stricter verifiers on some vendor BSP kernels accept the variable-offset packet pointer). */
	__u32 ihl = ip->ihl;
	if (ihl < 5 || ihl > 15) return -1;
	m->saddr = ip->saddr; m->daddr = ip->daddr; m->proto = ip->protocol;
	m->l3len = bpf_ntohs(ip->tot_len); m->is_syn = 0; m->sport = m->dport = 0;
	void *l4 = (void *)ip + ihl * 4;
	if (m->proto == IPPROTO_TCP) {
		struct tcphdr *t = l4; if ((void *)(t + 1) > data_end) return -1;
		m->sport = bpf_ntohs(t->source); m->dport = bpf_ntohs(t->dest);
		m->is_syn = t->syn && !t->ack;
	} else if (m->proto == IPPROTO_UDP) {
		struct udphdr *u = l4; if ((void *)(u + 1) > data_end) return -1;
		m->sport = bpf_ntohs(u->source); m->dport = bpf_ntohs(u->dest);
	} else if (m->proto != IPPROTO_ICMP) {
		return -1;
	}
	return 0;
}

static __always_inline void emit(struct pkt_meta *m, __u32 ifindex, __u8 role,
				 __u8 verdict, __u8 reason)
{
	struct napse_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) return;
	e->ts_ns = bpf_ktime_get_ns();
	e->saddr = m->saddr; e->daddr = m->daddr; e->sport = m->sport; e->dport = m->dport;
	e->proto = m->proto; e->role = role; e->verdict = verdict; e->reason = reason;
	e->ifindex = ifindex; e->pkt_len = m->l3len;
	bpf_ringbuf_submit(e, 0);
}

/* Map a would-be DROP to the runtime posture: ENFORCE drops; MONITOR passes but still escalates
 * (fail-open — never break connectivity in observe mode). */
static __always_inline enum napse_verdict enforce(struct pkt_meta *m, __u32 ifx, __u8 role, __u8 reason)
{
	if (cfg_mode() == MODE_ENFORCE) { emit(m, ifx, role, NAPSE_DROP, reason); return NAPSE_DROP; }
	emit(m, ifx, role, NAPSE_ESCALATE, reason); return NAPSE_ESCALATE;
}

/* ── Shed-v2 (base-tier-build-ticket.md Phase 2, ADR 0031 §E / ADR 0023 D3) ──────────────────
 * Deliberately INDEPENDENT of `cfg_mode()`/MODE_MONITOR-vs-ENFORCE above: like the nft
 * Layer-1/2/3 resource-shed it accelerates (a SEPARATE table from the identity-keyed
 * quarantine/blocklist/SYN-rate mechanisms this file's OTHER verdicts drive), this is the one
 * enforcement class keyed purely on measured RESOURCE REALITY, never identity — so it stays
 * live regardless of the detection engine's own observe/enforce posture, exactly matching the
 * nft mechanism's existing always-on behaviour (ADR 0023 D3). Tier 0 is a true bypass. */

/* Fail-open by construction: ANY map-read miss, a stale heartbeat (psid died/hung), or garbage
 * tier value yields tier 0 (mechanism bypassed) — never "hold the last known tier". */
static __always_inline void shed_ctrl_read(__u8 *tier, __u32 *rate_pps)
{
	*tier = SHED_TIER_BYPASSED;
	*rate_pps = 0;
	__u32 k = SHED_KEY_HEARTBEAT_NS;
	__u64 *hb = bpf_map_lookup_elem(&shed_ctrl, &k);
	if (!hb) return;                                              /* map-read error → fail-open */
	__u64 now = bpf_ktime_get_ns();
	if (now < *hb || now - *hb > SHED_HEARTBEAT_STALE_NS) return;  /* stale/skewed → fail-open   */
	k = SHED_KEY_TIER;
	__u64 *t = bpf_map_lookup_elem(&shed_ctrl, &k);
	if (!t || *t > SHED_TIER_MAX) return;                         /* error/garbage → fail-open  */
	k = SHED_KEY_RATE_PPS;
	__u64 *r = bpf_map_lookup_elem(&shed_ctrl, &k);
	if (!r) return;                                               /* map-read error → fail-open */
	__u64 rp = *r;
	if (rp > SHED_MAX_RATE_PPS) rp = SHED_MAX_RATE_PPS;           /* clamp untrusted control input */
	*tier = (__u8)*t;
	*rate_pps = (__u32)rp;
}

/* shed_admit — the fast loop: a per-source fixed-point token bucket. Returns 1 (admit/PASS) or
 * 0 (bucket empty/SHED). MUST-FIX #1 (base-tier-build-ticket.md): the refill below is FIXED-
 * POINT INTEGER arithmetic ONLY — `rate_scaled` is pre-scaled by SHED_TOKEN_SCALE ("micro-
 * tokens"), and `last_ns` always advances to the EXACT current time on every call (never
 * rounded), so fractional tokens smaller than one micro-token accumulate correctly across calls
 * instead of being discarded — the naive `rate * dt_ns / 1e9` computed fresh per packet (no
 * persisted fractional remainder, no scaling) truncates to 0 at sub-second per-packet dt and
 * would stick every bucket at 0 forever under tier>=1, dropping every new flow including
 * legitimate ones. eBPF has no FPU — this is integer-only end to end. */
static __always_inline int shed_admit(struct pkt_meta *m, __u8 tier, __u32 rate_pps)
{
	if (tier == SHED_TIER_BYPASSED || rate_pps == 0) return 1;   /* bypass / unconfigured → PASS */

	__u64 rate_scaled = (__u64)rate_pps * SHED_TOKEN_SCALE;      /* pps → micro-tokens/sec       */
	__u64 now = bpf_ktime_get_ns();
	struct shed_token *tk = bpf_map_lookup_elem(&shed_bucket, &m->saddr);
	if (!tk) {
		/* First packet from this source since pressure began: start the bucket FULL (the
		 * 1s burst depth below) minus the one token this packet itself consumes — a
		 * brand-new legitimate source is never cold-start-penalised the instant a tier
		 * engages, only once it sustains a rate above the tier's ceiling. */
		struct shed_token init = {
			.tokens_scaled = rate_scaled > SHED_TOKEN_SCALE ? rate_scaled - SHED_TOKEN_SCALE : 0,
			.last_ns = now,
		};
		bpf_map_update_elem(&shed_bucket, &m->saddr, &init, BPF_ANY);
		return 1;
	}

	__u64 elapsed = now > tk->last_ns ? now - tk->last_ns : 0;
	if (elapsed > SHED_ELAPSED_CAP_NS) elapsed = SHED_ELAPSED_CAP_NS; /* bounds the multiply; also
	                                                                    * the de-facto burst-depth
	                                                                    * cap (SHED_MAX_RATE_PPS
	                                                                    * makes this multiply
	                                                                    * overflow-safe for u64) */
	__u64 refill = (rate_scaled * elapsed) / NSEC_PER_SEC_U64;   /* fixed-point integer — no float */
	__u64 tokens = tk->tokens_scaled + refill;
	if (tokens > rate_scaled) tokens = rate_scaled;               /* cap burst depth at 1s worth  */
	tk->last_ns = now;                                            /* exact — never rounded        */
	if (tokens >= SHED_TOKEN_SCALE) {
		tk->tokens_scaled = tokens - SHED_TOKEN_SCALE;
		return 1;
	}
	tk->tokens_scaled = tokens;                                   /* insufficient balance → SHED  */
	return 0;
}

static __always_inline void emit_shed(struct pkt_meta *m, __u8 tier, __u32 rate_pps)
{
	struct shed_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) return;
	e->ts_ns = bpf_ktime_get_ns();
	e->saddr = m->saddr;
	e->tier = tier;
	e->disposition = NAPSE_DROP;
	e->_pad[0] = 0; e->_pad[1] = 0;
	e->rate_pps = rate_pps;
	bpf_ringbuf_submit(e, 0);
}

/* THE CORE — verdict from {flow, ct-established, WAN/LAN role}. Cover-all-round policy split. */
static __always_inline enum napse_verdict
napse_core(struct pkt_meta *m, int established, __u32 ifx, __u8 role)
{
	/* 1. Trusted — a DESTINATION match always passes (traffic addressed to a known-good
	 * internal/upstream address, e.g. this device's own LAN gateway or a HookProbe PoP we are
	 * legitimately talking to — safe regardless of role, since an attacker doesn't control what
	 * address a packet is addressed TO in order to reach us).
	 *
	 * 2026-07-05 threat-model fix (H4): ROLE_WAN no longer honors a SOURCE-only allowlist match
	 * as an unconditional, pre-blocklist, pre-rate-limit PASS. `allowlist` intentionally carries
	 * LAN-scoped CIDRs (see that map's own doc comment: "trusted CIDRs (edge, PoP, LAN gw)") —
	 * those addresses can NEVER legitimately be the SOURCE of a packet arriving on the public WAN
	 * ingress (no legitimate route puts a private/internal address on the wire as a WAN-facing
	 * source). Before this fix, a WAN attacker spoofing exactly one of them bought an
	 * unconditional pass over BOTH the threat-feed blocklist and the SYN-rate limiter below —
	 * this was the bypass. That impossible-ingress signature is now the SAME condition
	 * `R_RPF_FAIL` (declared in napse_detect.h, never previously emitted) exists for: flagged and
	 * run through `enforce()`'s normal posture gate (fail-open/ESCALATE in MODE_MONITOR, DROP in
	 * MODE_ENFORCE — never a silent, unconditional trust decision, same discipline every other
	 * verdict in this function already gets). ROLE_LAN is UNCHANGED (a LAN client's own address
	 * legitimately IS inside the allowlisted CIDR — saddr-OR-daddr still both pass). */
	if (lpm_hit(&allowlist, m->daddr)) return NAPSE_PASS;
	if (role != ROLE_WAN) {
		if (lpm_hit(&allowlist, m->saddr)) return NAPSE_PASS;
	} else if (lpm_hit(&allowlist, m->saddr)) {
		return enforce(m, ifx, role, R_RPF_FAIL);
	}
	/* 2. Threat-feed blocklist — drop known-bad (both directions). */
	if (lpm_hit(&blocklist, m->saddr) || lpm_hit(&blocklist, m->daddr))
		return enforce(m, ifx, role, R_BLOCKLIST);
	/* 3. Established (ct hit) — fast-pass in kernel (the stateful win over /proc polling).
	 * Established flows are NEVER shed — step 4 below only ever sees ct-new traffic. */
	if (established) return NAPSE_PASS;
	/* 4. Resource-shed v2 (base-tier-build-ticket.md Phase 2, ADR 0031 §E) — a per-source
	 * fixed-point token bucket gated by the PSI-driven pressure tier `hookprobe-psid` writes.
	 * Deliberately BEFORE the WAN-only SYN window below and covers EVERY protocol/role (mirrors
	 * the nft Layer-1 cap's "ct state new, any protocol, any source" semantics it accelerates),
	 * not just TCP SYNs — a UDP/ICMP connect-flood saturates the box just as well as a SYN
	 * flood. Independent of `cfg_mode()` (see shed_admit's doc) — tier 0 is a true bypass, so
	 * this is a no-op read+branch on a healthy box (observe-by-default holds). */
	if (m->proto == IPPROTO_TCP || m->proto == IPPROTO_UDP || m->proto == IPPROTO_ICMP) {
		__u8 shed_tier; __u32 shed_rate;
		shed_ctrl_read(&shed_tier, &shed_rate);
		if (shed_tier != SHED_TIER_BYPASSED && !shed_admit(m, shed_tier, shed_rate)) {
			emit_shed(m, shed_tier, shed_rate);
			return NAPSE_DROP;
		}
	}
	/* 5. WAN side: fixed-window SYN-flood rate on new flows. */
	if (role == ROLE_WAN && m->is_syn) {
		__u64 now = bpf_ktime_get_ns();
		struct syn_win *w = bpf_map_lookup_elem(&syn_rate, &m->saddr);
		if (w) {
			if (now - w->start_ns > SYN_WINDOW_NS) { w->start_ns = now; w->count = 1; }
			else if (++w->count > SYN_RATE_LIMIT) return enforce(m, ifx, role, R_SYN_RATE);
		} else {
			struct syn_win nw = { .start_ns = now, .count = 1 };
			bpf_map_update_elem(&syn_rate, &m->saddr, &nw, BPF_ANY);
		}
	}
	/* 6. ICMP: don't ESCALATE every packet (echo/reply spam the ringbuf); allow/block already ran. */
	if (m->proto == IPPROTO_ICMP) return NAPSE_PASS;
	/* 7. New/unknown flow — pass but ESCALATE to userspace NAPSE for DPI + behavioural scoring. */
	emit(m, ifx, role, NAPSE_ESCALATE, R_NEW_FLOW);
	return NAPSE_PASS;
}

/* conntrack lookup filling a v4 tuple; returns 1 if an established/related ct entry exists. */
static __always_inline int ct_established(struct pkt_meta *m, struct nf_conn *ct)
{
	/* Presence of a ct entry ⇒ conntrack already saw this flow (established/related). NEW packets
	 * miss. (A finer check can read ct->status; kept simple for the first cut.) */
	int r = ct != NULL;
	if (ct) bpf_ct_release(ct);
	return r;
}

static __always_inline void fill_tuple(struct pkt_meta *m, struct bpf_sock_tuple *t)
{
	__builtin_memset(t, 0, sizeof(*t));
	t->ipv4.saddr = m->saddr; t->ipv4.daddr = m->daddr;
	t->ipv4.sport = bpf_htons(m->sport); t->ipv4.dport = bpf_htons(m->dport);
}

/* ── Wrapper 1: native XDP (driver hook). ctx = xdp_md; verdicts XDP_PASS / XDP_DROP. ──────────── */
SEC("xdp")
int napse_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data, *data_end = (void *)(long)ctx->data_end;
	struct pkt_meta m;
	if (parse(data, data_end, &m) < 0) return XDP_PASS;   /* not v4 TCP/UDP/ICMP → pass  */

	int est = 0;
	if (m.proto == IPPROTO_TCP || m.proto == IPPROTO_UDP) {
		struct bpf_sock_tuple t; fill_tuple(&m, &t);
		struct bpf_ct_opts___local o; __builtin_memset(&o, 0, sizeof(o)); o.netns_id = -1; o.l4proto = m.proto;
		struct nf_conn *ct = bpf_xdp_ct_lookup(ctx, &t, sizeof(t.ipv4), &o, sizeof(o));
		est = ct_established(&m, ct);
	}
	enum napse_verdict v = napse_core(&m, est, ctx->ingress_ifindex, role_for(ctx->ingress_ifindex));
	return v == NAPSE_DROP ? XDP_DROP : XDP_PASS;
}

/* ── Wrapper 2: TC-bpf (clsact). ctx = __sk_buff; verdicts TC_ACT_OK / TC_ACT_SHOT. The ONLY
 *    in-kernel option for Wi-Fi (mac80211/brcmfmac) — sees post-802.11-decap Ethernet frames. ─── */
SEC("tc")
int napse_tc(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data, *data_end = (void *)(long)skb->data_end;
	struct pkt_meta m;
	if (parse(data, data_end, &m) < 0) return TC_ACT_OK;

	int est = 0;
	if (m.proto == IPPROTO_TCP || m.proto == IPPROTO_UDP) {
		struct bpf_sock_tuple t; fill_tuple(&m, &t);
		struct bpf_ct_opts___local o; __builtin_memset(&o, 0, sizeof(o)); o.netns_id = -1; o.l4proto = m.proto;
		struct nf_conn *ct = bpf_skb_ct_lookup(skb, &t, sizeof(t.ipv4), &o, sizeof(o));
		est = ct_established(&m, ct);
	}
	enum napse_verdict v = napse_core(&m, est, skb->ifindex, role_for(skb->ifindex));
	return v == NAPSE_DROP ? TC_ACT_SHOT : TC_ACT_OK;
}
