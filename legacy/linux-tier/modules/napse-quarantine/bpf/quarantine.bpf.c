// SPDX-License-Identifier: GPL-2.0
/* quarantine.bpf.c — Ring-0 line-rate quarantine enforcement (ADR 0009 "Ring-0 LPM enforcement",
 * sized here as an exact-match hash — see quarantine.h for why). Fixes a LIVE finding
 * (2026-07-03): a port scan from an iPhone enumerated every open port BEFORE the reactive
 * detect->nft-drop loop (napse-dpi -> scan-responder.sh -> `nft add element`, a userspace
 * tail -F + exec round trip) finished converging. This program is the earliest kernel point a
 * quarantined source's packets can be stopped: TC-bpf at clsact ingress, which runs immediately
 * after the driver hands the skb off — well before netfilter/nftables hooks, routing, or any
 * userspace wakeup.
 *
 * SCOPE, DELIBERATELY MINIMAL: this program does ONE thing — look up the source MAC and source
 * IPv4 against two small hash maps the reconciler maintains from
 * `/var/lib/hookprobe/scan-quarantine.json` (the scan-responder's existing, already-deterministic
 * quarantine STATE; this program adds no new decision logic, C9: the responder DECIDES, this
 * ENFORCES). No ct-lookup, no ringbuf, no DPI — that is `napse_detect.bpf.c`'s job. Keeping this
 * object tiny keeps the verifier trivial and keeps this layer attachable independently of whether
 * the full detection engine (napse-capture) has even shipped yet on a given device.
 *
 * TC-bpf ONLY, deliberately — no XDP wrapper. `wlan0` (brcmfmac/mac80211) has NO native XDP
 * (ADR 0005 point 3); `end0` (bcmgenet) is only copy-mode XDP. Attaching ONE TC-bpf program to
 * clsact ingress on BOTH covers the Wi-Fi LAN-scan path (today's live finding) and the WAN path
 * with a single code path, at the cost of XDP-native's extra pre-skb-alloc speed on end0 — an
 * honest trade the loader/module.yaml calls out; see docs/adr/0005 for the full ladder and
 * follow-ups for an XDP-native variant on NICs that support it.
 *
 * BUILD: CO-RE, compiled with clang -target bpf (this Makefile can run in CI OR on this dev box,
 * which happens to carry clang-18/bpftool/pahole — see modules/napse-quarantine/Makefile). The
 * DEVICE never compiles this; only the loader (native aarch64 binary) and the pre-built .bpf.o
 * ship to it.
 *
 * 2026-07-06 CRITICAL fix ("dead ingress mirror", live Pi pentest): every PASS-path return here
 * used to be `TC_ACT_OK`. In tc's direct-action mode (how this program is attached — see
 * crates/hookprobe-manifest/src/inspect.rs), `TC_ACT_OK` TERMINATES classification for that skb —
 * no lower-priority filter on the same clsact ingress hook runs afterward. The matchall mirror
 * filter that redirects a copy of ingress traffic to `hp-mirror` for `napse-dpi` is installed at a
 * LOWER priority (higher pref number) than this program specifically so this program's DROP
 * decision is authoritative; but that same ordering means a PASS returning `TC_ACT_OK` silently
 * ate every ingress packet before the mirror ever saw it — `napse-dpi` was structurally
 * egress-only, and confirm.rs's "mirror sees both directions" assumption was false on real
 * hardware. Fix: every non-drop ("let this frame continue") return below is now `TC_ACT_UNSPEC`,
 * which falls through to the next filter (the mirror) instead of terminating the pipeline. A
 * genuine drop decision is UNCHANGED — it still returns `TC_ACT_SHOT`, which still drops
 * unconditionally regardless of any lower-priority filter. Do NOT revert PASS paths back to
 * `TC_ACT_OK` — that reintroduces this exact bug.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "quarantine.h"

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef TC_ACT_OK
#define TC_ACT_OK 0
#endif
#ifndef TC_ACT_SHOT
#define TC_ACT_SHOT 2
#endif
#ifndef TC_ACT_UNSPEC
#define TC_ACT_UNSPEC (-1)
#endif

char LICENSE[] SEC("license") = "GPL";

#define QUARANTINE_MAX_IPS 8192
#define QUARANTINE_MAX_MACS 8192

/* Source IPv4 quarantine — exact /32 hash. Key = source addr, NETWORK byte order (see
 * quarantine.h). Value = `struct quarantine_val { ifindex; hits }` (2026-07-05 threat-model fix,
 * HIGH #3): `ifindex` is the ONE ingress plane this entry may drop on — see quarantine.h's doc
 * comment on why a bare hit counter let a LAN-plane entry leak onto the WAN ifindex and vice
 * versa. `hits` (0 on insert; incremented on every match) gives the loader's `--status` a "did
 * this entry actually see traffic" signal with no ringbuf/perf-event consumer needed (this device
 * ships no bpftool to poll a map by hand). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, QUARANTINE_MAX_IPS);
	__type(key, __u32);
	__type(value, struct quarantine_val);
} quarantine_ips SEC(".maps");

/* Source MAC quarantine — the LAN path (a scanner's L2 address OBSERVED at detection time by
 * `napse_loader::portscan::PortScanTracker` — 2026-07-05 threat-model fix CRITICAL #2, NEVER an
 * `ip neigh`/`/proc/net/arp` resolution of the claimed source IP, which is exactly as spoofable as
 * that IP). Key packs the 48-bit MAC MSB-first into a __u64 low 48 bits (see quarantine.h). Value:
 * `struct quarantine_val`, same meaning as quarantine_ips (always the LAN ifindex in practice —
 * the loader never emits a WAN-plane mac entry). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, QUARANTINE_MAX_MACS);
	__type(key, __u64);
	__type(value, struct quarantine_val);
} quarantine_macs SEC(".maps");

/* [QSTAT_PASS]/[QSTAT_DROP] — total packet counts, both interfaces combined. Cheap proof for the
 * live drop test: watch QSTAT_DROP climb while a quarantined source's SYNs get zero responses. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, QSTAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} quarantine_stats SEC(".maps");

static __always_inline void bump(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&quarantine_stats, &idx);
	if (v)
		__sync_fetch_and_add(v, 1);
}

/* Pack a 6-byte MAC (as laid out in the Ethernet header, MSB-first / big-endian on the wire)
 * into the low 48 bits of a u64 — the SAME packing napse-loader's Rust side does (bpf.rs), so a
 * quarantine_macs key computed here and one computed in the loader are byte-identical without
 * either side doing an explicit endian swap. */
static __always_inline __u64 pack_mac(const unsigned char *mac)
{
	__u64 key = 0;
#pragma unroll
	for (int i = 0; i < 6; i++)
		key = (key << 8) | mac[i];
	return key;
}

SEC("tc")
int quarantine_ingress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		/* truncated/malformed frame the verifier can't prove is safe to parse further —
		 * never drop on a parse failure; that would be a fail-CLOSED bug in a fail-open
		 * datapath. TC_ACT_UNSPEC (not TC_ACT_OK): let classification fall through to the
		 * mirror filter instead of terminating the clsact pipeline (2026-07-06 fix, see
		 * this file's top doc comment). */
		bump(QSTAT_PASS);
		return TC_ACT_UNSPEC;
	}

	/* MAC check first: covers a quarantined LAN client regardless of L3/L4 protocol — mirrors
	 * the nft LAN rule set, which drops on `ether saddr` in addition to `ip saddr`.
	 *
	 * 2026-07-05 threat-model fix (HIGH #3): a match ONLY drops if it also arrived on the ONE
	 * ingress ifindex this entry is bound to (`skb->ingress_ifindex` — the plane the loader
	 * resolved for it from `classify_source`, the SAME split the nft `iifname`-scoped rules use).
	 * A LAN-plane entry can therefore never fire on the WAN ifindex, and vice versa. A match on
	 * the WRONG ifindex falls through to the IP check / PASS, exactly as if there were no entry
	 * at all for this plane — never a silent alternate enforcement. */
	__u64 mac_key = pack_mac(eth->h_source);
	struct quarantine_val *mhit = bpf_map_lookup_elem(&quarantine_macs, &mac_key);
	if (mhit && mhit->ifindex == skb->ingress_ifindex) {
		__sync_fetch_and_add(&mhit->hits, 1);
		bump(QSTAT_DROP);
		return TC_ACT_SHOT;
	}

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > data_end) {
			/* TC_ACT_UNSPEC (not TC_ACT_OK) — see this file's top doc comment. */
			bump(QSTAT_PASS);
			return TC_ACT_UNSPEC;
		}
		__u32 saddr = ip->saddr; /* network order, matches the loader's key */
		struct quarantine_val *ihit = bpf_map_lookup_elem(&quarantine_ips, &saddr);
		if (ihit && ihit->ifindex == skb->ingress_ifindex) {
			__sync_fetch_and_add(&ihit->hits, 1);
			bump(QSTAT_DROP);
			return TC_ACT_SHOT;
		}
	}

	/* No match on either quarantine map for this ifindex — final PASS. TC_ACT_UNSPEC (not
	 * TC_ACT_OK): fall through to the mirror filter instead of terminating the clsact
	 * pipeline (2026-07-06 fix, see this file's top doc comment). */
	bump(QSTAT_PASS);
	return TC_ACT_UNSPEC;
}
