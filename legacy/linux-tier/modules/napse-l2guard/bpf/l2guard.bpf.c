// SPDX-License-Identifier: GPL-2.0
/* l2guard.bpf.c — Ring-0 line-rate DETERMINISTIC malformed-frame / malformed-ARP drop, the real
 * enforcement point `crates/hookprobe-manifest/src/l2_responder.rs`'s doc comment named as still
 * missing (`render_frame_drop_todo`'s stub): nft cannot express byte-level frame validation or
 * one packet field disagreeing with another, so this TC-bpf clsact-INGRESS program re-parses the
 * raw frame exactly like `napse_loader::dpi` (modules/napse-capture/loader/src/dpi.rs) already
 * does and returns TC_ACT_SHOT for precisely the conditions that module's `frame_anomaly_reason`/
 * `ArpObs::is_malformed`/`ArpObs::eth_mismatch` flag as `L2Verdict::FrameDrop`.
 *
 * SCOPE, DELIBERATELY EXACT-MATCHED (not decided independently — see l2guard.h's doc comment on
 * the shared-seam discipline and loader/src/predicates.rs for the anti-drift test):
 *   1. runt frame                          (skb->len < L2GUARD_MIN_FRAME_LEN)
 *   2. oversized frame                      (skb->len > L2GUARD_MAX_FRAME_LEN)
 *   3. source MAC multicast/group bit set   (eth->h_source[0] & 0x01 — IEEE 802.3 3.2.3 forbids a
 *                                            multicast/broadcast address as a frame's SOURCE)
 *   4. a declared 802.1Q tag too short to contain itself, OR a double/stacked 802.1Q tag (QinQ) on
 *      a topology that expects at most one, OR the reserved VLAN id 0xFFF
 *   5. ARP structural anomaly: non-standard htype/ptype/hlen/plen (`ArpObs::is_malformed`), OR the
 *      ARP payload's own sender_mac disagreeing with the Ethernet frame's OWN source mac
 *      (`ArpObs::eth_mismatch`)
 * Deliberately NOT covered here (out of THIS program's scope, stays alert-only via
 * `l2_responder`/`l2guard.rs`'s userspace path): ARP binding flip-flop and gratuitous-ARP flood —
 * both need cross-packet HISTORY (a per-IP binding table / per-source rate window), which is a
 * different, stateful engineering problem from "is this ONE frame structurally bad" that this
 * program answers. Extending this program with a pinned per-IP/per-source state map is a real,
 * separate follow-up, not a gap silently swallowed here.
 *
 * ANTI-SPOOF DISCIPLINE (ADR 0018, inherited one layer earlier — see l2_responder.rs's module
 * doc): every check above is a property of the FRAME ITSELF (its own length, its own header
 * bytes, two of its OWN fields disagreeing with each other) — never a claim about a spoofable
 * claimed identity being looked up against external state. This is the same structural guarantee
 * `hookprobe_manifest::l2_responder::L2Verdict::FrameDrop` encodes in Rust, enforced here in the
 * kernel with the identical scope.
 *
 * FAIL-OPEN CONTRACT (non-negotiable, mirrors modules/napse-quarantine/bpf/quarantine.bpf.c): a
 * parse failure (frame too short for the verifier to safely read a needed field, given the bounds
 * it can already prove) returns TC_ACT_OK, never TC_ACT_SHOT. A security tool must never
 * fail-closed the link on a frame it didn't understand. In practice, once `skb->len` clears
 * `L2GUARD_MIN_FRAME_LEN` (60) every subsequent field this program reads (a 14-byte Ethernet
 * header, an optional 4-byte 802.1Q tag, an 8-byte fixed ARP header, and — only when that header
 * declares the standard Ethernet/IPv4 shape — the ARP body's `sender_mac` at a fixed offset) fits
 * comfortably inside that 60-byte floor (14+4+8+6 = 32 <= 60), so these fail-open branches are
 * verifier-required defensive bounds checks that should not be reachable on a real skb, not a
 * routinely-hit code path — the same relationship `dpi::parse_arp_obs`'s own doc comment describes
 * for its (Rust-side) analogous fallback.
 *
 * SEPARATE program/table from modules/napse-quarantine/bpf/quarantine.bpf.c ON PURPOSE: that
 * program drops a packet because of who (a spoofable MAC/IP) is claimed to have sent it, once a
 * userspace decision already quarantined that identity; this program drops a packet because of
 * WHAT it structurally is, independent of source — the two are complementary Ring-0 layers, never
 * a replacement for each other. Attached at its own TC priority (see module.yaml / README) so the
 * two (and napse-capture's DPI mirror) can never collide/clobber one another's clsact filter.
 *
 * BUILD: CO-RE, `clang -target bpf` (see modules/napse-l2guard/Makefile — same recipe as
 * napse-quarantine's). The device never compiles this; only the loader (native binary) and the
 * pre-built .bpf.o ship to it.
 *
 * 2026-07-06 CRITICAL fix ("dead ingress mirror", live Pi pentest, same root cause as
 * modules/napse-quarantine/bpf/quarantine.bpf.c — see that file's identical doc-comment section
 * for the full mechanism): every PASS-path return here used to be `TC_ACT_OK`, which in tc's
 * direct-action mode TERMINATES clsact classification for that skb — the lower-priority matchall
 * mirror filter (installed by crates/hookprobe-manifest/src/inspect.rs) never ran for ingress, so
 * `napse-dpi` never saw inbound traffic. Fix: every non-drop ("frame is fine, or inspection
 * couldn't prove otherwise, let it continue") return below is now `TC_ACT_UNSPEC`, which falls
 * through to the next filter instead of stopping the pipeline. Every genuine `TC_ACT_SHOT` (a
 * proven structural anomaly) is UNCHANGED — it still drops unconditionally. Do NOT revert PASS
 * paths back to `TC_ACT_OK`.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "l2guard.h"

#ifndef ETH_P_ARP
#define ETH_P_ARP 0x0806
#endif
#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif
#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
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

/* 2026-07-05 false-positive fix (EDR #7), SUPERSEDED 2026-07-07 (see the "CRITICAL fix" doc
 * comment on `is_well_formed_ipv4_or_arp` and on `l2guard_ingress`'s runt check below for the
 * full story): this file used to gate its runt-frame exemption behind a single flat
 * `L2GUARD_RUNT_EXEMPT_MIN_LEN` (54u) floor, mirroring `dpi::RUNT_EXEMPT_MIN_LEN` — that covered
 * a bare 54-byte TCP control segment (ACK/SYN-ACK/RST/FIN, no payload/options — 14 eth + 20 ipv4
 * + 20 tcp) but NOT a well-formed ARP packet (14 eth + 28-byte ARP body = 42 bytes total, 12
 * bytes SHORTER than that floor), so this program dropped every legitimate small ARP frame
 * (breaking basic Wi-Fi client connectivity — confirmed live: an iPhone associating to the
 * `HookProbe` SSID got no ARP resolution at all). There is no longer a single flat length floor
 * here — see `is_well_formed_ipv4_or_arp` and the runt check in `l2guard_ingress`, both now
 * PROTOCOL-AWARE, matching `dpi::frame_anomaly_reason_local`'s identical 2026-07-07 fix exactly
 * (this is the shared-seam this file's own top doc comment requires staying in lockstep with). */

char LICENSE[] SEC("license") = "GPL";

/* [LSTAT_PASS]/[LSTAT_DROP] — total packet counts across every attached interface. Cheap proof
 * for a live drop test, same convention as quarantine.bpf.c's quarantine_stats. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, LSTAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} l2guard_stats SEC(".maps");

static __always_inline void bump(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&l2guard_stats, &idx);
	if (v)
		__sync_fetch_and_add(v, 1);
}

/* The 802.1Q tag this program strips AT MOST ONE of — `struct vlan_hdr` (fields `h_vlan_TCI` /
 * `h_vlan_encapsulated_proto`) comes from vmlinux.h (the kernel's own uapi/linux/if_vlan.h shape),
 * reused here rather than redeclared to avoid a duplicate-definition clash. Mirrors
 * `dpi::eth_type_and_offset`'s "does NOT recurse into a second stacked tag" contract exactly: a
 * double-tagged (QinQ) frame is a malformed-frame finding here (below), not something this
 * function tunnels through. */

/* The fixed 8-byte ARP header every ARP packet (malformed or not) begins with — mirrors
 * `dpi::parse_arp_obs`'s own field-by-field reads (htype/ptype/hlen/plen/opcode), same 8-byte
 * layout, no padding (2+2+1+1+2 bytes, all naturally aligned). `oper` is read for byte-offset
 * bookkeeping only (getting to `sender_mac` at the right offset) — this program, like
 * `ArpObs::is_malformed`, never validates the opcode's VALUE, only htype/ptype/hlen/plen; adding
 * an opcode check here without adding it to `dpi.rs` first would itself be an anti-drift bug (see
 * l2guard.h's doc comment on the shared-seam discipline). */
struct arp_fixed_hdr {
	__u16 htype;
	__u16 ptype;
	__u8  hlen;
	__u8  plen;
	__u16 oper;
};

/* 2026-07-05 false-positive fix (EDR #7), extended 2026-07-07 (CRITICAL fix — see this file's top
 * doc comment) — the runt-EXEMPTION structural check, mirroring
 * `dpi::frame_anomaly_reason_local`'s `parse_l4(frame).is_some() || parse_icmp_obs(frame).is_some()
 * || parse_arp_obs(frame).is_some_and(|a| !a.is_malformed())` predicate exactly (see that Rust
 * function's doc comment for the full rationale). `true` iff [data,data_end) is FULLY,
 * structurally a well-formed IPv4 TCP/UDP/ICMP packet (its own declared IHL/protocol/L4-header-
 * length chain is internally consistent and entirely present within the verified bounds) or a
 * well-formed ARP packet (standard Ethernet/IPv4 htype/ptype/hlen/plen, AND the full 28-byte ARP
 * body present — see the 2026-07-07 fix inline below). Called for ANY frame shorter than
 * `L2GUARD_MIN_FRAME_LEN` (60) — there is no separate flat length gate before this check anymore
 * (see this file's top doc comment); this function's OWN per-protocol bounds checks are the only
 * floor. */
static __always_inline int is_well_formed_ipv4_or_arp(void *data, void *data_end)
{
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return 0;
	__u16 ethertype = bpf_ntohs(eth->h_proto);

	if (ethertype == ETH_P_ARP) {
		struct arp_fixed_hdr *arp = (void *)(eth + 1);
		/* 2026-07-07 CRITICAL fix: this used to bounds-check only through `sender_mac`
		 * (eth + 8-byte fixed header + 6 bytes = 28 bytes total), which is 14 bytes SHORT
		 * of a complete ARP packet (RFC 826: 8-byte fixed header + sender_mac(6) +
		 * sender_ip(4) + target_mac(6) + target_ip(4) = 28-byte body, i.e. 14 + 28 = 42
		 * bytes total) — a genuinely TRUNCATED 28-42-byte ARP capture (missing
		 * sender_ip/target_mac/target_ip entirely) was wrongly accepted as "well-formed"
		 * by this function. Require the FULL 28-byte body (`arp_fixed_hdr` doubles as the
		 * fixed 8 bytes; +20 more for the address fields = 28) before accepting the
		 * htype/ptype/hlen/plen shape as proof of a COMPLETE packet, mirroring
		 * `dpi::parse_arp_obs`'s identical 2026-07-07 fix (returns `None`, not a
		 * "malformed-but-present" `ArpObs`, for exactly this truncated-body shape). */
		unsigned char *body_end = (unsigned char *)arp + 28;
		if ((void *)body_end > data_end)
			return 0;
		return bpf_ntohs(arp->htype) == L2GUARD_ARP_HTYPE_ETHERNET &&
		       bpf_ntohs(arp->ptype) == L2GUARD_ARP_PTYPE_IPV4 &&
		       arp->hlen == 6 && arp->plen == 4;
	}
	if (ethertype != ETH_P_IP)
		return 0;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return 0;
	__u32 ihl = ip->ihl;
	if (ihl < 5 || ihl > 15)
		return 0;
	void *l4 = (void *)ip + ihl * 4;
	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *t = l4;
		return (void *)(t + 1) <= data_end; /* fixed 20-byte header, no options needed here */
	} else if (ip->protocol == IPPROTO_UDP) {
		struct udphdr *u = l4;
		return (void *)(u + 1) <= data_end;
	} else if (ip->protocol == IPPROTO_ICMP) {
		return l4 <= data_end;
	}
	return 0;
}

SEC("tc")
int l2guard_ingress(struct __sk_buff *skb)
{
	/* 1/2. runt / oversized — dpi::frame_anomaly_reason_local checks #1-#3. `skb->len` is the
	 * TOTAL frame length (post-any-driver-padding), exactly what `napse_loader::dpi`'s
	 * AF_PACKET-captured `frame.len()` measures.
	 *
	 * 2026-07-07 CRITICAL fix (live pentest — see this file's top doc comment for the full
	 * story): below `L2GUARD_MIN_FRAME_LEN`(60) there is no single flat exemption floor anymore.
	 * A frame shorter than a bare 14-byte Ethernet header can never be classified at all and is
	 * always a runt drop — mirrors `dpi::frame_anomaly_reason_local`'s own unconditional
	 * `frame.len() < 14` branch exactly (never fail-open: this is a frame that doesn't even have
	 * 14 bytes ON THE WIRE, not merely a verifier-provable-window limit like the fail-open
	 * branches later in this function). A frame in `[14, 60)` is exempt from the runt drop if —
	 * and only if — `is_well_formed_ipv4_or_arp` (above) proves it is a FULLY, structurally
	 * complete ARP or IPv4 TCP/UDP/ICMP packet at ITS OWN protocol-correct minimum length (42
	 * bytes for ARP, 34 for a bare IPv4/ICMP header, 54 for a bare TCP segment, 42 for a bare UDP
	 * datagram — never one hand-picked number for every protocol). Anything that fails this
	 * structural check is still dropped exactly as before. */
	__u32 len = skb->len;
	if (len < 14) {
		bump(LSTAT_DROP);
		return TC_ACT_SHOT;
	}
	if (len < L2GUARD_MIN_FRAME_LEN) {
		if (is_well_formed_ipv4_or_arp((void *)(long)skb->data, (void *)(long)skb->data_end)) {
			/* TC_ACT_UNSPEC (not TC_ACT_OK) — see this file's top doc comment
			 * (2026-07-06 dead-ingress-mirror fix). */
			bump(LSTAT_PASS);
			return TC_ACT_UNSPEC;
		}
		bump(LSTAT_DROP);
		return TC_ACT_SHOT;
	}
	if (len > L2GUARD_MAX_FRAME_LEN) {
		bump(LSTAT_DROP);
		return TC_ACT_SHOT;
	}

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end) {
		/* skb->len already proved >= 60 bytes exist on the wire, but the LINEAR window the
		 * verifier can prove safe to dereference is shorter than one Ethernet header (see
		 * this file's fail-open doc comment — should not happen on a real skb). Never drop
		 * on an inspection limit, only on a PROVEN anomaly. TC_ACT_UNSPEC (not TC_ACT_OK) —
		 * see this file's top doc comment (2026-07-06 dead-ingress-mirror fix). */
		bump(LSTAT_PASS);
		return TC_ACT_UNSPEC;
	}

	/* 3. source MAC multicast/group bit set — dpi::frame_anomaly_reason check #4. Bit 0 (LSB)
	 * of the first octet is the I/G bit (IEEE 802.3 3.2.3) — identical bit test to dpi.rs's
	 * `frame[6] & 0x01`. */
	if (eth->h_source[0] & 0x01) {
		bump(LSTAT_DROP);
		return TC_ACT_SHOT;
	}

	__u16 ethertype = bpf_ntohs(eth->h_proto);
	void *l3 = (void *)(eth + 1);

	/* 4. VLAN tag checks — dpi::frame_anomaly_reason check #5 (truncated tag / double-tag /
	 * reserved vid), same order as `eth_type_and_offset`+`frame_anomaly_reason`. */
	if (ethertype == L2GUARD_ETH_P_8021Q) {
		struct vlan_hdr *vh = l3;
		if ((void *)(vh + 1) > data_end) {
			/* declared a VLAN tag but the frame is too short to contain it — dpi.rs
			 * flags this as a DETERMINISTIC anomaly (not a "can't tell" case; the
			 * frame is provably self-contradictory), so this is a real drop, not the
			 * fail-open path above. */
			bump(LSTAT_DROP);
			return TC_ACT_SHOT;
		}
		__u16 inner = bpf_ntohs(vh->h_vlan_encapsulated_proto);
		if (inner == L2GUARD_ETH_P_8021Q) {
			bump(LSTAT_DROP);
			return TC_ACT_SHOT; /* double/stacked 802.1Q tag (QinQ) */
		}
		__u16 vid = bpf_ntohs(vh->h_vlan_TCI) & 0x0FFF;
		if (vid == L2GUARD_VLAN_VID_RESERVED) {
			bump(LSTAT_DROP);
			return TC_ACT_SHOT; /* reserved VLAN id 0xFFF */
		}
		ethertype = inner;
		l3 = (void *)(vh + 1);
	}

	/* 5. ARP structural checks — L2Verdict::FrameDrop's "malformed ARP" + "sender-mac != eth-src"
	 * cases, mirroring dpi::ArpObs::is_malformed / eth_mismatch exactly. Deliberately does NOT
	 * cover binding_flip_flop / gratuitous_flood — see this file's top doc comment. */
	if (ethertype == ETH_P_ARP) {
		struct arp_fixed_hdr *arp = l3;
		if ((void *)(arp + 1) > data_end) {
			/* too short even for the fixed 8-byte ARP header — dpi::parse_arp_obs
			 * itself returns None here (not "malformed", simply "not recognized as
			 * ARP"), leaving it to the generic runt/oversized checks above, exactly
			 * as that function's own doc comment says. Fail-open, not a drop.
			 * TC_ACT_UNSPEC (not TC_ACT_OK) — see this file's top doc comment
			 * (2026-07-06 dead-ingress-mirror fix). */
			bump(LSTAT_PASS);
			return TC_ACT_UNSPEC;
		}
		__u16 htype = bpf_ntohs(arp->htype);
		__u16 ptype = bpf_ntohs(arp->ptype);
		if (htype != L2GUARD_ARP_HTYPE_ETHERNET || ptype != L2GUARD_ARP_PTYPE_IPV4 ||
		    arp->hlen != 6 || arp->plen != 4) {
			bump(LSTAT_DROP);
			return TC_ACT_SHOT; /* ArpObs::is_malformed() */
		}
		/* sender_mac sits immediately after the fixed 8-byte header (RFC 826 layout) —
		 * dpi::parse_arp_obs reads it at the same fixed offset once hlen/plen are
		 * confirmed standard. See this file's fail-open doc comment for why the
		 * `data_end` bound below is expected to always hold given the len>=60 gate
		 * already passed (14 eth + 8 arp-hdr + 6 sender_mac = 28 <= 60, or 32 <= 60 with
		 * one VLAN tag). */
		unsigned char *sender_mac = (unsigned char *)arp + sizeof(struct arp_fixed_hdr);
		if ((void *)(sender_mac + 6) > data_end) {
			/* TC_ACT_UNSPEC (not TC_ACT_OK) — see this file's top doc comment
			 * (2026-07-06 dead-ingress-mirror fix). */
			bump(LSTAT_PASS);
			return TC_ACT_UNSPEC;
		}
#pragma unroll
		for (int i = 0; i < 6; i++) {
			if (sender_mac[i] != eth->h_source[i]) {
				bump(LSTAT_DROP);
				return TC_ACT_SHOT; /* ArpObs::eth_mismatch() */
			}
		}
	}

	/* No structural anomaly found — final PASS. TC_ACT_UNSPEC (not TC_ACT_OK): fall through
	 * to the mirror filter instead of terminating the clsact pipeline (2026-07-06
	 * dead-ingress-mirror fix, see this file's top doc comment). */
	bump(LSTAT_PASS);
	return TC_ACT_UNSPEC;
}
