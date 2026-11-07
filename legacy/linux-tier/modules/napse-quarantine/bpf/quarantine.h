/* quarantine.h — shared schema between the CO-RE BPF program (quarantine.bpf.c) and the native
 * Rust loader (napse-quarantine). Kept dependency-free (plain C types), mirrors the pattern in
 * modules/napse-capture/bpf/napse_detect.h. See docs/adr/0009 (Ring-0 enforcement), the live
 * finding this responds to (2026-07-03 iPhone port-scan outran the reactive nft loop), and
 * docs/adr/0005 (why wlan0 is TC-bpf, never XDP).
 *
 * WHY A HASH MAP, NOT THE LPM-TRIE ADR 0009 SKETCHES: ADR 0009 Decision 4's LPM-trie +
 * atomic-double-buffer design is for the CLOUD ip_risk_scores feed — bulk CIDR blocks pushed down
 * from HYDRA/mesh, updated in big batches. The scan-responder's quarantine set is the opposite
 * shape: a handful of EXACT observed addresses (single /32s and single MACs), added and removed
 * one at a time as `scan_responder::reconcile_quarantine`/`sweep_quarantine` fire. A
 * BPF_MAP_TYPE_HASH keyed on the exact address is the right-sized structure for that — no CIDR
 * matching is needed here (the CIDR threat-feed blocklist already exists as an LPM-trie in
 * napse_detect.bpf.c and is a separate, complementary layer). Each single-key update/delete is
 * already atomic per the bpf() syscall semantics; the double-buffer machinery exists to avoid a
 * bulk *rebuild* stalling lookups mid-swap, which does not apply to a low-churn, small (<10k
 * entries typically single/low-digit) exact-match set. Revisit ONLY if this map must ever hold a
 * CIDR feed at that scale (documented as a follow-up, not a gap in this design).
 */
#ifndef NAPSE_QUARANTINE_H
#define NAPSE_QUARANTINE_H

#ifndef __VMLINUX_H__
#include <stdint.h>
typedef uint8_t __u8;
typedef uint32_t __u32;
typedef uint64_t __u64;
#endif

/* quarantine_stats[] array indices — cheap observability without a ringbuf/perf-event consumer
 * (the device has no bpftool to poll counters by hand; the loader's own `--status` reads these
 * pinned maps directly). */
#define QSTAT_PASS 0u
#define QSTAT_DROP 1u
#define QSTAT_MAX 2u

/* quarantine_ips key: source IPv4 in NETWORK byte order — exactly `iphdr->saddr` as read off the
 * wire, so the loader needs zero endian conversion to match what the kernel parses (it already
 * gets network-order bytes from `Ipv4Addr::octets()`/parse, packed MSB-first == network order). */

/* quarantine_macs key: the 48-bit source MAC packed MSB-first into the low 48 bits of a __u64
 * (BPF_MAP_TYPE_HASH needs a fixed-size key; a u64 keeps both the BPF-side packer and the Rust-side
 * packer a single, unambiguous shift-and-OR with no struct-padding ambiguity across compilers). */

/* quarantine_ips/quarantine_macs VALUE (2026-07-05 threat-model fix, HIGH #3 "ifindex-scoped
 * enforcement"): a bare hit counter used to let ANY entry drop on ANY attached interface — a
 * LAN-plane entry (added because of a LAN scan) could also fire on the WAN ifindex, and vice
 * versa, which the nft enforcement layer never allowed (it is `iifname`-scoped per source kind).
 * `ifindex` is the ONE ingress ifindex this entry is allowed to match on (the loader resolves the
 * LAN/WAN interfaces' ifindexes once at startup and binds each entry to the correct one via
 * `scan_responder::classify_source` — the SAME classification the nft rendering already uses).
 * `ifindex == 0` never matches a real interface (the kernel numbers ifindexes starting at 1, for
 * `lo`) — it is the safe "resolution failed" fallback, not a wildcard. Two `__u32` fields, no
 * padding (same size/alignment) — the Rust loader encodes/decodes this as 8 raw bytes
 * (`ifindex.to_ne_bytes() ++ hits.to_ne_bytes()`), matching this target's native struct layout. */
struct quarantine_val {
	__u32 ifindex;
	__u32 hits;
};

#endif /* NAPSE_QUARANTINE_H */
