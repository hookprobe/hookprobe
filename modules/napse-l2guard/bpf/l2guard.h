/* l2guard.h — shared schema/constants between the CO-RE BPF program (l2guard.bpf.c) and the
 * native Rust loader (napse-l2guard). Mirrors modules/napse-quarantine/bpf/quarantine.h's
 * dependency-free-plain-C-types convention.
 *
 * THE SHARED-SEAM THIS FILE IS PART OF (read before touching a numeric constant here):
 * every value below MUST equal the corresponding constant `napse_loader::dpi`
 * (modules/napse-capture/loader/src/dpi.rs) exports, because THIS program enforces exactly the
 * conditions that Rust module's `frame_anomaly_reason`/`ArpObs::is_malformed`/`ArpObs::eth_mismatch`
 * detect (crates/hookprobe-manifest/src/l2_responder.rs's `L2Verdict::FrameDrop`). A mismatch here
 * is a live security bug: either the detector alerts on a frame this program lets through (silent
 * enforcement gap), or this program drops a frame the detector would call benign (an availability
 * regression on real traffic). `modules/napse-l2guard/loader/src/predicates.rs` is the test-time
 * proof that the two stay in lockstep — see that file's doc comment.
 */
#ifndef NAPSE_L2GUARD_H
#define NAPSE_L2GUARD_H

#ifndef __VMLINUX_H__
#include <stdint.h>
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#endif

/* == dpi::DEFAULT_MIN_FRAME_LEN / DEFAULT_MAX_FRAME_LEN ==================================== */
#define L2GUARD_MIN_FRAME_LEN 60u    /* dpi.rs: standard 64-byte wire minimum minus the 4-byte FCS */
#define L2GUARD_MAX_FRAME_LEN 1522u  /* dpi.rs: 1500 MTU + 14 eth hdr + 4 802.1Q tag + small margin */

/* == dpi::ETHERTYPE_VLAN / the reserved VLAN id frame_anomaly_reason flags ================== */
#define L2GUARD_ETH_P_8021Q   0x8100u
#define L2GUARD_VLAN_VID_RESERVED 0x0FFFu

/* == dpi::ARP_HTYPE_ETHERNET / ARP_PTYPE_IPV4 (RFC 826/5227 standard Ethernet/IPv4 ARP shape) == */
#define L2GUARD_ARP_HTYPE_ETHERNET 1u
#define L2GUARD_ARP_PTYPE_IPV4     0x0800u

/* l2guard_stats[] array indices — same cheap observability convention as quarantine.h's
 * QSTAT_PASS/QSTAT_DROP (this device ships no bpftool-by-hand workflow; the loader's own
 * `--status` reads this pinned map directly). */
#define LSTAT_PASS 0u
#define LSTAT_DROP 1u
#define LSTAT_MAX  2u

#endif /* NAPSE_L2GUARD_H */
