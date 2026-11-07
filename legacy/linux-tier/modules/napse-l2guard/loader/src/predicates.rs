//! Anti-drift proof (`#[cfg(test)]` only — see Cargo.toml's `napse-loader` dev-dependency doc
//! comment): [`bpf_would_drop`] is a line-for-line Rust mirror of `bpf/l2guard.bpf.c`'s
//! `l2guard_ingress` drop decision. The compiled BPF bytecode itself can't be unit-tested on this
//! dev box (no CAP_BPF/root, no kernel+veth harness — see the module README's honesty section),
//! so this file is the strongest available proof that enforcement (the .bpf.c file) and detection
//! (`napse_loader::dpi::frame_anomaly_reason` / `ArpObs::is_malformed` / `ArpObs::eth_mismatch` —
//! the SAME functions `crates/hookprobe-manifest/src/l2_responder.rs`'s `L2Verdict::FrameDrop`
//! verdict is ultimately driven by, one layer upstream via `napse_loader::l2guard`) stay in
//! lockstep: every branch below cross-references the exact block in `l2guard.bpf.c` it mirrors,
//! and every test in `mod tests` asserts equality against `dpi`'s ACTUAL production predicates —
//! never against a second hand-copied definition. If either side (the `.c` file or this `.rs`
//! mirror) drifts, the corresponding test fails to compile-pass, which is the whole point of this
//! file's existence.
//!
//! NOT covered here (matches `l2guard.bpf.c`'s explicit, documented scope): ARP binding
//! flip-flop / gratuitous-ARP flood. Both need cross-packet HISTORY (a per-IP binding table / a
//! per-source rate window) — a genuinely different, stateful engineering problem from "is this
//! ONE frame structurally bad" that this stateless mirror (and the BPF program it mirrors)
//! answers. They remain alert-only, mitigated instead by `l2_responder::render_storm_control`'s
//! real nft rate-limiting (gratuitous_flood) or plain alerting (binding_flip_flop).

use napse_loader::dpi;

/// Numeric constants this crate's BPF object bakes in (`bpf/l2guard.h`), duplicated here as
/// literal `pub const`s — nothing on the Rust side parses the `.h` file, so
/// [`tests::l2guard_h_constants_match_dpi_rs_exactly`] is what keeps a human's edit to ONE of the
/// three copies (`.h`, here, `dpi.rs`) from silently drifting from the other two.
pub const L2GUARD_MIN_FRAME_LEN: usize = 60;
pub const L2GUARD_MAX_FRAME_LEN: usize = 1522;
pub const L2GUARD_ARP_HTYPE_ETHERNET: u16 = 1;
pub const L2GUARD_ARP_PTYPE_IPV4: u16 = 0x0800;
pub const L2GUARD_ETH_P_8021Q: u16 = 0x8100;
pub const L2GUARD_VLAN_VID_RESERVED: u16 = 0x0FFF;

/// Mirrors `is_well_formed_ipv4_or_arp` (l2guard.bpf.c) via the SAME production parsers
/// (`dpi::parse_tcp_obs`/`parse_udp_obs`/`parse_icmp_obs`/`parse_arp_obs`) rather than re-parsing
/// bytes a second time — this is the 2026-07-07 PROTOCOL-AWARE runt-exemption check (there is no
/// longer a single flat length floor on either side of the shared seam, see `l2guard.bpf.c`'s top
/// doc comment and `dpi::frame_anomaly_reason_local`'s identical doc section for the full story).
/// `true` iff the frame is FULLY, structurally a complete ARP packet, or a complete IPv4
/// TCP/UDP/ICMP packet, at its own protocol-correct minimum length — never a hand-picked number.
fn is_structurally_complete_arp_or_ipv4(frame: &[u8]) -> bool {
    dpi::parse_tcp_obs(frame).is_some()
        || dpi::parse_udp_obs(frame).is_some()
        || dpi::parse_icmp_obs(frame).is_some()
        || dpi::parse_arp_obs(frame).is_some_and(|a| !a.is_malformed())
}

/// Mirrors `l2guard_ingress`'s frame-level checks (that file's doc-comment items 1-4: runt,
/// oversized, multicast-bit source MAC, VLAN-tag anomalies) — the half that does NOT need ARP.
/// `true` iff the BPF program would return `TC_ACT_SHOT` on this half of its logic alone.
fn frame_level_would_drop(frame: &[u8]) -> bool {
    // l2guard.bpf.c: `if (len < 14) { ...SHOT... }` — 2026-07-07 fix: a frame shorter than a bare
    // Ethernet header can never be classified as anything at all and is ALWAYS a genuine drop
    // (never fail-open — this is a frame that doesn't even have 14 bytes ON THE WIRE, unlike the
    // verifier-provable-window fail-open branches elsewhere in that file). This REPLACES the
    // pre-2026-07-07 mirror's `return false` here, which was itself a latent drift bug: this file
    // never exercised a frame in the (already-shipped) 54-59-byte exemption window, so the fact
    // that this function used to treat EVERY frame `< L2GUARD_MIN_FRAME_LEN` as an unconditional
    // drop (see the removed `if !(MIN..=MAX).contains(&len) { return true; }` line) silently
    // disagreed with `l2guard.bpf.c`'s EDR #7 exemption the whole time — no test ever caught it
    // because none constructed a frame in that window. Fixed here as part of the 2026-07-07 pass.
    let len = frame.len();
    if len < 14 {
        return true;
    }
    // l2guard.bpf.c: `if (len < L2GUARD_MIN_FRAME_LEN) { if (is_well_formed_ipv4_or_arp(...)) ...
    // else ...SHOT... }` — 2026-07-07 fix: PROTOCOL-AWARE structural check, no flat exemption
    // floor (see `is_structurally_complete_arp_or_ipv4` above).
    if len < L2GUARD_MIN_FRAME_LEN {
        return !is_structurally_complete_arp_or_ipv4(frame);
    }
    if len > L2GUARD_MAX_FRAME_LEN {
        return true;
    }
    // l2guard.bpf.c: `if (eth->h_source[0] & 0x01) { ...drop... }` — I/G bit of the source MAC.
    if frame[6] & 0x01 != 0 {
        return true;
    }
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    if ethertype == L2GUARD_ETH_P_8021Q {
        // l2guard.bpf.c: `if ((void *)(vh + 1) > data_end) { ...drop, deterministic anomaly... }`
        if frame.len() < 18 {
            return true;
        }
        let inner = u16::from_be_bytes([frame[16], frame[17]]);
        if inner == L2GUARD_ETH_P_8021Q {
            return true; // double/stacked 802.1Q tag (QinQ)
        }
        let vid = u16::from_be_bytes([frame[14], frame[15]]) & 0x0FFF;
        if vid == L2GUARD_VLAN_VID_RESERVED {
            return true;
        }
    }
    false
}

/// Mirrors `l2guard_ingress`'s ARP-specific checks (that file's doc-comment item 5) via the SAME
/// production parser (`dpi::parse_arp_obs`) rather than re-parsing bytes a second time — this
/// function's job is only to assert "if `dpi` calls it malformed/mismatched, the BPF program's
/// logic (which reads the identical fields at the identical offsets, per `l2guard.bpf.c`'s
/// `struct arp_fixed_hdr` + fixed `sender_mac` offset) would too". `None` if the frame isn't ARP
/// at all (not this check's concern — mirrors `l2guard.bpf.c`'s `ethertype == ETH_P_ARP` guard).
fn arp_would_drop(frame: &[u8]) -> Option<bool> {
    let obs = dpi::parse_arp_obs(frame)?;
    Some(obs.is_malformed() || obs.eth_mismatch())
}

/// The FULL mirror of `l2guard_ingress`: what the compiled BPF program would decide for this
/// frame (`true` = `TC_ACT_SHOT`, `false` = `TC_ACT_OK`).
pub fn bpf_would_drop(frame: &[u8]) -> bool {
    if frame_level_would_drop(frame) {
        return true;
    }
    arp_would_drop(frame).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l2guard_h_constants_match_dpi_rs_exactly() {
        assert_eq!(L2GUARD_MIN_FRAME_LEN, dpi::DEFAULT_MIN_FRAME_LEN, "bpf/l2guard.h drifted from dpi::DEFAULT_MIN_FRAME_LEN");
        assert_eq!(L2GUARD_MAX_FRAME_LEN, dpi::DEFAULT_MAX_FRAME_LEN, "bpf/l2guard.h drifted from dpi::DEFAULT_MAX_FRAME_LEN");
        assert_eq!(L2GUARD_ARP_HTYPE_ETHERNET, dpi::ARP_HTYPE_ETHERNET, "bpf/l2guard.h drifted from dpi::ARP_HTYPE_ETHERNET");
        assert_eq!(L2GUARD_ARP_PTYPE_IPV4, dpi::ARP_PTYPE_IPV4, "bpf/l2guard.h drifted from dpi::ARP_PTYPE_IPV4");
        assert_eq!(L2GUARD_ETH_P_8021Q, dpi::ETHERTYPE_VLAN, "bpf/l2guard.h drifted from dpi::ETHERTYPE_VLAN");
    }

    // ---- local, independent frame builders (deliberately NOT shared with dpi.rs's own test mod
    // — this file must never accidentally inherit a bug from the very helpers it cross-checks) --

    const NORMAL_SRC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    const BCAST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

    fn eth_frame(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    fn pad_to(mut f: Vec<u8>, len: usize) -> Vec<u8> {
        while f.len() < len {
            f.push(0);
        }
        f
    }

    fn arp_frame(
        eth_src: [u8; 6],
        sender_mac: [u8; 6],
        sender_ip: [u8; 4],
        target_mac: [u8; 6],
        target_ip: [u8; 4],
        opcode: u16,
    ) -> Vec<u8> {
        let mut arp = Vec::new();
        arp.extend_from_slice(&1u16.to_be_bytes()); // htype ethernet
        arp.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype ipv4
        arp.push(6); // hlen
        arp.push(4); // plen
        arp.extend_from_slice(&opcode.to_be_bytes());
        arp.extend_from_slice(&sender_mac);
        arp.extend_from_slice(&sender_ip);
        arp.extend_from_slice(&target_mac);
        arp.extend_from_slice(&target_ip);
        pad_to(eth_frame(BCAST, eth_src, 0x0806, &arp), 60)
    }

    /// Same shape as [`arp_frame`], deliberately NOT padded to 60 — a real ARP packet on the wire
    /// (via a tc-mirror capture with no hardware wire-padding) is exactly 42 bytes, never 60. Used
    /// by the 2026-07-07 protocol-aware runt-floor regression tests below.
    fn arp_frame_exact(
        eth_src: [u8; 6],
        sender_mac: [u8; 6],
        sender_ip: [u8; 4],
        target_mac: [u8; 6],
        target_ip: [u8; 4],
        opcode: u16,
    ) -> Vec<u8> {
        let mut arp = Vec::new();
        arp.extend_from_slice(&1u16.to_be_bytes()); // htype ethernet
        arp.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype ipv4
        arp.push(6); // hlen
        arp.push(4); // plen
        arp.extend_from_slice(&opcode.to_be_bytes());
        arp.extend_from_slice(&sender_mac);
        arp.extend_from_slice(&sender_ip);
        arp.extend_from_slice(&target_mac);
        arp.extend_from_slice(&target_ip);
        eth_frame(BCAST, eth_src, 0x0806, &arp) // NOT padded — 14 + 28 = 42 bytes exactly
    }

    /// A bare, unpadded IPv4/UDP datagram: 14 eth + 20 ipv4 (no options) + 8 udp (no payload) = 42
    /// bytes exactly — the UDP analogue of `arp_frame_exact`'s 42-byte ARP case.
    fn udp_frame_exact(src_mac: [u8; 6], src_ip: [u8; 4], dst_ip: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45; // v4, ihl 5
        ip[9] = 17; // UDP
        ip[12..16].copy_from_slice(&src_ip);
        ip[16..20].copy_from_slice(&dst_ip);
        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&sport.to_be_bytes());
        udp[2..4].copy_from_slice(&dport.to_be_bytes());
        let mut payload = ip;
        payload.extend_from_slice(&udp);
        eth_frame(BCAST, src_mac, 0x0800, &payload)
    }

    /// The core parity assertion, reused by every case below: the BPF mirror and the REAL
    /// userspace detector (frame_anomaly_reason OR the ARP predicates, whichever applies) must
    /// agree on every sample frame.
    fn assert_parity(frame: &[u8]) {
        let eth_vlan_anomaly = dpi::frame_anomaly_reason(frame, dpi::DEFAULT_MIN_FRAME_LEN, dpi::DEFAULT_MAX_FRAME_LEN).is_some();
        let arp_anomaly = dpi::parse_arp_obs(frame).map(|o| o.is_malformed() || o.eth_mismatch()).unwrap_or(false);
        let detector_says_drop = eth_vlan_anomaly || arp_anomaly;
        assert_eq!(
            bpf_would_drop(frame),
            detector_says_drop,
            "BPF mirror and userspace detector DISAGREE on this frame — exactly the drift bug \
             this file exists to catch (frame: {frame:02x?})"
        );
    }

    #[test]
    fn benign_baseline_frame_passes_on_both_sides() {
        let f = pad_to(eth_frame([1, 2, 3, 4, 5, 6], NORMAL_SRC, 0x0800, &[0u8; 20]), 64);
        assert_parity(&f);
        assert!(!bpf_would_drop(&f));
    }

    #[test]
    fn runt_frame_drops_on_both_sides() {
        let f = eth_frame([1, 2, 3, 4, 5, 6], NORMAL_SRC, 0x0800, &[]); // 14 bytes, below 60
        assert_parity(&f);
        assert!(bpf_would_drop(&f));
    }

    #[test]
    fn oversized_frame_drops_on_both_sides() {
        let f = pad_to(eth_frame([1, 2, 3, 4, 5, 6], NORMAL_SRC, 0x0800, &[]), 2000);
        assert_parity(&f);
        assert!(bpf_would_drop(&f));
    }

    #[test]
    fn multicast_source_mac_drops_on_both_sides() {
        let bogus_src = [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]; // multicast bit set
        let f = pad_to(eth_frame([1, 2, 3, 4, 5, 6], bogus_src, 0x0800, &[]), 64);
        assert_parity(&f);
        assert!(bpf_would_drop(&f));
    }

    #[test]
    fn double_tagged_vlan_frame_drops_on_both_sides() {
        let mut f = Vec::new();
        f.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        f.extend_from_slice(&NORMAL_SRC);
        f.extend_from_slice(&dpi::ETHERTYPE_VLAN.to_be_bytes());
        f.extend_from_slice(&[0x00, 0x0a]);
        f.extend_from_slice(&dpi::ETHERTYPE_VLAN.to_be_bytes()); // stacked tag — QinQ
        f.extend_from_slice(&[0x00, 0x0b]);
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        let f = pad_to(f, 64);
        assert_parity(&f);
        assert!(bpf_would_drop(&f));
    }

    #[test]
    fn short_declared_vlan_tag_is_caught_by_the_runt_gate_not_the_truncated_tag_branch() {
        // A genuinely truncated 802.1Q tag (declared but < 4 bytes present) can ONLY occur below
        // the 60-byte minimum frame length (14 eth hdr + 4 tag = 18 << 60) — so under the fixed
        // `L2GUARD_MIN_FRAME_LEN`/`dpi::DEFAULT_MIN_FRAME_LEN` floor BOTH sides always catch this
        // shape via the earlier runt check, never via the VLAN-truncated-tag branch itself. That
        // branch exists (in both `l2guard.bpf.c` and `dpi::frame_anomaly_reason`) purely as a
        // verifier-safety / defensive-completeness net for a hypothetical smaller configured
        // minimum — `dpi.rs`'s own test (`frame_anomaly_reason_never_panics_on_a_truncated_vlan_tag`)
        // proves it only by passing a non-default `min_len: 0`, exactly the same "unreachable under
        // the shipped default" honesty this test documents rather than hides.
        let mut f = vec![0u8; 16];
        f[0..6].copy_from_slice(&BCAST);
        f[6..12].copy_from_slice(&NORMAL_SRC);
        f[12..14].copy_from_slice(&dpi::ETHERTYPE_VLAN.to_be_bytes());
        assert!(f.len() < L2GUARD_MIN_FRAME_LEN, "must be short enough to hit the runt gate first");
        assert_parity(&f);
        assert!(bpf_would_drop(&f), "still dropped — via the runt check, not the (unreachable-here) truncated-tag branch");
    }

    #[test]
    fn reserved_vlan_id_drops_on_both_sides() {
        let mut f = Vec::new();
        f.extend_from_slice(&BCAST);
        f.extend_from_slice(&NORMAL_SRC);
        f.extend_from_slice(&dpi::ETHERTYPE_VLAN.to_be_bytes());
        f.extend_from_slice(&0x0FFFu16.to_be_bytes()); // reserved vlan id
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        let f = pad_to(f, 64);
        assert_parity(&f);
        assert!(bpf_would_drop(&f));
    }

    #[test]
    fn well_formed_arp_request_passes_on_both_sides() {
        let f = arp_frame(NORMAL_SRC, NORMAL_SRC, [10, 0, 0, 5], [0; 6], [10, 0, 0, 1], 1);
        assert_parity(&f);
        assert!(!bpf_would_drop(&f));
    }

    /// A real, UNPADDED ARP frame — exactly 42 bytes (14 eth + 28-byte ARP body), no trailing
    /// padding at all — the SAME shape the confirmed live pentest finding hit (an iPhone's ARP
    /// request/reply on `HookProbe`, dropped as "runt" before the 2026-07-07 protocol-aware
    /// runt-floor fix, because the OLD flat 54-byte exemption floor never covered a 42-byte ARP
    /// packet). Uses a locally-administered (iOS-randomized-style) source MAC deliberately, so
    /// this test doubles as the multicast-bit regression guard for that MAC shape too.
    #[test]
    fn bare_42_byte_arp_frame_passes_on_both_sides_ios_randomized_mac() {
        let ios_random_mac = [0xaa, 0xff, 0x48, 0x06, 0xa6, 0x2d];
        assert_eq!(ios_random_mac[0] & 0x01, 0, "sanity: I/G bit clear (unicast)");
        let f = arp_frame_exact(ios_random_mac, ios_random_mac, [192, 168, 1, 50], [0; 6], [192, 168, 1, 1], 1);
        assert_eq!(f.len(), 42, "sanity: a real, unpadded ARP frame is exactly 42 bytes");
        assert_parity(&f);
        assert!(!bpf_would_drop(&f), "a well-formed, unpadded 42-byte ARP frame must pass — the exact live false positive");
    }

    /// One byte short of a complete ARP body (41 of 42 bytes) — must still drop on BOTH sides; the
    /// protocol-aware exemption is length-AND-structure, never "any ARP-shaped prefix passes".
    /// This is also the regression guard for the `is_well_formed_ipv4_or_arp` BPF fix (the ARP
    /// bounds check used to only cover through `sender_mac`, 14 bytes short of the true 28-byte
    /// body — see that function's 2026-07-07 doc comment in `l2guard.bpf.c`).
    #[test]
    fn truncated_41_byte_arp_frame_still_drops_on_both_sides() {
        let full = arp_frame_exact(NORMAL_SRC, NORMAL_SRC, [10, 0, 0, 5], [0; 6], [10, 0, 0, 1], 1);
        assert_eq!(full.len(), 42);
        let truncated = &full[..41];
        assert_parity(truncated);
        assert!(bpf_would_drop(truncated), "a genuinely truncated 41-byte ARP body must still be dropped");
    }

    /// The UDP analogue of the ARP case above: 14 eth + 20 ipv4 (no opts) + 8 udp (no payload) =
    /// 42 bytes exactly — legitimately shorter than the old 54-byte TCP-shaped exemption floor.
    #[test]
    fn bare_42_byte_udp_datagram_passes_on_both_sides() {
        let f = udp_frame_exact(NORMAL_SRC, [10, 0, 0, 5], [10, 0, 0, 1], 51000, 53);
        assert_eq!(f.len(), 42, "sanity: a bare UDP datagram with zero payload is exactly 42 bytes");
        assert_parity(&f);
        assert!(!bpf_would_drop(&f));
    }

    #[test]
    fn malformed_arp_header_drops_on_both_sides() {
        let mut arp = Vec::new();
        arp.extend_from_slice(&7u16.to_be_bytes()); // bogus htype
        arp.extend_from_slice(&0x0800u16.to_be_bytes());
        arp.push(6);
        arp.push(4);
        arp.extend_from_slice(&1u16.to_be_bytes());
        arp.extend_from_slice(&[0u8; 20]);
        let f = pad_to(eth_frame(BCAST, NORMAL_SRC, 0x0806, &arp), 60);
        assert_parity(&f);
        assert!(bpf_would_drop(&f));
    }

    #[test]
    fn arp_sender_mac_eth_src_mismatch_drops_on_both_sides() {
        let attacker_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        // Ethernet frame is sent BY attacker_mac; the ARP payload claims to be NORMAL_SRC.
        let f = arp_frame(attacker_mac, NORMAL_SRC, [10, 0, 0, 5], [0; 6], [10, 0, 0, 1], 2);
        assert_parity(&f);
        assert!(bpf_would_drop(&f));
    }

    #[test]
    fn gratuitous_arp_alone_does_not_drop_neither_side_treats_it_as_frame_level_malformed() {
        // sender == target (gratuitous) but otherwise well-formed and eth-consistent — this
        // program deliberately does NOT enforce the gratuitous-flood condition (stateful, see this
        // file's top doc comment); a single gratuitous ARP must pass on both sides.
        let f = arp_frame(NORMAL_SRC, NORMAL_SRC, [10, 0, 0, 5], [0; 6], [10, 0, 0, 5], 1);
        assert_parity(&f);
        assert!(!bpf_would_drop(&f));
    }

    #[test]
    fn non_arp_non_vlan_traffic_of_every_length_in_range_never_false_positives() {
        for len in [60usize, 64, 128, 512, 1500, 1522] {
            let f = pad_to(eth_frame([9, 9, 9, 9, 9, 9], NORMAL_SRC, 0x0800, &[]), len);
            assert_parity(&f);
            assert!(!bpf_would_drop(&f), "benign IPv4 frame of length {len} must never be dropped");
        }
    }
}
