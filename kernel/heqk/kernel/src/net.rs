//! Packet parser for the IDS/IPS datapath — Ethernet → IPv4 → TCP/UDP.
//!
//! This is the layer that turns a raw, attacker-controlled frame into a
//! validated `PacketMeta` (protocol + ports + L4 offset). Correctness here is a
//! security property: the detection rules key off these offsets, and a hostile
//! sender will craft truncated / malformed / lying-length frames to make a naive
//! parser read out of bounds or mislocate a field. Every access goes through
//! slice `.get()`, so any short/malformed frame yields `None` — never an OOB
//! read, never a panic. Pure logic (no `unsafe`), so it is host-unit-testable.
//!
//! (The prior threat rule read bytes 0..2 of the frame as the "dst port" — those
//! are actually the first two octets of the destination MAC. This module locates
//! the real L4 dst port, ~34+ bytes in after Ethernet + IP.)

pub const ETH_HLEN: usize = 14;
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_VLAN: u16 = 0x8100; // 802.1Q
pub const ETHERTYPE_QINQ: u16 = 0x88a8; // 802.1ad (stacked/service tag)
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const MAX_VLAN_TAGS: usize = 3; // bound stacked-tag unwrap
const MAX_V6_EXT: usize = 8; // bound IPv6 extension-header walk

/// Validated view of a parsed frame. All offsets are within the frame length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketMeta {
    pub ethertype: u16,
    pub ip_proto: u8, // 6=TCP, 17=UDP, else 0 (no L4 ports)
    pub l4_off: usize, // byte offset of the L4 header within the frame (0 if none)
    pub src_port: u16,
    pub dst_port: u16,
    pub payload_off: usize, // start of L4 payload (== frame.len() if none)
}

impl PacketMeta {
    /// True if the frame carries a TCP/UDP header with ports located.
    pub fn has_l4_ports(&self) -> bool {
        self.l4_off != 0 && (self.ip_proto == IPPROTO_TCP || self.ip_proto == IPPROTO_UDP)
    }
}

/// DET-11: the IPv4 source address (host-order u32) of a VLAN-NORMALIZED Ethernet
/// frame, for SIEM attribution on a detection. 0 if the frame is not IPv4 or too
/// short. Callers pass the normalized frame (IP starts at offset 14).
pub fn eth_ipv4_src(frame: &[u8]) -> u32 {
    if frame.len() < 30 {
        return 0;
    }
    let et = ((frame[12] as u16) << 8) | frame[13] as u16;
    if et != ETHERTYPE_IPV4 {
        return 0; // ARP / IPv6 / other — no IPv4 source to attribute
    }
    // IPv4 source address is 4 bytes at IP-header offset 12 (= frame 14+12 = 26).
    ((frame[26] as u32) << 24)
        | ((frame[27] as u32) << 16)
        | ((frame[28] as u32) << 8)
        | frame[29] as u32
}

/// M4.4 — the IPv4 DESTINATION address (host-order u32) of an Ethernet frame,
/// walking up to `MAX_VLAN_TAGS` 802.1Q/QinQ tags exactly like `parse`. `None` if
/// the frame is not IPv4 or is too short to hold the dst field. Used ONLY by the
/// WAN-egress kill-switch (`edge.rs`) to classify a well-formed egress frame's
/// destination scope. The kill-switch is consulted by `netq::tx_drain` AFTER
/// `packet::verdict` has already PASSed the frame, so a malformed/truncated IPv4
/// datagram is dropped by the IPS before this can ever see it (fail-closed upstream).
pub fn eth_ipv4_dst(frame: &[u8]) -> Option<u32> {
    let mut et = be16(frame, 12)?; // also checks len >= 14
    let mut l3_off = ETH_HLEN;
    let mut tags = 0;
    while (et == ETHERTYPE_VLAN || et == ETHERTYPE_QINQ) && tags < MAX_VLAN_TAGS {
        et = be16(frame, l3_off + 2)?; // inner ethertype after the 4-byte tag (2B TCI)
        l3_off += 4;
        tags += 1;
    }
    if et != ETHERTYPE_IPV4 {
        return None; // ARP / IPv6 / still-tagged — no IPv4 dst to classify
    }
    // IPv4 destination address is 4 bytes at IP-header offset 16.
    let d = l3_off + 16;
    if d + 4 > frame.len() {
        return None;
    }
    Some(((frame[d] as u32) << 24)
        | ((frame[d + 1] as u32) << 16)
        | ((frame[d + 2] as u32) << 8)
        | frame[d + 3] as u32)
}

/// M4.4 (IPv6 kill-switch fix) — does this frame carry an IPv6 datagram? Walks up to
/// `MAX_VLAN_TAGS` 802.1Q/QinQ tags exactly like `eth_ipv4_dst`, so a tagged IPv6
/// frame is not mistaken for a non-IP L2 frame. Used by the WAN-egress kill-switch to
/// distinguish "genuine link-local L2 mgmt (ARP/…)" — safe to pass — from "IPv6"
/// (which may be a plaintext WAN leak and must be scope-classified, fail-closed).
pub fn frame_is_ipv6(frame: &[u8]) -> bool {
    let mut et = match be16(frame, 12) {
        Some(v) => v,
        None => return false,
    };
    let mut off = ETH_HLEN;
    let mut tags = 0;
    while (et == ETHERTYPE_VLAN || et == ETHERTYPE_QINQ) && tags < MAX_VLAN_TAGS {
        et = match be16(frame, off + 2) {
            Some(v) => v,
            None => return false,
        };
        off += 4;
        tags += 1;
    }
    et == ETHERTYPE_IPV6
}

/// M4.4 (IPv6 kill-switch fix) — the IPv6 DESTINATION address (16 raw bytes,
/// network order) of an Ethernet frame, walking VLAN tags like `eth_ipv4_dst`.
/// `None` if the frame is not IPv6 or is too short to hold the dst field. Used ONLY
/// by the WAN-egress kill-switch (`edge.rs`) so an enrolled device with its tunnel
/// down cannot leak plaintext IPv6 to the internet. The kill-switch runs AFTER
/// `packet::verdict` has PASSed the frame, so a truncated/malformed IPv6 datagram is
/// already dropped by the IPS before this can see it (fail-closed upstream).
pub fn eth_ipv6_dst(frame: &[u8]) -> Option<[u8; 16]> {
    let mut et = be16(frame, 12)?;
    let mut l3_off = ETH_HLEN;
    let mut tags = 0;
    while (et == ETHERTYPE_VLAN || et == ETHERTYPE_QINQ) && tags < MAX_VLAN_TAGS {
        et = be16(frame, l3_off + 2)?;
        l3_off += 4;
        tags += 1;
    }
    if et != ETHERTYPE_IPV6 {
        return None;
    }
    // IPv6 destination address is 16 bytes at fixed-header offset 24.
    let d = l3_off + 24;
    let slice = frame.get(d..d + 16)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(slice);
    Some(out)
}

/// ICMPv6 (IPv6 next-header 58) and the Router Advertisement message type (134),
/// for the RA-guard tier (RFC 6105 / matrix rows L4 legit + A9 rogue).
pub const IPPROTO_ICMPV6: u8 = 58;
pub const ICMPV6_ROUTER_ADVERT: u8 = 134;

/// RA-guard predicate (RFC 6105): is this frame an ICMPv6 **Router Advertisement**
/// (type 134)? Walks VLAN tags → IPv6 → the bounded extension-header chain (reusing
/// `parse_ipv6`), then reads the ICMPv6 message type. A RA is legitimate ONLY from a
/// designated router/uplink port; on a client/access port it is a rogue gateway-hijack
/// the RA-guard verdict drops (A9), while a legit downstream-router RA on an uplink is
/// Observed + accepted (L4). Returns `false` (no RA verdict — fail-safe) for any
/// non-IPv6 / non-ICMPv6 / truncated frame, so a normal packet is never mis-flagged.
pub fn is_icmpv6_ra(frame: &[u8]) -> bool {
    let l3 = match ipv6_l3_offset(frame) {
        Some(o) => o,
        None => return false,
    };
    match parse_ipv6(frame, l3) {
        // parse_ipv6 returns the ICMPv6 header offset as the "L4" offset; the message
        // type is its first byte.
        Some((IPPROTO_ICMPV6, icmp_off, _end)) => {
            frame.get(icmp_off).copied() == Some(ICMPV6_ROUTER_ADVERT)
        }
        _ => false,
    }
}

/// The IPv6 base-header offset of `frame` after unwrapping up to `MAX_VLAN_TAGS`
/// tags, or `None` if the frame is not IPv6 (or is truncated in the tag stack).
fn ipv6_l3_offset(frame: &[u8]) -> Option<usize> {
    let mut et = be16(frame, 12)?;
    let mut l3 = ETH_HLEN;
    let mut tags = 0;
    while (et == ETHERTYPE_VLAN || et == ETHERTYPE_QINQ) && tags < MAX_VLAN_TAGS {
        et = be16(frame, l3 + 2)?;
        l3 += 4;
        tags += 1;
    }
    if et == ETHERTYPE_IPV6 {
        Some(l3)
    } else {
        None
    }
}

/// A9-7 (security-auditor ruling, heqk-detection-parity.md §5): an IPv6 frame whose
/// extension-header chain `parse_ipv6` REFUSES (over `MAX_V6_EXT` headers, a chain
/// running past the datagram, an inconsistent payload length). Such a frame is
/// invisible to every L4 predicate — an RA behind a padded Hop-by-Hop chain would
/// silently bypass the RA-guard — so the caller makes it VISIBLE as an observe-level
/// finding. Never a drop: legitimate extension-header users exist, and turning
/// unparseable into FrameDrop would be a new legit-drop cannon.
pub fn ipv6_unparseable(frame: &[u8]) -> bool {
    match ipv6_l3_offset(frame) {
        Some(l3) => parse_ipv6(frame, l3).is_none(),
        None => false,
    }
}

/// Maximum on-wire Ethernet frame size (802.1Q-tagged): 1518 + 4 = 1522. A frame
/// past this from an unrecognized source is a structural anomaly (F7). Mirrors
/// Linux `dpi::DEFAULT_MAX_FRAME_LEN`.
pub const MAX_FRAME_LEN: usize = 1522;

/// M2.1 — STRUCTURAL frame anomaly (F6/F7/F8): a fact about WHAT THE FRAME IS, never
/// who sent it, so a `true` here routes to a `MalformedFrame` FrameDrop that the
/// `Allowlisted` floor correctly does NOT exempt. Single-frame, stateless. Mirrors
/// the Linux `dpi::frame_anomaly_reason_local` rows exercised by
/// `separation_matrix_frames.rs`:
///   F6 — the SOURCE MAC has the I/G (multicast/broadcast) bit set. IEEE 802.3
///        forbids a group-bit source; a locally-administered *unicast* MAC (U/L bit
///        0x02 set, I/G bit 0x01 CLEAR — e.g. an iOS-randomized MAC) is NOT flagged.
///   F7 — the frame exceeds `MAX_FRAME_LEN` (1522) — oversize/jumbo from an
///        unrecognized source.
///   F8 — the frame carries ≥2 stacked 802.1Q/QinQ tags — the VLAN-hopping ambiguity
///        a single-tag topology must never accept.
/// A too-short frame (<14) is left to `parse` (→ `None` → fail-closed) as before.
pub fn structural_anomaly(frame: &[u8]) -> bool {
    if frame.len() < ETH_HLEN {
        return false; // truncation is handled by `parse` fail-closed, not here
    }
    // F6 — source MAC I/G bit (LSB of the first source octet, at offset 6).
    if frame[6] & 0x01 != 0 {
        return true;
    }
    // F7 — oversize.
    if frame.len() > MAX_FRAME_LEN {
        return true;
    }
    // F8 — count stacked VLAN tags; ≥2 (QinQ) is the anomaly.
    let mut et = match be16(frame, 12) {
        Some(e) => e,
        None => return false,
    };
    let mut off = ETH_HLEN;
    let mut tags = 0usize;
    while et == ETHERTYPE_VLAN || et == ETHERTYPE_QINQ {
        tags += 1;
        if tags >= 2 {
            return true; // double/stacked tag
        }
        et = match be16(frame, off + 2) {
            Some(e) => e,
            None => break, // truncated tag — parse fail-closes it later
        };
        off += 4;
        if tags > MAX_VLAN_TAGS {
            break;
        }
    }
    false
}

/// The Ethernet destination MAC is broadcast (all-ones) or multicast (dst I/G bit
/// set). Used by the broadcast-storm detector to decide what to count.
#[inline]
pub fn dst_is_bcast_or_mcast(frame: &[u8]) -> bool {
    frame.len() >= 6 && (frame[0] & 0x01 != 0)
}

#[inline]
fn be16(b: &[u8], off: usize) -> Option<u16> {
    Some(((*b.get(off)? as u16) << 8) | (*b.get(off + 1)? as u16))
}

/// Parse an Ethernet/IPv4/L4 frame. Returns `None` on any truncation or
/// inconsistency (unknown L3, bad IHL, header claims to run past the frame, …).
/// A `Some` guarantees every field it reports is in-bounds of `frame`.
pub fn parse(frame: &[u8]) -> Option<PacketMeta> {
    // --- Ethernet ---
    let mut et = be16(frame, 12)?; // also checks len >= 14
    let mut l3_off = ETH_HLEN;
    // Unwrap up to MAX_VLAN_TAGS stacked 802.1Q / 802.1ad (QinQ) tags. A single
    // tag is the common case; stacking must not let an L4 threat slip the rule.
    let mut tags = 0;
    while (et == ETHERTYPE_VLAN || et == ETHERTYPE_QINQ) && tags < MAX_VLAN_TAGS {
        et = be16(frame, l3_off + 2)?; // inner ethertype after the 4-byte tag (2B TCI)
        l3_off += 4;
        tags += 1;
    }
    // DET-3: fail CLOSED if the frame is STILL VLAN-tagged after the cap. Otherwise an
    // attacker buries an L4 threat (e.g. TCP/4444) under >MAX_VLAN_TAGS tags, the loop
    // stops with `et` still VLAN, and the `_ => Some(meta)` arm below PASSes it with
    // ip_proto=0 — skipping the entire L4/scan corpus. A legitimately >3-stacked frame
    // is pathological; dropping it is the correct sensor posture. `None` => classify
    // fail-closes to DROP.
    if et == ETHERTYPE_VLAN || et == ETHERTYPE_QINQ {
        return None;
    }

    let mut meta = PacketMeta {
        ethertype: et,
        ip_proto: 0,
        l4_off: 0,
        src_port: 0,
        dst_port: 0,
        payload_off: frame.len(),
    };

    // Locate the L4 header for IPv4 and IPv6 alike; everything else (ARP, still-
    // tagged after the cap, unknown L3) carries no port threat and PASSes.
    let (ip_proto, l4_off, ip_end) = match et {
        ETHERTYPE_IPV4 => parse_ipv4(frame, l3_off)?,
        ETHERTYPE_IPV6 => parse_ipv6(frame, l3_off)?,
        _ => return Some(meta),
    };
    meta.ip_proto = ip_proto;
    meta.payload_off = ip_end;

    // --- TCP / UDP ports (both put src@0, dst@2) ---
    if ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP {
        // Need at least 4 bytes of L4 header, and they must be within the datagram.
        if l4_off + 4 > ip_end {
            return None;
        }
        meta.src_port = be16(frame, l4_off)?;
        meta.dst_port = be16(frame, l4_off + 2)?;
        meta.l4_off = l4_off;
    }
    Some(meta)
}

/// IPv4 header at `l3_off` → (proto, L4 offset, datagram end). `None` on any
/// truncation or inconsistency; a `Some` guarantees `ip_end <= frame.len()`.
fn parse_ipv4(frame: &[u8], l3_off: usize) -> Option<(u8, usize, usize)> {
    let vihl = *frame.get(l3_off)?;
    if vihl >> 4 != 4 {
        return None; // not IPv4 despite the ethertype
    }
    let ihl = (vihl & 0x0f) as usize * 4;
    if ihl < 20 {
        return None; // IHL below the minimum header size
    }
    let total_len = be16(frame, l3_off + 2)? as usize;
    if total_len < ihl {
        return None; // total length can't be smaller than the header
    }
    // The IP datagram must not claim to extend past the captured frame.
    if l3_off + total_len > frame.len() {
        return None;
    }
    let ip_proto = *frame.get(l3_off + 9)?;
    // A NON-FIRST fragment (offset != 0) carries mid-datagram payload, not an L4 header:
    // report no L4 (proto 0) so payload bytes are never read as ports/flags. (Read as a
    // header, a legit fragment whose payload held e.g. 4444 at bytes 2-3 was FrameDropped
    // as a signature hit — an ADR 0023 legit-drop.) The FIRST fragment keeps its ports.
    if be16(frame, l3_off + 6)? & 0x1fff != 0 {
        return Some((0, l3_off + ihl, l3_off + total_len));
    }
    Some((ip_proto, l3_off + ihl, l3_off + total_len))
}

/// IPv6 header at `l3_off`, walking the extension-header chain (bounded) to the
/// L4 header → (proto, L4 offset, datagram end). Encrypted/opaque next-headers
/// (ESP, AH, ICMPv6, …) return with a non-TCP/UDP proto so the caller PASSes
/// (no port to inspect); a malformed/over-long chain fails closed to `None`.
fn parse_ipv6(frame: &[u8], l3_off: usize) -> Option<(u8, usize, usize)> {
    let ver = *frame.get(l3_off)?;
    if ver >> 4 != 6 {
        return None; // not IPv6 despite the ethertype
    }
    let payload_len = be16(frame, l3_off + 4)? as usize;
    let ip_end = l3_off + 40 + payload_len; // fixed 40-byte base header
    if ip_end > frame.len() {
        return None;
    }
    let mut next = *frame.get(l3_off + 6)?; // Next Header
    let mut off = l3_off + 40;
    for _ in 0..MAX_V6_EXT {
        match next {
            IPPROTO_TCP | IPPROTO_UDP => return Some((next, off, ip_end)),
            // Hop-by-Hop(0), Routing(43), Dest-Options(60): [next(0), hdr_ext_len(1)];
            // length is (hdr_ext_len + 1) * 8 bytes.
            0 | 43 | 60 => {
                let nh = *frame.get(off)?;
                let hlen = (*frame.get(off + 1)? as usize + 1) * 8;
                next = nh;
                off += hlen;
            }
            // Fragment(44): fixed 8 bytes; next-header at +0.
            44 => {
                next = *frame.get(off)?;
                // Non-first fragment (offset field != 0): payload, not an L4 header.
                if be16(frame, off + 2)? & 0xfff8 != 0 {
                    return Some((0, off + 8, ip_end));
                }
                off += 8;
            }
            // ESP(50)/AH(51)/ICMPv6(58)/unknown: opaque to us, no L4 ports here.
            _ => return Some((next, off, ip_end)),
        }
        if off > ip_end {
            return None; // extension chain ran past the datagram
        }
    }
    None // chain too long -> fail closed
}
