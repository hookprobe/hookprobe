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
pub const ETHERTYPE_VLAN: u16 = 0x8100;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

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

#[inline]
fn be16(b: &[u8], off: usize) -> Option<u16> {
    Some(((*b.get(off)? as u16) << 8) | (*b.get(off + 1)? as u16))
}

/// Parse an Ethernet/IPv4/L4 frame. Returns `None` on any truncation or
/// inconsistency (unknown L3, bad IHL, header claims to run past the frame, …).
/// A `Some` guarantees every field it reports is in-bounds of `frame`.
pub fn parse(frame: &[u8]) -> Option<PacketMeta> {
    // --- Ethernet ---
    let ethertype = be16(frame, 12)?; // also checks len >= 14
    let mut l3_off = ETH_HLEN;
    let mut et = ethertype;
    // One optional 802.1Q VLAN tag.
    if et == ETHERTYPE_VLAN {
        et = be16(frame, 16)?; // inner ethertype after the 4-byte tag
        l3_off = ETH_HLEN + 4;
    }

    let mut meta = PacketMeta {
        ethertype: et,
        ip_proto: 0,
        l4_off: 0,
        src_port: 0,
        dst_port: 0,
        payload_off: frame.len(),
    };

    if et != ETHERTYPE_IPV4 {
        return Some(meta); // non-IPv4 (ARP, IPv6, …): valid frame, no L4 ports
    }

    // --- IPv4 ---
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
    let l4_off = l3_off + ihl;
    let ip_end = l3_off + total_len; // L4 data ends here, not at frame.len()
    meta.ip_proto = ip_proto;
    meta.payload_off = ip_end;

    // --- TCP / UDP ports (both put src@0, dst@2) ---
    if ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP {
        // Need at least 4 bytes of L4 header, and they must be within the IP datagram.
        if l4_off + 4 > ip_end {
            return None;
        }
        meta.src_port = be16(frame, l4_off)?;
        meta.dst_port = be16(frame, l4_off + 2)?;
        meta.l4_off = l4_off;
    }
    Some(meta)
}
