//! Shared, pure (no `unsafe`) packet-crafting helpers for the L2-L4 probes — the same "packet
//! parsing vocabulary" `napse_loader::dpi` uses on the receive side (ADR 0020 D4: "the harness and
//! the DUT share a packet-parsing vocabulary, so a probe... maps 1:1 to what `PortScanTracker`/
//! `HandshakeTracker` observe"). Everything here is bytes-in/bytes-out; the only `unsafe` in the
//! probes crate tree is the raw-socket open/send calls themselves (`sockets.rs`), matching the
//! convention `modules/napse-capture/loader` already established (checked libc calls, not a
//! blanket crate-level forbid).
#![forbid(unsafe_code)]

/// Internet checksum (RFC 1071) over `data`, seeded with `initial` (already-summed pseudo-header
/// words, for TCP/UDP-over-IPv4). Same algorithm every IP stack uses; written here (not pulled from
/// a crate) to keep this dependency-light tool's send path auditable end-to-end.
pub fn checksum16(data: &[u8], initial: u32) -> u16 {
    let mut sum = initial;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Minimal IPv4 header, no options (20 bytes). `total_len` is the WHOLE packet (header+payload).
#[allow(clippy::too_many_arguments)]
pub fn build_ipv4_header(
    total_len: u16,
    ident: u16,
    ttl: u8,
    proto: u8,
    src: [u8; 4],
    dst: [u8; 4],
) -> [u8; 20] {
    let mut h = [0u8; 20];
    h[0] = 0x45; // version=4, ihl=5 (20 bytes)
    h[1] = 0x00; // dscp/ecn
    h[2..4].copy_from_slice(&total_len.to_be_bytes());
    h[4..6].copy_from_slice(&ident.to_be_bytes());
    h[6..8].copy_from_slice(&0u16.to_be_bytes()); // flags/frag offset
    h[8] = ttl;
    h[9] = proto;
    h[10..12].copy_from_slice(&[0, 0]); // checksum placeholder
    h[12..16].copy_from_slice(&src);
    h[16..20].copy_from_slice(&dst);
    let csum = checksum16(&h, 0);
    h[10..12].copy_from_slice(&csum.to_be_bytes());
    h
}

/// Minimal TCP header, no options (20 bytes), with the IPv4 pseudo-header folded into the checksum.
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_syn(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    syn: bool,
    ack: bool,
    fin: bool,
) -> [u8; 20] {
    let mut h = [0u8; 20];
    h[0..2].copy_from_slice(&src_port.to_be_bytes());
    h[2..4].copy_from_slice(&dst_port.to_be_bytes());
    h[4..8].copy_from_slice(&seq.to_be_bytes());
    h[8..12].copy_from_slice(&0u32.to_be_bytes()); // ack number
    h[12] = 5 << 4; // data offset = 5 words, no options
    let mut flags = 0u8;
    if fin {
        flags |= 0x01;
    }
    if syn {
        flags |= 0x02;
    }
    if ack {
        flags |= 0x10;
    }
    h[13] = flags;
    h[14..16].copy_from_slice(&65535u16.to_be_bytes()); // window
    h[16..18].copy_from_slice(&[0, 0]); // checksum placeholder
    h[18..20].copy_from_slice(&0u16.to_be_bytes()); // urgent pointer

    // pseudo-header: src+dst+zero+proto(6)+tcp_len, summed as 16-bit words feeding checksum16.
    let mut pseudo = Vec::with_capacity(12 + 20);
    pseudo.extend_from_slice(&src_ip);
    pseudo.extend_from_slice(&dst_ip);
    pseudo.push(0);
    pseudo.push(6); // IPPROTO_TCP
    pseudo.extend_from_slice(&(20u16).to_be_bytes());
    pseudo.extend_from_slice(&h);
    let csum = checksum16(&pseudo, 0);
    h[16..18].copy_from_slice(&csum.to_be_bytes());
    h
}

/// A full Ethernet+IPv4+TCP SYN (or SYN/ACK/FIN combination) frame, ready for an AF_PACKET send.
#[allow(clippy::too_many_arguments)]
pub fn build_eth_ipv4_tcp_frame(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ident: u16,
    syn: bool,
    ack: bool,
    fin: bool,
) -> Vec<u8> {
    let tcp = build_tcp_syn(src_ip, dst_ip, src_port, dst_port, seq, syn, ack, fin);
    let ip = build_ipv4_header(20 + 20, ident, 64, 6 /* TCP */, src_ip, dst_ip);
    let mut frame = Vec::with_capacity(14 + 20 + 20);
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&0x0800u16.to_be_bytes()); // ethertype IPv4
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    frame
}

/// The minimum valid Ethernet frame length (64 bytes on the wire including the 4-byte FCS the
/// kernel/NIC appends; 60 bytes as delivered to/from userspace, matching
/// `napse_loader::dpi::DEFAULT_MIN_FRAME_LEN` exactly — a real attacker's crafted frame is never
/// shorter than this, and neither should this probe's be, or `napse_loader::l2guard::
/// MalformedFrameGate` classifies it `l2_malformed` and short-circuits the mac-flood/broadcast/ARP
/// detectors for that frame entirely (see `napse-dpi.rs`'s main loop: malformed short-circuits the
/// rest). Confirmed empirically against a real running `napse-dpi` on a live netns DUT.
pub const MIN_ETH_FRAME_LEN: usize = 60;

/// A bare Ethernet frame with an arbitrary payload and a chosen (possibly forged) source MAC —
/// what the L2 mac-flood probe sends: no IP payload needed, `napse_loader::l2guard::MacFloodTracker`
/// keys purely on the observed source MAC of every frame. Zero-padded up to `MIN_ETH_FRAME_LEN` if
/// the caller's payload is shorter, exactly as a real NIC/driver would pad a short frame.
pub fn build_eth_frame(dst_mac: [u8; 6], src_mac: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len().max(MIN_ETH_FRAME_LEN.saturating_sub(14)));
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    if frame.len() < MIN_ETH_FRAME_LEN {
        frame.resize(MIN_ETH_FRAME_LEN, 0);
    }
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_empty_is_all_ones_complement() {
        assert_eq!(checksum16(&[], 0), 0xffff);
    }

    #[test]
    fn ipv4_header_is_20_bytes_and_checksums_to_zero_when_verified() {
        let h = build_ipv4_header(40, 1, 64, 6, [10, 99, 0, 2], [10, 99, 0, 3]);
        assert_eq!(h.len(), 20);
        // Verifying a correctly-checksummed header (re-summing it including its own checksum
        // field) must yield 0 — the standard IP-checksum self-check identity.
        assert_eq!(checksum16(&h, 0), 0);
    }

    #[test]
    fn tcp_syn_flag_bits_are_set_correctly() {
        let h = build_tcp_syn([10, 99, 0, 2], [10, 99, 0, 3], 40000, 22, 1, true, false, false);
        assert_eq!(h[13] & 0x02, 0x02, "SYN bit must be set");
        assert_eq!(h[13] & 0x10, 0, "ACK bit must be clear for a SYN-only segment");
    }

    #[test]
    fn syn_ack_sets_both_bits() {
        let h = build_tcp_syn([10, 99, 0, 2], [10, 99, 0, 3], 40000, 22, 1, true, true, false);
        assert_eq!(h[13] & 0x12, 0x12);
    }

    #[test]
    fn full_frame_has_expected_length_and_ethertype() {
        let f = build_eth_ipv4_tcp_frame(
            [0xff; 6], [0x02, 0, 0, 0, 0, 1], [10, 99, 0, 2], [10, 99, 0, 3], 40000, 22, 1, 1, true, false, false,
        );
        assert_eq!(f.len(), 14 + 20 + 20);
        assert_eq!(&f[12..14], &0x0800u16.to_be_bytes());
    }

    #[test]
    fn bare_eth_frame_round_trips_dst_src_ethertype_and_pads_to_minimum() {
        let f = build_eth_frame([0xff; 6], [0x02, 1, 2, 3, 4, 5], 0x88cc, &[0, 1, 2]);
        assert_eq!(&f[0..6], &[0xff; 6]);
        assert_eq!(&f[6..12], &[0x02, 1, 2, 3, 4, 5]);
        assert_eq!(&f[12..14], &0x88ccu16.to_be_bytes());
        assert_eq!(&f[14..17], &[0, 1, 2]);
        assert_eq!(f.len(), MIN_ETH_FRAME_LEN, "a short payload must be zero-padded to the Ethernet minimum");
    }

    #[test]
    fn bare_eth_frame_never_shrinks_a_payload_already_at_or_above_minimum() {
        let payload = vec![0xabu8; 60]; // 14 + 60 = 74 > MIN_ETH_FRAME_LEN
        let f = build_eth_frame([0xff; 6], [0x02, 1, 2, 3, 4, 5], 0x0800, &payload);
        assert_eq!(f.len(), 14 + 60);
    }
}
