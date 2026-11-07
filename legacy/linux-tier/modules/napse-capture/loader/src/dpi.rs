//! Deep-packet inspection on the mirror sink (`hp-mirror`) → dns/tls/http flow records in NAPSE's
//! schema (`/var/lib/hookprobe/flows`). This is the "deep" layer the fast-path (XDP/TC flow + ct)
//! can't do inline: it parses application payloads a Wasm/BPF program can't. Reads full-packet copies
//! the `tc-mirred` mirror delivers (ADR 0005). PURE parsers here, fully unit-tested; the AF_PACKET
//! capture loop lives in `bin/napse-dpi.rs`.
//!
//! Signals extracted (the ones that matter for IDS): DNS query + Shannon entropy (tunneling / DGA),
//! TLS SNI + version (encrypted-destination visibility), HTTP method/host/URI.

use std::net::Ipv4Addr;

/// Shannon entropy (bits/symbol, 0..8) over a byte slice — high on random subdomains (DGA/tunnels).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = data.len() as f64;
    -freq
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            p * p.log2()
        })
        .sum::<f64>()
}

/// TCP flag bits this module classifies. FIN/PSH/URG are needed (2026-07-05, EDR #2 fan-out
/// coverage) to recognize the classic nmap "stealth" scan flag shapes (FIN/NULL/XMAS) alongside
/// the original SYN-only classification — see [`classify_scan_probe`].
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;
const TCP_URG: u8 = 0x20;

/// Ethertypes the L1/L2 defensive detectors (`l2guard.rs`, ADR 0020 Phase-1a) need to recognize —
/// ARP and 802.1Q VLAN. Kept separate from `parse_l4`'s IPv4-only dispatch above: a mac-flood /
/// broadcast-storm / malformed-frame check must observe EVERY frame on the mirror, not just IPv4
/// TCP/UDP ones.
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_VLAN: u16 = 0x8100;

/// The destination + source Ethernet MAC of ANY frame (any ethertype). `None` only if the frame
/// is too short to even carry a bare Ethernet header (14 bytes) — used by the L2 defensive
/// detectors, which must see every frame, not just the IPv4/TCP/UDP ones `parse_l4` handles.
pub fn eth_addrs(frame: &[u8]) -> Option<([u8; 6], [u8; 6])> {
    if frame.len() < 14 {
        return None;
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&frame[0..6]);
    src.copy_from_slice(&frame[6..12]);
    Some((dst, src))
}

/// The frame's ethertype and the byte offset its payload starts at, stripping AT MOST one
/// 802.1Q/802.1ad VLAN tag. `None` if the frame is too short to contain a bare Ethernet header,
/// or too short to contain a VLAN tag its own ethertype declares. Deliberately does NOT recurse
/// into a SECOND stacked tag — a double-tagged (QinQ) frame is exactly what
/// [`frame_anomaly_reason`] flags as malformed on a topology that expects at most one tag; this
/// helper is for dispatching a well-formed frame (e.g. finding an ARP payload), not for
/// classifying malformed input.
pub fn eth_type_and_offset(frame: &[u8]) -> Option<(u16, usize)> {
    if frame.len() < 14 {
        return None;
    }
    let et = be16(&frame[12..14]);
    if et == ETHERTYPE_VLAN {
        if frame.len() < 18 {
            return None;
        }
        Some((be16(&frame[16..18]), 18))
    } else {
        Some((et, 14))
    }
}

/// Minimum well-formed Ethernet frame length this parser accepts — 60 bytes (the standard 64-byte
/// wire minimum minus the 4-byte FCS, which AF_PACKET capture never delivers to userspace). A
/// shorter frame is a "runt" — either a hardware fault or a deliberately truncated fuzzing probe.
pub const DEFAULT_MIN_FRAME_LEN: usize = 60;
/// Maximum frame length this parser accepts by default — standard Ethernet MTU (1500) + 14-byte
/// header + 4-byte 802.1Q tag + a small margin, WITHOUT assuming jumbo frames are in use (a
/// platform that legitimately runs jumbo frames raises this via config, same knob discipline as
/// `PortScanConfig`/`HandshakeConfig`).
pub const DEFAULT_MAX_FRAME_LEN: usize = 1522;

/// Deterministic, stateless malformed-frame classification — the frame itself IS the evidence,
/// never a claim about who sent it (ADR 0020's anti-spoof discipline: a malformed frame is
/// dropped because it's malformed, not because of a spoofable identity). Bounds-checked over
/// fully attacker-controlled bytes; returns a short, stable reason tag (never panics on garbage
/// input — mirrors `parse_http`'s raw-byte discipline). Checked, in order:
///   1. shorter than a bare Ethernet header (14 bytes) — cannot even be classified further.
///   2. shorter than `min_len` — a runt frame, UNLESS it fully, structurally parses as a
///      well-formed IPv4 TCP/UDP/ICMP packet or a well-formed ARP packet (see
///      [`frame_anomaly_reason_local`]'s "protocol-aware runt floor" doc for why there is no
///      single flat length floor for this exemption anymore).
///   3. longer than `max_len` — oversized/jumbo beyond what this platform's config declares.
///   4. the source MAC has the multicast/group bit set (IEEE 802.3 §3.2.3 forbids a multicast or
///      broadcast address as a frame's SOURCE) — a strong, cheap, universal malformed-source tell
///      that catches a wide class of fuzzed/spoofed frames independent of protocol.
///   5. an 802.1Q tag is declared (ethertype 0x8100) but the frame is too short to contain it, OR
///      it is immediately followed by a SECOND 802.1Q ethertype (a QinQ/double-tag on a topology
///      that expects at most one tag — the exact ambiguity a VLAN-hopping attack relies on), OR
///      it declares the reserved VLAN id 0xFFF.
pub fn frame_anomaly_reason(frame: &[u8], min_len: usize, max_len: usize) -> Option<&'static str> {
    // No local-MAC context here (the plain 3-arg entry point is the pre-existing, still-supported
    // call shape — see [`frame_anomaly_reason_local`]'s doc for why a caller who KNOWS this host's
    // own interface MAC(s) should call that one instead so the F6 GSO/TSO exemption below applies).
    frame_anomaly_reason_local(frame, min_len, max_len, &[])
}

/// Same classification as [`frame_anomaly_reason`], PLUS the 2026-07-06 GSO/TSO false-positive fix
/// (EDR/pentest finding F6): a caller that knows this host's OWN interface Ethernet MAC address(es)
/// (`local_macs` — e.g. read once at startup from `/sys/class/net/<iface>/address` for every
/// interface this box owns) passes them here so a **locally-originated** oversized frame is never
/// misclassified as an attack.
///
/// ## Why this is needed
/// Every `rule_id 1000033` ("malformed/oversized frame") alert observed live on-device carried
/// `end0`'s OWN Ethernet source MAC. These are TSO/GSO "super-frames": the kernel's GSO/TSO
/// offload defers segmentation to the NIC hardware, so a `tc-mirred` mirror copy (this module's
/// capture source, per the module doc) taken BEFORE that hardware segmentation runs sees one large,
/// still-unsegmented frame that legitimately EXCEEDS [`DEFAULT_MAX_FRAME_LEN`] by design — not a
/// malformed or hostile packet. Scoring the device's own NIC as an L2 attacker against itself is a
/// straightforward false positive (confirmed: 25 such rows polluted the evidence DB), and if the
/// (currently detection-only) L2 dropper were ever wired to enforce on this rule, it would drop the
/// device's own locally-originated, entirely legitimate egress traffic.
///
/// ## The exemption (length-and-structure-and-provenance carve-out, never "trust the claimed MAC alone")
/// A frame that exceeds `max_len` is exempted from the oversized classification **only** when BOTH:
/// 1. its own Ethernet source address is one of `local_macs` (this host's OWN interface(s) — never
///    a claim accepted from a remote/attacker source; a spoofed source MAC on WAN-received traffic
///    could never equal a MAC this function's caller independently read from `/sys/class/net`), AND
/// 2. it fully, structurally parses as a well-formed IPv4 TCP/UDP packet ([`parse_l4`] succeeding
///    proves the declared IHL/protocol/L4-header-length chain is internally consistent and fully
///    present within the frame's own bytes) — the SAME structural-proof technique the runt-frame
///    exemption above already uses, so a genuinely garbage/fuzzed frame that merely happens to be
///    long is never exempted just because condition 1 alone matched.
///
/// Anything oversized that fails either check — including a well-formed oversized packet from a
/// MAC that ISN'T one of `local_macs` — is still flagged exactly as before: this is a provenance
/// exemption for THIS host's own egress, never a blanket "any big well-formed packet is fine" rule.
/// The runt-frame and VLAN/multicast-source checks are unaffected by `local_macs` — GSO/TSO only
/// ever produces an OVERSIZED frame, never a runt one, so widening any other check here would be
/// unjustified scope creep on a fix that targets exactly the confirmed false-positive shape.
///
/// ## 2026-07-07 CRITICAL fix — the runt floor is now PROTOCOL-AWARE, not one flat length
/// Live pentest finding: an iPhone (`aa:ff:48:06:a6:2d`, iOS locally-administered/randomized MAC)
/// associated to the `HookProbe` SSID and got NO connectivity — its ARP requests/replies (a real,
/// well-formed 42-byte Ethernet+ARP frame: 14 eth + 28-byte ARP body) were dropped as "runt" and
/// never reached the host's ARP table. The 2026-07-05 EDR #7 fix already carved out a runt
/// exemption for a bare 54-byte TCP control segment (the minimum legitimate encapsulated TCP
/// packet), but a well-formed ARP packet is legitimately SHORTER than that (42 bytes, not 54) —
/// gating BOTH shapes behind one flat 54-byte floor meant every ARP frame in `[42, 54)` still
/// fell through to the runt drop, which is exactly the "can't distinguish attacker from
/// non-attacker" defect this fix closes.
///
/// The fix: there is no longer a single hand-picked length floor for this exemption at all. A
/// frame in `[14, min_len)` (at least a bare Ethernet header, but short of the configured
/// minimum) is exempt from the runt classification if — and only if — it fully, structurally
/// parses as ONE of:
///   - a well-formed IPv4 TCP/UDP packet ([`parse_l4`] succeeding proves the declared
///     IHL/protocol/L4-header-length chain is internally consistent and entirely present within
///     the frame's own bytes — the true minimum this implies is 34 bytes for UDP/no-payload, 54
///     for TCP/no-options/no-payload, never an arbitrary flat number), or
///   - a well-formed IPv4 ICMP packet ([`parse_icmp_obs`] succeeding — true minimum 36 bytes:
///     14 eth + 20 ip + 2-byte type/code), or
///   - a well-formed ARP packet ([`parse_arp_obs`] succeeding with `!is_malformed()` — true
///     minimum 42 bytes: 14 eth + the full 28-byte fixed-shape ARP body; [`parse_arp_obs`] itself
///     now returns `None` — not a "not malformed" placeholder — for a frame that declares the
///     standard ARP shape but is genuinely too short to carry the full body, so a merely
///     TRUNCATED ARP capture is never misread as "complete and benign", see that function's doc).
///
/// A frame that is below 14 bytes, or that fails every one of the above structural parses, is
/// still flagged as a runt/malformed frame exactly as before — this is a length-AND-structure
/// carve-out per protocol, never a blanket "anything short is fine" relaxation, and never a
/// source-identity exemption (it stays inside this function's existing "the frame itself IS the
/// evidence" discipline, and is fully independent from the `local_macs` provenance exemption
/// above, which still applies on top for this host's own egress).
pub fn frame_anomaly_reason_local(
    frame: &[u8],
    min_len: usize,
    max_len: usize,
    local_macs: &[[u8; 6]],
) -> Option<&'static str> {
    if frame.len() < 14 {
        return Some("frame shorter than a minimum Ethernet header (14 bytes)");
    }
    if frame.len() < min_len {
        // F6-extension (2026-07-06, confirmed live): a runt frame sourced from THIS host's OWN NIC
        // MAC is our own EGRESS frame captured on the mirror BEFORE the NIC pads it to the 64-byte
        // wire minimum — never an L2 attack, exactly like the oversized GSO/TSO case below. (The
        // original F6 assumed GSO only produces oversized frames; on-device evidence showed the
        // local NIC's own small egress frames — stripped-padding TCP ACKs etc. — also surface here
        // as runts, so the same provenance exemption applies.) For genuine WIRE frames (non-local
        // MAC) the PROTOCOL-AWARE structural exemption (2026-07-07 fix, see this function's doc
        // comment) still governs — there is no flat length floor here anymore.
        let locally_originated = eth_addrs(frame).is_some_and(|(_, src)| local_macs.contains(&src));
        let structurally_complete = parse_l4(frame).is_some()
            || parse_icmp_obs(frame).is_some()
            || parse_arp_obs(frame).is_some_and(|a| !a.is_malformed());
        if !locally_originated && !structurally_complete {
            return Some("runt frame (below the configured minimum Ethernet frame length, and not a structurally complete ARP/IPv4 TCP/UDP/ICMP packet)");
        }
    }
    if frame.len() > max_len {
        // F6 GSO/TSO exemption (see doc comment above): locally-originated AND structurally a
        // well-formed IPv4 TCP/UDP packet — never exempted on either signal alone.
        let locally_originated = eth_addrs(frame).is_some_and(|(_, src)| local_macs.contains(&src));
        let structurally_valid = parse_l4(frame).is_some();
        if !(locally_originated && structurally_valid) {
            return Some("oversized frame (exceeds the configured MTU/jumbo cap)");
        }
    }
    if frame[6] & 0x01 != 0 {
        return Some("source MAC has the multicast/group bit set (IEEE 802.3 forbids a multicast/broadcast source address)");
    }
    let ethertype = be16(&frame[12..14]);
    if ethertype == ETHERTYPE_VLAN {
        if frame.len() < 18 {
            return Some("802.1Q VLAN tag declared but the frame is too short to contain it");
        }
        let inner = be16(&frame[16..18]);
        if inner == ETHERTYPE_VLAN {
            return Some("double/stacked 802.1Q VLAN tag (QinQ) on a topology that expects at most one tag");
        }
        let vlan_id = be16(&frame[14..16]) & 0x0FFF;
        if vlan_id == 0x0FFF {
            return Some("reserved VLAN id 0xFFF");
        }
    }
    None
}

/// Standard Ethernet/IPv4 ARP field values (RFC 826, RFC 5227) — what a WELL-FORMED ARP packet
/// on an Ethernet/IPv4 network must carry. Anything else is itself the "malformed ARP" signal
/// (see [`ArpObs::is_malformed`]).
pub const ARP_HTYPE_ETHERNET: u16 = 1;
pub const ARP_PTYPE_IPV4: u16 = 0x0800;

/// One parsed ARP packet: both its self-declared shape (`htype`/`ptype`/`hlen`/`plen`) and, when
/// that shape is the standard Ethernet/IPv4 one, the sender/target mac+ip fields the anti-spoof
/// detectors (`l2guard::ArpGuard`) need. `eth_src_mac` is the OUTER Ethernet frame's source
/// address — comparing it against the ARP payload's OWN `sender_mac` field is exactly the
/// "sender-MAC ≠ Ethernet-src mismatch" check the task calls for (a real host's ARP stack always
/// sets these identically; disagreement is a classic spoofing/injection tell).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ArpObs {
    pub eth_src_mac: [u8; 6],
    pub htype: u16,
    pub ptype: u16,
    pub hlen: u8,
    pub plen: u8,
    pub opcode: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

impl ArpObs {
    /// True if this packet's self-declared shape isn't the standard Ethernet/IPv4 ARP shape — a
    /// non-1 `htype`, non-0x0800 `ptype`, or an hlen/plen other than 6/4. Not a legitimate
    /// address-resolution packet on an Ethernet/IPv4 network; must be dropped outright — the
    /// packet itself is malformed, independent of any claimed identity (its mac/ip fields are
    /// zeroed placeholders in this case — see [`parse_arp_obs`] — never trust them here).
    pub fn is_malformed(&self) -> bool {
        self.htype != ARP_HTYPE_ETHERNET || self.ptype != ARP_PTYPE_IPV4 || self.hlen != 6 || self.plen != 4
    }

    /// True if the ARP payload's OWN `sender_mac` field disagrees with the outer Ethernet frame's
    /// source MAC. Never meaningful on an already-malformed packet.
    pub fn eth_mismatch(&self) -> bool {
        !self.is_malformed() && self.sender_mac != self.eth_src_mac
    }

    /// True if this is a gratuitous ARP (sender address == target address) — legitimate at a low
    /// rate (IP-conflict detection, failover announce), a flood at a high one.
    pub fn is_gratuitous(&self) -> bool {
        !self.is_malformed() && self.sender_ip == self.target_ip
    }
}

/// Parse an ARP packet from a raw frame (optionally single-VLAN-tagged — see
/// [`eth_type_and_offset`]). `None` if the frame isn't ARP at all, is too short to contain even
/// the fixed 8-byte ARP header (htype/ptype/hlen/plen/opcode), OR (2026-07-07 fix) declares the
/// STANDARD Ethernet/IPv4 shape (hlen==6, plen==4) but is too short to carry the full 28-byte
/// body those fields promise — a genuinely TRUNCATED capture is left to
/// [`frame_anomaly_reason`]'s generic runt-frame check rather than misread here as "complete and
/// benign" (see the inline comment at that check for the false-positive this closes: a
/// truncated-but-standard-shaped packet used to parse with zeroed mac/ip fields WITHOUT being
/// flagged [`ArpObs::is_malformed`], which then misfired `eth_mismatch`/`is_gratuitous` on
/// nothing more than a short capture). A packet long enough for the 8-byte fixed header but
/// declaring a NON-standard hlen/plen still parses — with its mac/ip fields zeroed — so
/// [`ArpObs::is_malformed`] can flag that anomaly explicitly rather than this function silently
/// discarding it as "not ARP"; this is the one case a non-standard header returns `Some`, because
/// there the "malformed" verdict genuinely IS length-independent evidence, unlike a mere
/// truncation of an otherwise-standard header.
pub fn parse_arp_obs(frame: &[u8]) -> Option<ArpObs> {
    let (ethertype, off) = eth_type_and_offset(frame)?;
    if ethertype != ETHERTYPE_ARP {
        return None;
    }
    let (_, eth_src_mac) = eth_addrs(frame)?;
    let p = frame.get(off..)?;
    if p.len() < 8 {
        return None;
    }
    let htype = be16(&p[0..2]);
    let ptype = be16(&p[2..4]);
    let hlen = p[4];
    let plen = p[5];
    let opcode = be16(&p[6..8]);
    if hlen != 6 || plen != 4 {
        // Non-standard shape — malformed independent of length; the mac/ip fields below don't
        // even exist at a well-defined offset for a non-6/4 hlen/plen, so they're zeroed
        // placeholders (never trusted — `ArpObs::is_malformed` is what callers must check first).
        return Some(ArpObs {
            eth_src_mac,
            htype,
            ptype,
            hlen,
            plen,
            opcode,
            sender_mac: [0; 6],
            sender_ip: Ipv4Addr::UNSPECIFIED,
            target_mac: [0; 6],
            target_ip: Ipv4Addr::UNSPECIFIED,
        });
    }
    if p.len() < 28 {
        // 2026-07-07 fix: the header DECLARES the standard Ethernet/IPv4 shape (hlen==6, plen==4)
        // but the frame is too short to carry the full 28-byte body (8-byte fixed header + 20
        // bytes of sender/target mac+ip). Before this fix this fell into the same branch as the
        // non-standard-shape case above, returning zeroed sender/target fields WITHOUT setting
        // `is_malformed()` (since htype/ptype/hlen/plen were all standard) — a genuinely
        // TRUNCATED ARP capture then read as "not malformed", and its zeroed `sender_mac` almost
        // always compared unequal to the real Ethernet source, misfiring `ArpObs::eth_mismatch()`
        // as a false "ARP spoofing" alert on a merely-truncated frame, and its zeroed
        // `sender_ip`/`target_ip` (both `0.0.0.0`) always compared equal, misfiring
        // `ArpObs::is_gratuitous()` too. Returning `None` here instead — exactly the same "too
        // short to be recognized as a complete ARP packet, leave it to the generic runt-frame
        // check" contract this function already uses for a frame shorter than the fixed 8-byte
        // header above — means a truncated ARP capture is never misread as "complete and benign",
        // and never spuriously misread as "spoofed"/"gratuitous" either.
        return None;
    }
    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&p[8..14]);
    let sender_ip = Ipv4Addr::new(p[14], p[15], p[16], p[17]);
    let mut target_mac = [0u8; 6];
    target_mac.copy_from_slice(&p[18..24]);
    let target_ip = Ipv4Addr::new(p[24], p[25], p[26], p[27]);
    Some(ArpObs { eth_src_mac, htype, ptype, hlen, plen, opcode, sender_mac, sender_ip, target_mac, target_ip })
}

struct L4<'a> {
    /// Ethernet source MAC (frame bytes 6..12) — the OBSERVED L2 address of whoever put this
    /// frame on the wire, captured at the SAME instant as the rest of this record. Security
    /// note (2026-07-05 threat-model fix): this is the ONLY MAC the quarantine responder is
    /// allowed to bind enforcement to. An ARP/`/proc/net/arp` lookup keyed on the CLAIMED L3
    /// source IP is a *different*, spoofable value (a WAN attacker's claimed src IP resolves to
    /// the REAL gateway's MAC, poisoning the LAN-side quarantine key) — see
    /// `hookprobe_manifest::scan_responder::resolve_mac`'s doc comment.
    src_mac: [u8; 6],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    proto: u8,
    sport: u16,
    dport: u16,
    payload: &'a [u8],
    /// Raw TCP flags byte (header offset 13). Always 0 for UDP (there are no TCP flags to read).
    tcp_flags: u8,
    /// TCP sequence number (header bytes 4..8), host-order value of the wire bytes. 0 for UDP.
    /// Needed ONLY for handshake confirmation (`portscan::HandshakeTracker`) — an off-path
    /// spoofer can send an unlimited number of bare SYNs but can never learn (and therefore
    /// never correctly echo) the responder's chosen ISN, which is what makes a validated
    /// SYN→SYN-ACK→ACK completion a real anti-spoofing signal.
    seq: u32,
    /// TCP acknowledgment number (header bytes 8..12). 0 for UDP or a SYN with ACK clear.
    ack_num: u32,
}

impl L4<'_> {
    /// A pure connection-attempt SYN: SYN set AND ACK clear. This is what a port-scan probe looks
    /// like on the wire — a SYN-ACK reply or any established/ACK traffic must return false.
    fn is_syn_only(&self) -> bool {
        self.proto == 6 && (self.tcp_flags & (TCP_SYN | TCP_ACK)) == TCP_SYN
    }
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Parse eth→ipv4→tcp/udp from a raw frame; return the L4 payload + 5-tuple + TCP flags, or None
/// if malformed or not v4 TCP/UDP.
fn parse_l4(frame: &[u8]) -> Option<L4<'_>> {
    if frame.len() < 14 + 20 {
        return None;
    }
    if be16(&frame[12..14]) != 0x0800 {
        return None; // not IPv4
    }
    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&frame[6..12]);
    let ip = &frame[14..];
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    let proto = ip[9];
    let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    let l4 = &ip[ihl..];
    let (sport, dport, payload, tcp_flags, seq, ack_num) = match proto {
        6 => {
            // TCP
            if l4.len() < 20 {
                return None;
            }
            let doff = ((l4[12] >> 4) as usize) * 4;
            if doff < 20 || l4.len() < doff {
                return None;
            }
            (be16(&l4[0..2]), be16(&l4[2..4]), &l4[doff..], l4[13], be32(&l4[4..8]), be32(&l4[8..12]))
        }
        17 => {
            // UDP
            if l4.len() < 8 {
                return None;
            }
            (be16(&l4[0..2]), be16(&l4[2..4]), &l4[8..], 0u8, 0u32, 0u32)
        }
        _ => return None,
    };
    Some(L4 { src_mac, src, dst, proto, sport, dport, payload, tcp_flags, seq, ack_num })
}

/// One TCP-packet observation for the port-scan fan-out tracker (`portscan.rs`): the 4-tuple plus
/// whether this is a pure connection-attempt SYN. Kept separate from `parse_frame` (which only
/// looks at DNS/TLS/HTTP on their well-known ports) because a port scan probes ARBITRARY ports.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TcpSyn {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub sport: u16,
    pub dport: u16,
    /// SYN set, ACK clear — a fresh connection attempt (not a SYN-ACK reply, not established
    /// traffic).
    pub syn_only: bool,
}

/// Parse eth→ipv4→tcp from a raw frame for the port-scan tracker. Returns None for non-IPv4,
/// non-TCP, or malformed frames — UDP is irrelevant to a TCP SYN scan.
pub fn parse_tcp_syn(frame: &[u8]) -> Option<TcpSyn> {
    let l4 = parse_l4(frame)?;
    if l4.proto != 6 {
        return None;
    }
    Some(TcpSyn { src: l4.src, dst: l4.dst, sport: l4.sport, dport: l4.dport, syn_only: l4.is_syn_only() })
}

/// One TCP-packet observation carrying everything the confirmation-gating layer
/// (`portscan::HandshakeTracker`) and the observed-MAC quarantine key need: the observed L2
/// source MAC (never resolved from the claimed IP — see `L4::src_mac`'s doc comment), the SYN/ACK
/// flags (not collapsed to a single `syn_only` bool — a handshake needs to see ALL three stages:
/// SYN, SYN-ACK, and the final ACK), and the raw seq/ack numbers so a completed handshake can be
/// cryptographically-adjacent-verified (the responder's chosen ISN is exactly what an off-path
/// spoofer can never learn).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TcpObs {
    pub src_mac: [u8; 6],
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub sport: u16,
    pub dport: u16,
    pub syn: bool,
    pub ack: bool,
    pub seq: u32,
    pub ack_num: u32,
    pub payload_len: usize,
    /// The raw TCP flags byte — needed by [`TcpObs::scan_probe_kind`] to recognize FIN/NULL/XMAS
    /// scan shapes, which `syn`/`ack` alone can't distinguish from each other (2026-07-05, EDR #2).
    pub tcp_flags: u8,
}

/// Parse eth→ipv4→tcp from a raw frame into the full observation the confirmation layer needs.
/// Returns None for non-IPv4, non-TCP, or malformed frames.
pub fn parse_tcp_obs(frame: &[u8]) -> Option<TcpObs> {
    let l4 = parse_l4(frame)?;
    if l4.proto != 6 {
        return None;
    }
    Some(TcpObs {
        src_mac: l4.src_mac,
        src: l4.src,
        dst: l4.dst,
        sport: l4.sport,
        dport: l4.dport,
        syn: l4.tcp_flags & TCP_SYN != 0,
        ack: l4.tcp_flags & TCP_ACK != 0,
        seq: l4.seq,
        ack_num: l4.ack_num,
        payload_len: l4.payload.len(),
        tcp_flags: l4.tcp_flags,
    })
}

/// 2026-07-05 fan-out coverage fix (EDR #2): which "stealth" scan probe SHAPE a raw TCP flags byte
/// matches, if any. A classic half-open scanner sends a bare SYN, but the SAME "probe one dst port,
/// see what comes back" intent is also expressed with the SYN bit deliberately CLEAR — the three
/// shapes an nmap-class scanner uses specifically BECAUSE a naive SYN-only tracker never counts
/// them: **FIN** (only the FIN bit set), **NULL** (no flags at all), and **XMAS** (FIN+PSH+URG all
/// set, "lighting up" the flags byte). `ACK` set on ANY of these disqualifies the packet outright —
/// that is real established/return traffic (a RST or FIN from an open connection's teardown),
/// never a probe — mirroring `L4::is_syn_only`'s existing SYN/ACK discipline, generalized. Anything
/// else (a normal data/ACK packet, or a nonstandard flag combination that isn't one of these four
/// well-known probe shapes) is `None` — deliberately conservative: this function only names the
/// SPECIFIC shapes a scanner is documented to use, never "any packet without ACK".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanProbeKind {
    /// SYN set, everything else clear — the classic half-open scan (unchanged from before this
    /// fix; kept as an explicit variant so a caller can distinguish it from the newer three).
    Syn,
    /// FIN set, everything else clear — a "FIN scan" (relies on RFC 793: a closed port MUST
    /// reply RST to an unexpected FIN; an open one is expected to ignore it silently).
    Fin,
    /// No flags set at all — a "NULL scan" (same RFC 793 closed-port-replies-RST logic as FIN).
    Null,
    /// FIN + PSH + URG all set — a "XMAS scan" (same logic again; the name comes from the flags
    /// byte "lighting up" like a Christmas tree).
    Xmas,
}
pub fn classify_scan_probe(tcp_flags: u8) -> Option<ScanProbeKind> {
    if tcp_flags & TCP_ACK != 0 {
        return None; // ACK set → established/return/teardown traffic, never a probe shape
    }
    match tcp_flags {
        0 => Some(ScanProbeKind::Null),
        f if f == TCP_SYN => Some(ScanProbeKind::Syn),
        f if f == TCP_FIN => Some(ScanProbeKind::Fin),
        f if f == (TCP_FIN | TCP_PSH | TCP_URG) => Some(ScanProbeKind::Xmas),
        _ => None,
    }
}
impl TcpObs {
    /// Convenience wrapper around [`classify_scan_probe`] over this observation's own raw flags —
    /// the SAME broadened "is this a scan-probe packet" signal `portscan::PortScanTracker` (once
    /// its caller passes it through — see that module's doc) should count toward a source's
    /// distinct-dst-port fan-out, alongside the original SYN-only case.
    pub fn scan_probe_kind(&self) -> Option<ScanProbeKind> {
        classify_scan_probe(self.tcp_flags)
    }
}

/// One UDP-packet observation for the UDP-fanout scan tracker (`portscan::UdpScanTracker`) — UDP
/// has no SYN/handshake concept at all, so EVERY UDP datagram to a new destination port is itself
/// the probe signal (unlike TCP, where only the SYN/FIN/NULL/XMAS shapes above qualify).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UdpObs {
    pub src_mac: [u8; 6],
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub sport: u16,
    pub dport: u16,
}

/// Parse eth→ipv4→udp from a raw frame. Returns None for non-IPv4, non-UDP, or malformed frames.
pub fn parse_udp_obs(frame: &[u8]) -> Option<UdpObs> {
    let l4 = parse_l4(frame)?;
    if l4.proto != 17 {
        return None;
    }
    Some(UdpObs { src_mac: l4.src_mac, src: l4.src, dst: l4.dst, sport: l4.sport, dport: l4.dport })
}

/// One ICMPv4 observation for the ICMP host-sweep tracker (`portscan::IcmpSweepTracker`). ICMP has
/// no port concept at all — `parse_l4` (TCP/UDP-shaped, expects a port pair) doesn't apply, so this
/// is a dedicated, small eth→ipv4→icmp parse.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IcmpObs {
    pub src_mac: [u8; 6],
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub icmp_type: u8,
    pub icmp_code: u8,
}

/// ICMPv4 "Echo Request" (type 8) — the packet shape a ping/host-discovery sweep sends; every
/// other ICMP type (echo reply, unreachable, time-exceeded, …) is irrelevant to a sweep tracker.
pub const ICMP_ECHO_REQUEST: u8 = 8;

/// Parse eth→ipv4→icmp from a raw frame. Returns None for non-IPv4, non-ICMPv4, or malformed
/// frames (too short to contain even the 2-byte type+code the sweep tracker needs).
pub fn parse_icmp_obs(frame: &[u8]) -> Option<IcmpObs> {
    if frame.len() < 14 + 20 {
        return None;
    }
    if be16(&frame[12..14]) != 0x0800 {
        return None; // not IPv4
    }
    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&frame[6..12]);
    let ip = &frame[14..];
    let ihl = (ip[0] & 0x0f) as usize * 4;
    if ihl < 20 || ip.len() < ihl {
        return None;
    }
    if ip[9] != 1 {
        return None; // not ICMPv4 (protocol 1)
    }
    let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
    let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
    let icmp = &ip[ihl..];
    if icmp.len() < 2 {
        return None;
    }
    Some(IcmpObs { src_mac, src, dst, icmp_type: icmp[0], icmp_code: icmp[1] })
}

fn tuple_json(l4: &L4, wall_ts: f64, rtype: &str) -> String {
    format!(
        "{{\"type\":\"{rtype}\",\"ts\":{wall_ts:.3},\"src_ip\":\"{}\",\"src_port\":{},\
         \"dst_ip\":\"{}\",\"dst_port\":{},\"proto\":\"{}\"",
        l4.src, l4.sport, l4.dst, l4.dport,
        if l4.proto == 6 { "tcp" } else { "udp" }
    )
}

fn jesc(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).map(|c| if c == '"' || c == '\\' { ' ' } else { c }).collect()
}

/// Parse a frame; if it carries a DNS query, TLS ClientHello (SNI), or HTTP request, return one
/// NAPSE flow-record JSON line, else None.
pub fn parse_frame(frame: &[u8], wall_ts: f64) -> Option<String> {
    let l4 = parse_l4(frame)?;
    match (l4.proto, l4.sport, l4.dport) {
        (17, _, 53) => parse_dns(&l4, wall_ts), // query to a resolver
        (6, _, 443) => parse_tls_client_hello(&l4, wall_ts),
        // Server->client direction (sport 443): the ServerHello half of the SAME handshake, JA4S.
        // Checked AFTER the ClientHello arm above so a (rare, non-standard) 443<->443 packet still
        // tries the ClientHello parse first; both parsers bounds-check their own handshake-type
        // byte and cleanly return None rather than misparse the other message type.
        (6, 443, _) => parse_tls_server_hello(&l4, wall_ts),
        (6, _, 80) => parse_http(&l4, wall_ts),
        _ => None,
    }
}

/// DNS query name from the question section (no compression in a query). Returns dotted name.
fn dns_qname(p: &[u8]) -> Option<String> {
    if p.len() < 12 {
        return None;
    }
    let qdcount = be16(&p[4..6]);
    if qdcount == 0 {
        return None;
    }
    let mut i = 12;
    let mut labels = Vec::new();
    loop {
        if i >= p.len() {
            return None;
        }
        let len = p[i] as usize;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return None; // compression pointer — unexpected in a question
        }
        i += 1;
        if i + len > p.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&p[i..i + len]).to_string());
        i += len;
    }
    if labels.is_empty() {
        return None;
    }
    Some(labels.join("."))
}

fn parse_dns(l4: &L4, wall_ts: f64) -> Option<String> {
    let name = dns_qname(l4.payload)?;
    // entropy over the name minus dots — high for DGA/tunneling.
    let joined: Vec<u8> = name.bytes().filter(|&b| b != b'.').collect();
    let ent = shannon_entropy(&joined);
    let mut s = tuple_json(l4, wall_ts, "dns");
    s.push_str(&format!(
        ",\"service\":\"dns\",\"query\":\"{}\",\"query_len\":{},\"query_entropy\":{:.4}}}",
        jesc(&name), name.len(), ent
    ));
    Some(s)
}

/// A TLS value is GREASE (RFC 8701) iff both bytes are equal and the low nibble is 0xa
/// (0x0a0a, 0x1a1a, … 0xfafa). GREASE ciphers/extensions/curves must be excluded from JA3.
fn is_grease(v: u16) -> bool {
    (v >> 8) == (v & 0xff) && (v & 0x0f) == 0x0a
}

fn join_dec<T: std::fmt::Display>(xs: &[T]) -> String {
    xs.iter().map(|x| x.to_string()).collect::<Vec<_>>().join("-")
}

// ---- JA4 / JA4S / JA4H (FoxIO JA4+ suite) ------------------------------------------------------
// The modern fingerprint suite computed ALONGSIDE the legacy JA3 above (JA3 stays first-class —
// existing feeds/dashboards key on it; JA4+ is additive, never a replacement). Algorithm exactly
// per the FoxIO reference implementation (BSD-3 for JA4, FoxIO-License-1.1 for JA4S/JA4H — this is
// an independent from-scratch Rust re-implementation of the PUBLISHED ALGORITHM, no FoxIO source
// copied): https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md +
// https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4.py (`to_ja4`/`to_ja4s`) +
// https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4h.py (`to_ja4h`) — verified 2026-07-09
// against the reference implementation's own logic byte-for-byte (see this module's tests, whose
// expected strings were independently cross-computed against that reference algorithm).
//
// Two ambiguities the published prose (`JA4.md`) leaves under-specified but the reference
// implementation resolves, followed here:
//   1. **JA4_a's extension count includes SNI/ALPN** (only GREASE is excluded from the count) —
//      SNI/ALPN are excluded ONLY from the JA4_c hash input, not from the JA4_a count field.
//   2. **JA4_c hashes even when GREASE-filtered-but-otherwise-empty**: if the SNI/ALPN-stripped,
//      sorted extension list is empty AND signature_algorithms is non-empty, the hash input is
//      `_<sigalgs>` (a LEADING underscore, no extensions before it) — never skipped.
//
// TLS extension-type ids this suite reads (RFC 8446 §4.2 / IANA TLS ExtensionType registry) — named
// so a reader never has to memorize a magic number:
const TLS_EXT_SERVER_NAME: u16 = 0x0000; // SNI (also used by the existing JA3/tls_sni parsing above)
const TLS_EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d; // JA4's "_<sigalgs>" suffix on JA4_c
const TLS_EXT_ALPN: u16 = 0x0010; // JA4_a's 2-char alpn field; excluded from the JA4_c hash input
const TLS_EXT_SUPPORTED_VERSIONS: u16 = 0x002b; // overrides the legacy_version field when present

/// Truncated (first 12 lowercase hex chars) SHA-256 — the JA4+ suite's own hash convention (never
/// JA3's MD5, see `is_grease`'s neighbor `parse_tls_client_hello`'s own doc for why MD5 stays
/// JA3-only: it is cryptographically broken and used ONLY to match that legacy fingerprint format
/// bit-for-bit). Real SHA-256 via the `sha2` crate (already a workspace dependency elsewhere —
/// `hookprobe-manifest`/`hookprobe-rbac` use it the same way).
fn ja4_sha_trunc12(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(s.as_bytes());
    let mut out = String::with_capacity(12);
    for b in digest.iter().take(6) {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn hex4(v: u16) -> String {
    format!("{v:04x}")
}

fn join_hex4<I: IntoIterator<Item = u16>>(xs: I) -> String {
    xs.into_iter().map(hex4).collect::<Vec<_>>().join(",")
}

/// JA4's 2-character TLS-version code (FoxIO `TLS_MAPPER`) — "00" for anything not in the table
/// (an unrecognized/future version code, never a panic or a fabricated guess).
fn ja4_version_code(v: u16) -> &'static str {
    match v {
        0x0002 => "s2",
        0x0300 => "s3",
        0x0301 => "10",
        0x0302 => "11",
        0x0303 => "12",
        0x0304 => "13",
        _ => "00",
    }
}

/// The highest non-GREASE value in a `supported_versions` extension, or `legacy_version` when the
/// extension was absent/empty — the SAME "supported_versions wins when present" precedence the
/// reference implementation's `get_supported_version` applies (a TLS 1.3 ClientHello always sets
/// the legacy `client_version` field to 0x0303 for middlebox compatibility; the REAL negotiated
/// version only ever appears in this extension).
fn ja4_client_version(legacy_version: u16, supported_versions: &[u16]) -> u16 {
    supported_versions.iter().copied().filter(|v| !is_grease(*v)).max().unwrap_or(legacy_version)
}

/// JA4's 2-character ALPN field: the first offered/negotiated ALPN protocol id's first+last raw
/// byte (both taken from the SAME byte when the protocol id is exactly 1 byte long). ALPN protocol
/// ids are ASCII-only by convention (RFC 7301) — "00" when no ALPN value is present at all; a first
/// byte with the high bit set (non-ASCII / binary garbage from a hostile peer) collapses the whole
/// field to "99" rather than emitting a non-printable byte into the fingerprint string, mirroring
/// the reference implementation's own `if ord(alpn[0]) > 127: alpn = '99'` simplification. Never
/// panics on adversarial/empty input.
///
/// DELIBERATE spec-vs-reference-code choice (re-verified 2026-07-16 against FoxIO ja4.py `main`,
/// roadmap-B audit GAP-8): the PROSE spec (technical_details/JA4.md) says "if the first OR last byte
/// is not ASCII-alphanumeric, print the first+last chars of the HEX representation", but the FoxIO
/// REFERENCE IMPLEMENTATION (`ja4.py` lines 206/279) checks only `ord(alpn[0]) > 127` and collapses
/// to `'99'`. We match the reference CODE, NOT the prose, on purpose: real-world JA4 threat-intel
/// feeds are produced by ja4.py-derived tooling, so matching the code is what lets our computed
/// fingerprint EQUAL a feed's — diverging to the prose spec would make every feed lookup miss. The
/// remaining edge (ASCII first byte, non-ASCII LAST byte) keeps the raw last byte exactly as ja4.py
/// does; in Rust `u8 as char` maps 0x80–0xFF to valid Latin-1 code points, so the output is always
/// valid UTF-8 (no corruption/panic) even though such an ALPN is pathological and never in any feed.
/// DO NOT "fix" this to the prose spec without also re-generating every JA4 IOC we ship.
fn ja4_alpn_field(first_proto: Option<&[u8]>) -> String {
    let Some(p) = first_proto.filter(|p| !p.is_empty()) else {
        return "00".to_string();
    };
    if p[0] > 0x7f {
        return "99".to_string();
    }
    format!("{}{}", p[0] as char, *p.last().unwrap() as char)
}

/// Everything [`ja4_client`] needs, already extracted by [`parse_tls_client_hello`]'s existing
/// bounds-checked extension walk — kept as a small struct purely so the assembly function reads
/// like the spec's own `a_b_c` structure instead of a 6-argument call.
struct Ja4ClientFields<'a> {
    version: u16,
    sni_present: bool,
    /// GREASE-excluded, wire (insertion) order — the SAME `ciphers`/`exts` vectors
    /// `parse_tls_client_hello` already builds for JA3.
    ciphers: &'a [u16],
    extensions: &'a [u16],
    /// GREASE-excluded, wire order (extension 0x000d's payload) — empty when the extension was
    /// absent, never fabricated.
    sig_algs: &'a [u16],
    alpn_first: Option<&'a [u8]>,
}

/// The JA4 TLS-CLIENT fingerprint: `t<version><sni><cipher_count><ext_count><alpn>_<b>_<c>` where
/// `<b>` = truncated-sha256 of the SORTED, GREASE-excluded cipher list and `<c>` = truncated-sha256
/// of the SORTED, GREASE+SNI+ALPN-excluded extension list, followed by `_<sigalgs>` (wire order) if
/// any signature_algorithms were present. `000000000000` stands in for an empty `<b>`/`<c>` hash
/// input (see this module's doc note 2) — never a `sha256("")` of nothing, so an operator can tell
/// "no ciphers/extensions at all" apart from "this exact GREASE-only set" at a glance.
fn ja4_client(f: &Ja4ClientFields) -> String {
    let version = ja4_version_code(f.version);
    let sni = if f.sni_present { 'd' } else { 'i' };
    let cipher_count = format!("{:02}", f.ciphers.len().min(99));
    let ext_count = format!("{:02}", f.extensions.len().min(99));
    let alpn = ja4_alpn_field(f.alpn_first);

    let mut sorted_ciphers = f.ciphers.to_vec();
    sorted_ciphers.sort_unstable();
    let b = if sorted_ciphers.is_empty() {
        "000000000000".to_string()
    } else {
        ja4_sha_trunc12(&join_hex4(sorted_ciphers))
    };

    let mut sorted_exts: Vec<u16> = f
        .extensions
        .iter()
        .copied()
        .filter(|e| *e != TLS_EXT_SERVER_NAME && *e != TLS_EXT_ALPN)
        .collect();
    sorted_exts.sort_unstable();
    let mut c_input = join_hex4(sorted_exts);
    if !f.sig_algs.is_empty() {
        c_input.push('_');
        c_input.push_str(&join_hex4(f.sig_algs.iter().copied()));
    }
    let c = if c_input.is_empty() { "000000000000".to_string() } else { ja4_sha_trunc12(&c_input) };

    format!("t{version}{sni}{cipher_count}{ext_count}{alpn}_{b}_{c}")
}

/// The JA4S TLS-SERVER fingerprint: `t<version><ext_count><alpn>_<cipher>_<c>`. Deliberately
/// DIFFERENT from JA4 in three ways the reference implementation makes explicit (a server's
/// response has no SNI concept, and echoing back exactly ONE chosen cipher/GREASE-extension IS
/// itself server-identifying signal, unlike a client's large offered list):
///   - no `sni` field (a server hello never carries one);
///   - `<cipher>` is the server's single CHOSEN cipher suite, written RAW (not hashed — there is
///     only ever one, so hashing it would just obscure a value already fully informative in the
///     clear);
///   - the extension list feeding `<c>` is **wire order, WITH GREASE INCLUDED** (never sorted,
///     never GREASE-filtered) — a server that echoes a GREASE extension back is itself a
///     distinguishing tell the client-side JA4 deliberately normalizes away, but JA4S deliberately
///     keeps.
fn ja4_server(version: u16, extensions_wire_order: &[u16], cipher: u16, alpn_first: Option<&[u8]>) -> String {
    let vcode = ja4_version_code(version);
    let ext_count = format!("{:02}", extensions_wire_order.len().min(99));
    let alpn = ja4_alpn_field(alpn_first);
    let c = if extensions_wire_order.is_empty() {
        "000000000000".to_string()
    } else {
        ja4_sha_trunc12(&join_hex4(extensions_wire_order.iter().copied()))
    };
    format!("t{vcode}{ext_count}{alpn}_{cipher:04x}_{c}")
}

/// JA4H's 2-lowercase-char HTTP-method field (`GET`->`ge`, `POST`->`po`, …) — every method
/// [`is_http_method`] accepts is already ≥3 ASCII bytes, so `take(2)` never underflows.
fn ja4_http_method(method: &[u8]) -> String {
    String::from_utf8_lossy(&method.to_ascii_lowercase()).chars().take(2).collect()
}

/// JA4H's 2-digit HTTP-version field: `"HTTP/1.1"` -> `"11"`, `"HTTP/1.0"` -> `"10"` (strip the
/// `"HTTP/"` prefix and the `.` separator). Falls back to `"11"` (HTTP/1.1) for anything that
/// doesn't cleanly reduce to two ASCII digits — the SAME default the reference implementation uses
/// when no version is known at all; never a fabricated/guessed digit pair.
fn ja4_http_version(proto: &[u8]) -> String {
    let rest = proto.strip_prefix(b"HTTP/").unwrap_or(proto);
    let digits: Vec<u8> = rest.iter().copied().filter(|&b| b != b'.').collect();
    if digits.len() == 2 && digits.iter().all(u8::is_ascii_digit) {
        String::from_utf8_lossy(&digits).to_string()
    } else {
        "11".to_string()
    }
}

/// JA4H's 4-char primary-language field from an `Accept-Language` header value (e.g.
/// `"en-US,en;q=0.9"` -> `"enus"`): strip `-`, fold `;` to `,`, lowercase, take the first
/// comma-separated token, then left-truncate/right-pad with `'0'` to exactly 4 characters.
/// `"0000"` when no `Accept-Language` header was present at all.
fn ja4_http_lang(accept_language: Option<&str>) -> String {
    let Some(raw) = accept_language else {
        return "0000".to_string();
    };
    let cleaned: String = raw
        .chars()
        .filter(|&c| c != '-')
        .map(|c| if c == ';' { ',' } else { c })
        .collect::<String>()
        .to_ascii_lowercase();
    let first = cleaned.split(',').next().unwrap_or("");
    let mut out: String = first.chars().take(4).collect();
    while out.len() < 4 {
        out.push('0');
    }
    out
}

/// The JA4H HTTP-CLIENT fingerprint:
/// `<method><version><cookie><referer><header_count><lang>_<headers>_<cookie_fields>_<cookie_values>`.
/// `<headers>` hashes the request's OTHER header NAMES (excluding Cookie/Referer), in WIRE ORDER,
/// ORIGINAL CASE — unlike JA4/JA4S this is truncated-sha256 of the header-name list EVEN WHEN
/// EMPTY (no `000000000000` empty-input special case here — a deliberate JA4H spec difference from
/// JA4/JA4S, per the reference implementation's unconditional `sha_encode(x['headers'])`).
/// `<cookie_fields>`/`<cookie_values>` are `"000000000000"` literally (not a hash of nothing) when
/// no `Cookie` header was present, else truncated-sha256 of the cookie NAMES / full `name=value`
/// pairs, both sorted by cookie name.
#[allow(clippy::too_many_arguments)]
fn ja4_http(
    method: &[u8],
    proto: &[u8],
    header_names: &[String],
    has_cookie: bool,
    has_referer: bool,
    accept_language: Option<&str>,
    sorted_cookie_pairs: &[(String, String)],
) -> String {
    let m = ja4_http_method(method);
    let v = ja4_http_version(proto);
    let cookie_flag = if has_cookie { 'c' } else { 'n' };
    let referer_flag = if has_referer { 'r' } else { 'n' };
    let header_count = format!("{:02}", header_names.len().min(99));
    let lang = ja4_http_lang(accept_language);
    let headers_hash = ja4_sha_trunc12(&header_names.join(","));
    let (fields_hash, values_hash) = if sorted_cookie_pairs.is_empty() {
        ("000000000000".to_string(), "000000000000".to_string())
    } else {
        let names = join_str(sorted_cookie_pairs.iter().map(|(n, _)| n.as_str()));
        let vals = join_str(sorted_cookie_pairs.iter().map(|(_, v)| v.as_str()));
        (ja4_sha_trunc12(&names), ja4_sha_trunc12(&vals))
    };
    format!("{m}{v}{cookie_flag}{referer_flag}{header_count}{lang}_{headers_hash}_{fields_hash}_{values_hash}")
}

fn join_str<'a, I: IntoIterator<Item = &'a str>>(xs: I) -> String {
    xs.into_iter().collect::<Vec<_>>().join(",")
}

/// Parse a TLS ClientHello → SNI, version, and the JA3 fingerprint (md5 of
/// version,ciphers,extensions,curves,point-formats — GREASE-filtered). Fully bounds-checked over
/// attacker-controlled bytes. None if not a ClientHello.
fn parse_tls_client_hello(l4: &L4, wall_ts: f64) -> Option<String> {
    let p = l4.payload;
    // TLS record: type(22=handshake) ver(2) len(2); handshake: type(1=client_hello) len(3) ver(2)...
    if p.len() < 43 || p[0] != 22 || p[5] != 1 {
        return None;
    }
    let ja3_ver = be16(p.get(9..11)?); // the ClientHello version (JA3 field 1)
    let ver = match ja3_ver {
        0x0301 => "TLSv1.0",
        0x0302 => "TLSv1.1",
        0x0303 => "TLSv1.2", // TLS1.3 also shows 0x0303 here; real version is in supported_versions
        0x0300 => "SSLv3",
        _ => "TLS",
    };
    // [0..5] record hdr, [5..9] hs hdr, [9..11] client version, [11..43] random.
    let mut i = 43;
    let sid_len = *p.get(i)? as usize;
    i += 1 + sid_len;
    // cipher suites
    let cs_len = be16(p.get(i..i + 2)?) as usize;
    i += 2;
    let cs_end = i + cs_len;
    let mut ciphers = Vec::new();
    while i + 2 <= cs_end && i + 2 <= p.len() {
        let c = be16(&p[i..i + 2]);
        if !is_grease(c) {
            ciphers.push(c);
        }
        i += 2;
    }
    i = cs_end;
    let comp_len = *p.get(i)? as usize;
    i += 1 + comp_len;
    let _ext_total = be16(p.get(i..i + 2)?);
    i += 2;
    let mut sni = None;
    // 2026-07-09 JA4 addition: `sni_ext_present` tracks the extension's EXISTENCE (JA4's 'd'/'i'
    // flag), independent of `sni`'s successful-parse content — a too-short-to-parse SNI extension
    // still counts as "SNI present" for JA4 even though `sni` itself stays `None` in that case.
    let mut sni_ext_present = false;
    let mut sig_algs: Vec<u16> = Vec::new(); // JA4's sigalg suffix (ext 0x000d), GREASE-excluded, wire order
    let mut alpn_first: Option<Vec<u8>> = None; // JA4's alpn field (ext 0x0010), first protocol offered
    let mut supported_versions: Vec<u16> = Vec::new(); // JA4's version override (ext 0x002b), raw (grease filtered later)
    let (mut exts, mut curves, mut formats) = (Vec::new(), Vec::new(), Vec::new());
    while i + 4 <= p.len() {
        let etype = be16(&p[i..i + 2]);
        let elen = be16(&p[i + 2..i + 4]) as usize;
        i += 4;
        if i + elen > p.len() {
            break;
        }
        let ext = &p[i..i + elen];
        if !is_grease(etype) {
            exts.push(etype);
        }
        match etype {
            TLS_EXT_SERVER_NAME => {
                sni_ext_present = true;
                if elen >= 5 {
                    // server_name: list_len(2) name_type(1) name_len(2) name
                    let nlen = be16(&ext[3..5]) as usize;
                    if 5 + nlen <= ext.len() {
                        sni = Some(String::from_utf8_lossy(&ext[5..5 + nlen]).to_string());
                    }
                }
            }
            10 if elen >= 2 => {
                // supported_groups: list_len(2) then u16 groups
                let mut j = 2;
                while j + 2 <= ext.len() {
                    let g = be16(&ext[j..j + 2]);
                    if !is_grease(g) {
                        curves.push(g);
                    }
                    j += 2;
                }
            }
            11 if elen >= 1 => {
                // ec_point_formats: list_len(1) then u8 formats
                let n = ext[0] as usize;
                for &f in ext.iter().skip(1).take(n) {
                    formats.push(f);
                }
            }
            TLS_EXT_SIGNATURE_ALGORITHMS if elen >= 2 => {
                // signature_algorithms: list_len(2) then u16 sig-scheme values, in wire order.
                let mut j = 2;
                while j + 2 <= ext.len() {
                    let sa = be16(&ext[j..j + 2]);
                    if !is_grease(sa) {
                        sig_algs.push(sa);
                    }
                    j += 2;
                }
            }
            TLS_EXT_ALPN if elen >= 2 => {
                // protocol_name_list: list_len(2) then (proto_len(1)+bytes)* — JA4 only needs the
                // FIRST offered protocol.
                let list_len = be16(&ext[0..2]) as usize;
                let mut j = 2;
                if list_len > 0 && j < ext.len() {
                    let plen = ext[j] as usize;
                    j += 1;
                    if j + plen <= ext.len() {
                        alpn_first = Some(ext[j..j + plen].to_vec());
                    }
                }
            }
            TLS_EXT_SUPPORTED_VERSIONS if elen >= 1 => {
                // ClientHello form: list_len(1) then u16 versions (GREASE included in the raw
                // list; `ja4_client_version` filters it when picking the max).
                let list_len = ext[0] as usize;
                let mut j = 1;
                while j + 2 <= ext.len() && (j - 1) < list_len {
                    supported_versions.push(be16(&ext[j..j + 2]));
                    j += 2;
                }
            }
            _ => {}
        }
        i += elen;
    }
    let ja3 = format!(
        "{},{},{},{},{}",
        ja3_ver,
        join_dec(&ciphers),
        join_dec(&exts),
        join_dec(&curves),
        join_dec(&formats)
    );
    let ja3_hash = hookprobe_manifest::md5::md5_hex(ja3.as_bytes());
    let ja4 = ja4_client(&Ja4ClientFields {
        version: ja4_client_version(ja3_ver, &supported_versions),
        sni_present: sni_ext_present,
        ciphers: &ciphers,
        extensions: &exts,
        sig_algs: &sig_algs,
        alpn_first: alpn_first.as_deref(),
    });

    let mut s = tuple_json(l4, wall_ts, "tls");
    s.push_str(&format!(
        ",\"service\":\"tls\",\"tls_version\":\"{ver}\",\"ja3\":\"{ja3_hash}\",\"ja4\":\"{ja4}\""
    ));
    if let Some(sni) = sni {
        s.push_str(&format!(",\"tls_sni\":\"{}\"", jesc(&sni)));
    }
    s.push('}');
    Some(s)
}

/// Parse a TLS ServerHello (the response half of the handshake JA4 hashes as JA4S) → the JA4S
/// fingerprint. Fully bounds-checked over attacker-controlled bytes; `None` if not a well-formed
/// ServerHello. The emitted flow record deliberately SWAPS src/dst relative to the raw packet: a
/// ServerHello is captured server→client on the wire (this function's `l4.src`/`l4.sport` IS the
/// server, port 443), but every OTHER record this module emits is attributed from the LAN
/// initiator's perspective (dst_port is always the server's well-known port) — swapping here keeps
/// that same convention, so `ingest_flow`'s device/application bucketing never misattributes a
/// `devices` row to a remote server's IP.
///
/// **Known, documented scope limit**: unlike the ClientHello record (whose `ja3`/`ja4`/`tls_sni`
/// all ride the SAME JSON line), this ServerHello record has no `tls_sni` of its own to bucket by
/// (a server hello carries no SNI) — it lands in `ingest_flow`'s `service:dst_port` ("tls:443")
/// application bucket, the SAME documented fallback bucket the module's own `ingest_flow` doc
/// comment already describes for any TLS record that doesn't carry a domain. This module does not
/// track ClientHello↔ServerHello state across packets to merge JA4 and JA4S onto the SAME
/// `applications` row when SNI was present — that would need a stateful per-flow tracker (like
/// `confirm::HandshakeTracker`), out of scope for this pure-parser addition; JA4S is still real,
/// non-fabricated, independently queryable evidence either way.
fn parse_tls_server_hello(l4: &L4, wall_ts: f64) -> Option<String> {
    let p = l4.payload;
    if p.len() < 43 || p[0] != 22 || p[5] != 2 {
        return None; // not a (TLS-record-framed) ServerHello
    }
    let legacy_version = be16(p.get(9..11)?);
    let mut i = 43usize;
    let sid_len = *p.get(i)? as usize;
    i += 1 + sid_len;
    let cipher = be16(p.get(i..i + 2)?); // the server's single CHOSEN cipher suite
    i += 2;
    i += 1; // compression_method — a single byte in a ServerHello (no length prefix, unlike ClientHello)

    let mut extensions_wire_order: Vec<u16> = Vec::new(); // JA4S keeps GREASE + wire order, see ja4_server's doc
    let mut supported_versions: Vec<u16> = Vec::new();
    let mut alpn_first: Option<Vec<u8>> = None;
    if let Some(ext_total_bytes) = p.get(i..i + 2) {
        let _ext_total = be16(ext_total_bytes);
        i += 2;
        while i + 4 <= p.len() {
            let etype = be16(&p[i..i + 2]);
            let elen = be16(&p[i + 2..i + 4]) as usize;
            i += 4;
            if i + elen > p.len() {
                break;
            }
            let ext = &p[i..i + elen];
            extensions_wire_order.push(etype); // GREASE included on purpose (JA4S, not JA4)
            match etype {
                TLS_EXT_SUPPORTED_VERSIONS if elen >= 2 => {
                    // ServerHello form: a BARE single u16 (not a length-prefixed list like the
                    // client's) — the server states exactly the ONE version it picked.
                    supported_versions.push(be16(&ext[0..2]));
                }
                TLS_EXT_ALPN if elen >= 2 => {
                    let list_len = be16(&ext[0..2]) as usize;
                    let mut j = 2;
                    if list_len > 0 && j < ext.len() {
                        let plen = ext[j] as usize;
                        j += 1;
                        if j + plen <= ext.len() {
                            alpn_first = Some(ext[j..j + plen].to_vec());
                        }
                    }
                }
                _ => {}
            }
            i += elen;
        }
    }
    let version = supported_versions.first().copied().unwrap_or(legacy_version);
    let ja4s = ja4_server(version, &extensions_wire_order, cipher, alpn_first.as_deref());

    Some(format!(
        "{{\"type\":\"tls\",\"ts\":{wall_ts:.3},\"src_ip\":\"{}\",\"src_port\":{},\
         \"dst_ip\":\"{}\",\"dst_port\":{},\"proto\":\"tcp\",\"service\":\"tls\",\"ja4s\":\"{}\"}}",
        l4.dst, l4.dport, l4.src, l4.sport, jesc(&ja4s)
    ))
}

/// Parse an HTTP request line + Host header from a plaintext request. Operates on RAW BYTES (the
/// payload is attacker-controlled and not necessarily UTF-8): `str` slicing would panic on a
/// non-char-boundary index (remote DoS), and requiring valid UTF-8 lets an attacker evade DPI with
/// one non-UTF-8 byte. We split on `\r\n` bytes, match ASCII tokens, and lossily convert only the
/// fields we emit.
fn parse_http(l4: &L4, wall_ts: f64) -> Option<String> {
    let mut lines = l4.payload.split(|&b| b == b'\n');
    // request line: METHOD SP URI SP HTTP/x (strip a trailing \r)
    let req = lines.next()?;
    let req = req.strip_suffix(b"\r").unwrap_or(req);
    let mut parts = req.split(|&b| b == b' ');
    let method = parts.next()?;
    let uri = parts.next()?;
    let proto = parts.next()?;
    if !proto.starts_with(b"HTTP/") || !is_http_method(method) {
        return None;
    }

    // Single pass over the header block — collects EVERYTHING this parser + JA4H (2026-07-09) need
    // from one walk (Host / Cookie / Accept-Language / a Referer-named header / the ordered
    // non-cookie-non-referer header-name list JA4H hashes): `lines` is a plain iterator, so it can
    // only be walked once, unlike the old Host-only `.find()`. Never panics on a malformed/
    // non-UTF-8 header line — a line with no `:` at all is skipped (less signal, not a wrong
    // parse), and every string field goes through `String::from_utf8_lossy` (byte-prefix matching
    // and raw `&[u8]` slicing only, never `str` slicing at a possibly-non-boundary index — the SAME
    // raw-byte discipline this function's own module doc calls out).
    let mut host = None;
    let mut accept_language: Option<String> = None;
    let mut has_cookie = false;
    let mut has_referer = false;
    let mut header_names: Vec<String> = Vec::new(); // JA4H_b input: wire order, original case, minus cookie/referer
    let mut cookie_pairs: Vec<(String, String)> = Vec::new(); // (name, "name=value") — sorted by name below
    for raw_line in lines {
        let l = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if l.is_empty() {
            break; // the blank line ends the header block (anything after is body, e.g. a POST payload)
        }
        let Some(colon) = l.iter().position(|&b| b == b':') else {
            continue; // malformed header line (no colon) — skip, never abort the whole parse
        };
        let name = String::from_utf8_lossy(&l[..colon]).to_string();
        let name_lower = name.to_ascii_lowercase();
        let value = String::from_utf8_lossy(l.get(colon + 1..).unwrap_or(&[])).trim().to_string();

        if name_lower == "host" && host.is_none() {
            host = Some(value.clone());
        }
        if name_lower.contains("referer") {
            has_referer = true;
        }
        if name_lower == "cookie" {
            has_cookie = true;
            // "a=1; b=2" -> [("a","a=1"), ("b","b=2")] — name = text before the first `=`, value =
            // the FULL trimmed "name=value" pair (matches the FoxIO reference implementation's own
            // cookie-pair construction, which JA4H_c/_d hash the name-half/whole-pair-half of).
            for part in value.split(';') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                let cname = part.split('=').next().unwrap_or("").trim().to_string();
                cookie_pairs.push((cname, part.to_string()));
            }
        } else if name_lower == "accept-language" && accept_language.is_none() {
            accept_language = Some(value);
        }
        if name_lower != "cookie" && !name_lower.contains("referer") {
            header_names.push(name);
        }
    }
    cookie_pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let ja4h = ja4_http(method, proto, &header_names, has_cookie, has_referer, accept_language.as_deref(), &cookie_pairs);

    let mut s = tuple_json(l4, wall_ts, "http");
    s.push_str(&format!(
        ",\"service\":\"http\",\"method\":\"{}\",\"uri\":\"{}\",\"ja4h\":\"{}\"",
        jesc(&String::from_utf8_lossy(method)), jesc(&String::from_utf8_lossy(uri)), jesc(&ja4h)
    ));
    if let Some(h) = host {
        s.push_str(&format!(",\"http_host\":\"{}\"", jesc(&h)));
    }
    s.push('}');
    Some(s)
}

fn is_http_method(m: &[u8]) -> bool {
    matches!(
        m,
        b"GET" | b"POST" | b"PUT" | b"DELETE" | b"HEAD" | b"OPTIONS" | b"PATCH" | b"CONNECT" | b"TRACE"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build eth+ipv4+udp/tcp around an L4 payload for the parsers. TCP flags default to 0.
    fn frame(proto: u8, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        frame_flags(proto, sport, dport, 0, payload)
    }

    // Same as `frame`, with an explicit TCP flags byte (ignored for UDP).
    fn frame_flags(proto: u8, sport: u16, dport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        frame_full(proto, sport, dport, flags, 0, 0, payload)
    }

    // Full control: explicit flags + seq + ack, and a fixed, recognizable src MAC so the MAC
    // extraction can be asserted on.
    fn frame_full(proto: u8, sport: u16, dport: u16, flags: u8, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // dst mac (unused)
        f[6..12].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // src mac — the observed one
        f[12] = 0x08; // ethertype IPv4
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45; // v4, ihl 5
        ip[9] = proto;
        ip[12..16].copy_from_slice(&[10, 66, 0, 20]);
        ip[16..20].copy_from_slice(&[1, 1, 1, 1]);
        f.extend_from_slice(&ip);
        if proto == 17 {
            let mut udp = vec![0u8; 8];
            udp[0..2].copy_from_slice(&sport.to_be_bytes());
            udp[2..4].copy_from_slice(&dport.to_be_bytes());
            f.extend_from_slice(&udp);
        } else {
            let mut tcp = vec![0u8; 20];
            tcp[0..2].copy_from_slice(&sport.to_be_bytes());
            tcp[2..4].copy_from_slice(&dport.to_be_bytes());
            tcp[4..8].copy_from_slice(&seq.to_be_bytes());
            tcp[8..12].copy_from_slice(&ack.to_be_bytes());
            tcp[12] = 5 << 4; // data offset 5
            tcp[13] = flags;
            f.extend_from_slice(&tcp);
        }
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn entropy_low_for_repeats_high_for_random() {
        assert!(shannon_entropy(b"aaaaaaaa") < 0.1);
        assert!(shannon_entropy(b"a7Fq9zK2Xp") > 2.5);
    }

    #[test]
    fn parses_dns_query_with_entropy() {
        // DNS header (id, flags, qd=1, others 0) + question "www.example.com" A IN
        let mut dns = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in ["www", "example", "com"] {
            dns.push(label.len() as u8);
            dns.extend_from_slice(label.as_bytes());
        }
        dns.push(0);
        dns.extend_from_slice(&[0, 1, 0, 1]); // type A, class IN
        let j = parse_frame(&frame(17, 40000, 53, &dns), 100.0).expect("dns");
        assert!(j.contains("\"type\":\"dns\""));
        assert!(j.contains("\"query\":\"www.example.com\""));
        assert!(j.contains("\"query_entropy\":"));
        assert!(j.contains("\"src_ip\":\"10.66.0.20\""));
    }

    #[test]
    fn parses_http_method_and_host() {
        let req = b"GET /login HTTP/1.1\r\nHost: intranet.local\r\nUser-Agent: x\r\n\r\n";
        let j = parse_frame(&frame(6, 51000, 80, req), 100.0).expect("http");
        assert!(j.contains("\"type\":\"http\""));
        assert!(j.contains("\"method\":\"GET\""));
        assert!(j.contains("\"uri\":\"/login\""));
        assert!(j.contains("\"http_host\":\"intranet.local\""));
    }

    #[test]
    fn ignores_non_signal_traffic() {
        // TCP to port 22 (ssh) — not one of the DPI ports
        assert!(parse_frame(&frame(6, 50000, 22, b"SSH-2.0-x"), 100.0).is_none());
    }

    #[test]
    fn parse_tcp_syn_flags_pure_syn_only() {
        // SYN set, ACK clear — a real connection attempt (what a port scan looks like).
        let f = frame_flags(6, 51000, 8080, TCP_SYN, b"");
        let syn = parse_tcp_syn(&f).expect("tcp frame parses");
        assert!(syn.syn_only);
        assert_eq!(syn.dport, 8080);
        assert_eq!(syn.sport, 51000);
        assert_eq!(syn.src, Ipv4Addr::new(10, 66, 0, 20));
        assert_eq!(syn.dst, Ipv4Addr::new(1, 1, 1, 1));
    }

    #[test]
    fn parse_tcp_syn_flags_synack_is_not_syn_only() {
        // SYN+ACK reply from an open port — not a scan probe, must not be classified syn_only.
        let f = frame_flags(6, 8080, 51000, TCP_SYN | TCP_ACK, b"");
        let syn = parse_tcp_syn(&f).expect("tcp frame parses");
        assert!(!syn.syn_only);
    }

    #[test]
    fn parse_tcp_syn_flags_ack_only_is_not_syn_only() {
        // Established-connection ACK/data traffic — must not count toward a scan.
        let f = frame_flags(6, 51000, 22, TCP_ACK, b"payload");
        let syn = parse_tcp_syn(&f).expect("tcp frame parses");
        assert!(!syn.syn_only);
    }

    #[test]
    fn parse_tcp_syn_rejects_udp() {
        assert!(parse_tcp_syn(&frame(17, 40000, 53, b"")).is_none());
    }

    // ---- parse_tcp_obs — observed MAC + full flags + seq/ack (the confirmation-gating feed) ---

    #[test]
    fn parse_tcp_obs_extracts_the_observed_src_mac_never_a_resolved_one() {
        let f = frame_full(6, 51000, 8080, TCP_SYN, 1000, 0, b"");
        let obs = parse_tcp_obs(&f).expect("tcp frame parses");
        assert_eq!(obs.src_mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], "must be the frame's OWN src mac");
        assert!(obs.syn && !obs.ack);
        assert_eq!(obs.seq, 1000);
        assert_eq!(obs.ack_num, 0);
    }

    #[test]
    fn parse_tcp_obs_reports_synack_flags_and_seq_ack_numbers() {
        let f = frame_full(6, 8080, 51000, TCP_SYN | TCP_ACK, 5000, 1001, b"");
        let obs = parse_tcp_obs(&f).expect("tcp frame parses");
        assert!(obs.syn && obs.ack);
        assert_eq!(obs.seq, 5000);
        assert_eq!(obs.ack_num, 1001);
    }

    #[test]
    fn parse_tcp_obs_reports_final_ack_only_and_payload_len() {
        let f = frame_full(6, 51000, 8080, TCP_ACK, 1001, 5001, b"hi");
        let obs = parse_tcp_obs(&f).expect("tcp frame parses");
        assert!(!obs.syn && obs.ack);
        assert_eq!(obs.seq, 1001);
        assert_eq!(obs.ack_num, 5001);
        assert_eq!(obs.payload_len, 2);
    }

    #[test]
    fn parse_tcp_obs_rejects_udp() {
        assert!(parse_tcp_obs(&frame(17, 40000, 53, b"")).is_none());
    }

    // ---- 2026-07-05 fan-out coverage fix (EDR #2): classify_scan_probe / ScanProbeKind ---------

    const TCP_FIN_BIT: u8 = 0x01;
    const TCP_PSH_BIT: u8 = 0x08;
    const TCP_URG_BIT: u8 = 0x20;

    #[test]
    fn classify_scan_probe_recognizes_syn_fin_null_and_xmas() {
        assert_eq!(classify_scan_probe(TCP_SYN), Some(ScanProbeKind::Syn));
        assert_eq!(classify_scan_probe(TCP_FIN_BIT), Some(ScanProbeKind::Fin));
        assert_eq!(classify_scan_probe(0), Some(ScanProbeKind::Null));
        assert_eq!(classify_scan_probe(TCP_FIN_BIT | TCP_PSH_BIT | TCP_URG_BIT), Some(ScanProbeKind::Xmas));
    }

    #[test]
    fn classify_scan_probe_never_fires_when_ack_is_set() {
        // ACK set on ANY of these shapes is established/return/teardown traffic, never a probe.
        for flags in [TCP_ACK, TCP_SYN | TCP_ACK, TCP_FIN_BIT | TCP_ACK, TCP_FIN_BIT | TCP_PSH_BIT | TCP_URG_BIT | TCP_ACK] {
            assert_eq!(classify_scan_probe(flags), None, "ACK set (flags {flags:#x}) must never classify as a probe");
        }
    }

    #[test]
    fn classify_scan_probe_ignores_ordinary_data_traffic() {
        // A normal PSH+ACK data segment, or a bare RST, are neither ACK-set nor one of the four
        // named probe shapes handled above (RST alone isn't a scan probe shape this covers).
        assert_eq!(classify_scan_probe(TCP_PSH_BIT), None, "bare PSH (no ACK) isn't one of the four named shapes");
        assert_eq!(classify_scan_probe(0x04 /* RST */), None, "bare RST isn't one of the four named shapes");
    }

    #[test]
    fn tcp_obs_scan_probe_kind_matches_the_raw_flags_classification() {
        let f = frame_flags(6, 51000, 8080, TCP_FIN_BIT, b"");
        let obs = parse_tcp_obs(&f).expect("tcp frame parses");
        assert_eq!(obs.scan_probe_kind(), Some(ScanProbeKind::Fin));
    }

    // ---- 2026-07-05 fan-out coverage fix (EDR #2): parse_udp_obs / parse_icmp_obs ---------------

    #[test]
    fn parse_udp_obs_extracts_the_4_tuple_and_observed_mac() {
        let f = frame_full(17, 40000, 33434, 0, 0, 0, b"");
        let obs = parse_udp_obs(&f).expect("udp frame parses");
        assert_eq!(obs.src_mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(obs.dport, 33434);
        assert_eq!(obs.src, Ipv4Addr::new(10, 66, 0, 20));
    }

    #[test]
    fn parse_udp_obs_rejects_tcp() {
        assert!(parse_udp_obs(&frame(6, 51000, 80, b"")).is_none());
    }

    fn icmp_frame(icmp_type: u8, icmp_code: u8) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[6..12].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        f[12] = 0x08; // ethertype IPv4
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = 1; // ICMPv4
        ip[12..16].copy_from_slice(&[10, 66, 0, 20]);
        ip[16..20].copy_from_slice(&[10, 66, 0, 99]);
        f.extend_from_slice(&ip);
        f.extend_from_slice(&[icmp_type, icmp_code, 0, 0]); // type, code, checksum(unused here)
        f
    }

    #[test]
    fn parse_icmp_obs_extracts_type_code_and_addresses() {
        let f = icmp_frame(ICMP_ECHO_REQUEST, 0);
        let obs = parse_icmp_obs(&f).expect("icmp frame parses");
        assert_eq!(obs.icmp_type, ICMP_ECHO_REQUEST);
        assert_eq!(obs.src, Ipv4Addr::new(10, 66, 0, 20));
        assert_eq!(obs.dst, Ipv4Addr::new(10, 66, 0, 99));
        assert_eq!(obs.src_mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn parse_icmp_obs_rejects_tcp() {
        assert!(parse_icmp_obs(&frame(6, 51000, 80, b"")).is_none());
    }

    // ---- L1/L2 defensive primitives (ADR 0020 Phase-1a) ---------------------------------------

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

    const NORMAL_SRC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    const BCAST: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

    #[test]
    fn eth_addrs_extracts_dst_and_src() {
        let f = pad_to(eth_frame(BCAST, NORMAL_SRC, 0x0800, &[]), 60);
        let (dst, src) = eth_addrs(&f).expect("long enough");
        assert_eq!(dst, BCAST);
        assert_eq!(src, NORMAL_SRC);
        assert!(eth_addrs(&[0u8; 10]).is_none(), "too short for even a bare eth header");
    }

    #[test]
    fn eth_type_and_offset_strips_exactly_one_vlan_tag() {
        let untagged = pad_to(eth_frame(BCAST, NORMAL_SRC, 0x0806, &[]), 60);
        assert_eq!(eth_type_and_offset(&untagged), Some((0x0806, 14)));

        let mut tagged = Vec::new();
        tagged.extend_from_slice(&BCAST);
        tagged.extend_from_slice(&NORMAL_SRC);
        tagged.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        tagged.extend_from_slice(&[0x00, 0x0a]); // VLAN id 10
        tagged.extend_from_slice(&0x0806u16.to_be_bytes());
        let tagged = pad_to(tagged, 60);
        assert_eq!(eth_type_and_offset(&tagged), Some((0x0806, 18)));
    }

    #[test]
    fn frame_anomaly_reason_is_none_for_a_benign_baseline_frame() {
        let f = pad_to(eth_frame([1, 2, 3, 4, 5, 6], NORMAL_SRC, 0x0800, &[0u8; 20]), 64);
        assert_eq!(frame_anomaly_reason(&f, DEFAULT_MIN_FRAME_LEN, DEFAULT_MAX_FRAME_LEN), None);
    }

    #[test]
    fn frame_anomaly_reason_flags_a_runt_frame() {
        let f = eth_frame([1, 2, 3, 4, 5, 6], NORMAL_SRC, 0x0800, &[]); // 14 bytes, below 60
        assert!(frame_anomaly_reason(&f, DEFAULT_MIN_FRAME_LEN, DEFAULT_MAX_FRAME_LEN).is_some());
    }

    // ---- 2026-07-05 false-positive fix (EDR #7) + 2026-07-07 protocol-aware runt floor fix -------

    #[test]
    fn frame_anomaly_reason_exempts_a_bare_54_byte_tcp_control_segment() {
        // 14 eth + 20 ipv4 (no options) + 20 tcp (no options) + 0 payload = 54 bytes exactly — a
        // real, well-formed bare ACK (what every handshake/teardown control packet looks like).
        for flags in [TCP_ACK, TCP_SYN, TCP_SYN | TCP_ACK, 0x04 /* RST */, 0x01 /* FIN */] {
            let f = frame_flags(6, 51000, 443, flags, b"");
            assert_eq!(f.len(), 54, "sanity: this frame shape must be exactly 54 bytes");
            assert_eq!(
                frame_anomaly_reason(&f, DEFAULT_MIN_FRAME_LEN, DEFAULT_MAX_FRAME_LEN),
                None,
                "a well-formed bare 54-byte TCP control segment (flags {flags:#x}) must NOT be flagged runt"
            );
        }
    }

    #[test]
    fn frame_anomaly_reason_exempts_a_well_formed_arp_frame_in_the_54_to_59_byte_window() {
        // A real ARP request (42 real bytes) with a FEW trailing pad bytes — short of the 60-byte
        // hardware floor but still >= the 54-byte exemption threshold and fully well-formed.
        let mut arp = Vec::new();
        arp.extend_from_slice(&1u16.to_be_bytes()); // htype ethernet
        arp.extend_from_slice(&0x0800u16.to_be_bytes()); // ptype ipv4
        arp.push(6); // hlen
        arp.push(4); // plen
        arp.extend_from_slice(&1u16.to_be_bytes()); // opcode: request
        arp.extend_from_slice(&NORMAL_SRC); // sender mac
        arp.extend_from_slice(&[10, 0, 0, 5]); // sender ip
        arp.extend_from_slice(&[0; 6]); // target mac
        arp.extend_from_slice(&[10, 0, 0, 1]); // target ip
        let f = pad_to(eth_frame(BCAST, NORMAL_SRC, ETHERTYPE_ARP, &arp), 57);
        assert!((54..60).contains(&f.len()), "sanity: must land inside the exemption window");
        assert_eq!(
            frame_anomaly_reason(&f, DEFAULT_MIN_FRAME_LEN, DEFAULT_MAX_FRAME_LEN),
            None,
            "a well-formed ARP packet in [54,60) must NOT be flagged runt"
        );
    }

    #[test]
    fn frame_anomaly_reason_still_flags_anything_shorter_than_54_bytes() {
        // 53 bytes — one short of the exemption floor, even though it's otherwise a well-formed
        // TCP header shape (just missing the last byte) — must still runt-flag.
        let f = frame_flags(6, 51000, 443, TCP_ACK, b"");
        let truncated = &f[..f.len() - 1];
        assert_eq!(truncated.len(), 53);
        assert!(
            frame_anomaly_reason(truncated, DEFAULT_MIN_FRAME_LEN, DEFAULT_MAX_FRAME_LEN).is_some(),
            "below the 54-byte exemption floor must still be flagged, well-formed-looking or not"
        );
    }

    #[test]
    fn frame_anomaly_reason_still_flags_54_to_59_byte_garbage_that_fails_to_parse() {
        // 56 bytes of an ethertype this parser doesn't recognize as IPv4/ARP at all — the
        // exemption must NOT apply to garbage merely because it clears the length floor.
        let f = pad_to(eth_frame([1, 2, 3, 4, 5, 6], NORMAL_SRC, 0x1234, &[0u8; 10]), 56);
        assert!(
            frame_anomaly_reason(&f, DEFAULT_MIN_FRAME_LEN, DEFAULT_MAX_FRAME_LEN).is_some(),
            "a frame in [54,60) that isn't well-formed IPv4/ARP must still runt-flag"
        );
    }

    #[test]
    fn frame_anomaly_reason_flags_an_oversized_frame() {
        let f = pad_to(eth_frame([1, 2, 3, 4, 5, 6], NORMAL_SRC, 0x0800, &[]), 2000);
        assert!(frame_anomaly_reason(&f, DEFAULT_MIN_FRAME_LEN, DEFAULT_MAX_FRAME_LEN).is_some());
    }

    // ---- 2026-07-07 CRITICAL fix: a real, UNPADDED ARP frame (42 bytes, not 54) must pass -------
    // Live pentest: an iPhone (locally-administered/randomized MAC) associated to `HookProbe` but
    // got NO connectivity — its ARP requests are a real, complete, 42-byte frame (14 eth + 28-byte
    // ARP body) with no hardware padding on a tc-mirror capture path, which used to be dropped as
    // "runt" because the old exemption floor (54) only covered TCP control segments, not ARP.

    fn arp_frame_exact(eth_src: [u8; 6], sender_mac: [u8; 6], sender_ip: [u8; 4], target_mac: [u8; 6], target_ip: [u8; 4], opcode: u16) -> Vec<u8> {
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
        eth_frame(BCAST, eth_src, ETHERTYPE_ARP, &arp) // NOT padded — 14 + 28 = 42 bytes exactly
    }

    #[test]
    fn frame_anomaly_reason_exempts_a_bare_42_byte_arp_frame_not_padded_to_54() {
        // The iOS-randomized-MAC regression case: a locally-administered unicast source MAC
        // (I/G bit clear — see the dedicated multicast-bit regression test below) sending a
        // completely ordinary, unpadded ARP request.
        let ios_random_mac = [0xaa, 0xff, 0x48, 0x06, 0xa6, 0x2d];
        let f = arp_frame_exact(ios_random_mac, ios_random_mac, [192, 168, 1, 50], [0; 6], [192, 168, 1, 1], 1);
        assert_eq!(f.len(), 42, "sanity: a real ARP frame with zero padding is exactly 42 bytes");
        assert_eq!(
            frame_anomaly_reason(&f, DEFAULT_MIN_FRAME_LEN, DEFAULT_MAX_FRAME_LEN),
            None,
            "a well-formed, unpadded 42-byte ARP frame must NOT be flagged runt — this is the exact \
             live false positive that broke Wi-Fi client connectivity"
        );
    }

    #[test]
    fn frame_anomaly_reason_still_flags_a_genuinely_truncated_arp_frame_below_42_bytes() {
        // One byte short of a complete ARP body (41 bytes total) — declares the standard shape
        // (hlen=6, plen=4) but is missing the last byte of `target_ip`. Must still runt-flag: the
        // protocol-aware exemption is length-AND-structure, never "any ARP-shaped prefix passes".
        let full = arp_frame_exact(NORMAL_SRC, NORMAL_SRC, [10, 0, 0, 5], [0; 6], [10, 0, 0, 1], 1);
        assert_eq!(full.len(), 42);
        let truncated = &full[..41];
        assert_eq!(
            frame_anomaly_reason(truncated, DEFAULT_MIN_FRAME_LEN, DEFAULT_MAX_FRAME_LEN),
            Some("runt frame (below the configured minimum Ethernet frame length, and not a structurally complete ARP/IPv4 TCP/UDP/ICMP packet)"),
            "a genuinely truncated ARP body (41 of 42 bytes) must still be flagged, not silently exempted"
        );
        // ...and it must not be silently misread as a non-malformed, non-mismatching, gratuitous
        // packet either — parse_arp_obs itself must return None for this shape (see its own doc
        // comment on the 2026-07-07 fix), not a "benign-looking" zeroed ArpObs.
        assert_eq!(parse_arp_obs(truncated), None, "a truncated-but-standard-shape ARP body must not parse as a complete (and therefore falsely non-malformed) ArpObs");
    }

    #[test]
    fn frame_anomaly_reason_still_flags_frames_shorter_than_a_bare_ethernet_header() {
        // Even shorter than the ARP case above — must hit the unconditional < 14 check, not the
        // protocol-aware exemption at all.
        let f = vec![0u8; 10];
        assert!(frame_anomaly_reason(&f, DEFAULT_MIN_FRAME_LEN, DEFAULT_MAX_FRAME_LEN).is_some());
    }

    #[test]
    fn frame_anomaly_reason_exempts_a_bare_42_byte_udp_datagram() {
        // The UDP analogue of the ARP fix above: 14 eth + 20 ipv4 (no opts) + 8 udp (no payload)
        // = 42 bytes exactly — legitimately shorter than the 54-byte TCP floor, and shorter than
        // the old flat exemption window, but a real, complete, well-formed packet.
        let f = frame(17, 51000, 53, b"");
        assert_eq!(f.len(), 42, "sanity: a bare UDP datagram with zero payload is exactly 42 bytes");
        assert_eq!(
            frame_anomaly_reason(&f, DEFAULT_MIN_FRAME_LEN, DEFAULT_MAX_FRAME_LEN),
            None,
            "a well-formed, unpadded 42-byte UDP datagram must NOT be flagged runt"
        );
    }

    #[test]
    fn frame_anomaly_reason_never_flags_a_locally_administered_unicast_source_mac() {
        // Regression guard for the multicast/group-bit (I/G bit, LSB of the first octet) source
        // MAC check: iOS's randomized MAC feature sets the LOCALLY-ADMINISTERED bit (bit 1,
        // 0x02) but leaves the INDIVIDUAL/GROUP bit (bit 0, 0x01) clear — it is still a unicast
        // address, and must never be confused with (or trip the same check as) a multicast/
        // broadcast SOURCE address. `0xaa` = 0b10101010: locally-administered bit set, I/G bit
        // clear.
        let ios_random_mac = [0xaa, 0xff, 0x48, 0x06, 0xa6, 0x2d];
        assert_eq!(ios_random_mac[0] & 0x01, 0, "sanity: this MAC's I/G bit must be clear (unicast)");
        assert_eq!(ios_random_mac[0] & 0x02, 0x02, "sanity: this MAC's locally-administered bit must be set");
        let f = pad_to(eth_frame([1, 2, 3, 4, 5, 6], ios_random_mac, 0x0800, &[0u8; 20]), 64);
        assert_eq!(
            frame_anomaly_reason(&f, DEFAULT_MIN_FRAME_LEN, DEFAULT_MAX_FRAME_LEN),
            None,
            "a locally-administered (randomized) but still-unicast source MAC must never be flagged \
             as a multicast/broadcast source"
        );
    }

    // ---- 2026-07-06 F6 fix (GSO/TSO false-positive on rule_id 1000033) -------------------------

    /// A 9000-byte TSO/GSO super-frame (a well-formed IPv4/TCP header chain with a large payload,
    /// exactly what a mirror-sink capture sees before hardware segmentation runs) whose Ethernet
    /// source IS one of the caller-supplied `local_macs` must NOT be flagged oversized/malformed —
    /// this is the confirmed live false positive (every rule 1000033 hit carried end0's own MAC).
    #[test]
    fn frame_anomaly_reason_local_exempts_a_9000_byte_tso_frame_from_the_local_mac() {
        let payload = vec![0u8; 9000 - 14 - 20 - 20]; // eth + ipv4(no opts) + tcp(no opts)
        let f = frame_full(6, 51000, 443, TCP_ACK, 1000, 5000, &payload);
        assert_eq!(f.len(), 9000, "sanity: this frame shape must be exactly 9000 bytes");
        // frame_full's fixed src mac (see its own doc) — this test's stand-in for "this host's own
        // end0 interface MAC".
        let local_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(
            frame_anomaly_reason_local(&f, DEFAULT_MIN_FRAME_LEN, DEFAULT_MAX_FRAME_LEN, &[local_mac]),
            None,
            "a well-formed 9000-byte TSO frame from this host's OWN mac must not be flagged"
        );
    }

    /// The SAME 9000-byte frame from a mac that ISN'T in `local_macs` (i.e. NOT this host's own
    /// interface) is still flagged — the exemption is a provenance carve-out for this host's own
    /// egress, never a blanket "any well-formed big packet is fine" rule.
    #[test]
    fn frame_anomaly_reason_local_still_flags_an_oversized_wellformed_frame_from_a_non_local_mac() {
        let payload = vec![0u8; 9000 - 14 - 20 - 20];
        let f = frame_full(6, 51000, 443, TCP_ACK, 1000, 5000, &payload);
        let unrelated_local_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x99]; // NOT this frame's src mac
        assert!(
            frame_anomaly_reason_local(&f, DEFAULT_MIN_FRAME_LEN, DEFAULT_MAX_FRAME_LEN, &[unrelated_local_mac])
                .is_some(),
            "a well-formed oversized frame from a mac that ISN'T in local_macs must still be flagged"
        );
    }

    /// A genuinely malformed, oversized, ingress (non-local-mac) frame — garbage bytes that fail
    /// `parse_l4`, not a well-formed TSO super-frame — must still fire even when the caller happens
    /// to pass a non-empty `local_macs` list: the structural-validity leg of the exemption still
    /// gates it out.
    #[test]
    fn frame_anomaly_reason_local_still_flags_a_genuinely_malformed_oversized_ingress_frame() {
        let attacker_mac = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
        // Garbage ethertype + garbage payload — never parses as IPv4 TCP/UDP.
        let f = pad_to(eth_frame([1, 2, 3, 4, 5, 6], attacker_mac, 0x1234, &vec![0xffu8; 2000]), 2000);
        let local_mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]; // some OTHER local interface
        assert!(
            frame_anomaly_reason_local(&f, DEFAULT_MIN_FRAME_LEN, DEFAULT_MAX_FRAME_LEN, &[local_mac])
                .is_some(),
            "a genuinely malformed oversized frame from a non-local mac must still be flagged"
        );
    }

    /// F6-extension (confirmed live on 10.200.0.4: end0's OWN mac firing rule 1000033 as a runt):
    /// a runt frame sourced from THIS host's own NIC mac is our own EGRESS frame captured before the
    /// NIC pads it to the 64-byte wire minimum — exempt, exactly like the oversized TSO case. The
    /// SAME runt from a non-local mac is still flagged (a real wire runt / fuzzing probe).
    #[test]
    fn frame_anomaly_reason_local_exempts_a_runt_frame_from_the_local_mac() {
        let local_mac = [0xdc, 0xa6, 0x32, 0xa4, 0xb6, 0x87]; // stand-in for this host's end0 mac
        // 14 eth + 26 payload = 40 bytes: below the [54, min_len) well-formed-IPv4 exemption floor,
        // so the ONLY thing that can exempt it is the local-mac provenance carve-out.
        let ours = eth_frame([1, 2, 3, 4, 5, 6], local_mac, 0x0800, &vec![0u8; 26]);
        assert_eq!(ours.len(), 40, "sanity: this is a runt frame");
        assert_eq!(
            frame_anomaly_reason_local(&ours, DEFAULT_MIN_FRAME_LEN, DEFAULT_MAX_FRAME_LEN, &[local_mac]),
            None,
            "a runt frame from this host's OWN mac must be exempt (pre-padding egress artifact)"
        );
        let attacker = eth_frame([1, 2, 3, 4, 5, 6], [0x02, 0, 0, 0, 0, 0x01], 0x0800, &vec![0u8; 26]);
        assert!(
            frame_anomaly_reason_local(&attacker, DEFAULT_MIN_FRAME_LEN, DEFAULT_MAX_FRAME_LEN, &[local_mac])
                .is_some(),
            "a runt frame from a NON-local mac must still be flagged"
        );
    }

    /// The plain (pre-existing) 3-arg `frame_anomaly_reason` entry point has no local-MAC context at
    /// all (`local_macs` is implicitly empty) — a locally-shaped TSO frame through THAT entry point
    /// still flags exactly as before this fix (no silent behavior change for any caller that hasn't
    /// been updated to pass local MACs — see the module's own doc for why the plain entry point
    /// stays supported unchanged).
    #[test]
    fn frame_anomaly_reason_plain_entry_point_is_unaffected_by_the_f6_fix() {
        let payload = vec![0u8; 9000 - 14 - 20 - 20];
        let f = frame_full(6, 51000, 443, TCP_ACK, 1000, 5000, &payload);
        assert!(
            frame_anomaly_reason(&f, DEFAULT_MIN_FRAME_LEN, DEFAULT_MAX_FRAME_LEN).is_some(),
            "the plain entry point (no local-mac context) must keep flagging oversized frames"
        );
    }

    #[test]
    fn frame_anomaly_reason_flags_a_multicast_source_mac() {
        let bogus_src = [0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]; // multicast bit set — invalid source
        let f = pad_to(eth_frame([1, 2, 3, 4, 5, 6], bogus_src, 0x0800, &[]), 64);
        let r = frame_anomaly_reason(&f, DEFAULT_MIN_FRAME_LEN, DEFAULT_MAX_FRAME_LEN);
        assert!(r.is_some_and(|s| s.contains("multicast/group bit")));
    }

    #[test]
    fn frame_anomaly_reason_flags_a_double_tagged_vlan_frame() {
        let mut f = Vec::new();
        f.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        f.extend_from_slice(&NORMAL_SRC);
        f.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        f.extend_from_slice(&[0x00, 0x0a]);
        f.extend_from_slice(&ETHERTYPE_VLAN.to_be_bytes()); // stacked tag — QinQ
        f.extend_from_slice(&[0x00, 0x0b]);
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        let f = pad_to(f, 64);
        let r = frame_anomaly_reason(&f, DEFAULT_MIN_FRAME_LEN, DEFAULT_MAX_FRAME_LEN);
        assert!(r.is_some_and(|s| s.contains("double/stacked")));
    }

    #[test]
    fn frame_anomaly_reason_never_panics_on_a_truncated_vlan_tag() {
        // Declares a VLAN ethertype but has no room for the tag's 4 bytes — must not panic/index
        // out of bounds on attacker-controlled length.
        let mut f = vec![0u8; 16];
        f[12..14].copy_from_slice(&ETHERTYPE_VLAN.to_be_bytes());
        assert!(frame_anomaly_reason(&f, 0, 65535).is_some());
    }

    fn arp_frame(eth_src: [u8; 6], sender_mac: [u8; 6], sender_ip: [u8; 4], target_mac: [u8; 6], target_ip: [u8; 4], opcode: u16) -> Vec<u8> {
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
        pad_to(eth_frame(BCAST, eth_src, ETHERTYPE_ARP, &arp), 60)
    }

    #[test]
    fn parse_arp_obs_extracts_a_well_formed_request() {
        let f = arp_frame(NORMAL_SRC, NORMAL_SRC, [10, 0, 0, 5], [0; 6], [10, 0, 0, 1], 1);
        let obs = parse_arp_obs(&f).expect("valid arp");
        assert!(!obs.is_malformed());
        assert!(!obs.eth_mismatch(), "sender mac matches eth src here");
        assert!(!obs.is_gratuitous());
        assert_eq!(obs.sender_ip, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(obs.target_ip, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn parse_arp_obs_flags_gratuitous_arp() {
        let f = arp_frame(NORMAL_SRC, NORMAL_SRC, [10, 0, 0, 5], [0; 6], [10, 0, 0, 5], 1);
        let obs = parse_arp_obs(&f).expect("valid arp");
        assert!(obs.is_gratuitous());
    }

    #[test]
    fn parse_arp_obs_flags_sender_mac_eth_src_mismatch() {
        let attacker_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        // Ethernet frame is sent BY attacker_mac, but the ARP payload claims to be NORMAL_SRC.
        let f = arp_frame(attacker_mac, NORMAL_SRC, [10, 0, 0, 5], [0; 6], [10, 0, 0, 1], 2);
        let obs = parse_arp_obs(&f).expect("valid arp");
        assert!(obs.eth_mismatch(), "sender_mac in the ARP body must be compared to the eth frame's OWN src mac");
    }

    #[test]
    fn parse_arp_obs_flags_a_non_standard_htype_or_plen_as_malformed() {
        let mut arp = Vec::new();
        arp.extend_from_slice(&7u16.to_be_bytes()); // bogus htype
        arp.extend_from_slice(&0x0800u16.to_be_bytes());
        arp.push(6);
        arp.push(4);
        arp.extend_from_slice(&1u16.to_be_bytes());
        arp.extend_from_slice(&[0u8; 20]);
        let f = pad_to(eth_frame(BCAST, NORMAL_SRC, ETHERTYPE_ARP, &arp), 60);
        let obs = parse_arp_obs(&f).expect("still parses — malformed, not absent");
        assert!(obs.is_malformed());
        assert!(!obs.eth_mismatch(), "malformed packets never assert an eth-mismatch on zeroed fields");
        assert!(!obs.is_gratuitous());
    }

    #[test]
    fn parse_arp_obs_rejects_non_arp_ethertype() {
        let f = pad_to(eth_frame(BCAST, NORMAL_SRC, 0x0800, &[0u8; 20]), 60);
        assert!(parse_arp_obs(&f).is_none());
    }

    #[test]
    fn parse_arp_obs_never_panics_on_a_truncated_arp_header() {
        let f = eth_frame(BCAST, NORMAL_SRC, ETHERTYPE_ARP, &[0u8; 3]); // shorter than the 8-byte header
        assert!(parse_arp_obs(&f).is_none());
    }

    #[test]
    fn http_hostile_input_does_not_panic() {
        // A Host header whose byte 5 lands mid-codepoint used to panic on `l[..5]`.
        let mut req = b"GET / HTTP/1.1\r\n".to_vec();
        req.extend_from_slice("a\u{20ac}\u{20ac}x\r\n\r\n".as_bytes()); // € = 3 bytes
        // must not panic; parses the request line, ignores the malformed header
        let j = parse_frame(&frame(6, 50000, 80, &req), 100.0).expect("http still parses");
        assert!(j.contains("\"method\":\"GET\""));
        // and a raw non-UTF-8 byte in the payload must not stop parsing (evasion)
        let mut req2 = b"POST /x HTTP/1.1\r\nHost: h\xffst.local\r\n\r\n".to_vec();
        req2.push(0);
        let j2 = parse_frame(&frame(6, 50000, 80, &req2), 100.0).expect("non-utf8 still parses");
        assert!(j2.contains("\"method\":\"POST\""));
    }

    // ================================================================================================
    // 2026-07-09 detection-surface expansion: JA4 / JA4S / JA4H (roadmap item B).
    //
    // Every expected fingerprint string below was cross-computed against the FoxIO reference
    // algorithm (an independent Python re-implementation of `to_ja4`/`to_ja4s`/`to_ja4h` — see the
    // `ja4_client`/`ja4_server`/`ja4_http` doc comments for the exact source URLs) over the SAME
    // byte layout these builders construct, so a passing test here is a byte-for-byte match against
    // the published spec, not just internal self-consistency.
    // ================================================================================================

    /// A tiny TLS extension serializer: `type(2) len(2) data` — used by the ClientHello/ServerHello
    /// builders below so their byte layout is computed (never manually summed/hand-counted).
    fn tls_ext(etype: u16, data: &[u8]) -> Vec<u8> {
        let mut e = etype.to_be_bytes().to_vec();
        e.extend_from_slice(&(data.len() as u16).to_be_bytes());
        e.extend_from_slice(data);
        e
    }

    /// Builds a well-formed TLS 1.3-shaped ClientHello record: legacy_version 0x0303, 2 ciphers
    /// (offered in NON-sorted wire order, proving JA4_b's own sort), SNI "example.com",
    /// `supported_versions` (TLS 1.3 only, no GREASE), `signature_algorithms` (one scheme), and ALPN
    /// "h2" — deliberately including one extension the OLD JA3-only parser already understood
    /// (SNI) and three brand-new-to-JA4 ones (supported_versions/signature_algorithms/ALPN) in the
    /// SAME hello, so this one fixture exercises every new code path at once.
    fn client_hello_record() -> Vec<u8> {
        let sni_host = b"example.com";
        let sni_data = {
            let mut d = vec![0u8, 0u8]; // server_name_list length placeholder
            let list_len = (1 + 2 + sni_host.len()) as u16;
            d[0..2].copy_from_slice(&list_len.to_be_bytes());
            d.push(0); // name_type = host_name
            d.extend_from_slice(&(sni_host.len() as u16).to_be_bytes());
            d.extend_from_slice(sni_host);
            d
        };
        let supported_versions_data = {
            let mut d = vec![2u8]; // list length in BYTES (1 entry * 2 bytes)
            d.extend_from_slice(&0x0304u16.to_be_bytes()); // TLS 1.3, no GREASE
            d
        };
        let sigalgs_data = {
            let mut d = 2u16.to_be_bytes().to_vec(); // list length in BYTES (1 entry * 2 bytes)
            d.extend_from_slice(&0x0403u16.to_be_bytes());
            d
        };
        let alpn_proto = b"h2";
        let alpn_data = {
            let mut entry = vec![alpn_proto.len() as u8];
            entry.extend_from_slice(alpn_proto);
            let mut d = (entry.len() as u16).to_be_bytes().to_vec();
            d.extend_from_slice(&entry);
            d
        };
        let mut extensions = Vec::new();
        extensions.extend(tls_ext(TLS_EXT_SERVER_NAME, &sni_data));
        extensions.extend(tls_ext(TLS_EXT_SUPPORTED_VERSIONS, &supported_versions_data));
        extensions.extend(tls_ext(TLS_EXT_SIGNATURE_ALGORITHMS, &sigalgs_data));
        extensions.extend(tls_ext(TLS_EXT_ALPN, &alpn_data));

        let ciphers_wire = [0x1302u16, 0x1301u16]; // deliberately unsorted
        let mut cipher_bytes = Vec::new();
        for c in ciphers_wire {
            cipher_bytes.extend_from_slice(&c.to_be_bytes());
        }

        let mut body = 0x0303u16.to_be_bytes().to_vec(); // legacy client_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id_len = 0
        body.extend_from_slice(&(cipher_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(&cipher_bytes);
        body.push(1); // compression methods length = 1
        body.push(0); // compression method: null
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![1u8]; // handshake type: client_hello
        let hs_len = (body.len() as u32).to_be_bytes();
        handshake.extend_from_slice(&hs_len[1..4]); // 3-byte length
        handshake.extend_from_slice(&body);

        let mut record = vec![22u8]; // content type: handshake
        record.extend_from_slice(&0x0301u16.to_be_bytes()); // record-layer version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn ja4_client_matches_the_foxio_reference_algorithm() {
        let payload = client_hello_record();
        let j = parse_frame(&frame(6, 51000, 443, &payload), 100.0).expect("clienthello parses");
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        // Independently cross-computed (see this test-module-section's own doc comment) against
        // the SAME byte layout `client_hello_record()` builds: version=TLS1.3 (from
        // supported_versions, NOT the 0x0303 legacy field), sni='d', cipher_count=02 (sorted
        // "1301,1302"), ext_count=04 (SNI+supported_versions+sigalgs+ALPN, none GREASE), alpn="h2",
        // JA4_c over the SNI/ALPN-stripped+sorted [supported_versions,sigalgs]="000d,002b" plus the
        // "_0403" signature-algorithm suffix.
        assert_eq!(v["ja4"], "t13d0204h2_62ed6f6ca7ad_3953dc75acc4");
        // JA3 must still be present + unaffected — JA4 is additive, never a replacement.
        assert!(v["ja3"].as_str().is_some_and(|s| s.len() == 32), "ja3 stays a 32-hex-char md5");
        assert_eq!(v["tls_sni"], "example.com");
    }

    #[test]
    fn ja4_client_empty_ciphers_and_extensions_use_the_all_zero_sentinel() {
        // A degenerate (but structurally well-formed) ClientHello with zero ciphers and zero
        // extensions must render JA4_b/JA4_c as the literal "000000000000" sentinel, never
        // `sha256("")` truncated — see `ja4_client`'s own doc note on this.
        let mut body = 0x0303u16.to_be_bytes().to_vec();
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // session_id_len
        body.extend_from_slice(&0u16.to_be_bytes()); // zero ciphers
        body.push(1);
        body.push(0); // compression
        body.extend_from_slice(&0u16.to_be_bytes()); // zero extensions
        let mut handshake = vec![1u8];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        handshake.extend_from_slice(&body);
        let mut record = vec![22u8];
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        let j = parse_frame(&frame(6, 51000, 443, &record), 100.0).expect("clienthello parses");
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        // legacy_version 0x0303 (no supported_versions ext -> "12"), no SNI ext ('i'), zero
        // ciphers/extensions ("00"/"00"), no ALPN ("00").
        assert_eq!(v["ja4"], "t12i000000_000000000000_000000000000");
    }

    #[test]
    fn ja4_grease_values_are_excluded_from_ja4_but_never_cause_a_panic() {
        // GREASE ciphers/extensions/supported_versions interleaved with real ones — JA4's own
        // count/sort/hash fields must all be computed as if the GREASE entries were never there
        // (RFC 8701; the SAME discipline JA3 above already applies via `is_grease`).
        let sni_host = b"g.example";
        let sni_data = {
            let mut d = 0u16.to_be_bytes().to_vec();
            let list_len = (1 + 2 + sni_host.len()) as u16;
            d[0..2].copy_from_slice(&list_len.to_be_bytes());
            d.push(0);
            d.extend_from_slice(&(sni_host.len() as u16).to_be_bytes());
            d.extend_from_slice(sni_host);
            d
        };
        let mut extensions = Vec::new();
        extensions.extend(tls_ext(0x0a0a, &[])); // GREASE extension, zero-length
        extensions.extend(tls_ext(TLS_EXT_SERVER_NAME, &sni_data));

        let ciphers_wire = [0x0a0au16, 0x1301u16, 0x1a1au16]; // GREASE, real, GREASE
        let mut cipher_bytes = Vec::new();
        for c in ciphers_wire {
            cipher_bytes.extend_from_slice(&c.to_be_bytes());
        }
        let mut body = 0x0303u16.to_be_bytes().to_vec();
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&(cipher_bytes.len() as u16).to_be_bytes());
        body.extend_from_slice(&cipher_bytes);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut handshake = vec![1u8];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        handshake.extend_from_slice(&body);
        let mut record = vec![22u8];
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        let j = parse_frame(&frame(6, 51000, 443, &record), 100.0).expect("clienthello parses");
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        let ja4 = v["ja4"].as_str().unwrap();
        // cipher_count "01" (only the one real, non-GREASE cipher); ext_count "01" (only SNI —
        // GREASE extensions are excluded from JA4_a's count, unlike JA4S below).
        assert!(ja4.starts_with("t12d0101"), "ja4={ja4}");
    }

    #[test]
    fn ja4_never_panics_on_truncated_extension_data() {
        // A ClientHello whose LAST extension declares a length that overruns the buffer — the
        // existing bounds check (`if i + elen > p.len() { break; }`) must still hold with the new
        // JA4 extension-parsing arms added; this must return a value (JA4 computed over whatever
        // extensions WERE fully readable), never panic.
        let mut body = 0x0303u16.to_be_bytes().to_vec();
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&0u16.to_be_bytes()); // zero ciphers
        body.push(1);
        body.push(0);
        // one extension header claiming 100 bytes of data that isn't actually there
        let mut ext_block = TLS_EXT_SIGNATURE_ALGORITHMS.to_be_bytes().to_vec();
        ext_block.extend_from_slice(&100u16.to_be_bytes());
        ext_block.extend_from_slice(&[0u8; 4]); // far short of the declared 100
        body.extend_from_slice(&(ext_block.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_block);
        let mut handshake = vec![1u8];
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        handshake.extend_from_slice(&body);
        let mut record = vec![22u8];
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        let j = parse_frame(&frame(6, 51000, 443, &record), 100.0).expect("still parses, doesn't panic");
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        // The truncated extension is discarded BEFORE being counted (the existing bounds check
        // breaks the loop before `exts.push(etype)` runs) — same all-zero shape as the empty-hello
        // case above: zero ciphers, zero (successfully parsed) extensions, no SNI, no ALPN.
        assert_eq!(v["ja4"], "t12i000000_000000000000_000000000000");
    }

    /// Builds a well-formed TLS 1.3-shaped ServerHello record: legacy_version 0x0303, ONE chosen
    /// cipher, and three extensions in wire order — a GREASE extension FIRST (proving JA4S keeps
    /// it, unlike JA4), then `supported_versions` (TLS 1.3, bare single u16 — the ServerHello wire
    /// form, NOT the ClientHello's length-prefixed list), then ALPN "h2".
    fn server_hello_record() -> Vec<u8> {
        let mut extensions = Vec::new();
        extensions.extend(tls_ext(0x0a0a, &[])); // GREASE — must survive into JA4S's hash+count
        extensions.extend(tls_ext(TLS_EXT_SUPPORTED_VERSIONS, &0x0304u16.to_be_bytes()));
        let alpn_proto = b"h2";
        let alpn_data = {
            let mut entry = vec![alpn_proto.len() as u8];
            entry.extend_from_slice(alpn_proto);
            let mut d = (entry.len() as u16).to_be_bytes().to_vec();
            d.extend_from_slice(&entry);
            d
        };
        extensions.extend(tls_ext(TLS_EXT_ALPN, &alpn_data));

        let mut body = 0x0303u16.to_be_bytes().to_vec(); // legacy_version
        body.extend_from_slice(&[0u8; 32]); // random
        body.push(0); // session_id_len
        body.extend_from_slice(&0x1302u16.to_be_bytes()); // the ONE chosen cipher
        body.push(0); // compression method
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![2u8]; // handshake type: server_hello
        handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..4]);
        handshake.extend_from_slice(&body);

        let mut record = vec![22u8];
        record.extend_from_slice(&0x0301u16.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn ja4s_matches_the_foxio_reference_algorithm_and_keeps_grease() {
        // Captured server->client (sport 443) — parse_frame's ServerHello arm.
        let payload = server_hello_record();
        let j = parse_frame(&frame(6, 443, 55000, &payload), 100.0).expect("serverhello parses");
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        // Independently cross-computed: version=13 (from the bare supported_versions u16), ext_count
        // =03 (GREASE included!), alpn="h2", cipher="1302" (raw, not hashed), JA4S_c over the WIRE-
        // ORDER (not sorted) extension list INCLUDING the GREASE entry: "0a0a,002b,0010".
        assert_eq!(v["ja4s"], "t1303h2_1302_02a34fb8a812");
        // The record is attributed from the CLIENT's perspective (src/dst swapped from the raw
        // server->client packet) — dst_port must be 443 (the server), not the packet's own sport.
        assert_eq!(v["dst_port"], 443);
        assert_eq!(v["src_port"], 55000);
    }

    #[test]
    fn ja4s_never_panics_on_a_truncated_serverhello() {
        assert!(parse_frame(&frame(6, 443, 55000, &[22, 3, 1, 0, 2, 2]), 100.0).is_none());
        assert!(parse_frame(&frame(6, 443, 55000, &[]), 100.0).is_none());
    }

    #[test]
    fn ja4s_rejects_a_clienthello_shaped_packet_from_port_443() {
        // p[5]==1 (client_hello), not 2 (server_hello) — even though it arrives with sport==443,
        // it must not be misparsed as a ServerHello.
        let payload = client_hello_record();
        assert!(parse_tls_server_hello(
            &L4 {
                src_mac: [0; 6], src: Ipv4Addr::new(1, 1, 1, 1), dst: Ipv4Addr::new(2, 2, 2, 2),
                proto: 6, sport: 443, dport: 55000, payload: &payload, tcp_flags: 0, seq: 0, ack_num: 0,
            },
            100.0
        ).is_none());
    }

    // ---- JA4H (HTTP client) -------------------------------------------------------------------

    fn http_request(extra_headers: &str) -> Vec<u8> {
        let mut req = b"GET /path HTTP/1.1\r\n".to_vec();
        req.extend_from_slice(extra_headers.as_bytes());
        req.extend_from_slice(b"\r\n");
        req
    }

    #[test]
    fn ja4h_matches_the_foxio_reference_algorithm_with_cookies_and_referer() {
        let req = http_request(
            "Host: example.com\r\nAccept-Language: en-US,en;q=0.9\r\nUser-Agent: test-agent\r\n\
             Cookie: a=1; b=2\r\nReferer: http://example.com/\r\n",
        );
        let j = parse_frame(&frame(6, 51000, 80, &req), 100.0).expect("http parses");
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        // Independently cross-computed: method="ge", version="11", cookie='c', referer='r',
        // header_count="03" (Host/Accept-Language/User-Agent — Cookie+Referer excluded), lang=
        // "enus", headers hash over "Host,Accept-Language,User-Agent" (wire order, original case),
        // cookie-name hash over sorted "a,b", cookie-pair hash over sorted "a=1,b=2".
        assert_eq!(v["ja4h"], "ge11cr03enus_295e410d3834_1eb7c54d5283_06beefe2b477");
    }

    #[test]
    fn ja4h_no_cookie_no_referer_no_lang_uses_the_all_zero_cookie_sentinel() {
        let req = http_request("Host: intranet.local\r\nUser-Agent: x\r\n");
        let j = parse_frame(&frame(6, 51000, 80, &req), 100.0).expect("http parses");
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        let ja4h = v["ja4h"].as_str().unwrap();
        // "n" cookie, "n" referer, "0000" lang, header_count "02" — and the cookie-hash HALVES are
        // the literal all-zero sentinel (never a hash of an empty string) when no Cookie header at
        // all was present, mirroring JA4/JA4S's own empty-input sentinel discipline.
        assert!(ja4h.starts_with("ge11nn020000_"), "ja4h={ja4h}");
        assert!(ja4h.ends_with("_000000000000_000000000000"), "ja4h={ja4h}");
    }

    #[test]
    fn ja4h_never_panics_on_a_cookie_header_with_hostile_bytes() {
        let mut req = b"GET / HTTP/1.1\r\nHost: x\r\nCookie: ".to_vec();
        req.extend_from_slice(b"\xff\xfe=;;;===\r\n\r\n");
        let j = parse_frame(&frame(6, 51000, 80, &req), 100.0).expect("still parses, doesn't panic");
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert!(v["ja4h"].as_str().unwrap().starts_with("ge11c"));
    }
}
