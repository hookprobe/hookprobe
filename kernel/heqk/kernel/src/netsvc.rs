//! PH6 — smoltcp net service (stack-integration core).
//!
//! smoltcp runs ABOVE the P17 rule plane, never beside it: an ingress frame is admitted to
//! smoltcp ONLY if `packet::verdict` PASSes it, and any egress frame smoltcp produces is
//! emitted ONLY if it PASSes too — the exact dual-gate the P17 netq enforces (`rx_publish`
//! ingress, `tx_drain` egress). On the production target this runs as an EL0-ISOLATED
//! service over the netq (the largest attack surface, so it must not sit in the kernel TCB —
//! that isolation + a TRNG seed + a PCR3 measurement is the metal half, deferred). THIS
//! module is the stack integration and its QEMU gate: smoltcp answers an ARP for its own IP
//! with both the request and the reply passing the rule plane.
#![cfg(feature = "netsvc")]

use crate::packet;
use smoltcp::iface::{Config, Interface, SocketSet, SocketStorage};
use smoltcp::phy::{self, Checksum, ChecksumCapabilities, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};

const MTU: usize = 1514;

struct TxSink {
    buf: [u8; MTU],
    len: usize,
    ready: bool,
    dropped_out: u32,
    tx_lost: u32, // AUDIT D1: frames smoltcp emitted that overwrote an undrained slot
}

/// A `phy::Device` backed by one rule-gated rx slot + one egress-gated tx capture.
pub struct RuleGatedDev {
    rx: Option<([u8; MTU], usize)>,
    tx: TxSink,
    /// Per-device checksum policy. Default `ignored()` (the ARP-only / hand-built-frame
    /// selftests need no valid checksums); the MetalBridge sets tx-compute so ICMP/IP replies
    /// carry VALID checksums the real host kernel will accept (an ARP reply has none, which is
    /// why ARP first-light worked with `ignored()`, but ICMP echo does).
    csum: ChecksumCapabilities,
}

impl RuleGatedDev {
    fn new() -> Self {
        RuleGatedDev {
            rx: None,
            tx: TxSink { buf: [0; MTU], len: 0, ready: false, dropped_out: 0, tx_lost: 0 },
            csum: ChecksumCapabilities::ignored(),
        }
    }
    /// INGRESS gate — admit a frame to smoltcp only if the verified rule plane PASSes it.
    fn ingress(&mut self, frame: &[u8]) -> bool {
        if packet::verdict(frame).1 != packet::PASS {
            return false;
        }
        let n = frame.len().min(MTU);
        let mut b = [0u8; MTU];
        b[..n].copy_from_slice(&frame[..n]);
        self.rx = Some((b, n));
        true
    }
}

pub struct RxTok {
    frame: [u8; MTU],
    len: usize,
}
impl phy::RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.frame[..self.len])
    }
}

pub struct TxTok<'a> {
    sink: &'a mut TxSink,
}
impl<'a> phy::TxToken for TxTok<'a> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let n = len.min(MTU);
        let mut tmp = [0u8; MTU];
        let r = f(&mut tmp[..n]);
        // EGRESS gate — emit only what the rule plane PASSes (mirrors P17 tx_drain).
        if packet::verdict(&tmp[..n]).1 == packet::PASS {
            // AUDIT D1: smoltcp can emit several frames per poll; this single-slot sink
            // keeps the latest, but an undrained previous frame is a COUNTED loss, never
            // a silent one. (The metal netq service uses a real multi-slot ring.)
            if self.sink.ready {
                self.sink.tx_lost += 1;
            }
            self.sink.buf[..n].copy_from_slice(&tmp[..n]);
            self.sink.len = n;
            self.sink.ready = true;
        } else {
            self.sink.dropped_out += 1;
        }
        r
    }
}

impl Device for RuleGatedDev {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.max_transmission_unit = MTU;
        c.medium = Medium::Ethernet;
        c.checksum = self.csum.clone();
        c
    }
    fn receive(&mut self, _t: Instant) -> Option<(RxTok, TxTok<'_>)> {
        // Split-borrow: the rx frame is MOVED out (owned by RxTok); tx borrows a
        // disjoint field — so both tokens can coexist.
        let (frame, len) = self.rx.take()?;
        Some((RxTok { frame, len }, TxTok { sink: &mut self.tx }))
    }
    fn transmit(&mut self, _t: Instant) -> Option<TxTok<'_>> {
        Some(TxTok { sink: &mut self.tx })
    }
}

fn build_arp_request(out: &mut [u8]) -> usize {
    out[0..6].copy_from_slice(&[0xff; 6]); // dst broadcast
    out[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x02]); // src mac
    out[12] = 0x08;
    out[13] = 0x06; // ethertype ARP
    out[14] = 0;
    out[15] = 1; // htype ethernet
    out[16] = 0x08;
    out[17] = 0x00; // ptype ipv4
    out[18] = 6;
    out[19] = 4; // hlen/plen
    out[20] = 0;
    out[21] = 1; // oper = request
    out[22..28].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x02]); // sha
    out[28..32].copy_from_slice(&[192, 0, 2, 2]); // spa
    out[32..38].copy_from_slice(&[0; 6]); // tha
    out[38..42].copy_from_slice(&[192, 0, 2, 1]); // tpa = our IP
    42
}

/// PH6 QEMU gate: smoltcp answers an ARP request for its own IP, with the rule plane
/// gating both the ingress request and the egress reply. `seed` seeds smoltcp's PRNG
/// (production: from the TRNG). Returns true iff a valid ARP REPLY (oper=2, spa=our IP)
/// was emitted through the egress gate.
pub fn netsvc_selftest(seed: u64) -> bool {
    let mac = EthernetAddress([0x02, 0, 0, 0, 0, 0x01]);
    let mut dev = RuleGatedDev::new();
    let mut cfg = Config::new(HardwareAddress::Ethernet(mac));
    cfg.random_seed = seed;
    let mut iface = Interface::new(cfg, &mut dev, Instant::from_millis(0));
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::v4(192, 0, 2, 1), 24));
    });

    let mut req = [0u8; MTU];
    let rlen = build_arp_request(&mut req);
    let ingress_ok = dev.ingress(&req[..rlen]); // rule-gated admission (ARP request PASSes)

    let mut storage: [SocketStorage; 0] = [];
    let mut sockets = SocketSet::new(&mut storage[..]);
    iface.poll(Instant::from_millis(1), &mut dev, &mut sockets);

    let reply_ok = dev.tx.ready
        && dev.tx.len >= 42
        && dev.tx.buf[12] == 0x08
        && dev.tx.buf[13] == 0x06 // ethertype ARP
        && dev.tx.buf[21] == 2 // oper = reply
        && dev.tx.buf[28..32] == [192, 0, 2, 1]; // spa = our IP

    // AUDIT D7 — prove the gate DROPS, not just PASSes: a threat frame (UDP :4444) must be
    // REFUSED admission by the ingress gate, so it never reaches the smoltcp stack.
    let mut threat = [0u8; MTU];
    let tlen = build_udp_threat(&mut threat);
    let threat_refused = !dev.ingress(&threat[..tlen]);

    ingress_ok && reply_ok && threat_refused
}

/// A minimal Ethernet/IPv4/UDP frame to port 4444 — the rule plane DROPs it, so the
/// ingress gate must refuse it (AUDIT D7 negative case).
fn build_udp_threat(out: &mut [u8]) -> usize {
    out[0..6].copy_from_slice(&[0xff; 6]);
    out[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    out[12] = 0x08;
    out[13] = 0x00; // ethertype IPv4
    out[14] = 0x45; // IPv4, IHL=5
    let total: u16 = 20 + 8;
    out[16] = (total >> 8) as u8;
    out[17] = (total & 0xff) as u8;
    out[22] = 64; // TTL
    out[23] = 17; // proto UDP
    out[26..30].copy_from_slice(&[192, 0, 2, 2]); // src
    out[30..34].copy_from_slice(&[192, 0, 2, 1]); // dst
    out[34] = 0x30;
    out[35] = 0x39; // src port 12345
    out[36] = (4444u16 >> 8) as u8;
    out[37] = (4444u16 & 0xff) as u8; // dst port 4444 (threat)
    out[38] = 0;
    out[39] = 8; // UDP length
    42
}

// ===========================================================================================
// M4 GEM↔smoltcp bridge — FIRST-LIGHT (os-architect design 2026-09-08).
// A persistent EL1 smoltcp instance fed frame-by-frame from the prod GEM drain loop. The
// kernel already copies + `packet::verdict`-gates every frame, so handing a for-heqk PASS
// frame to this in-kernel smoltcp adds no new access to the EL0-isolated ring; the EL0/EL1
// boundary is untouched. This proves "smoltcp lives on the real GEM": the host ARPs heqk's
// IP over the real wire and heqk answers — the metal analog of `netsvc_selftest`. The
// EL0-isolated netq service (moving smoltcp out of the TCB) is the deferred end-state.
// ===========================================================================================

/// The first-light demux (§2): is `frame` an ARP REQUEST whose target-protocol-address is
/// heqk's own IP? Bounds-safe. (ICMP echo needs no demux — smoltcp answers unicast-to-us.)
pub fn is_arp_request_for(frame: &[u8], ip: [u8; 4]) -> bool {
    frame.len() >= 42
        && frame[12] == 0x08
        && frame[13] == 0x06 // ethertype ARP
        && frame[20] == 0
        && frame[21] == 1 // oper = request
        && frame[38] == ip[0]
        && frame[39] == ip[1]
        && frame[40] == ip[2]
        && frame[41] == ip[3] // tpa == our IP
}

/// The full first-light demux: is this frame FOR heqk? True iff its destination MAC is heqk's
/// own unicast MAC (covers unicast ICMP echo requests AND the ARP replies smoltcp needs to fill
/// its neighbour cache before it can answer an echo), OR it is a broadcast ARP request for
/// heqk's IP. A for-heqk frame TERMINATES at heqk (never hairpin-forwarded). Bounds-safe.
pub fn is_for_heqk(frame: &[u8], mac: [u8; 6], ip: [u8; 4]) -> bool {
    if frame.len() < 14 {
        return false;
    }
    frame[0..6] == mac || is_arp_request_for(frame, ip)
}

/// A persistent smoltcp bridge over the real GEM. Owns the `Interface` + the `RuleGatedDev`;
/// `step` feeds one for-heqk frame through the dual verdict gate + smoltcp and returns any
/// egress reply for the caller to TX out `gem::tx_frame`. ARP + ICMP-echo need no sockets, so
/// a fresh empty `SocketSet` is built per `step` (avoids a self-referential storage borrow).
pub struct MetalBridge {
    iface: Interface,
    dev: RuleGatedDev,
    our_ip: [u8; 4],
    our_mac: [u8; 6],
    /// Counters for the heartbeat (not threat metrics).
    pub seen: u32,
    pub answered: u32,
}

impl MetalBridge {
    /// Bring the bridge up with heqk's LA MAC + static IP/prefix and a TRNG `seed` (the caller
    /// draws it fail-closed from `rng200::next_word_strict`; a dead TRNG ⇒ no bridge).
    pub fn new(mac: [u8; 6], ip: [u8; 4], prefix: u8, seed: u64) -> MetalBridge {
        let mut dev = RuleGatedDev::new();
        // Egress checksums COMPUTED (rx not verified) so ICMP/IP replies carry valid checksums
        // the real host kernel accepts — ARP first-light worked with `ignored()` (ARP has none),
        // ICMP echo does not. `Checksum::Tx` = compute on transmit, skip verify on receive (real
        // host frames are valid anyway; a hand-built selftest frame needn't be).
        let mut cs = ChecksumCapabilities::ignored();
        cs.ipv4 = Checksum::Tx;
        cs.icmpv4 = Checksum::Tx;
        cs.tcp = Checksum::Tx;
        cs.udp = Checksum::Tx;
        dev.csum = cs;
        let mut cfg = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
        cfg.random_seed = seed;
        let mut iface = Interface::new(cfg, &mut dev, Instant::from_millis(0));
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::v4(ip[0], ip[1], ip[2], ip[3]), prefix));
        });
        MetalBridge { iface, dev, our_ip: ip, our_mac: mac, seen: 0, answered: 0 }
    }

    /// The first-light demux predicate: any frame addressed to heqk (ARP-for-us or unicast-to-
    /// our-MAC, so ICMP echo + smoltcp's neighbour-cache ARP replies are included).
    pub fn wants(&self, frame: &[u8]) -> bool {
        is_for_heqk(frame, self.our_mac, self.our_ip)
    }

    /// Feed one for-heqk frame → dual-gated smoltcp poll → return any egress reply (frame +
    /// len) to TX out GEM. `now_ms` = a monotonic ms clock (cntpct-derived). Ingress is
    /// verdict-gated by `RuleGatedDev::ingress` (belt-and-suspenders on the already-PASSed
    /// demux path); egress is verdict-gated in `TxTok::consume`.
    pub fn step(&mut self, frame: &[u8], now_ms: i64) -> Option<([u8; MTU], usize)> {
        self.seen += 1;
        self.dev.ingress(frame);
        let mut storage: [SocketStorage; 0] = [];
        let mut sockets = SocketSet::new(&mut storage[..]);
        self.iface.poll(Instant::from_millis(now_ms), &mut self.dev, &mut sockets);
        if self.dev.tx.ready {
            let n = self.dev.tx.len.min(MTU);
            let mut out = [0u8; MTU];
            out[..n].copy_from_slice(&self.dev.tx.buf[..n]);
            self.dev.tx.ready = false;
            self.answered += 1;
            Some((out, n))
        } else {
            None
        }
    }
}

// ── M4 DHCPv4 CLIENT (feature `dhcp`) ───────────────────────────────────────────────────────
// heqk obtains its IPv4 lease over the real GEM via smoltcp's dhcpv4 socket, rule-gated both
// directions like the bridge. The socket is PERSISTENT (DORA state spans polls), so its
// SocketSet is backed by a `static` storage array — the no_std-lifetime approach the gap-plan
// flagged (avoids a self-referential SocketSet-borrows-own-storage struct).
#[cfg(feature = "dhcp")]
use smoltcp::iface::SocketHandle;
#[cfg(feature = "dhcp")]
use smoltcp::socket::dhcpv4;

#[cfg(feature = "dhcp")]
static mut DHCP_STORAGE: [SocketStorage<'static>; 1] = [SocketStorage::EMPTY];

/// A DHCPv4 client over the real GEM. Starts with NO IP; drives DISCOVER→OFFER→REQUEST→ACK via
/// `service` (periodic, no-RX poll → emits the next DHCP msg) + `ingress` (a DORA reply → poll →
/// next msg). On `Configured` it records + installs the leased address. Both directions pass the
/// P17 rule plane (RuleGatedDev).
#[cfg(feature = "dhcp")]
pub struct DhcpClient {
    iface: Interface,
    dev: RuleGatedDev,
    sockets: SocketSet<'static>,
    dhcp: SocketHandle,
    pub assigned: Option<[u8; 4]>,
    pub router: Option<[u8; 4]>,
    pub dns: Option<[u8; 4]>,
    pub seen: u32,
}

#[cfg(feature = "dhcp")]
impl DhcpClient {
    pub fn new(mac: [u8; 6], seed: u64) -> DhcpClient {
        let mut dev = RuleGatedDev::new();
        let mut cs = ChecksumCapabilities::ignored();
        cs.ipv4 = Checksum::Tx;
        cs.udp = Checksum::Tx;
        dev.csum = cs;
        let mut cfg = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
        cfg.random_seed = seed;
        let iface = Interface::new(cfg, &mut dev, Instant::from_millis(0)); // no static IP — DHCP assigns
        #[allow(static_mut_refs)]
        let mut sockets = SocketSet::new(unsafe { &mut DHCP_STORAGE[..] });
        let dhcp = sockets.add(dhcpv4::Socket::new());
        DhcpClient { iface, dev, sockets, dhcp, assigned: None, router: None, dns: None, seen: 0 }
    }

    /// A DHCP reply bound for the client (IPv4/UDP dst port 68) — route these to `ingress`.
    pub fn wants(&self, frame: &[u8]) -> bool {
        frame.len() >= 42
            && frame[12] == 0x08
            && frame[13] == 0x00
            && (frame[14] & 0xf0) == 0x40
            && frame[23] == 17
            && u16::from_be_bytes([frame[36], frame[37]]) == 68
    }

    /// Periodic tick (no RX): drive DHCP TX (DISCOVER / REQUEST / retransmit). Returns any egress.
    pub fn service(&mut self, now_ms: i64) -> Option<([u8; MTU], usize)> {
        self.iface.poll(Instant::from_millis(now_ms), &mut self.dev, &mut self.sockets);
        self.check_event();
        self.take_tx()
    }

    /// Feed one DHCP reply; poll; return any egress (e.g. the REQUEST after an OFFER).
    pub fn ingress(&mut self, frame: &[u8], now_ms: i64) -> Option<([u8; MTU], usize)> {
        self.seen += 1;
        self.dev.ingress(frame);
        self.iface.poll(Instant::from_millis(now_ms), &mut self.dev, &mut self.sockets);
        self.check_event();
        self.take_tx()
    }

    fn check_event(&mut self) {
        let cfg = {
            let sock = self.sockets.get_mut::<dhcpv4::Socket>(self.dhcp);
            match sock.poll() {
                Some(dhcpv4::Event::Configured(c)) => Some((c.address, c.router, c.dns_servers.first().copied())),
                Some(dhcpv4::Event::Deconfigured) => None,
                None => return,
            }
        };
        match cfg {
            Some((addr, router, dns)) => {
                self.assigned = Some(addr.address().octets());
                self.router = router.map(|r| r.octets());
                self.dns = dns.map(|d| d.octets());
                self.iface.update_ip_addrs(|a| {
                    a.clear();
                    let _ = a.push(IpCidr::Ipv4(addr));
                });
            }
            None => {
                self.assigned = None;
                self.iface.update_ip_addrs(|a| a.clear());
            }
        }
    }

    fn take_tx(&mut self) -> Option<([u8; MTU], usize)> {
        if self.dev.tx.ready {
            let n = self.dev.tx.len.min(MTU);
            let mut out = [0u8; MTU];
            out[..n].copy_from_slice(&self.dev.tx.buf[..n]);
            self.dev.tx.ready = false;
            Some((out, n))
        } else {
            None
        }
    }
}

/// A minimal Ethernet/IPv4/ICMP echo REQUEST from 192.0.2.2 (mac 02:..:02) to heqk (192.0.2.1,
/// mac 02:..:01). Checksums left zero — the bridge device skips rx verification (`Checksum::Tx`);
/// the REPLY smoltcp emits DOES get valid checksums, which is the property the metal `ping` needs.
fn build_icmp_echo_request(out: &mut [u8]) -> usize {
    out[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x01]); // dst = heqk's MAC (unicast to us)
    out[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x02]); // src
    out[12] = 0x08;
    out[13] = 0x00; // ethertype IPv4
    out[14] = 0x45; // IPv4, IHL=5
    let total: u16 = 20 + 8;
    out[16] = (total >> 8) as u8;
    out[17] = (total & 0xff) as u8;
    out[22] = 64; // TTL
    out[23] = 1; // proto ICMP
    out[26..30].copy_from_slice(&[192, 0, 2, 2]); // src
    out[30..34].copy_from_slice(&[192, 0, 2, 1]); // dst = our IP
    out[34] = 8; // ICMP type 8 = echo request
    out[35] = 0; // code
    out[38] = 0x00;
    out[39] = 0x01; // identifier
    out[40] = 0x00;
    out[41] = 0x2a; // sequence
    42
}

/// QEMU gate for the FIRST-LIGHT bridge (the metal analog runs the SAME `MetalBridge` from the
/// prod drain loop). Constructs the bridge at 192.0.2.1/24 so it can reuse `build_arp_request`
/// (tpa == 192.0.2.1): (1) feeds an ARP request through `wants` + `step` and asserts a well-formed
/// ARP REPLY with our IP as sender (the metal-PROVEN capability — heqk answers ARP on the wire);
/// (2) asserts the broadened `is_for_heqk` demux CLAIMS a unicast ICMP-echo-for-us AND that frame
/// PASSes the rule plane (so it is admitted and TERMINATES at heqk, never hairpin-forwarded) — the
/// L2/L3 first-light property; the actual echo *reply* needs an ICMP/raw socket (smoltcp 0.13 does
/// NOT auto-answer echo) and is DEFERRED, not faked here; (3) asserts a broadcast threat frame is
/// NOT `wants`-matched. Deterministic; proves the exact demux + admission path metal runs.
pub fn metalbridge_selftest(seed: u64) -> bool {
    let mac = [0x02, 0, 0, 0, 0, 0x01];
    let mut br = MetalBridge::new(mac, [192, 0, 2, 1], 24, seed);

    // (1) ARP-for-us -> ARP reply (the metal-proven capability).
    let mut req = [0u8; MTU];
    let rlen = build_arp_request(&mut req);
    if !br.wants(&req[..rlen]) {
        return false;
    }
    let (r, n) = match br.step(&req[..rlen], 1) {
        Some(x) => x,
        None => return false,
    };
    let arp_ok = n >= 42
        && r[12] == 0x08
        && r[13] == 0x06 // ethertype ARP
        && r[21] == 2 // oper = reply
        && r[28..32] == [192, 0, 2, 1]; // spa = our IP

    // (2) a unicast ICMP-echo-for-us is demux-CLAIMED (dst MAC is ours) AND PASSes the rule plane,
    //     so it is admitted to the stack and terminates at heqk. The echo REPLY itself is deferred
    //     (needs an ICMP/raw socket; smoltcp does not auto-answer echo) — we do NOT assert a reply.
    let mut echo = [0u8; MTU];
    let elen = build_icmp_echo_request(&mut echo);
    let icmp_claimed = br.wants(&echo[..elen]) && packet::verdict(&echo[..elen]).1 == packet::PASS;

    // (3) the demux must NOT hand a broadcast threat frame to the stack.
    let mut threat = [0u8; MTU];
    let tlen = build_udp_threat(&mut threat);
    let threat_not_wanted = !br.wants(&threat[..tlen]);

    arp_ok && icmp_claimed && threat_not_wanted && br.seen == 1 && br.answered == 1
}

// ===========================================================================
// M4 Noise-over-bridge — the control-plane TRANSPORT first-light, Linux-`macb`-aligned.
//
// LESSON FROM LINUX (drivers/net/ethernet/cadence/macb_main.c — the RP1 GEM is a Cadence GEM):
// the RX descriptor ring has EXACTLY ONE software owner (the NAPI `gem_rx` drain); the network
// stack receives frames as buffers handed UP by that drain (`napi_gro_receive`) and NEVER walks
// descriptors. A second raw-ring walker (the deleted `GemPhy`/`cm5_enroll_bringup`) left RX_USED
// bits set, the GEM raised BNA ("buffers not available"), and RX DMA wedged (metal: sensor
// `seen=0` forever). So the control plane must ride the sensor's SINGLE drain: RX by demux/tee
// (already how MetalBridge is fed), TX through the ONE `gem::tx_frame` path.
//
// This first-light is a fire-and-forget BROADCAST UDP presence beacon: hand-built (no smoltcp
// socket state, no neighbour resolution — broadcast needs none), returned for the sensor's one
// TX path, emitted once when the PHY link is up. It proves heqk emits a UDP datagram on the real
// wire via the single owner without disturbing the ring. The full Noise handshake (a persistent
// smoltcp socket teed off the one drain + a host MSSP-sim) is the next increment.
// ===========================================================================

/// IPv4 header checksum (RFC 1071 ones-complement) over `hdr` (checksum field must be 0).
fn ipv4_checksum(hdr: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < hdr.len() {
        sum += u16::from_be_bytes([hdr[i], hdr[i + 1]]) as u32;
        i += 2;
    }
    if i < hdr.len() {
        sum += (hdr[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build a fire-and-forget BROADCAST UDP presence beacon: Ethernet(bcast)/IPv4(src=`our_ip`,
/// dst=255.255.255.255)/UDP(dport=`port`) carrying a device-identity payload (marker ‖ device_id
/// ‖ fp). Valid IPv4 header checksum; UDP checksum 0 (permitted for IPv4). Broadcast needs no ARP
/// resolution, so it is stateless — no smoltcp socket. Returns the frame length written to `out`
/// (which must be ≥ 62). This is emitted through the SENSOR's single `gem::tx_frame` path.
pub fn build_enroll_beacon(our_mac: [u8; 6], our_ip: [u8; 4], port: u16, device_id: u64, out: &mut [u8]) -> usize {
    const PAYLOAD: usize = 48;
    const FRAME: usize = 14 + 20 + 8 + PAYLOAD; // 90
    for b in out[..FRAME].iter_mut() {
        *b = 0;
    }
    // Ethernet
    out[0..6].copy_from_slice(&[0xff; 6]); // dst = broadcast
    out[6..12].copy_from_slice(&our_mac);
    out[12] = 0x08;
    out[13] = 0x00; // IPv4
                    // IPv4 header (20 B)
    out[14] = 0x45; // v4, IHL=5
    let total = (20 + 8 + PAYLOAD) as u16;
    out[16..18].copy_from_slice(&total.to_be_bytes());
    out[22] = 64; // TTL
    out[23] = 17; // UDP
    out[26..30].copy_from_slice(&our_ip);
    out[30..34].copy_from_slice(&[255, 255, 255, 255]); // limited broadcast
    let csum = ipv4_checksum(&out[14..34]);
    out[24..26].copy_from_slice(&csum.to_be_bytes());
    // UDP header (8 B) — checksum 0 (optional for IPv4)
    out[34..36].copy_from_slice(&port.to_be_bytes()); // sport = same port (beacon)
    out[36..38].copy_from_slice(&port.to_be_bytes()); // dport
    out[38..40].copy_from_slice(&((8 + PAYLOAD) as u16).to_be_bytes());
    // UDP payload: device-identity beacon
    let p = 42;
    out[p..p + 16].copy_from_slice(b"HEQK-ENROLL-HELO");
    out[p + 16..p + 24].copy_from_slice(&device_id.to_le_bytes());
    let fp = boot_abi::sha256::digest(&device_id.to_le_bytes());
    out[p + 24..p + 48].copy_from_slice(&fp[..24]);
    FRAME
}

/// Build a UDP datagram carrying `framed_chunk` (one Noise-handshake chunk from `hs_chunk`):
/// Ethernet(`dst_mac`)/IPv4(`our_ip`→`dst_ip`)/UDP(`port`→`port`) ‖ framed_chunk. Valid IPv4
/// header checksum; UDP checksum 0 (permitted for IPv4). `dst_mac`=ff.. + `dst_ip`=255.255.255.255
/// broadcasts (avoids ARP — the responder replies unicast to our MAC, caught by `is_for_heqk`).
/// Returns the frame length written to `out` (needs ≥ 42 + framed_chunk.len()). The ControlPlane
/// emits these through the sensor's SINGLE gem::tx_frame path (single-owner discipline).
pub fn build_hs_datagram(
    our_mac: [u8; 6],
    our_ip: [u8; 4],
    dst_mac: [u8; 6],
    dst_ip: [u8; 4],
    port: u16,
    framed_chunk: &[u8],
    out: &mut [u8],
) -> usize {
    let plen = framed_chunk.len();
    let frame = 14 + 20 + 8 + plen;
    for b in out[..frame].iter_mut() {
        *b = 0;
    }
    out[0..6].copy_from_slice(&dst_mac);
    out[6..12].copy_from_slice(&our_mac);
    out[12] = 0x08;
    out[13] = 0x00; // IPv4
    out[14] = 0x45; // v4, IHL=5
    out[16..18].copy_from_slice(&((20 + 8 + plen) as u16).to_be_bytes());
    out[22] = 64; // TTL
    out[23] = 17; // UDP
    out[26..30].copy_from_slice(&our_ip);
    out[30..34].copy_from_slice(&dst_ip);
    let csum = ipv4_checksum(&out[14..34]);
    out[24..26].copy_from_slice(&csum.to_be_bytes());
    out[34..36].copy_from_slice(&port.to_be_bytes());
    out[36..38].copy_from_slice(&port.to_be_bytes());
    out[38..40].copy_from_slice(&((8 + plen) as u16).to_be_bytes());
    out[42..42 + plen].copy_from_slice(framed_chunk);
    frame
}

/// DISCRIMINATOR (feature `txsweep`): build a BROADCAST UDP frame of EXACTLY `total` bytes
/// (Ethernet(bcast)/IPv4(src=`our_ip`,dst=255.255.255.255)/UDP(sport=total,dport=`dport`) ‖
/// 0xA5 padding). `sport` carries the frame length and `dport` the sweep index so a host
/// `tcpdump -e` capture maps every frame that reaches the wire back to its (length, index)
/// without the kernel log. Valid IPv4 checksum; UDP checksum 0. `total` is clamped to
/// [42, out.len()]. Returns the frame length written.
#[cfg(feature = "txsweep")]
pub fn build_sweep_frame(our_mac: [u8; 6], our_ip: [u8; 4], dport: u16, total: usize, out: &mut [u8]) -> usize {
    let total = total.max(42).min(out.len());
    for b in out[..42].iter_mut() {
        *b = 0;
    }
    for b in out[42..total].iter_mut() {
        *b = 0xA5;
    }
    // Ethernet: bcast dst, our src, IPv4
    out[0..6].copy_from_slice(&[0xff; 6]);
    out[6..12].copy_from_slice(&our_mac);
    out[12] = 0x08;
    out[13] = 0x00;
    // IPv4 header
    out[14] = 0x45; // v4, IHL=5
    out[16..18].copy_from_slice(&((total - 14) as u16).to_be_bytes());
    out[22] = 64; // TTL
    out[23] = 17; // UDP
    out[26..30].copy_from_slice(&our_ip);
    out[30..34].copy_from_slice(&[255, 255, 255, 255]);
    let csum = ipv4_checksum(&out[14..34]);
    out[24..26].copy_from_slice(&csum.to_be_bytes());
    // UDP header — sport = length marker, dport = sweep index code
    out[34..36].copy_from_slice(&(total as u16).to_be_bytes());
    out[36..38].copy_from_slice(&dport.to_be_bytes());
    out[38..40].copy_from_slice(&((total - 34) as u16).to_be_bytes());
    // UDP checksum 0 (already zeroed), payload already 0xA5
    total
}

/// DNS-SINKHOLE (feature `dnssink`): if `qframe` is a standard untagged Ethernet/IPv4/UDP DNS
/// QUERY (dst port 53) for an RPZ-blocked name, build the spoofed SINKHOLE reply into `out`
/// (eth/IP/UDP addresses swapped so it appears to come from the queried resolver; UDP sport=53;
/// the crafted A-record answer points at `dnssink::SINKHOLE_IP`) and return its length. `None`
/// for anything else (not a blocked DNS query) — the caller then forwards the query untouched, so
/// a legit name always flows (ADR 0023 "refuse a NAME, never a PACKET"). Only the NO-VLAN /
/// IHL=5 common case is handled; anything unusual falls through to normal forwarding (fail-open).
#[cfg(feature = "dnssink")]
pub fn build_dns_sinkhole_frame(qframe: &[u8], out: &mut [u8]) -> Option<usize> {
    // eth(14) + IPv4(20) + UDP(8) + at least a DNS header(12).
    if qframe.len() < 42 + 12 {
        return None;
    }
    if qframe[12] != 0x08 || qframe[13] != 0x00 {
        return None; // not IPv4
    }
    if qframe[14] != 0x45 {
        return None; // IHL != 5 (options) — fall through
    }
    if qframe[23] != 17 {
        return None; // not UDP
    }
    if u16::from_be_bytes([qframe[36], qframe[37]]) != 53 {
        return None; // not a DNS query (dst port 53)
    }
    let ip_total = u16::from_be_bytes([qframe[16], qframe[17]]) as usize;
    let dns_end = 14 + ip_total; // IP total length measured from the eth start
    let dns_off = 42usize;
    if dns_end > qframe.len() || dns_end <= dns_off {
        return None;
    }
    let dns_query = &qframe[dns_off..dns_end];
    // RPZ decision (fail-closed parse). Not blocked ⇒ None ⇒ the query is forwarded normally.
    let mut nm = [0u8; 256];
    let nlen = crate::dnssink::parse_qname(dns_query, &mut nm)?;
    if !crate::dnssink::rpz_blocked(&nm[..nlen]) {
        return None;
    }
    // Craft the sinkhole DNS answer.
    let mut dresp = [0u8; 512];
    let rlen = crate::dnssink::build_sinkhole_response(dns_query, crate::dnssink::SINKHOLE_IP, &mut dresp)?;
    let frame = 42 + rlen;
    if frame > out.len() {
        return None;
    }
    for b in out[..42].iter_mut() {
        *b = 0;
    }
    // eth: dst = query's src MAC, src = query's dst MAC (heqk answers AS the resolver).
    out[0..6].copy_from_slice(&qframe[6..12]);
    out[6..12].copy_from_slice(&qframe[0..6]);
    out[12] = 0x08;
    out[13] = 0x00;
    // IPv4: src = query's dst IP (the resolver), dst = query's src IP (the client).
    out[14] = 0x45;
    out[16..18].copy_from_slice(&((20 + 8 + rlen) as u16).to_be_bytes());
    out[22] = 64; // TTL
    out[23] = 17; // UDP
    out[26..30].copy_from_slice(&qframe[30..34]);
    out[30..34].copy_from_slice(&qframe[26..30]);
    let csum = ipv4_checksum(&out[14..34]);
    out[24..26].copy_from_slice(&csum.to_be_bytes());
    // UDP: sport = 53, dport = query's src port; checksum 0 (permitted for IPv4).
    out[34..36].copy_from_slice(&53u16.to_be_bytes());
    out[36..38].copy_from_slice(&qframe[34..36]);
    out[38..40].copy_from_slice(&((8 + rlen) as u16).to_be_bytes());
    out[42..42 + rlen].copy_from_slice(&dresp[..rlen]);
    Some(frame)
}

/// The L4-payload slice of a UDP frame destined to `port`, or `None` (not IPv4/UDP or wrong
/// port). Used by the ControlPlane to extract a handshake chunk from a received frame.
pub fn udp_payload_for_port(frame: &[u8], port: u16) -> Option<&[u8]> {
    let m = crate::net::parse(frame)?;
    // `net::parse` sets `payload_off` = the IP datagram END (`ip_end`); the UDP payload is the
    // slice AFTER the 8-byte UDP header (l4_off+8) up to that end.
    let start = m.l4_off.checked_add(8)?;
    if m.ip_proto == crate::net::IPPROTO_UDP
        && m.dst_port == port
        && m.l4_off != 0
        && start <= m.payload_off
        && m.payload_off <= frame.len()
    {
        Some(&frame[start..m.payload_off])
    } else {
        None
    }
}
