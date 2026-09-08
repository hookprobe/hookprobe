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
// M4 Noise-over-bridge — the metal transport (GemPhy) + a bounded enrollment BRING-UP.
// A persistent UDP socket in MetalBridge is not expressible in no_std/no-heap (self-referential
// SocketSet<'a> borrowing the socket buffers), so the handshake transport gets a dedicated
// single-function-scope driver that stack-owns the SocketSet + UDP buffers for its bounded
// lifetime — exactly `netcfg::real_slirp`'s proven arrangement. It runs ONCE before the sensor
// loop, owns the GEM cursor for its window, and hands `rx_head` back advanced. Air-gap invariant:
// no responder ⇒ the bounded window elapses and the sensor loop runs; a dead HW-TRNG ⇒ no wire
// touch at all (fail-closed). Off by default; `netmetal`(+`securechannel`) only.
// ===========================================================================

#[cfg(feature = "netmetal")]
fn now_ms() -> i64 {
    let cnt: u64;
    let frq: u64;
    unsafe {
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) cnt, options(nomem, nostack));
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) frq, options(nomem, nostack));
    }
    if frq == 0 {
        return 0;
    }
    ((cnt as u128 * 1000) / frq as u128) as i64
}
#[cfg(feature = "netmetal")]
fn now() -> Instant {
    Instant::from_millis(now_ms())
}

/// A smoltcp `phy::Device` over the REAL RP1 GEM (mirrors `netcfg::VirtioPhy`, dual verdict gate).
/// `pump_rx` drains ONE RX descriptor — staging it for smoltcp only if it is for-heqk AND PASSes
/// the rule plane (ingress gate) — then always recycles + advances the shared cursor so the ring
/// never stalls. `pump_tx` flushes one egress frame (already egress-verdict-gated in `TxTok`) via
/// `gem::tx_frame`. Egress checksums are computed (`Checksum::Tx`) so datagrams carry valid
/// UDP/IP checksums the host kernel accepts.
#[cfg(feature = "netmetal")]
pub struct GemPhy<'c> {
    rx: Option<([u8; MTU], usize)>,
    tx: TxSink,
    rx_head: &'c mut usize,
    our_mac: [u8; 6],
    our_ip: [u8; 4],
    csum: ChecksumCapabilities,
    pub rx_staged: u32,
    pub dropped_in: u32,
}

#[cfg(feature = "netmetal")]
impl<'c> GemPhy<'c> {
    pub fn new(mac: [u8; 6], ip: [u8; 4], rx_head: &'c mut usize) -> GemPhy<'c> {
        let mut cs = ChecksumCapabilities::ignored();
        cs.ipv4 = Checksum::Tx;
        cs.icmpv4 = Checksum::Tx;
        cs.tcp = Checksum::Tx;
        cs.udp = Checksum::Tx;
        GemPhy {
            rx: None,
            tx: TxSink { buf: [0; MTU], len: 0, ready: false, dropped_out: 0, tx_lost: 0 },
            rx_head,
            our_mac: mac,
            our_ip: ip,
            csum: cs,
            rx_staged: 0,
            dropped_in: 0,
        }
    }
    fn pump_rx(&mut self) {
        if self.rx.is_some() {
            return;
        }
        let head = *self.rx_head;
        if !arch_aarch64::gem::rx_desc_used(head) {
            return;
        }
        if let Some(l) = arch_aarch64::gem::rx_desc_status(head) {
            if l >= 14 {
                let mut buf = [0u8; MTU];
                let n = l.min(MTU);
                arch_aarch64::gem::peek_rx_frame(head, &mut buf[..n]);
                if is_for_heqk(&buf[..n], self.our_mac, self.our_ip)
                    && packet::verdict(&buf[..n]).1 == packet::PASS
                {
                    self.rx = Some((buf, n));
                    self.rx_staged += 1;
                } else {
                    self.dropped_in += 1;
                }
            }
        }
        arch_aarch64::gem::recycle_rx(head);
        *self.rx_head = (head + 1) % arch_aarch64::gem::RX_NDESC;
    }
    fn pump_tx(&mut self) {
        if self.tx.ready {
            let _ = arch_aarch64::gem::tx_frame(&self.tx.buf[..self.tx.len]);
            self.tx.ready = false;
        }
    }
}

#[cfg(feature = "netmetal")]
impl<'c> Device for GemPhy<'c> {
    type RxToken<'a>
        = RxTok
    where
        Self: 'a;
    type TxToken<'a>
        = TxTok<'a>
    where
        Self: 'a;
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.max_transmission_unit = MTU;
        c.medium = Medium::Ethernet;
        c.checksum = self.csum.clone();
        c
    }
    fn receive(&mut self, _t: Instant) -> Option<(RxTok, TxTok<'_>)> {
        let (frame, len) = self.rx.take()?;
        Some((RxTok { frame, len }, TxTok { sink: &mut self.tx }))
    }
    fn transmit(&mut self, _t: Instant) -> Option<TxTok<'_>> {
        Some(TxTok { sink: &mut self.tx })
    }
}

/// The bounded enrollment bring-up outcome.
#[cfg(all(feature = "netmetal", feature = "securechannel"))]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BringupOutcome {
    /// The GEM/RP1 link did not come up within the wait budget — no point emitting (frames would
    /// hit a not-ready MAC and never reach the wire, the metal-observed early-boot failure). The
    /// sensor loop drains the ring once the link settles.
    LinkDown,
    /// Fail-closed: the HW-TRNG could not produce session entropy → NO wire touch (the control
    /// plane never proceeds without real entropy); the sensor loop still runs.
    NoTrng,
    /// The bounded window elapsed with no datagram emitted (e.g. peer never ARP-resolved).
    TimedOut { tx: u32 },
    /// The enrollment hello was emitted on the wire (`tx` frames out, `rx` for-heqk frames in).
    Emitted { tx: u32, rx: u32 },
}

/// Bounded enrollment bring-up over the real GEM: draw fail-closed HW-TRNG session entropy, bring
/// up a smoltcp UDP socket on `GemPhy`, ARP-resolve the peer, and emit an enrollment HELLO
/// datagram (a stable device-identity beacon) to `peer:port`. This is the TRANSPORT first-light —
/// it proves GemPhy + smoltcp-UDP-over-GEM + the egress verdict gate + the fail-closed-TRNG gate
/// on real silicon. The full Noise msg1 (to the PROVISIONED MSSP pubkey, using the drawn
/// ephemerals) + the handshake ride the next increment (a host MSSP-sim generates the keypair).
/// Hard-bounded by `window_ms` AND `max_attempts` (air-gap invariant); returns `rx_head` advanced.
#[cfg(all(feature = "netmetal", feature = "securechannel"))]
pub fn cm5_enroll_bringup(
    mac: [u8; 6],
    ip: [u8; 4],
    prefix: u8,
    peer: [u8; 4],
    port: u16,
    device_id: u64,
    rx_head: &mut usize,
    link_wait_ms: u32,
    window_ms: i64,
    max_attempts: u32,
) -> BringupOutcome {
    use crate::entropy::EntropySource; // brings fill_32 into scope
    use smoltcp::socket::udp;
    use smoltcp::wire::{IpAddress, IpEndpoint, Ipv4Address};

    // (0) WAIT FOR LINK-UP first (metal finding 2026-09-08): the bring-up fires early in boot,
    // and frames emitted before the GEM/RP1 autoneg completes are dropped by the not-ready MAC
    // (never reach the wire — observed as tx>0 but zero on-wire). Gate on the PHY link bit; if the
    // link never settles in-budget, don't emit — the sensor loop drains the ring once it does.
    if arch_aarch64::gem::wait_link(link_wait_ms) & 1 == 0 {
        return BringupOutcome::LinkDown;
    }

    // (1) FAIL-CLOSED session entropy from the real HW-TRNG. A dead TRNG ⇒ no enrollment at all
    // (never a seeded path on metal); the sensor loop is unaffected.
    let mut e = crate::entropy::MetalEntropy::new(crate::entropy::HwTrng::new());
    let _irand = match crate::securechannel::InitiatorRandomness::from_entropy(&mut e) {
        Ok(r) => r, // the msg1 ephemerals — consumed by the full handshake next increment
        Err(_) => return BringupOutcome::NoTrng,
    };
    let seed = e
        .fill_32()
        .map(|s| u64::from_le_bytes(s[..8].try_into().unwrap()))
        .unwrap_or(0);

    // (2) bring up a smoltcp iface + one UDP socket bound to `port`, over the GEM.
    let mut phy = GemPhy::new(mac, ip, rx_head);
    let mut cfg = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
    cfg.random_seed = seed;
    let mut iface = Interface::new(cfg, &mut phy, now());
    iface.update_ip_addrs(|a| {
        let _ = a.push(IpCidr::new(IpAddress::v4(ip[0], ip[1], ip[2], ip[3]), prefix));
    });
    let mut store = [SocketStorage::EMPTY; 1];
    let mut sockets = SocketSet::new(&mut store[..]);
    let mut rxm = [udp::PacketMetadata::EMPTY; 4];
    let mut rxb = [0u8; 2048];
    let mut txm = [udp::PacketMetadata::EMPTY; 4];
    let mut txb = [0u8; 2048];
    let uh = sockets.add(udp::Socket::new(
        udp::PacketBuffer::new(&mut rxm[..], &mut rxb[..]),
        udp::PacketBuffer::new(&mut txm[..], &mut txb[..]),
    ));
    let _ = sockets.get_mut::<udp::Socket>(uh).bind(port);

    // (3) the enrollment HELLO: a stable device-identity beacon (marker ‖ device_id ‖ fp).
    let mut hello = [0u8; 48];
    hello[..16].copy_from_slice(b"HEQK-ENROLL-HELO");
    hello[16..24].copy_from_slice(&device_id.to_le_bytes());
    let fp = boot_abi::sha256::digest(&device_id.to_le_bytes());
    hello[24..48].copy_from_slice(&fp[..24]);
    let ep = IpEndpoint::new(
        IpAddress::Ipv4(Ipv4Address::new(peer[0], peer[1], peer[2], peer[3])),
        port,
    );

    let deadline = now_ms() + window_ms;
    let mut attempts = 0u32;
    let mut tx_seen = 0u32;
    let mut sent = false;
    let mut last_send = 0i64;
    while now_ms() < deadline {
        phy.pump_rx();
        iface.poll(now(), &mut phy, &mut sockets);
        if phy.tx.ready {
            tx_seen += 1;
        }
        phy.pump_tx();

        // (re)send the hello up to `max_attempts`, ~500 ms apart. smoltcp ARP-resolves the peer,
        // holding the datagram until the reply, then emits it.
        let t = now_ms();
        if attempts < max_attempts && (last_send == 0 || t - last_send >= 500) {
            if sockets.get_mut::<udp::Socket>(uh).send_slice(&hello, ep).is_ok() {
                attempts += 1;
                last_send = t;
                sent = true;
            }
        }
        // drain any inbound datagram (transport-RX confirm; content used next increment).
        let mut ib = [0u8; 256];
        let _ = sockets.get_mut::<udp::Socket>(uh).recv_slice(&mut ib);
    }

    if sent && tx_seen > 0 {
        BringupOutcome::Emitted { tx: tx_seen, rx: phy.rx_staged }
    } else {
        BringupOutcome::TimedOut { tx: tx_seen }
    }
}
