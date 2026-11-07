//! M4.1 — network configuration clients over the smoltcp stack: DHCP + DNS + SNTP.
//!
//! This is the first time heqk drives smoltcp UDP (PH6/`netsvc.rs` only ever
//! answered one ARP). Every path here keeps the two invariants that make the net
//! stack trustworthy:
//!
//!  1. **Rule-gated** (the PH6net property, `netq.rs`/`netsvc.rs`): every ingress
//!     frame is admitted to smoltcp ONLY if `packet::verdict` PASSes it, and every
//!     egress frame is emitted ONLY if it PASSes too. A spoofed/hostile DHCP/DNS
//!     response is subject to the signed rules exactly like any other traffic.
//!  2. **Standalone / air-gapped stays FULLY functional (CLAUDE.md core invariant).**
//!     Config is ADDITIVE. With NO DHCP/DNS/NTP server the device falls back to
//!     static / last-known config and the local SOC runs unchanged. The DHCP
//!     attempt is strictly time-bounded — it can NEVER block boot on a missing lease.
//!
//! Proof split (honest, Track-C):
//!  - **Deterministic (gates `P18-netcfg`), host-logic, no server needed:** smoltcp's
//!    `dhcpv4` socket EMITS a well-formed DISCOVER through the egress verdict gate;
//!    the DNS/SNTP request builders + response parsers round-trip; the ingress gate
//!    PASSes benign DHCP/DNS/NTP and DROPs a threat; the air-gap fallback returns a
//!    static config without blocking.
//!  - **Real SLIRP over virtio-net (reported bonus):** a full DHCP handshake against
//!    QEMU `-netdev user` yields the real lease (10.0.2.15, gw 10.0.2.2, DNS 10.0.2.3)
//!    and a real DNS query is answered by SLIRP's forwarder. The real RP1 GEM / RTL8111
//!    datapath, a real DHCP/DNS server, and a real NTP server are metal (Gate R) —
//!    SLIRP has no NTP, so the SNTP client is proven send-well-formed + parse-stub here.
#![cfg(feature = "netsvc")]

use crate::packet;
use smoltcp::iface::{Config, Interface, SocketSet, SocketStorage};
use smoltcp::phy::{self, ChecksumCapabilities, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{dhcpv4, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{
    EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address,
};

const MTU: usize = 1514;

/// Local console print (the `kprint!` macro lives in main.rs and isn't exported;
/// every module reaches the early console through the same arch seam).
macro_rules! kprint {
    ($($t:tt)*) => { arch_aarch64::_print(format_args!($($t)*)) };
}

// ---------------------------------------------------------------------------
// Pure, host-testable config primitives (no I/O; bounds-safe like net.rs).
// ---------------------------------------------------------------------------

/// The resolved network configuration and where it came from. `source` makes the
/// air-gap fallback auditable: an operator can see the device is on Static/LastKnown
/// (no lease) versus Dhcp (enrolled to a network) — both are fully-functional states.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NetConfig {
    pub ip: [u8; 4],
    pub prefix: u8,
    pub gw: [u8; 4],
    pub dns: [u8; 4],
    pub source: ConfigSource,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfigSource {
    Dhcp,
    LastKnown,
    Static,
}

/// The air-gap invariant, as one deterministic function: prefer a fresh DHCP lease,
/// else the last-known config, else the compiled static default. It ALWAYS returns a
/// usable config — there is no "unconfigured / wait for a server" state, so the local
/// SOC is never gated on connectivity.
pub fn resolve_or_fallback(
    lease: Option<NetConfig>,
    last_known: Option<NetConfig>,
    static_default: NetConfig,
) -> NetConfig {
    if let Some(mut l) = lease {
        l.source = ConfigSource::Dhcp;
        return l;
    }
    if let Some(mut lk) = last_known {
        lk.source = ConfigSource::LastKnown;
        return lk;
    }
    let mut s = static_default;
    s.source = ConfigSource::Static;
    s
}

#[inline]
fn be16(b: &[u8], o: usize) -> Option<u16> {
    Some(((*b.get(o)? as u16) << 8) | (*b.get(o + 1)? as u16))
}

/// Build a DNS standard query (opcode 0, RD=1) for `name` type A / class IN into
/// `out`. Returns the byte length, or `None` if it does not fit / a label is >63.
pub fn build_dns_query(id: u16, name: &str, out: &mut [u8]) -> Option<usize> {
    if out.len() < 12 {
        return None;
    }
    out[0..2].copy_from_slice(&id.to_be_bytes());
    out[2..4].copy_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    out[4..6].copy_from_slice(&1u16.to_be_bytes()); // qdcount=1
    out[6..12].copy_from_slice(&[0u8; 6]); // an/ns/ar = 0
    let mut o = 12;
    for label in name.split('.') {
        let l = label.len();
        if l == 0 || l > 63 || o + 1 + l > out.len() {
            return None;
        }
        out[o] = l as u8;
        out[o + 1..o + 1 + l].copy_from_slice(label.as_bytes());
        o += 1 + l;
    }
    if o + 5 > out.len() {
        return None;
    }
    out[o] = 0; // root label
    out[o + 1..o + 3].copy_from_slice(&1u16.to_be_bytes()); // QTYPE=A
    out[o + 3..o + 5].copy_from_slice(&1u16.to_be_bytes()); // QCLASS=IN
    Some(o + 5)
}

/// Parse the FIRST A record out of a DNS response, verifying the transaction id.
/// Bounds-safe: every access goes through `.get()`, so a truncated / malformed /
/// hostile response yields `None` (fail-closed), never an OOB read.
pub fn parse_dns_a(resp: &[u8], expect_id: u16) -> Option<[u8; 4]> {
    if be16(resp, 0)? != expect_id {
        return None;
    }
    let qd = be16(resp, 4)?;
    let an = be16(resp, 6)?;
    if an == 0 {
        return None;
    }
    let mut o = 12usize;
    // Skip the question section (names in questions are not compressed here).
    for _ in 0..qd {
        o = skip_name(resp, o)?;
        o = o.checked_add(4)?; // QTYPE + QCLASS
    }
    for _ in 0..an {
        o = skip_name(resp, o)?; // may be a compression pointer
        let rtype = be16(resp, o)?;
        let rclass = be16(resp, o + 2)?;
        let rdlen = be16(resp, o + 8)? as usize; // after TTL (4 bytes)
        let rdata = o.checked_add(10)?;
        if rtype == 1 && rclass == 1 && rdlen == 4 {
            let a = resp.get(rdata..rdata + 4)?;
            return Some([a[0], a[1], a[2], a[3]]);
        }
        o = rdata.checked_add(rdlen)?;
    }
    None
}

/// Advance past a DNS name at `o`: a run of length-prefixed labels ending in a 0
/// byte, or a 2-byte compression pointer (top two bits set). Returns the offset
/// just past the name, or `None` on truncation / an over-long chain.
fn skip_name(resp: &[u8], mut o: usize) -> Option<usize> {
    for _ in 0..128 {
        let len = *resp.get(o)?;
        if len & 0xc0 == 0xc0 {
            return Some(o + 2); // compression pointer: 2 bytes total
        }
        if len == 0 {
            return Some(o + 1); // root label terminates the name
        }
        o = o.checked_add(1 + len as usize)?;
    }
    None
}

/// NTP epoch (1900-01-01) to Unix epoch (1970-01-01) offset in seconds.
pub const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

/// Build a 48-byte SNTP (NTPv4) client request: LI=0, VN=4, Mode=3(client).
pub fn build_sntp_request(out: &mut [u8; 48]) -> usize {
    *out = [0u8; 48];
    out[0] = 0x23; // 0b00_100_011 = LI 0 | VN 4 | Mode 3 (client)
    48
}

/// Parse an SNTP response: return Unix seconds from the Transmit Timestamp, or
/// `None` if it is not a well-formed server reply. Bounds- and epoch-checked.
pub fn parse_sntp(resp: &[u8]) -> Option<u64> {
    if resp.len() < 48 {
        return None;
    }
    let mode = resp[0] & 0x07;
    if mode != 4 && mode != 5 {
        return None; // not a server / broadcast reply
    }
    // Transmit Timestamp seconds: big-endian u32 at offset 40.
    let secs = u32::from_be_bytes([resp[40], resp[41], resp[42], resp[43]]) as u64;
    if secs < NTP_UNIX_OFFSET {
        return None; // pre-1970 / unset clock
    }
    Some(secs - NTP_UNIX_OFFSET)
}

// ---------------------------------------------------------------------------
// Clock: a smoltcp Instant from the ARM generic timer (CNTPCT_EL0 / CNTFRQ_EL0).
// ---------------------------------------------------------------------------

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

fn now() -> Instant {
    Instant::from_millis(now_ms())
}

// ---------------------------------------------------------------------------
// Synthetic rule-gated device (deterministic proofs — no server needed).
// Mirrors netsvc.rs::RuleGatedDev: ingress admits only verdict-PASS frames, egress
// emits only verdict-PASS frames. Used to prove smoltcp EMITS a DISCOVER through
// the egress gate, and that the air-gap fallback returns without a server.
// ---------------------------------------------------------------------------

struct TxCap {
    buf: [u8; MTU],
    len: usize,
    ready: bool,
}

struct SynthDev {
    rx: Option<([u8; MTU], usize)>,
    tx: TxCap,
}

impl SynthDev {
    fn new() -> Self {
        SynthDev {
            rx: None,
            tx: TxCap { buf: [0; MTU], len: 0, ready: false },
        }
    }
    /// Inject a frame for smoltcp to receive — but only if the rule plane PASSes it
    /// (the ingress gate). Returns whether it was admitted.
    fn inject(&mut self, frame: &[u8]) -> bool {
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

struct SynthRx {
    frame: [u8; MTU],
    len: usize,
}
impl phy::RxToken for SynthRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.frame[..self.len])
    }
}
struct SynthTx<'a> {
    sink: &'a mut TxCap,
}
impl<'a> phy::TxToken for SynthTx<'a> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let n = len.min(MTU);
        let mut tmp = [0u8; MTU];
        let r = f(&mut tmp[..n]);
        // Egress gate: emit only what the rule plane PASSes.
        if packet::verdict(&tmp[..n]).1 == packet::PASS {
            self.sink.buf[..n].copy_from_slice(&tmp[..n]);
            self.sink.len = n;
            self.sink.ready = true;
        }
        r
    }
}
impl Device for SynthDev {
    type RxToken<'a> = SynthRx;
    type TxToken<'a> = SynthTx<'a>;
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.max_transmission_unit = MTU;
        c.medium = Medium::Ethernet;
        c.checksum = ChecksumCapabilities::ignored();
        c
    }
    fn receive(&mut self, _t: Instant) -> Option<(SynthRx, SynthTx<'_>)> {
        let (frame, len) = self.rx.take()?;
        Some((SynthRx { frame, len }, SynthTx { sink: &mut self.tx }))
    }
    fn transmit(&mut self, _t: Instant) -> Option<SynthTx<'_>> {
        Some(SynthTx { sink: &mut self.tx })
    }
}

// ---------------------------------------------------------------------------
// Real rule-gated device over the persistent virtio-net driver.
// Hardware I/O is decoupled from smoltcp's token lifetimes via pump_rx/pump_tx
// (called around iface.poll), so the tokens only ever borrow the staging fields —
// the same split-borrow discipline as netsvc.rs, extended for real RX/TX.
// ---------------------------------------------------------------------------

struct VirtioPhy<'d> {
    nic: &'d mut arch_aarch64::virtio_net::VirtioNet,
    rx_pending: Option<([u8; MTU], usize)>,
    tx: TxCap,
    dropped_in: u32,  // ingress frames the rule plane REFUSED
    dropped_out: u32, // egress frames the rule plane REFUSED
    rx_seen: u32,     // frames the NIC handed us (pre-verdict) — RX liveness
}

impl<'d> VirtioPhy<'d> {
    fn new(nic: &'d mut arch_aarch64::virtio_net::VirtioNet) -> Self {
        VirtioPhy {
            nic,
            rx_pending: None,
            tx: TxCap { buf: [0; MTU], len: 0, ready: false },
            dropped_in: 0,
            dropped_out: 0,
            rx_seen: 0,
        }
    }
    /// Pull one frame off the NIC into the rx staging slot IFF the rule plane PASSes
    /// it (the ingress gate — a DROP frame never reaches smoltcp). No-op if the slot
    /// is occupied or nothing is available.
    fn pump_rx(&mut self) {
        if self.rx_pending.is_some() {
            return;
        }
        let mut tmp = [0u8; MTU];
        if let Some(n) = self.nic.rx(&mut tmp) {
            self.rx_seen += 1;
            if packet::verdict(&tmp[..n]).1 == packet::PASS {
                self.rx_pending = Some((tmp, n));
            } else {
                self.dropped_in += 1; // refused admission — never seen by smoltcp
            }
        }
    }
    /// Flush a staged egress frame onto the wire (already verdict-gated in the token).
    fn pump_tx(&mut self) {
        if self.tx.ready {
            self.nic.tx(&self.tx.buf[..self.tx.len]);
            self.tx.ready = false;
        }
    }
}

impl<'d> Device for VirtioPhy<'d> {
    type RxToken<'a>
        = SynthRx
    where
        Self: 'a;
    type TxToken<'a>
        = PhyTx<'a>
    where
        Self: 'a;
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.max_transmission_unit = MTU;
        c.medium = Medium::Ethernet;
        // Compute+verify IP/UDP checksums in software: there is NO hardware offload
        // on this virtio-net path, so a real DHCP/DNS server (SLIRP) would drop a
        // zero-checksum datagram. (The synthetic SynthDev keeps `ignored` — its
        // frames never hit a real checksum validator.)
        c.checksum = ChecksumCapabilities::default();
        c
    }
    fn receive(&mut self, _t: Instant) -> Option<(SynthRx, PhyTx<'_>)> {
        let (frame, len) = self.rx_pending.take()?;
        Some((
            SynthRx { frame, len },
            PhyTx { sink: &mut self.tx, dropped: &mut self.dropped_out },
        ))
    }
    fn transmit(&mut self, _t: Instant) -> Option<PhyTx<'_>> {
        Some(PhyTx { sink: &mut self.tx, dropped: &mut self.dropped_out })
    }
}

struct PhyTx<'a> {
    sink: &'a mut TxCap,
    dropped: &'a mut u32,
}
impl<'a> phy::TxToken for PhyTx<'a> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let n = len.min(MTU);
        let mut tmp = [0u8; MTU];
        let r = f(&mut tmp[..n]);
        if packet::verdict(&tmp[..n]).1 == packet::PASS {
            self.sink.buf[..n].copy_from_slice(&tmp[..n]);
            self.sink.len = n;
            self.sink.ready = true;
        } else {
            *self.dropped += 1; // a compromised stack still cannot put this on the wire
        }
        r
    }
}

// ---------------------------------------------------------------------------
// Deterministic proofs.
// ---------------------------------------------------------------------------

/// Prove smoltcp's `dhcpv4` socket EMITS a well-formed DISCOVER (UDP 68→67,
/// broadcast) through the EGRESS verdict gate — i.e. heqk drives a smoltcp UDP
/// socket for the first time, rule-gated. Deterministic: needs no server.
fn discover_emitted() -> bool {
    let mut dev = SynthDev::new();
    let mac = EthernetAddress([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
    let mut cfg = Config::new(HardwareAddress::Ethernet(mac));
    cfg.random_seed = 0x4d34_0001;
    let mut iface = Interface::new(cfg, &mut dev, Instant::from_millis(0));
    // No IP: the whole point of DHCP.
    let dhcp = dhcpv4::Socket::new();
    let mut store = [SocketStorage::EMPTY; 1];
    let mut sockets = SocketSet::new(&mut store[..]);
    let _h = sockets.add(dhcp);
    // Poll a few times so the socket transmits its DISCOVER.
    for i in 1..8 {
        iface.poll(Instant::from_millis(i * 200), &mut dev, &mut sockets);
        if dev.tx.ready {
            break;
        }
    }
    if !dev.tx.ready {
        return false;
    }
    // The emitted frame must be a DHCP DISCOVER that PASSed the egress gate:
    // broadcast dst, IPv4/UDP, src port 68 → dst port 67.
    let f = &dev.tx.buf[..dev.tx.len];
    let bcast = f.len() >= 6 && f[..6] == [0xff; 6];
    match crate::net::parse(f) {
        Some(m) => bcast && m.ip_proto == 17 && m.src_port == 68 && m.dst_port == 67,
        None => false,
    }
}

/// Prove the ingress gate is LIVE for config traffic: a benign DNS reply and an
/// NTP frame are ADMITTED, while a threat frame (UDP:4444) is REFUSED — so a real
/// OFFER/DNS/NTP response would be admitted, but a hostile one keyed on a threat
/// rule would not.
fn gate_admits_config_refuses_threat() -> bool {
    let mut dev = SynthDev::new();
    let benign_dns = build_udp_frame(53, 40000, &[0u8; 20]); // DNS server → client
    let benign_ntp = build_udp_frame(123, 40001, &[0u8; 48]); // NTP server → client
    let threat = build_udp_frame(40002, 4444, &[0u8; 8]); // → C2 port 4444 → DROP
    let a = dev.inject(&benign_dns);
    let b = dev.inject(&benign_ntp);
    let c = dev.inject(&threat);
    kprint!("   config-gate: dns_admit={} ntp_admit={} threat_refused={}\n", yn(a), yn(b), yn(!c));
    a && b && !c
}

/// The air-gap invariant: with NO lease (no server), fallback returns a usable
/// static/last-known config and NEVER blocks. Also proves a bounded DHCP attempt
/// against a silent (no-inject) device RETURNS — no boot-block on a missing lease.
fn airgap_fallback_never_blocks() -> bool {
    let static_default = NetConfig {
        ip: [10, 200, 0, 4],
        prefix: 24,
        gw: [10, 200, 0, 1],
        dns: [10, 200, 0, 1],
        source: ConfigSource::Static,
    };
    // (1) No lease, no last-known → Static, no hang.
    let c = resolve_or_fallback(None, None, static_default);
    if c.source != ConfigSource::Static || c.ip != [10, 200, 0, 4] {
        return false;
    }
    // (2) A bounded DHCP attempt against a device that never answers must TERMINATE
    //     (Discovering forever would be a boot-block; we cap the polls).
    let mut dev = SynthDev::new();
    let mac = EthernetAddress([0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc]);
    let mut cfg = Config::new(HardwareAddress::Ethernet(mac));
    cfg.random_seed = 0x4d34_0002;
    let mut iface = Interface::new(cfg, &mut dev, Instant::from_millis(0));
    let mut store = [SocketStorage::EMPTY; 1];
    let mut sockets = SocketSet::new(&mut store[..]);
    let h = sockets.add(dhcpv4::Socket::new());
    let mut configured = false;
    for i in 1..32 {
        iface.poll(Instant::from_millis(i * 250), &mut dev, &mut sockets);
        if let Some(dhcpv4::Event::Configured(_)) =
            sockets.get_mut::<dhcpv4::Socket>(h).poll()
        {
            configured = true; // must NOT happen — no server
        }
    }
    // Never configured (no server) AND the loop returned → fallback stands, no block.
    !configured
}

/// A minimal Ethernet/IPv4/UDP frame (server→host) for gate tests.
fn build_udp_frame(src_port: u16, dst_port: u16, payload: &[u8]) -> [u8; MTU] {
    let mut f = [0u8; MTU];
    f[0..6].copy_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]); // dst = our MAC
    f[6..12].copy_from_slice(&[0x52, 0x54, 0x00, 0x00, 0x02, 0x03]); // src = server MAC
    f[12] = 0x08;
    f[13] = 0x00; // IPv4
    f[14] = 0x45; // v4, IHL=5
    let total = (20 + 8 + payload.len()) as u16;
    f[16] = (total >> 8) as u8;
    f[17] = total as u8;
    f[22] = 64; // TTL
    f[23] = 17; // UDP
    f[26..30].copy_from_slice(&[10, 0, 2, 3]); // src IP (SLIRP DNS)
    f[30..34].copy_from_slice(&[10, 0, 2, 15]); // dst IP (us)
    f[34..36].copy_from_slice(&src_port.to_be_bytes());
    f[36..38].copy_from_slice(&dst_port.to_be_bytes());
    let ulen = (8 + payload.len()) as u16;
    f[38..40].copy_from_slice(&ulen.to_be_bytes());
    f[42..42 + payload.len()].copy_from_slice(payload);
    f
}

fn dns_sntp_roundtrip() -> bool {
    // DNS build → parse: craft a response with one A record for the query and
    // recover the address; a truncated response must fail closed.
    let mut q = [0u8; 64];
    let qlen = match build_dns_query(0x1234, "sensor.hookprobe.local", &mut q) {
        Some(n) => n,
        None => return false,
    };
    let mut resp = [0u8; 128];
    let rlen = build_dns_response_a(0x1234, &q[..qlen], [93, 184, 216, 34], &mut resp);
    let dns_ok = parse_dns_a(&resp[..rlen], 0x1234) == Some([93, 184, 216, 34])
        && parse_dns_a(&resp[..8], 0x1234).is_none() // truncated → fail closed
        && parse_dns_a(&resp[..rlen], 0x9999).is_none(); // wrong id → refused
    // SNTP build → parse: a stubbed server reply (mode 4) with a known transmit
    // timestamp yields the right Unix time; the real NTP server is metal (Gate R).
    let mut req = [0u8; 48];
    let n = build_sntp_request(&mut req);
    let sntp_req_ok = n == 48 && req[0] == 0x23;
    let ntp_secs: u32 = 3_927_000_000; // arbitrary 2024-era NTP timestamp
    let mut sresp = [0u8; 48];
    sresp[0] = 0x24; // LI 0 | VN 4 | Mode 4 (server)
    sresp[40..44].copy_from_slice(&ntp_secs.to_be_bytes());
    let sntp_ok = parse_sntp(&sresp) == Some(ntp_secs as u64 - NTP_UNIX_OFFSET)
        && parse_sntp(&sresp[..40]).is_none() // short → fail closed
        && {
            let mut bad = sresp;
            bad[0] = 0x23; // mode 3 (client, not a server reply) → refused
            parse_sntp(&bad).is_none()
        };
    dns_ok && sntp_req_ok && sntp_ok
}

/// Build a DNS response echoing the question and appending one A record. (Test-only
/// helper — the device never generates responses; this stands in for a server.)
fn build_dns_response_a(id: u16, query: &[u8], addr: [u8; 4], out: &mut [u8]) -> usize {
    out[0..2].copy_from_slice(&id.to_be_bytes());
    out[2..4].copy_from_slice(&0x8180u16.to_be_bytes()); // response, RD, RA
    out[4..6].copy_from_slice(&1u16.to_be_bytes()); // qdcount
    out[6..8].copy_from_slice(&1u16.to_be_bytes()); // ancount
    out[8..12].copy_from_slice(&[0u8; 4]);
    let qbody = &query[12..]; // question (name+qtype+qclass)
    out[12..12 + qbody.len()].copy_from_slice(qbody);
    let mut o = 12 + qbody.len();
    out[o..o + 2].copy_from_slice(&0xc00cu16.to_be_bytes()); // name pointer → offset 12
    o += 2;
    out[o..o + 2].copy_from_slice(&1u16.to_be_bytes()); // TYPE A
    out[o + 2..o + 4].copy_from_slice(&1u16.to_be_bytes()); // CLASS IN
    out[o + 4..o + 8].copy_from_slice(&300u32.to_be_bytes()); // TTL
    out[o + 8..o + 10].copy_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    out[o + 10..o + 14].copy_from_slice(&addr);
    o + 14
}

// ---------------------------------------------------------------------------
// Real SLIRP leg (reported bonus): full DHCP handshake over virtio-net, then a
// real DNS query answered by SLIRP's forwarder. Strictly time-bounded.
// ---------------------------------------------------------------------------

/// Attempt a real DHCP lease + DNS resolution against QEMU `-netdev user` (SLIRP).
/// Returns the leased config on success. Bounded — a missing NIC/lease returns None
/// promptly (the air-gap path takes over). Prints its own progress line.
fn real_slirp() -> Option<NetConfig> {
    let mut nic = match arch_aarch64::virtio_net::VirtioNet::open() {
        Some(n) => n,
        None => {
            kprint!("   real: no virtio-net device (air-gap path) — SKIP real leg\n");
            return None;
        }
    };
    let mac = EthernetAddress(nic.mac());
    let mut dev = VirtioPhy::new(&mut nic);
    let mut cfg = Config::new(HardwareAddress::Ethernet(mac));
    cfg.random_seed = now_ms() as u64 ^ 0x4d34_0003;
    let mut iface = Interface::new(cfg, &mut dev, now());

    // DHCP socket + a UDP socket (for the follow-up DNS query) sized without heap.
    let mut store = [SocketStorage::EMPTY; 2];
    let mut sockets = SocketSet::new(&mut store[..]);
    let dh = sockets.add(dhcpv4::Socket::new());
    let mut urx_meta = [udp::PacketMetadata::EMPTY; 4];
    let mut urx = [0u8; 1024];
    let mut utx_meta = [udp::PacketMetadata::EMPTY; 4];
    let mut utx = [0u8; 1024];
    let uh = sockets.add(udp::Socket::new(
        udp::PacketBuffer::new(&mut urx_meta[..], &mut urx[..]),
        udp::PacketBuffer::new(&mut utx_meta[..], &mut utx[..]),
    ));

    let deadline = now_ms() + 6000; // hard 6 s cap — never blocks boot
    let mut lease: Option<NetConfig> = None;
    let mut dns_sent = false;
    let mut resolved: Option<[u8; 4]> = None;
    let mut iters: u64 = 0;
    let mut tx_seen = 0u32;

    while now_ms() < deadline {
        iters += 1;
        dev.pump_rx();
        iface.poll(now(), &mut dev, &mut sockets);
        if dev.tx.ready {
            tx_seen += 1;
        }
        dev.pump_tx();

        if lease.is_none() {
            if let Some(dhcpv4::Event::Configured(c)) =
                sockets.get_mut::<dhcpv4::Socket>(dh).poll()
            {
                let ip = c.address.address().octets();
                let gw = c.router.map(|r| r.octets()).unwrap_or([0; 4]);
                let dns = c
                    .dns_servers
                    .first()
                    .map(|d| d.octets())
                    .unwrap_or([0; 4]);
                iface.update_ip_addrs(|a| {
                    a.clear();
                    let _ = a.push(IpCidr::Ipv4(c.address));
                });
                if let Some(r) = c.router {
                    let _ = iface.routes_mut().add_default_ipv4_route(r);
                }
                kprint!(
                    "   real: DHCP lease {}.{}.{}.{}/{} gw {}.{}.{}.{} dns {}.{}.{}.{}\n",
                    ip[0], ip[1], ip[2], ip[3], c.address.prefix_len(),
                    gw[0], gw[1], gw[2], gw[3], dns[0], dns[1], dns[2], dns[3]
                );
                lease = Some(NetConfig {
                    ip, prefix: c.address.prefix_len(), gw, dns,
                    source: ConfigSource::Dhcp,
                });
                // Bind the UDP socket for the DNS query now that we have an address.
                let _ = sockets.get_mut::<udp::Socket>(uh).bind(40053);
            }
        } else if !dns_sent {
            // Fire one DNS A query at the learned resolver (SLIRP forwards it).
            let l = lease.unwrap();
            let mut q = [0u8; 64];
            if let Some(qlen) = build_dns_query(0x2600, "example.com", &mut q) {
                let ep = IpEndpoint::new(IpAddress::Ipv4(Ipv4Address::from(l.dns)), 53);
                if sockets
                    .get_mut::<udp::Socket>(uh)
                    .send_slice(&q[..qlen], ep)
                    .is_ok()
                {
                    dns_sent = true;
                }
            } else {
                dns_sent = true;
            }
        } else if resolved.is_none() {
            let mut buf = [0u8; 512];
            if let Ok((n, _ep)) = sockets.get_mut::<udp::Socket>(uh).recv_slice(&mut buf) {
                if let Some(a) = parse_dns_a(&buf[..n], 0x2600) {
                    kprint!(
                        "   real: DNS example.com -> {}.{}.{}.{} (via {}.{}.{}.{})\n",
                        a[0], a[1], a[2], a[3], l_dns(&lease)[0], l_dns(&lease)[1],
                        l_dns(&lease)[2], l_dns(&lease)[3]
                    );
                    resolved = Some(a);
                    break; // both real proofs done
                }
            }
        }
    }
    kprint!(
        "   real: virtio-net liveness — polls={} tx_frames={} rx_frames={} (rule-gate refused: in={} out={})\n",
        iters, tx_seen, dev.rx_seen, dev.dropped_in, dev.dropped_out
    );
    if lease.is_none() {
        kprint!("   real: no lease within 6s (SLIRP timing / no server) — air-gap path\n");
    } else if resolved.is_none() {
        kprint!("   real: lease OK; DNS unanswered in window (SLIRP forwarder timing = note)\n");
    }
    lease
}

fn l_dns(lease: &Option<NetConfig>) -> [u8; 4] {
    lease.map(|l| l.dns).unwrap_or([0; 4])
}

// ---------------------------------------------------------------------------
// The P18-netcfg selftest: deterministic core GATES the PASS; the real SLIRP leg
// is a reported bonus (its outcome never fails the gate — honest Track-C).
// ---------------------------------------------------------------------------

/// Returns true iff the deterministic, host-provable core all passes.
pub fn netcfg_selftest() -> bool {
    let discover = discover_emitted();
    let gate = gate_admits_config_refuses_threat();
    let airgap = airgap_fallback_never_blocks();
    let dns_sntp = dns_sntp_roundtrip();

    kprint!(
        "   deterministic: dhcp-DISCOVER-emitted(gated)={} config-gate(admit/refuse)={} air-gap-fallback={} dns+sntp-build/parse={}\n",
        yn(discover), yn(gate), yn(airgap), yn(dns_sntp)
    );

    // Real SLIRP leg (bonus, reported): a full lease + DNS over virtio-net.
    let _ = real_slirp();

    discover && gate && airgap && dns_sntp
}

fn yn(b: bool) -> &'static str {
    if b {
        "PASS"
    } else {
        "FAIL"
    }
}
