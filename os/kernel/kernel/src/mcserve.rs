//! `mcserve` — heqk serves Mission Control itself (ADR 0047 D2): the IPS-gated datapath, the
//! SOAR → evidence state, and an HTTP server for the UI + API, in ONE loop on the device. QEMU
//! virt (virtio-net) today; the CM5 GEM path reuses the same pieces (`mcstate`/`http`) behind the
//! existing MetalBridge drain (metal day).
//!
//! Every received frame goes through `packet::verdict` FIRST: a threat is enforced (dropped,
//! counted, SOAR event) and never reaches the TCP stack; only PASS frames addressed to heqk are
//! handed to smoltcp. Every frame smoltcp emits is verdict-gated again on egress. So the
//! operator's own UI connection is inspected by the same detection plane it reports on.
//!
//! Allocation-free: static socket buffers + per-connection fixed scratch (heqk's heap never
//! frees). `CONNS` connection slots on :80; SSE clients hold one each.

use crate::http::{self, Body};
use crate::mcauth::{Auth, Owner};
use crate::mcstate::McState;
use crate::{events, packet};
#[cfg(not(feature = "cm5"))]
use crate::telemetry;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::{self, ChecksumCapabilities, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv4Address};

#[cfg(not(feature = "cm5"))]
macro_rules! kprint {
    ($($t:tt)*) => { arch_aarch64::_print(format_args!($($t)*)) };
}

const MTU: usize = 1514;
const TXQ: usize = 32;
// Browsers open ~6 parallel connections per host and each tab holds one SSE stream; smoltcp has
// no listen backlog (a SYN with no free listener is RST), so the pool must cover a real browser
// session. 4 slots reset 5 of 8 parallel requests in the first e2e run.
const CONNS: usize = 16;
const TCP_RX: usize = 2048;
const TCP_TX: usize = 16 * 1024;
const SCRATCH: usize = 64 * 1024;
const HTTP_PORT: u16 = 80;
const HTTPS_PORT: u16 = 443;
/// TLS connections (ADR 0051): one EL0 TLS-server slot each, on top of the plain-HTTP pool.
#[cfg(feature = "mctls")]
const TLS_N: usize = hal::tlsabi::SLOTS;
#[cfg(not(feature = "mctls"))]
const TLS_N: usize = 0;
/// Every TCP connection slot: plain HTTP `0..CONNS`, HTTPS `CONNS..ALL`.
const ALL: usize = CONNS + TLS_N;

#[cfg(not(feature = "cm5"))]
#[inline]
fn cntpct() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) v, options(nomem, nostack)) };
    v
}
#[cfg(not(feature = "cm5"))]
#[inline]
fn cntfrq() -> u64 {
    let v: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) v, options(nomem, nostack)) };
    v
}

/// QEMU virt PL031 RTC data register: seconds since the epoch (QEMU seeds it from the host).
#[cfg(not(feature = "cm5"))]
fn rtc_epoch_secs() -> u64 {
    const PL031_DR: usize = 0x0901_0000;
    unsafe { core::ptr::read_volatile(PL031_DR as *const u32) as u64 }
}

// ---- the smoltcp device: one ingress slot, a multi-slot egress queue, egress verdict-gated ----

struct McDev {
    rx: Option<([u8; MTU], usize)>,
    txq: [([u8; MTU], usize); TXQ],
    txn: usize,
    pub tx_lost: u32,
    pub egress_dropped: u32,
}

impl McDev {
    const fn new() -> Self {
        McDev { rx: None, txq: [([0; MTU], 0); TXQ], txn: 0, tx_lost: 0, egress_dropped: 0 }
    }
}

struct RxTok([u8; MTU], usize);
impl phy::RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0[..self.1])
    }
}

struct TxTok<'a> {
    dev_txq: &'a mut [([u8; MTU], usize); TXQ],
    txn: &'a mut usize,
    lost: &'a mut u32,
    gated: &'a mut u32,
}
impl phy::TxToken for TxTok<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let n = len.min(MTU);
        let mut tmp = [0u8; MTU];
        let r = f(&mut tmp[..n]);
        if packet::verdict(&tmp[..n]).1 != packet::PASS {
            *self.gated += 1; // EGRESS gate: never emit what the rule plane refuses
        } else if *self.txn < TXQ {
            self.dev_txq[*self.txn].0[..n].copy_from_slice(&tmp[..n]);
            self.dev_txq[*self.txn].1 = n;
            *self.txn += 1;
        } else {
            *self.lost += 1; // counted, never silent (TCP retransmits)
        }
        r
    }
}

impl Device for McDev {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.max_transmission_unit = MTU;
        c.medium = Medium::Ethernet;
        // virtio-net here offloads nothing: compute checksums on egress, verify on ingress.
        c.checksum = ChecksumCapabilities::default();
        c
    }
    fn receive(&mut self, _t: Instant) -> Option<(RxTok, TxTok<'_>)> {
        let (f, n) = self.rx.take()?;
        Some((RxTok(f, n), TxTok { dev_txq: &mut self.txq, txn: &mut self.txn, lost: &mut self.tx_lost, gated: &mut self.egress_dropped }))
    }
    fn transmit(&mut self, _t: Instant) -> Option<TxTok<'_>> {
        Some(TxTok { dev_txq: &mut self.txq, txn: &mut self.txn, lost: &mut self.tx_lost, gated: &mut self.egress_dropped })
    }
}

// ---- per-connection HTTP state ----

#[derive(Clone, Copy)]
enum Src {
    Static(&'static [u8]),
    Scratch(usize),
}

#[derive(Clone, Copy)]
enum Conn {
    /// Accumulating the request header block. `since` = when this wait began (0 = not yet started — the
    /// keep-alive idle clock); `served` = requests already answered on this connection.
    Reading { got: usize, since: u64, served: u16 },
    /// Streaming head (in `head`) then body.
    Sending { hlen: usize, hoff: usize, body: Src, boff: usize, keep: bool, carry: usize, served: u16 },
    /// Long-lived SSE stream.
    Sse { last_change: u64, last_ping_ms: u64 },
}

static mut STORAGE: [SocketStorage<'static>; ALL + 1] = [SocketStorage::EMPTY; ALL + 1];
// The SNTP client's one UDP socket (the +1 storage slot): two packets of 48 B each way.
static mut NTP_RX_META: [udp::PacketMetadata; 2] = [udp::PacketMetadata::EMPTY; 2];
static mut NTP_RX_BUF: [u8; 128] = [0; 128];
static mut NTP_TX_META: [udp::PacketMetadata; 2] = [udp::PacketMetadata::EMPTY; 2];
static mut NTP_TX_BUF: [u8; 128] = [0; 128];
static mut TCP_RX_BUF: [[u8; TCP_RX]; ALL] = [[0; TCP_RX]; ALL];
static mut TCP_TX_BUF: [[u8; TCP_TX]; ALL] = [[0; TCP_TX]; ALL];
static mut REQ: [[u8; 4096]; ALL] = [[0; 4096]; ALL];
static mut HEAD: [[u8; 512]; ALL] = [[0; 512]; ALL];
static mut SCRATCH_BUF: [[u8; SCRATCH]; ALL] = [[0; SCRATCH]; ALL];
static mut DEV: McDev = McDev::new();
static mut STATE: McState = McState::new();
static mut AUTH: Auth = Auth::new(None);
static RAND_CTR: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn is_for_us(frame: &[u8], mac: [u8; 6]) -> bool {
    frame.len() >= 14 && (frame[..6] == mac || frame[..6] == [0xff; 6])
}

/// The device's Mission Control state (one instance; single-core, owned by the serve loop).
#[allow(static_mut_refs)]
pub fn state() -> &'static mut McState {
    unsafe { &mut STATE }
}

/// Install the owner verifier read from the boot partition (`None` = unclaimed: every protected
/// route refuses — no open claim window).
#[allow(static_mut_refs)]
pub fn set_owner(owner: Option<Owner>) {
    unsafe { AUTH = Auth::new(owner) };
}

#[allow(static_mut_refs)]
fn auth() -> &'static mut Auth {
    unsafe { &mut AUTH }
}

/// 16 bytes for a session id: the hardware TRNG on the CM5 (fail-closed: no TRNG => `None`, the
/// login is refused, the sensor keeps running); QEMU has no TRNG, so a hash of the cycle counter + a counter stands in
/// (QEMU-ONLY — never shipped: the CM5 build takes the TRNG branch).
fn rand16() -> Option<[u8; 16]> {
    #[cfg(feature = "cm5")]
    {
        let a = arch_aarch64::rng200::next_word_strict();
        let b = arch_aarch64::rng200::next_word_strict();
        match (a, b) {
            (Some(a), Some(b)) => {
                let mut o = [0u8; 16];
                o[..8].copy_from_slice(&a.to_le_bytes());
                o[8..].copy_from_slice(&b.to_le_bytes());
                Some(o)
            }
            _ => None, // fail-closed: this login fails, the sensor keeps running
        }
    }
    #[cfg(not(feature = "cm5"))]
    {
        let n = RAND_CTR.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        let mut h = boot_abi::sha256::Hasher::new();
        h.update(&cntpct().to_le_bytes());
        h.update(&n.to_le_bytes());
        h.update(b"heqk-qemu-session");
        let d = h.finish();
        let mut o = [0u8; 16];
        o.copy_from_slice(&d[..16]);
        Some(o)
    }
}

/// How the node gets its IPv4 address.
#[derive(Clone, Copy)]
#[allow(dead_code)] // Static is the QEMU/fixed-address path; the CM5 profile uses Dhcp
pub enum NetMode {
    Static { ip: [u8; 4], prefix: u8, gw: [u8; 4] },
    /// DHCP; until a lease arrives the node keeps the link-local fallback below.
    Dhcp,
}

/// RFC 3927 link-local fallback while DHCP has not answered (operator can still reach the box
/// on a direct cable). The exact host part is derived from the MAC so two devices differ.
const NTP_LOCAL_PORT: u16 = 40123;
const NTP_RETRY_MS: i64 = 16_000;
const NTP_RESYNC_MS: i64 = 3_600_000;
struct Sntp {
    sock: SocketHandle,
    /// Our outstanding request's transmit timestamp (0 = none outstanding).
    nonce: u64,
    rng: u64,
    server: Option<[u8; 4]>,
    next_ms: i64,
    tries: u32,
    synced_once: bool,
    result: Option<u64>,
}

fn link_local(mac: [u8; 6]) -> [u8; 4] {
    [169, 254, 1 + (mac[4] % 254), 1 + (mac[5] % 254)]
}

/// NIC-agnostic Mission Control node (ADR 0047 D2): smoltcp interface + DHCP + the HTTP
/// connection pool. The caller owns the NIC and the detection plane: it calls `ingress` only for
/// frames that already PASSed `packet::verdict` and that `wants` claims, `service` every loop
/// iteration, and `flush` to put egress frames (verdict-gated in `McDev`) on its NIC.
pub struct McNode {
    iface: Interface,
    sockets: SocketSet<'static>,
    handles: [Option<SocketHandle>; ALL],
    conns: [Conn; ALL],
    /// HTTPS slot `k` (socket `CONNS + k`) has an open session in the EL0 TLS server.
    tls_open: [bool; TLS_N],
    /// HTTPS slot `k` completed its handshake (counted once).
    tls_hs: [bool; TLS_N],
    dhcp: Option<SocketHandle>,
    mac: [u8; 6],
    pub ip: [u8; 4],
    pub leased: bool,
    gw: Option<[u8; 4]>,
    ntp: Sntp,
}

static NODE_TAKEN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

impl McNode {
    /// Build the node (once per boot: it owns the module's static buffers).
    #[allow(static_mut_refs)]
    pub fn new(mac: [u8; 6], mode: NetMode, seed: u64) -> Option<McNode> {
        if NODE_TAKEN.swap(true, core::sync::atomic::Ordering::SeqCst) {
            return None;
        }
        let dev = unsafe { &mut DEV };
        let mut cfg = Config::new(HardwareAddress::Ethernet(EthernetAddress(mac)));
        cfg.random_seed = seed;
        let mut iface = Interface::new(cfg, dev, Instant::from_millis(0));
        let (ip, prefix, gw) = match mode {
            NetMode::Static { ip, prefix, gw } => (ip, prefix, Some(gw)),
            NetMode::Dhcp => (link_local(mac), 16, None),
        };
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::v4(ip[0], ip[1], ip[2], ip[3]), prefix));
        });
        if let Some(g) = gw {
            let _ = iface.routes_mut().add_default_ipv4_route(Ipv4Address::new(g[0], g[1], g[2], g[3]));
        }
        let mut sockets = SocketSet::new(unsafe { &mut STORAGE[..] });
        let mut handles: [Option<SocketHandle>; ALL] = [None; ALL];
        // Reserve one slot of the pool for the DHCP socket in DHCP mode.
        let tcp_slots = if matches!(mode, NetMode::Dhcp) { CONNS - 1 } else { CONNS };
        for (i, h) in handles.iter_mut().enumerate().take(tcp_slots) {
            let rx = tcp::SocketBuffer::new(unsafe { &mut TCP_RX_BUF[i][..] });
            let tx = tcp::SocketBuffer::new(unsafe { &mut TCP_TX_BUF[i][..] });
            let mut s = tcp::Socket::new(rx, tx);
            let _ = s.listen(HTTP_PORT);
            *h = Some(sockets.add(s));
        }
        // HTTPS listeners only when the EL0 TLS server is up with a certificate (ADR 0051).
        #[cfg(feature = "mctls")]
        if crate::tlshost::host().map_or(false, |h| h.ready) {
            for i in CONNS..ALL {
                let rx = tcp::SocketBuffer::new(unsafe { &mut TCP_RX_BUF[i][..] });
                let tx = tcp::SocketBuffer::new(unsafe { &mut TCP_TX_BUF[i][..] });
                let mut s = tcp::Socket::new(rx, tx);
                let _ = s.listen(HTTPS_PORT);
                handles[i] = Some(sockets.add(s));
            }
        }
        let dhcp = match mode {
            NetMode::Dhcp => Some(sockets.add(smoltcp::socket::dhcpv4::Socket::new())),
            NetMode::Static { .. } => None,
        };
        let ntp_sock = {
            let rx = udp::PacketBuffer::new(unsafe { &mut NTP_RX_META[..] }, unsafe { &mut NTP_RX_BUF[..] });
            let tx = udp::PacketBuffer::new(unsafe { &mut NTP_TX_META[..] }, unsafe { &mut NTP_TX_BUF[..] });
            let mut u = udp::Socket::new(rx, tx);
            let _ = u.bind(NTP_LOCAL_PORT);
            sockets.add(u)
        };
        Some(McNode {
            iface, sockets, handles, conns: [Conn::Reading { got: 0, since: 0, served: 0 }; ALL], tls_open: [false; TLS_N], tls_hs: [false; TLS_N], dhcp, mac, ip, leased: dhcp.is_none(), gw,
            ntp: Sntp { sock: ntp_sock, nonce: 0, rng: seed | 1, server: None, next_ms: 0, tries: 0, synced_once: false, result: None },
        })
    }

    /// Does this frame belong to the node (our MAC or broadcast)?
    pub fn wants(&self, frame: &[u8]) -> bool {
        is_for_us(frame, self.mac)
    }

    /// Feed one frame that already PASSed the detection plane.
    #[allow(static_mut_refs)]
    pub fn ingress(&mut self, frame: &[u8], now_ms: i64) {
        let dev = unsafe { &mut DEV };
        let n = frame.len().min(MTU);
        let mut b = [0u8; MTU];
        b[..n].copy_from_slice(&frame[..n]);
        dev.rx = Some((b, n));
        self.iface.poll(Instant::from_millis(now_ms), dev, &mut self.sockets);
    }

    /// DHCP progress + every HTTP connection + one stack poll. Returns true when the lease
    /// changed (so the caller can announce the new address).
    #[allow(static_mut_refs)]
    pub fn service(&mut self, st: &McState, now_ms: i64) -> bool {
        let mut changed = false;
        if let Some(dh) = self.dhcp {
            use smoltcp::socket::dhcpv4::Event;
            match self.sockets.get_mut::<smoltcp::socket::dhcpv4::Socket>(dh).poll() {
                Some(Event::Configured(c)) => {
                    let a = c.address.address().octets();
                    self.iface.update_ip_addrs(|v| {
                        v.clear();
                        let _ = v.push(IpCidr::Ipv4(c.address));
                    });
                    if let Some(r) = c.router {
                        let _ = self.iface.routes_mut().add_default_ipv4_route(r);
                    }
                    self.gw = c.router.map(|r| r.octets());
                    self.ntp.next_ms = 0; // a new lease: try time right away
                    self.ip = a;
                    self.leased = true;
                    changed = true;
                }
                Some(Event::Deconfigured) => {
                    let ll = link_local(self.mac);
                    self.iface.update_ip_addrs(|v| {
                        v.clear();
                        let _ = v.push(IpCidr::new(IpAddress::v4(ll[0], ll[1], ll[2], ll[3]), 16));
                    });
                    self.iface.routes_mut().remove_default_ipv4_route();
                    self.gw = None;
                    self.ip = ll;
                    self.leased = false;
                    changed = true;
                }
                None => {}
            }
        }
        for i in 0..CONNS {
            let Some(h) = self.handles[i] else { continue };
            let s = self.sockets.get_mut::<tcp::Socket>(h);
            // A slot in TIME-WAIT has already exchanged FINs; holding it for the 2*MSL timer only starves
            // the listener pool under bursts — recycle it straight to Listen.
            if s.state() == tcp::State::TimeWait {
                s.abort();
            }
            if !s.is_open() {
                let _ = s.listen(HTTP_PORT);
                self.conns[i] = Conn::Reading { got: 0, since: 0, served: 0 };
                continue;
            }
            serve_conn(i, &mut Plain(s), &mut self.conns[i], st, now_ms as u64);
        }
        #[cfg(feature = "mctls")]
        for i in CONNS..ALL {
            self.tls_service(i, st, now_ms);
        }
        if self.leased {
            self.sntp_step(now_ms);
        }
        let dev = unsafe { &mut DEV };
        self.iface.poll(Instant::from_millis(now_ms), dev, &mut self.sockets);
        changed
    }

    /// No SNTP from this node (the AP's node lives on the LAN side; its gateway is itself).
    pub fn disable_sntp(&mut self) {
        self.ntp.next_ms = i64::MAX;
    }

    /// A validated wall-clock reading (Unix ms at the moment it was taken), once per reply. The
    /// caller applies it with `McState::sync_clock(ms, cntpct())`.
    pub fn take_time(&mut self) -> Option<u64> {
        self.ntp.result.take()
    }

    /// The SNTP client (RFC 4330): ask the DHCP router first, then the public anycast servers;
    /// accept ONLY a reply from the server asked, from port 123, that echoes our nonce.
    fn sntp_step(&mut self, now_ms: i64) {
        let n = &mut self.ntp;
        let u = self.sockets.get_mut::<udp::Socket>(n.sock);
        let mut buf = [0u8; 64];
        while let Ok((len, meta)) = u.recv_slice(&mut buf) {
            #[allow(unreachable_patterns)]
            let from = match meta.endpoint.addr {
                IpAddress::Ipv4(a) => a.octets(),
                _ => continue,
            };
            let asked = n.server.map_or(false, |s| s == from);
            if !asked || meta.endpoint.port != 123 || n.nonce == 0 {
                continue;
            }
            if let Some(ms) = crate::mcstate::sntp_parse_strict(&buf[..len], n.nonce) {
                n.result = Some(ms);
                n.nonce = 0; // one answer per request (a replayed copy is refused)
                n.synced_once = true;
                n.tries = 0;
                n.next_ms = now_ms + NTP_RESYNC_MS;
            }
        }
        if now_ms < n.next_ms {
            return;
        }
        // Candidate list: the router this lease named, then two anycast servers.
        let cands: [Option<[u8; 4]>; 3] = [self.gw, Some([162, 159, 200, 1]), Some([162, 159, 200, 123])];
        let pick = cands.iter().cycle().skip(n.tries as usize % 3).take(3).flatten().next().copied();
        let Some(srv) = pick else { return };
        n.rng ^= n.rng << 13;
        n.rng ^= n.rng >> 7;
        n.rng ^= n.rng << 17;
        n.nonce = n.rng | 1;
        let mut req = [0u8; 48];
        req[0] = 0x23; // LI 0 | VN 4 | Mode 3 (client)
        req[40..48].copy_from_slice(&n.nonce.to_be_bytes()); // transmit timestamp = our nonce
        let ep = (IpAddress::v4(srv[0], srv[1], srv[2], srv[3]), 123u16);
        if u.send_slice(&req, ep).is_ok() {
            n.server = Some(srv);
        }
        n.tries = n.tries.wrapping_add(1);
        n.next_ms = now_ms + if n.synced_once { NTP_RESYNC_MS } else { NTP_RETRY_MS };
    }

    /// Put queued egress frames on the NIC via `tx` (returns false when the NIC cannot take one
    /// yet — the rest stay queued, in order).
    #[allow(static_mut_refs)]
    pub fn flush(&mut self, mut tx: impl FnMut(&[u8]) -> bool) {
        let dev = unsafe { &mut DEV };
        let mut sent = 0;
        while sent < dev.txn {
            let (ref f, n) = dev.txq[sent];
            if !tx(&f[..n]) {
                break;
            }
            sent += 1;
        }
        if sent > 0 {
            dev.txq.copy_within(sent..dev.txn, 0);
            dev.txn -= sent;
        }
    }

    /// (tx_lost, egress_gated) — counted, never silent.
    #[allow(static_mut_refs)]
    pub fn tx_stats(&self) -> (u32, u32) {
        let dev = unsafe { &DEV };
        (dev.tx_lost, dev.egress_dropped)
    }
}

/// Drain the SOAR ring into the device's Mission Control state (the ONE drain point when the
/// node runs; callers that also persist/export feed the same events onward via `each`).
pub fn drain_events(st: &mut McState, mut each: impl FnMut(&events::Event)) {
    let mut evs = [events::Event::EMPTY; 32];
    loop {
        let k = events::drain(&mut evs);
        for e in &evs[..k] {
            st.push_event(e);
            each(e);
        }
        if k < evs.len() {
            break;
        }
    }
}

/// QEMU virt: boot straight into the device's Mission Control service. Never returns.
#[cfg(not(feature = "cm5"))]
pub fn run() -> ! {
    let Some(mut nic) = arch_aarch64::virtio_net::VirtioNet::open() else {
        kprint!(" [MC] FAIL — no virtio-net device; cannot serve Mission Control\n");
        loop {
            core::hint::spin_loop();
        }
    };
    // ARM THE RULE PLANE first: until rules::init verifies (+JITs) the corpora, every rule is
    // skipped and packet::verdict passes everything (found by this path's first e2e run).
    let (rv, rj) = crate::rules::init();
    kprint!(" [MC] rule plane armed: {} rules verified, {} JIT-compiled\n", rv, rj);
    let mac = nic.mac();
    let frq = cntfrq().max(1);
    let t0 = cntpct();
    let st = state();
    st.set_clock(rtc_epoch_secs() * 1000, t0, frq);
    // Owner verifier from the attached boot disk's OWNER.TXT (ADR 0037 D3); none = unclaimed.
    let owner = arch_aarch64::virtio_blk::VirtioBlk::open().and_then(|d| crate::mcauth::load_owner(&d));
    set_owner(owner);
    kprint!(" [MC] owner: {}\n", if owner.is_some() { "CLAIMED (OWNER.TXT verifier loaded) — sign-in required" } else { "UNCLAIMED — every protected route refuses (flash with the owner key)" });
    // ADR 0051: the EL0 TLS server + MCTLS.CRT from the same boot disk (before the node: it decides :443).
    #[cfg(feature = "mctls")]
    crate::tlshost::bring_up(arch_aarch64::virtio_blk::VirtioBlk::open().as_ref());
    let now_ms = || (cntpct().wrapping_sub(t0) / (frq / 1000).max(1)) as i64;
    // DHCP (QEMU's user-mode network serves 10.0.2.15), the production address path.
    let mut node = McNode::new(mac, NetMode::Dhcp, t0 ^ 0x4D43_5345_5256_4500).expect("one node per boot");
    kprint!(" [MC] heqk Mission Control up — {} UI assets embedded; every frame IPS-gated both ways; DHCP in progress (fallback {}.{}.{}.{})\n",
        http::UI_ASSETS.len(), node.ip[0], node.ip[1], node.ip[2], node.ip[3]);

    let mut frame = [0u8; MTU];
    let mut last_sample = 0i64;
    let mut last_hb = 0i64;
    loop {
        let now = now_ms();
        let mut budget = 64;
        while budget > 0 {
            budget -= 1;
            let Some(n) = nic.rx(&mut frame) else { break };
            st.seen += 1;
            let src = crate::net::eth_ipv4_src(&frame[..n]);
            if src != 0 && crate::behavioral::is_internal(src) {
                let ms = st.epoch_ms(cntpct());
                st.note_host(src, ms);
            }
            if packet::verdict(&frame[..n]).1 != packet::PASS {
                st.dropped += 1;
                continue;
            }
            st.forwarded += 1;
            if node.wants(&frame[..n]) {
                node.ingress(&frame[..n], now);
            }
        }
        drain_events(st, |_| {});
        if now - last_sample >= 1000 {
            last_sample = now;
            st.sample_qsecbit(cntpct(), telemetry::score());
        }
        if let Some(ms) = node.take_time() {
            match st.sync_clock(ms, cntpct()) {
                Some(step) => kprint!(" [MC] clock synced by SNTP (step {} ms)\n", step),
                None => kprint!(" [MC] SNTP re-sync REFUSED (step > 1 h)\n"),
            }
        }
        if node.service(st, now) {
            kprint!(" [MC] heqk Mission Control serving on http://{}.{}.{}.{}:{} ({})\n",
                node.ip[0], node.ip[1], node.ip[2], node.ip[3], HTTP_PORT, if node.leased { "DHCP lease" } else { "link-local fallback" });
        }
        node.flush(|f| nic.tx(f));
        if now - last_hb >= 10_000 {
            last_hb = now;
            let (lost, gated) = node.tx_stats();
            #[cfg(feature = "mctls")]
            {
                let mut ss = [0u8; TLS_N * 2];
                node.tls_slot_states(&mut ss);
                kprint!(" [MC-TLS slots] {}\n", core::str::from_utf8(&ss).unwrap_or("?"));
            }
            #[cfg(feature = "mctls")]
            if let Some(h) = crate::tlshost::host() {
                let t = unsafe { TLS_STATS };
                kprint!(" [MC-TLS hb] ready={} calls={} handshakes={} pq_hybrid={} records_out={} failed_closed={} rate_limited={} tls_errors={} timeouts={} faults={} restarts={}\n",
                    h.ready, h.calls, t[0], t[3], t[1], t[2], t[4], h.tls_errors, h.timeouts, h.faults, h.restarts);
            }
            kprint!(" [MC hb] seen={} passed={} dropped={} detections={} qsecbit_raw={} rules_active={} tx_lost={} egress_gated={}\n",
                st.seen, st.forwarded, st.dropped, st.detections(), telemetry::score(), crate::rules::active_rules(), lost, gated);
        }
    }
}

#[allow(static_mut_refs)]
fn serve_conn<P: Pipe>(i: usize, s: &mut P, c: &mut Conn, st: &McState, now_ms: u64) {
    let req = unsafe { &mut REQ[i] };
    let head = unsafe { &mut HEAD[i] };
    let scratch = unsafe { &mut SCRATCH_BUF[i] };
    match *c {
        Conn::Reading { got, since, served } => {
            // Keep-alive idle clock: a connection waiting too long for its next request is closed (HTTPS
            // has only TLS_N slots — idle browsers must not pin them).
            let since = if since == 0 { now_ms.max(1) } else { since };
            if now_ms.saturating_sub(since) > http::KEEPALIVE_SECS * 1000 {
                s.close();
                *c = Conn::Reading { got: 0, since: 0, served: 0 };
                return;
            }
            if !s.may_recv() && got == 0 {
                if s.peer_closed() {
                    s.close(); // the client ended a kept-alive connection
                    *c = Conn::Reading { got: 0, since: 0, served: 0 };
                } else {
                    *c = Conn::Reading { got, since, served };
                }
                return;
            }
            // (A carried-over pipelined request is parsed even when no new bytes arrived.)
            let n = if s.may_recv() { s.recv(&mut req[got..]) } else { 0 };
            let got = got + n;
            *c = Conn::Reading { got, since, served };
            match http::parse(&req[..got]) {
                Err(http::ParseErr::Incomplete) => {}
                Err(http::ParseErr::Bad) => {
                    let _ = s.send(http::BAD_REQUEST);
                    s.close();
                }
                Ok(r) => {
                    if !s.secure() && https_ready() {
                        let n = http::https_redirect(&r, &mut head[..]);
                        let _ = s.send(&head[..n]);
                        s.close();
                        return;
                    }
                    let resp = http::handle(&r, st, auth(), now_ms, rand16, &mut scratch[..]);
                    let keep = r.keep_alive && served + 1 < http::KEEPALIVE_MAX && !matches!(resp.body, Body::Sse);
                    let consumed = r.consumed.min(got);
                    let hlen = http::write_head_ka(&resp, &mut head[..], s.secure(), keep);
                    // Bytes after this request are the next (pipelined) one: keep them at the buffer start.
                    req.copy_within(consumed..got, 0);
                    let carry = got - consumed;
                    let served = served + 1;
                    *c = match resp.body {
                        Body::Static(b) => Conn::Sending { hlen, hoff: 0, body: Src::Static(b), boff: 0, keep, carry, served },
                        Body::Scratch(n) => Conn::Sending { hlen, hoff: 0, body: Src::Scratch(n), boff: 0, keep, carry, served },
                        Body::Sse => {
                            let _ = s.send(&head[..hlen]);
                            Conn::Sse { last_change: u64::MAX, last_ping_ms: now_ms }
                        }
                    };
                }
            }
        }
        Conn::Sending { hlen, mut hoff, body, mut boff, keep, carry, served } => {
            if hoff < hlen {
                hoff += s.send(&head[hoff..hlen]);
            }
            if hoff >= hlen {
                let src: &[u8] = match body {
                    Src::Static(b) => b,
                    Src::Scratch(n) => &scratch[..n],
                };
                if boff < src.len() {
                    boff += s.send(&src[boff..]);
                }
                if boff >= src.len() {
                    if keep {
                        // Response complete: wait for the next request on the same connection.
                        *c = Conn::Reading { got: carry, since: now_ms.max(1), served };
                        return;
                    }
                    s.close(); // FIN after the queued bytes drain
                }
            }
            *c = Conn::Sending { hlen, hoff, body, boff, keep, carry, served };
        }
        Conn::Sse { last_change, last_ping_ms } => {
            // SSE is server→client only: a client FIN means the EventSource is gone. Without the
            // peer_closed() check a closed tab/reload held its slot (CloseWait) until the next 15 s ping
            // drew an RST — HTTPS has only TLS_N slots (mc-e2e "slots not recycled", 2026-11-08).
            if !s.may_send() || s.peer_closed() {
                s.close();
                return;
            }
            if st.change != last_change && s.room() > 4096 {
                let n = http::sse_update(st, &mut scratch[..8192]);
                if n > 0 && s.send(&scratch[..n]) > 0 {
                    *c = Conn::Sse { last_change: st.change, last_ping_ms: now_ms };
                }
            } else if now_ms.saturating_sub(last_ping_ms) >= 15_000 {
                let _ = s.send(http::SSE_PING);
                *c = Conn::Sse { last_change, last_ping_ms: now_ms };
            }
        }
    }
}

/// A byte pipe `serve_conn` talks HTTP over: the TCP socket itself (plain HTTP), or the TLS session that
/// encrypts through the EL0 TLS server (ADR 0051) — one HTTP code path for both ports.
trait Pipe {
    fn may_recv(&self) -> bool;
    fn recv(&mut self, buf: &mut [u8]) -> usize;
    /// Accepts a prefix of `d`; returns how many bytes were taken.
    fn send(&mut self, d: &[u8]) -> usize;
    fn may_send(&self) -> bool;
    /// Free send space (plaintext bytes that would currently be accepted).
    fn room(&self) -> usize;
    fn close(&mut self);
    /// The pipe is TLS (cookies get `Secure`; no https redirect).
    fn secure(&self) -> bool {
        false
    }
    /// The client closed its sending side (FIN) — a kept-alive connection can be released now.
    fn peer_closed(&self) -> bool {
        false
    }
}

/// HTTPS is up (a certificate is installed): plain :80 then only redirects (ADR 0051 D4).
fn https_ready() -> bool {
    #[cfg(feature = "mctls")]
    {
        crate::tlshost::host().map_or(false, |h| h.ready)
    }
    #[cfg(not(feature = "mctls"))]
    {
        false
    }
}

struct Plain<'a, 'b>(&'a mut tcp::Socket<'b>);
impl Pipe for Plain<'_, '_> {
    fn may_recv(&self) -> bool {
        self.0.may_recv()
    }
    fn recv(&mut self, buf: &mut [u8]) -> usize {
        self.0.recv_slice(buf).unwrap_or(0)
    }
    fn send(&mut self, d: &[u8]) -> usize {
        self.0.send_slice(d).unwrap_or(0)
    }
    fn may_send(&self) -> bool {
        self.0.may_send()
    }
    fn room(&self) -> usize {
        self.0.send_capacity() - self.0.send_queue()
    }
    fn close(&mut self) {
        self.0.close()
    }
    fn peer_closed(&self) -> bool {
        // FIN received (a LISTENING socket also has !may_recv — it must never be closed here).
        self.0.state() == tcp::State::CloseWait
    }
}

#[cfg(feature = "mctls")]
mod tls_side {
    use super::*;
    use crate::tlshost::{host, TlsHost};
    use hal::tlsabi::*;

    /// Decrypted request bytes waiting for `serve_conn`, per HTTPS slot.
    pub(super) static mut RX: [[u8; 4096]; TLS_N] = [[0; 4096]; TLS_N];
    pub(super) static mut RXN: [usize; TLS_N] = [0; TLS_N];
    /// Ciphertext staging between the EL0 server's IO region and the socket.
    pub(super) static mut CT: [u8; OUT_TLS_MAX] = [0; OUT_TLS_MAX];
    /// TLS-side counters for the heartbeat: [handshakes, records out, sessions failed closed, of the
    /// handshakes: hybrid post-quantum X25519MLKEM768].
    pub static mut STATS: [u32; 5] = [0; 5]; // [4] = new sessions refused by the handshake rate limit

    /// Handshake rate limit (ADR 0051): every handshake costs an ECDSA signature + ML-KEM work and is a
    /// timing sample of the signing key; a browser with keep-alive needs a handful. Token bucket over all
    /// clients: BURST sessions, refilled at RATE per second; an empty bucket refuses the new session.
    pub(super) const HS_BURST: u32 = 32;
    pub(super) const HS_RATE: u32 = 16;
    pub(super) static mut HS_TOKENS: u32 = HS_BURST;
    pub(super) static mut HS_LAST_MS: i64 = 0;

    #[allow(static_mut_refs)]
    pub(super) fn hs_take(now_ms: i64) -> bool {
        unsafe {
            let dt = now_ms.saturating_sub(HS_LAST_MS).max(0) as u64;
            let add = (dt * HS_RATE as u64 / 1000) as u32;
            if add > 0 {
                HS_TOKENS = (HS_TOKENS + add).min(HS_BURST);
                HS_LAST_MS = now_ms;
            }
            if HS_TOKENS == 0 {
                STATS[4] += 1;
                return false;
            }
            HS_TOKENS -= 1;
            true
        }
    }

    /// Copy the server's OUT_TLS bytes onto the socket. False if the socket could not take all of them
    /// (a partial TLS record on the wire would corrupt the stream — the caller aborts instead).
    #[allow(static_mut_refs)]
    pub(super) fn flush_tls(h: &TlsHost, s: &mut tcp::Socket, n: usize) -> bool {
        if n == 0 {
            return true;
        }
        let ct = unsafe { &mut CT };
        h.read(OUT_TLS_OFF, &mut ct[..n]);
        s.send_slice(&ct[..n]).map_or(false, |k| k == n)
    }

    pub(super) struct TlsPipe<'a, 'b> {
        pub s: &'a mut tcp::Socket<'b>,
        pub slot: usize,
        pub secs: u64,
        pub open: &'a mut bool,
    }

    #[allow(static_mut_refs)]
    impl Pipe for TlsPipe<'_, '_> {
        fn may_recv(&self) -> bool {
            unsafe { RXN[self.slot] > 0 }
        }
        fn recv(&mut self, buf: &mut [u8]) -> usize {
            let (rx, n) = unsafe { (&mut RX[self.slot], &mut RXN[self.slot]) };
            let k = buf.len().min(*n);
            buf[..k].copy_from_slice(&rx[..k]);
            rx.copy_within(k..*n, 0);
            *n -= k;
            k
        }
        fn send(&mut self, d: &[u8]) -> usize {
            let Some(h) = host() else { return 0 };
            if !*self.open || !self.s.may_send() {
                return 0;
            }
            // Leave room for the record header + tag (+ inner type); one record per call.
            let room = (self.s.send_capacity() - self.s.send_queue()).saturating_sub(64);
            let chunk = d.len().min(SEND_CHUNK).min(room);
            if chunk == 0 {
                return 0;
            }
            let r = h.call(CMD_SEND, self.slot, &d[..chunk], self.secs);
            if r.status != ST_OK || !flush_tls(h, self.s, r.tls_len) {
                unsafe { STATS[2] += 1 };
                *self.open = false;
                self.s.abort();
                return 0;
            }
            unsafe { STATS[1] += 1 };
            chunk
        }
        fn may_send(&self) -> bool {
            *self.open && self.s.may_send()
        }
        fn secure(&self) -> bool {
            true
        }
        fn room(&self) -> usize {
            (self.s.send_capacity() - self.s.send_queue()).saturating_sub(64)
        }
        /// FIN received AND every decrypted byte consumed — same contract as the plain-TCP pipe, so
        /// kept-alive / SSE connections over TLS are released on client close, not by a timer.
        fn peer_closed(&self) -> bool {
            self.s.state() == tcp::State::CloseWait && unsafe { RXN[self.slot] } == 0
        }
        fn close(&mut self) {
            if *self.open {
                if let Some(h) = host() {
                    let r = h.call(CMD_CLOSE, self.slot, &[], self.secs);
                    let _ = flush_tls(h, self.s, r.tls_len); // close_notify, best effort
                }
                *self.open = false;
            }
            self.s.close();
        }
    }
}

#[cfg(feature = "mctls")]
pub use tls_side::STATS as TLS_STATS;

#[cfg(feature = "mctls")]
impl McNode {
    /// Diagnostics: one letter per HTTPS slot — L listen, S syn-recv, E established, W close-wait,
    /// F fin-wait, C closing/last-ack, T time-wait, X closed, - none; uppercase+'*' = TLS session open.
    pub fn tls_slot_states(&mut self, out: &mut [u8; TLS_N * 2]) {
        for k in 0..TLS_N {
            let (c, open) = match self.handles[CONNS + k] {
                None => (b'-', false),
                Some(h) => {
                    let st = self.sockets.get_mut::<tcp::Socket>(h).state();
                    (match st {
                        tcp::State::Listen => b'L',
                        tcp::State::SynReceived | tcp::State::SynSent => b'S',
                        tcp::State::Established => b'E',
                        tcp::State::CloseWait => b'W',
                        tcp::State::FinWait1 | tcp::State::FinWait2 => b'F',
                        tcp::State::Closing | tcp::State::LastAck => b'C',
                        tcp::State::TimeWait => b'T',
                        tcp::State::Closed => b'X',
                    }, self.tls_open[k])
                }
            };
            out[k * 2] = c;
            out[k * 2 + 1] = if open { b'*' } else { b' ' };
        }
    }

    /// One HTTPS slot per iteration: accept → OPEN; ciphertext → RECV (handshake / app data out, plaintext
    /// staged); then the same `serve_conn` as plain HTTP over the TLS pipe. Any TLS failure aborts that
    /// connection only (ADR 0050 D5).
    #[allow(static_mut_refs)]
    fn tls_service(&mut self, i: usize, st: &McState, now_ms: i64) {
        use crate::tlshost::host;
        use hal::tlsabi::*;
        use tls_side::*;
        let Some(h) = self.handles[i] else { return };
        let k = i - CONNS;
        let secs = st.epoch_at_ms(now_ms as u64) / 1000;
        let s = self.sockets.get_mut::<tcp::Socket>(h);
        let Some(th) = host() else { return };
        if s.state() == tcp::State::TimeWait {
            s.abort(); // recycle (see the plain-HTTP loop)
        }
        // The client went away (FIN) before / between requests: release the TLS session and the slot now
        // instead of waiting for the idle clock — a burst of abandoned connections must not pin all slots.
        // A connection that never got a TLS session and is already past Established (the client gave up —
        // its FIN arrived with or before the ClientHello) can never be served: drop it now, unread data and
        // all (metal/QEMU flood 2026-11-07: all 8 slots pinned in CloseWait this way).
        if !self.tls_open[k]
            && !matches!(s.state(), tcp::State::Listen | tcp::State::SynReceived | tcp::State::Established | tcp::State::Closed)
        {
            s.abort();
        }
        // With a session open: answer whatever the client sent before its FIN, then release.
        if self.tls_open[k] && s.state() == tcp::State::CloseWait && !s.can_recv() && unsafe { RXN[k] } == 0
            && matches!(self.conns[i], Conn::Reading { got: 0, .. })
        {
            let _ = th.call(CMD_CLOSE, k, &[], secs);
            self.tls_open[k] = false;
            s.close();
        }
        if !s.is_open() {
            if self.tls_open[k] {
                let _ = th.call(CMD_CLOSE, k, &[], secs);
                self.tls_open[k] = false;
            }
            unsafe { RXN[k] = 0 };
            let _ = s.listen(HTTPS_PORT);
            self.conns[i] = Conn::Reading { got: 0, since: 0, served: 0 };
            return;
        }
        if !self.tls_open[k] {
            if s.state() != tcp::State::Established {
                return;
            }
            if !hs_take(now_ms) || th.call(CMD_OPEN, k, &[], secs).status != ST_OK {
                s.abort();
                return;
            }
            self.tls_open[k] = true;
            self.tls_hs[k] = false;
            unsafe { RXN[k] = 0 };
        }
        // Ciphertext in.
        let mut ct = [0u8; 2048];
        while s.can_recv() && self.tls_open[k] {
            let n = s.recv_slice(&mut ct).unwrap_or(0);
            if n == 0 {
                break;
            }
            let r = th.call(CMD_RECV, k, &ct[..n], secs);
            if r.status != ST_OK || !flush_tls(th, s, r.tls_len) {
                unsafe { STATS[2] += 1 };
                self.tls_open[k] = false;
                s.abort();
                return;
            }
            if r.flags & F_HANDSHAKE_DONE != 0 && !self.tls_hs[k] {
                self.tls_hs[k] = true; // counted once per session
                unsafe { STATS[0] += 1 };
                if r.flags & F_PQ != 0 {
                    unsafe { STATS[3] += 1 };
                }
            }
            if r.plain_len > 0 {
                let (rx, rn) = unsafe { (&mut RX[k], &mut RXN[k]) };
                if *rn + r.plain_len > rx.len() {
                    self.tls_open[k] = false;
                    s.abort();
                    return;
                }
                th.read(OUT_PLAIN_OFF, &mut rx[*rn..*rn + r.plain_len]);
                *rn += r.plain_len;
            }
            if r.flags & (F_CLOSED | F_PEER_CLOSED) != 0 {
                self.tls_open[k] = false;
                s.close();
                return;
            }
        }
        let mut open = self.tls_open[k];
        let mut p = TlsPipe { s, slot: k, secs, open: &mut open };
        serve_conn(i, &mut p, &mut self.conns[i], st, now_ms as u64);
        self.tls_open[k] = open;
    }
}
