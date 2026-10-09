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
use crate::mcstate::McState;
use crate::{events, packet};
#[cfg(not(feature = "cm5"))]
use crate::telemetry;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::{self, ChecksumCapabilities, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
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
    /// Accumulating the request header block.
    Reading { got: usize },
    /// Streaming head (in `head`) then body.
    Sending { hlen: usize, hoff: usize, body: Src, boff: usize },
    /// Long-lived SSE stream.
    Sse { last_change: u64, last_ping_ms: u64 },
}

static mut STORAGE: [SocketStorage<'static>; CONNS] = [SocketStorage::EMPTY; CONNS];
static mut TCP_RX_BUF: [[u8; TCP_RX]; CONNS] = [[0; TCP_RX]; CONNS];
static mut TCP_TX_BUF: [[u8; TCP_TX]; CONNS] = [[0; TCP_TX]; CONNS];
static mut REQ: [[u8; 4096]; CONNS] = [[0; 4096]; CONNS];
static mut HEAD: [[u8; 512]; CONNS] = [[0; 512]; CONNS];
static mut SCRATCH_BUF: [[u8; SCRATCH]; CONNS] = [[0; SCRATCH]; CONNS];
static mut DEV: McDev = McDev::new();
static mut STATE: McState = McState::new();

fn is_for_us(frame: &[u8], mac: [u8; 6]) -> bool {
    frame.len() >= 14 && (frame[..6] == mac || frame[..6] == [0xff; 6])
}

/// The device's Mission Control state (one instance; single-core, owned by the serve loop).
#[allow(static_mut_refs)]
pub fn state() -> &'static mut McState {
    unsafe { &mut STATE }
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
    handles: [Option<SocketHandle>; CONNS],
    conns: [Conn; CONNS],
    dhcp: Option<SocketHandle>,
    mac: [u8; 6],
    pub ip: [u8; 4],
    pub leased: bool,
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
        let mut handles: [Option<SocketHandle>; CONNS] = [None; CONNS];
        // Reserve one slot of the pool for the DHCP socket in DHCP mode.
        let tcp_slots = if matches!(mode, NetMode::Dhcp) { CONNS - 1 } else { CONNS };
        for (i, h) in handles.iter_mut().enumerate().take(tcp_slots) {
            let rx = tcp::SocketBuffer::new(unsafe { &mut TCP_RX_BUF[i][..] });
            let tx = tcp::SocketBuffer::new(unsafe { &mut TCP_TX_BUF[i][..] });
            let mut s = tcp::Socket::new(rx, tx);
            let _ = s.listen(HTTP_PORT);
            *h = Some(sockets.add(s));
        }
        let dhcp = match mode {
            NetMode::Dhcp => Some(sockets.add(smoltcp::socket::dhcpv4::Socket::new())),
            NetMode::Static { .. } => None,
        };
        Some(McNode { iface, sockets, handles, conns: [Conn::Reading { got: 0 }; CONNS], dhcp, mac, ip, leased: dhcp.is_none() })
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
            if !s.is_open() {
                let _ = s.listen(HTTP_PORT);
                self.conns[i] = Conn::Reading { got: 0 };
                continue;
            }
            serve_conn(i, s, &mut self.conns[i], st, now_ms as u64);
        }
        let dev = unsafe { &mut DEV };
        self.iface.poll(Instant::from_millis(now_ms), dev, &mut self.sockets);
        changed
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
        if node.service(st, now) {
            kprint!(" [MC] heqk Mission Control serving on http://{}.{}.{}.{}:{} ({})\n",
                node.ip[0], node.ip[1], node.ip[2], node.ip[3], HTTP_PORT, if node.leased { "DHCP lease" } else { "link-local fallback" });
        }
        node.flush(|f| nic.tx(f));
        if now - last_hb >= 10_000 {
            last_hb = now;
            let (lost, gated) = node.tx_stats();
            kprint!(" [MC hb] seen={} passed={} dropped={} detections={} qsecbit_raw={} rules_active={} tx_lost={} egress_gated={}\n",
                st.seen, st.forwarded, st.dropped, st.detections(), telemetry::score(), crate::rules::active_rules(), lost, gated);
        }
    }
}

#[allow(static_mut_refs)]
fn serve_conn(i: usize, s: &mut tcp::Socket, c: &mut Conn, st: &McState, now_ms: u64) {
    let req = unsafe { &mut REQ[i] };
    let head = unsafe { &mut HEAD[i] };
    let scratch = unsafe { &mut SCRATCH_BUF[i] };
    match *c {
        Conn::Reading { got } => {
            if !s.may_recv() {
                return;
            }
            let n = s.recv_slice(&mut req[got..]).unwrap_or(0);
            let got = got + n;
            *c = Conn::Reading { got };
            match http::parse(&req[..got]) {
                Err(http::ParseErr::Incomplete) => {}
                Err(http::ParseErr::Bad) => {
                    let _ = s.send_slice(http::BAD_REQUEST);
                    s.close();
                }
                Ok(r) => {
                    let resp = http::handle(&r, st, &mut scratch[..]);
                    let hlen = http::write_head(&resp, &mut head[..]);
                    *c = match resp.body {
                        Body::Static(b) => Conn::Sending { hlen, hoff: 0, body: Src::Static(b), boff: 0 },
                        Body::Scratch(n) => Conn::Sending { hlen, hoff: 0, body: Src::Scratch(n), boff: 0 },
                        Body::Sse => {
                            let _ = s.send_slice(&head[..hlen]);
                            Conn::Sse { last_change: u64::MAX, last_ping_ms: now_ms }
                        }
                    };
                }
            }
        }
        Conn::Sending { hlen, mut hoff, body, mut boff } => {
            if hoff < hlen {
                hoff += s.send_slice(&head[hoff..hlen]).unwrap_or(0);
            }
            if hoff >= hlen {
                let src: &[u8] = match body {
                    Src::Static(b) => b,
                    Src::Scratch(n) => &scratch[..n],
                };
                if boff < src.len() {
                    boff += s.send_slice(&src[boff..]).unwrap_or(0);
                }
                if boff >= src.len() {
                    s.close(); // FIN after the queued bytes drain
                }
            }
            *c = Conn::Sending { hlen, hoff, body, boff };
        }
        Conn::Sse { last_change, last_ping_ms } => {
            if !s.may_send() {
                s.close();
                return;
            }
            if st.change != last_change && s.send_capacity() - s.send_queue() > 4096 {
                let n = http::sse_update(st, &mut scratch[..8192]);
                if n > 0 && s.send_slice(&scratch[..n]).is_ok() {
                    *c = Conn::Sse { last_change: st.change, last_ping_ms: now_ms };
                }
            } else if now_ms.saturating_sub(last_ping_ms) >= 15_000 {
                let _ = s.send_slice(http::SSE_PING);
                *c = Conn::Sse { last_change, last_ping_ms: now_ms };
            }
        }
    }
}
