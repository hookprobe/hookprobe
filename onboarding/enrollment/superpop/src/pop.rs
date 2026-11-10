//! The super-PoP protocol core — pure state machine, no sockets/TUN (so it is fully testable
//! in-process against the device's real initiator code). `main.rs` wires it to UDP + TUN.
//!
//! Handshake (UDP 7654): reassemble the chunked msg1 per source, authenticate it against the
//! operator allowlist (PQ-hybrid Noise IK, the kernel's own securechannel), require the msg1
//! payload to equal sha256(authenticated device pk), answer msg2 (payload = tenant LE64) unicast
//! to the source, install a session keyed by `sid`.
//! Data (UDP 7655): G19 v1 records (see wire.rs). DATA is anti-spoofed (inner src must be the
//! device's assigned address) and never routed device→device; replies from the TUN are sealed to
//! the device's CURRENT endpoint (updated on every authenticated record — NAT rebinding/roaming).

use crate::entropy::EntropySource;
use crate::securechannel::{
    hs_chunk, responder_read_msg1_with, responder_write_msg2, AntiReplayRx, CipherState, HsReasm, ResponderRandomness,
    ResponderStatic,
};
use crate::wire::{self, Assign, Msg, Sid};
use boot_abi::sha256;
use ed25519_compact::PublicKey as EdPub;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

/// A session idle (no authenticated record) this long is dropped; devices keepalive every 15 s.
pub const SESSION_IDLE_MS: u64 = 120_000;
/// Hard session lifetime: devices re-handshake every 24 h (controlplane SESSION_MAX_MS); allow slack.
pub const SESSION_MAX_MS: u64 = 25 * 3600 * 1000;
/// An incomplete msg1 reassembly older than this is discarded.
const REASM_TTL_MS: u64 = 10_000;
/// Bounded handshake state (anti-DoS): at most this many concurrent reassemblies.
const REASM_MAX: usize = 256;
/// Per-source-IP handshake budget: this many completed msg1 per window.
const HS_PER_WINDOW: u32 = 6;
const HS_WINDOW_MS: u64 = 60_000;

#[derive(Clone)]
pub struct Device {
    pub name: String,
    pub pk: EdPub,
    pub fp: [u8; 32],
    pub inner: [u8; 4],
}

impl Device {
    pub fn new(name: &str, pk: EdPub, inner: [u8; 4]) -> Device {
        Device { name: name.to_string(), fp: sha256::digest(pk.as_ref()), pk, inner }
    }
}

pub struct Config {
    pub tenant: u64,
    pub dns: [u8; 4],
    pub mtu: u16,
    /// The inner address pool (devices' assigned addresses must lie inside; dst inside is never routed).
    pub pool: ([u8; 4], u8),
}

impl Default for Config {
    fn default() -> Self {
        Config { tenant: 0, dns: [1, 1, 1, 1], mtu: wire::DEFAULT_MTU, pool: ([100, 64, 0, 0], 10) }
    }
}

pub fn in_prefix(ip: [u8; 4], (net, plen): ([u8; 4], u8)) -> bool {
    let m: u32 = if plen == 0 { 0 } else { u32::MAX << (32 - plen as u32) };
    (u32::from_be_bytes(ip) & m) == (u32::from_be_bytes(net) & m)
}

struct Sess {
    dev: usize,
    send: CipherState,
    rx: AntiReplayRx,
    endpoint: SocketAddr,
    created_ms: u64,
    last_rx_ms: u64,
}

/// What the I/O layer must do after an event.
#[derive(Debug, PartialEq, Eq)]
pub enum Out {
    /// Send on the handshake socket (UDP 7654).
    Hs(SocketAddr, Vec<u8>),
    /// Send on the data socket (UDP 7655).
    Data(SocketAddr, Vec<u8>),
    /// Write one inner packet to the TUN.
    Tun(Vec<u8>),
}

#[derive(Default, Debug, Clone)]
pub struct Stats {
    pub handshakes_ok: u64,
    pub handshakes_refused: u64,
    pub handshakes_ratelimited: u64,
    pub records_ok: u64,
    pub records_bad: u64,
    pub unknown_sid: u64,
    pub spoofed: u64,
    pub d2d_dropped: u64,
    pub tun_no_route: u64,
    pub rebinds: u64,
}

pub struct Pop {
    resp: ResponderStatic,
    cfg: Config,
    devices: Vec<Device>,
    by_inner: HashMap<[u8; 4], usize>,
    sessions: HashMap<Sid, Sess>,
    sid_by_dev: HashMap<usize, Sid>,
    reasm: HashMap<SocketAddr, (HsReasm, u64)>,
    hs_budget: HashMap<IpAddr, (u64, u32)>,
    pub stats: Stats,
}

impl Pop {
    pub fn new(resp: ResponderStatic, cfg: Config, devices: Vec<Device>) -> Result<Pop, String> {
        let mut by_inner = HashMap::new();
        for (i, d) in devices.iter().enumerate() {
            if !in_prefix(d.inner, cfg.pool) {
                return Err(format!("device {}: inner {:?} is outside the pool", d.name, d.inner));
            }
            if by_inner.insert(d.inner, i).is_some() {
                return Err(format!("device {}: inner {:?} assigned twice", d.name, d.inner));
            }
        }
        let mut seen = std::collections::HashSet::new();
        for d in &devices {
            if !seen.insert(d.fp) {
                return Err(format!("device {}: public key listed twice", d.name));
            }
        }
        Ok(Pop {
            resp,
            cfg,
            devices,
            by_inner,
            sessions: HashMap::new(),
            sid_by_dev: HashMap::new(),
            reasm: HashMap::new(),
            hs_budget: HashMap::new(),
            stats: Stats::default(),
        })
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// A handshake datagram (UDP 7654) from `from`.
    pub fn on_hs(&mut self, from: SocketAddr, d: &[u8], now_ms: u64, ent: &mut dyn EntropySource) -> Vec<Out> {
        if !self.reasm.contains_key(&from) && self.reasm.len() >= REASM_MAX {
            self.gc(now_ms);
            if self.reasm.len() >= REASM_MAX {
                return vec![];
            }
        }
        let entry = self.reasm.entry(from).or_insert_with(|| (HsReasm::new(), now_ms));
        let total = match entry.0.feed(d) {
            Ok(Some(t)) => t,
            Ok(None) => return vec![],
            Err(_) => {
                self.reasm.remove(&from);
                return vec![];
            }
        };
        let (reasm, _) = self.reasm.remove(&from).expect("present");
        let msg1 = &reasm.message()[..total];

        // Per-source budget, charged per COMPLETED msg1 (the expensive part: ML-KEM decap).
        let b = self.hs_budget.entry(from.ip()).or_insert((now_ms, 0));
        if now_ms.saturating_sub(b.0) > HS_WINDOW_MS {
            *b = (now_ms, 0);
        }
        if b.1 >= HS_PER_WINDOW {
            self.stats.handshakes_ratelimited += 1;
            return vec![];
        }
        b.1 += 1;

        // Identify the device: the IK msg1 carries its identity encrypted; one decapsulation, then
        // the allowlist predicate sees the decrypted identity (constant-time compare per entry).
        let hit = std::cell::Cell::new(None);
        let devices = &self.devices;
        let res = responder_read_msg1_with(
            &self.resp,
            |id| {
                let mut found = None;
                for (i, d) in devices.iter().enumerate() {
                    if boot_abi::kdf::ct_eq(id, d.pk.as_ref()) {
                        found = Some(i);
                    }
                }
                hit.set(found);
                found.is_some()
            },
            msg1,
        );
        let found = match (res, hit.get()) {
            (Ok(p), Some(i)) => Some((i, p)),
            _ => None,
        };
        let Some((di, pend)) = found else {
            self.stats.handshakes_refused += 1;
            return vec![]; // unauthenticated: no keys, so silence (no CLOSE possible)
        };
        // Review Q2-H1 (as responder-sim): the claimed fingerprint must be the authenticated key's.
        if pend.payload1.as_slice() != &self.devices[di].fp[..] {
            self.stats.handshakes_refused += 1;
            return vec![];
        }
        let rnd = match ResponderRandomness::from_entropy(ent) {
            Ok(r) => r,
            Err(_) => return vec![],
        };
        let Some((msg2, session)) = responder_write_msg2(pend, &rnd, &self.cfg.tenant.to_le_bytes()) else {
            self.stats.handshakes_refused += 1;
            return vec![];
        };
        let mut out = Vec::new();
        hs_chunk(msg2.as_slice(), |c| {
            out.push(Out::Hs(from, c.to_vec()));
            true
        });
        // One live session per device: a new handshake replaces (and wipes) the old one.
        if let Some(old) = self.sid_by_dev.remove(&di) {
            if let Some(mut s) = self.sessions.remove(&old) {
                s.send.wipe();
            }
        }
        let sid = wire::sid_from_handshake_hash(&session.handshake_hash);
        let mut session = session;
        let rx = session.recv.into_anti_replay();
        session.recv.wipe();
        let send = session.send;
        // The data endpoint is learned from the first authenticated data record (the device's
        // data socket may differ from its handshake socket, and NATs remap ports).
        let endpoint = SocketAddr::new(from.ip(), 0);
        self.sessions.insert(sid, Sess { dev: di, send, rx, endpoint, created_ms: now_ms, last_rx_ms: now_ms });
        self.sid_by_dev.insert(di, sid);
        self.stats.handshakes_ok += 1;
        out
    }

    /// A data datagram (UDP 7655) from `from`.
    pub fn on_data(&mut self, from: SocketAddr, d: &[u8], now_ms: u64) -> Vec<Out> {
        let Some((sid, rec)) = wire::parse_dgram(d) else {
            self.stats.records_bad += 1;
            return vec![];
        };
        let Some(s) = self.sessions.get_mut(&sid) else {
            self.stats.unknown_sid += 1;
            return vec![];
        };
        let mut pt = [0u8; wire::MAX_PT + 16];
        let n = match s.rx.open_record(&wire::ad(&sid), rec, &mut pt) {
            Ok(n) => n,
            Err(_) => {
                self.stats.records_bad += 1;
                return vec![];
            }
        };
        // Authenticated: refresh liveness and (re)bind the endpoint.
        s.last_rx_ms = now_ms;
        if s.endpoint != from {
            if s.endpoint.port() != 0 {
                self.stats.rebinds += 1;
            }
            s.endpoint = from;
        }
        self.stats.records_ok += 1;
        let dev = s.dev;
        match wire::decode(&pt[..n]) {
            Some(Msg::Data(p)) => {
                let Some((src, dst)) = wire::ipv4_src_dst(p) else {
                    self.stats.records_bad += 1;
                    return vec![];
                };
                if src != self.devices[dev].inner {
                    self.stats.spoofed += 1;
                    return vec![];
                }
                if in_prefix(dst, self.cfg.pool) {
                    self.stats.d2d_dropped += 1;
                    return vec![];
                }
                vec![Out::Tun(p.to_vec())]
            }
            Some(Msg::Keepalive) => self.seal(sid, &Msg::Keepalive).into_iter().collect(),
            Some(Msg::AddrReq) => {
                let a = Assign { inner: self.devices[dev].inner, plen: 32, dns: self.cfg.dns, mtu: self.cfg.mtu };
                self.seal(sid, &Msg::Assign(a)).into_iter().collect()
            }
            Some(Msg::Close(_)) => {
                if let Some(mut s) = self.sessions.remove(&sid) {
                    s.send.wipe();
                }
                self.sid_by_dev.remove(&dev);
                vec![]
            }
            Some(Msg::Assign(_)) | None => {
                self.stats.records_bad += 1;
                vec![]
            }
        }
    }

    /// One packet read from the TUN (return traffic from the internet, already un-NATed by the host).
    pub fn on_tun(&mut self, pkt: &[u8]) -> Vec<Out> {
        let Some((_src, dst)) = wire::ipv4_src_dst(pkt) else {
            return vec![];
        };
        let Some(&dev) = self.by_inner.get(&dst) else {
            self.stats.tun_no_route += 1;
            return vec![];
        };
        let Some(&sid) = self.sid_by_dev.get(&dev) else {
            self.stats.tun_no_route += 1;
            return vec![];
        };
        self.seal(sid, &Msg::Data(pkt)).into_iter().collect()
    }

    /// Expire idle/over-age sessions and stale reassemblies; bound the rate-limit table.
    pub fn gc(&mut self, now_ms: u64) {
        let dead: Vec<Sid> = self
            .sessions
            .iter()
            .filter(|(_, s)| {
                now_ms.saturating_sub(s.last_rx_ms) > SESSION_IDLE_MS || now_ms.saturating_sub(s.created_ms) > SESSION_MAX_MS
            })
            .map(|(k, _)| *k)
            .collect();
        for sid in dead {
            if let Some(mut s) = self.sessions.remove(&sid) {
                s.send.wipe();
                if self.sid_by_dev.get(&s.dev) == Some(&sid) {
                    self.sid_by_dev.remove(&s.dev);
                }
            }
        }
        self.reasm.retain(|_, (_, t)| now_ms.saturating_sub(*t) <= REASM_TTL_MS);
        self.hs_budget.retain(|_, (t, _)| now_ms.saturating_sub(*t) <= HS_WINDOW_MS);
    }

    fn seal(&mut self, sid: Sid, m: &Msg<'_>) -> Option<Out> {
        let s = self.sessions.get_mut(&sid)?;
        if s.endpoint.port() == 0 {
            return None; // no authenticated data record yet: we don't know where to send
        }
        let mut pt = [0u8; wire::MAX_PT];
        let n = wire::encode(m, &mut pt)?;
        let mut dg = vec![0u8; wire::MAX_DGRAM];
        dg[..4].copy_from_slice(&wire::MAGIC);
        dg[4..wire::HDR_LEN].copy_from_slice(&sid);
        let rl = s.send.seal_record(&wire::ad(&sid), &pt[..n], &mut dg[wire::HDR_LEN..])?;
        dg.truncate(wire::HDR_LEN + rl);
        Some(Out::Data(s.endpoint, dg))
    }
}
