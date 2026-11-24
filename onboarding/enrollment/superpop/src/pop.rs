//! The super-PoP protocol core — pure state machine, no sockets/TUN (so it is fully testable
//! in-process against the device's real initiator code). `main.rs` wires it to UDP + TUN.
//!
//! Handshake (UDP 7654): reassemble the chunked msg1 per source, authenticate it against the
//! operator allowlist (PQ-hybrid Noise IK, the kernel's own securechannel), require the msg1
//! payload to start with sha256(authenticated device pk), answer msg2 (payload = tenant LE64) unicast
//! to the source, install a session keyed by `sid`.
//! ADR 0069: the msg1 payload is `fp ‖ ctr` (LE u64). A msg1 is accepted only if ctr is above the highest counter
//! accepted for that device; the high-water mark is written durably (`CtrState`) before msg2 is sent. Migration:
//! the old 32-byte payload is accepted until the device has once sent a counter, never after (no downgrade).
//! Data (UDP 7655): G19 v1 records (see wire.rs). DATA is anti-spoofed (inner src must be the
//! device's assigned address) and never routed device→device; replies from the TUN are sealed to
//! the device's CURRENT endpoint (updated on every authenticated record — NAT rebinding/roaming).

use crate::entropy::EntropySource;
use crate::securechannel::{
    hs_chunk, responder_read_msg1_with, responder_write_msg2, HsReasm, RecordRx, RecordTx, RekeyPolicy,
    ResponderRandomness, ResponderStatic,
};
use crate::wire::{self, Assign, Msg, Sid};
use boot_abi::sha256;
use ed25519_compact::PublicKey as EdPub;
use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

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
/// F-S1-1: a device retransmits the IDENTICAL msg1 until a msg2 arrives and keeps the FIRST msg2 it gets. A
/// byte-identical msg1 inside this window is answered with the cached msg2 (a responder retransmit: no new
/// session, no new key material, no crypto). Covers the device's whole retransmit span with margin.
const HS_DUP_MS: u64 = 30_000;
/// At most this many cached-msg2 resends per msg1 (a captured msg1 cannot drive unbounded replies).
const HS_DUP_RESENDS: u32 = 8;
/// After the duplicate window, a byte-identical msg1 is a REPLAY: silently ignored, so a captured msg1 can no
/// longer tear down the device's live session. Remembered for a session lifetime, bounded in count. (A PoP
/// restart forgets them; the full fix is an initiator timestamp in msg1, a wire change for the ADR process.)
const HS_SEEN_MAX: usize = 4096;

/// ADR 0069: the per-device msg1 counter high-water marks, keyed by fingerprint (stable across edits of the
/// devices file). With a path, every raise is written to `path.tmp`, fsynced, renamed over `path`, and the
/// directory fsynced — before the msg2 that accepts it goes out. File: one `fp-hex ctr` line per device.
#[derive(Default)]
pub struct CtrState {
    marks: HashMap<[u8; 32], u64>,
    path: Option<PathBuf>,
}

impl CtrState {
    /// In memory only (tests).
    pub fn memory() -> CtrState {
        CtrState::default()
    }

    /// Load `path` (a missing file = no marks yet). A malformed file is an error: the PoP must not start with its
    /// replay floor silently reset.
    pub fn load(path: &str) -> Result<CtrState, String> {
        let mut marks = HashMap::new();
        match std::fs::read_to_string(path) {
            Ok(txt) => {
                for (i, l) in txt.lines().enumerate() {
                    let l = l.trim();
                    if l.is_empty() || l.starts_with('#') {
                        continue;
                    }
                    let bad = || format!("{path}:{}: expected `fp-hex counter`", i + 1);
                    let mut it = l.split_whitespace();
                    let (Some(f), Some(c), None) = (it.next(), it.next(), it.next()) else { return Err(bad()) };
                    if f.len() != 64 {
                        return Err(bad());
                    }
                    let mut fp = [0u8; 32];
                    for (j, b) in fp.iter_mut().enumerate() {
                        *b = u8::from_str_radix(&f[2 * j..2 * j + 2], 16).map_err(|_| bad())?;
                    }
                    marks.insert(fp, c.parse::<u64>().map_err(|_| bad())?);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{path}: {e}")),
        }
        Ok(CtrState { marks, path: Some(PathBuf::from(path)) })
    }

    pub fn get(&self, fp: &[u8; 32]) -> Option<u64> {
        self.marks.get(fp).copied()
    }

    /// Raise `fp`'s mark to `ctr` and make it durable. Err = not durable: the caller refuses the handshake (the
    /// in-memory mark is rolled back so state and disk agree).
    pub fn raise(&mut self, fp: [u8; 32], ctr: u64) -> std::io::Result<()> {
        let prev = self.marks.insert(fp, ctr);
        if let Err(e) = self.persist() {
            match prev {
                Some(p) => self.marks.insert(fp, p),
                None => self.marks.remove(&fp),
            };
            return Err(e);
        }
        Ok(())
    }

    fn persist(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let mut lines: Vec<String> = self.marks.iter().map(|(fp, c)| {
            let h: String = fp.iter().map(|b| format!("{b:02x}")).collect();
            format!("{h} {c}\n")
        }).collect();
        lines.sort();
        let tmp = path.with_extension("tmp");
        {
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&tmp)?;
            f.write_all(b"# superpop ADR 0069 msg1 counter high-water marks: fp-hex counter\n")?;
            for l in &lines {
                f.write_all(l.as_bytes())?;
            }
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        if let Some(dir) = path.parent() {
            let d = if dir.as_os_str().is_empty() { std::path::Path::new(".") } else { dir };
            std::fs::File::open(d)?.sync_all()?;
        }
        Ok(())
    }
}

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
    send: RecordTx,
    rx: RecordRx,
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
    /// W4: devices that announced they follow rekey epochs (CAPS)
    pub caps_rekey: u64,
    /// F-S1-1: identical msg1 retransmits answered from the msg2 cache (no new session)
    pub hs_duplicate: u64,
    /// byte-identical msg1 seen after the duplicate window: ignored (no session teardown)
    pub hs_replayed: u64,
    /// ADR 0069: msg1 refused because its counter is not above the device's mark (or an old-format msg1 from a
    /// device that already sent a counter)
    pub hs_stale_ctr: u64,
    /// ADR 0069: old-format msg1 (no counter) accepted during the migration
    pub hs_legacy: u64,
    /// ADR 0069: msg1 refused because the counter mark could not be written durably
    pub hs_ctr_unsaved: u64,
}

/// The msg2 a completed msg1 produced, kept for the duplicate window.
struct Msg2Cache {
    chunks: Vec<Vec<u8>>,
    at_ms: u64,
    resends: u32,
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
    /// sha256(msg1) → the msg2 it produced (duplicate window only)
    msg2_cache: HashMap<[u8; 32], Msg2Cache>,
    /// sha256(msg1) of every ACCEPTED msg1 → when (replay guard; bounded)
    msg1_seen: HashMap<[u8; 32], u64>,
    /// ADR 0069: per-device msg1 counter marks
    ctr: CtrState,
    /// The latest event time seen (TUN reads carry none): drives the senders' time-based rekey.
    now_ms: u64,
    /// The thresholds this PoP's senders rekey at (once the device announced CAPS).
    pub rekey: RekeyPolicy,
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
            msg2_cache: HashMap::new(),
            msg1_seen: HashMap::new(),
            ctr: CtrState::memory(),
            now_ms: 0,
            rekey: RekeyPolicy::DEFAULT,
            stats: Stats::default(),
        })
    }

    /// ADR 0069: use durable counter marks (`superpop run --ctr-state FILE`).
    pub fn with_ctr_state(mut self, st: CtrState) -> Pop {
        self.ctr = st;
        self
    }

    /// The counter mark for a device (tests / status).
    pub fn ctr_mark(&self, fp: &[u8; 32]) -> Option<u64> {
        self.ctr.get(fp)
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

        // F-S1-1: an identical msg1 is the device retransmitting because our msg2 was slow or lost. Answer
        // with the SAME msg2 (so the device's first-msg2-wins choice and our session agree); never re-key.
        // Checked before the budget and before any crypto: it derives nothing new.
        let digest = sha256::digest(msg1);
        if let Some(c) = self.msg2_cache.get_mut(&digest) {
            if now_ms.saturating_sub(c.at_ms) <= HS_DUP_MS {
                if c.resends >= HS_DUP_RESENDS {
                    return vec![];
                }
                c.resends += 1;
                self.stats.hs_duplicate += 1;
                return c.chunks.iter().map(|ch| Out::Hs(from, ch.clone())).collect();
            }
        }
        if self.msg1_seen.contains_key(&digest) {
            // Seen and accepted before, outside the duplicate window: a replay. It must not replace the
            // device's live session.
            self.stats.hs_replayed += 1;
            return vec![];
        }

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
        let fp = self.devices[di].fp;
        let pl = pend.payload1.as_slice();
        if pl.len() < 32 || pl[..32] != fp[..] {
            self.stats.handshakes_refused += 1;
            return vec![];
        }
        // ADR 0069: the counter must be above the device's mark; the old 32-byte payload only until the device has
        // once sent a counter.
        let new_ctr = match pl.len() {
            32 => {
                if self.ctr.get(&fp).is_some() {
                    self.stats.hs_stale_ctr += 1; // a downgrade to the old format
                    return vec![];
                }
                None
            }
            40 => {
                let c = u64::from_le_bytes(pl[32..40].try_into().expect("8 bytes"));
                if self.ctr.get(&fp).is_some_and(|m| c <= m) {
                    self.stats.hs_stale_ctr += 1;
                    return vec![];
                }
                Some(c)
            }
            _ => {
                self.stats.handshakes_refused += 1;
                return vec![];
            }
        };
        let rnd = match ResponderRandomness::from_entropy(ent) {
            Ok(r) => r,
            Err(_) => return vec![],
        };
        let Some((msg2, session)) = responder_write_msg2(pend, &rnd, &self.cfg.tenant.to_le_bytes()) else {
            self.stats.handshakes_refused += 1;
            return vec![];
        };
        // ADR 0069: the mark is durable before msg2 leaves; not durable = no handshake (the device retries).
        match new_ctr {
            Some(c) => {
                if self.ctr.raise(fp, c).is_err() {
                    self.stats.hs_ctr_unsaved += 1;
                    let mut session = session;
                    session.wipe();
                    return vec![];
                }
            }
            None => self.stats.hs_legacy += 1,
        }
        let mut out = Vec::new();
        hs_chunk(msg2.as_slice(), |c| {
            out.push(Out::Hs(from, c.to_vec()));
            true
        });
        // One live session per device: a new handshake replaces (and wipes) the old one.
        if let Some(old) = self.sid_by_dev.remove(&di) {
            if let Some(mut s) = self.sessions.remove(&old) {
                s.send.wipe();
                s.rx.wipe();
            }
        }
        let sid = wire::sid_from_handshake_hash(&session.handshake_hash);
        let mut session = session;
        let rx = session.recv.into_record_rx();
        let send = RecordTx::new(session.send.clone(), now_ms as i64, self.rekey);
        session.wipe();
        self.now_ms = self.now_ms.max(now_ms);
        // The data endpoint is learned from the first authenticated data record (the device's
        // data socket may differ from its handshake socket, and NATs remap ports).
        let endpoint = SocketAddr::new(from.ip(), 0);
        self.sessions.insert(sid, Sess { dev: di, send, rx, endpoint, created_ms: now_ms, last_rx_ms: now_ms });
        self.sid_by_dev.insert(di, sid);
        self.stats.handshakes_ok += 1;
        let chunks = out
            .iter()
            .map(|o| match o {
                Out::Hs(_, c) => c.clone(),
                _ => unreachable!("handshake output only"),
            })
            .collect();
        self.msg2_cache.insert(digest, Msg2Cache { chunks, at_ms: now_ms, resends: 0 });
        if self.msg1_seen.len() >= HS_SEEN_MAX {
            // Bounded: drop the oldest remembered msg1 (a replay that old meets an already-replaced session).
            if let Some(oldest) = self.msg1_seen.iter().min_by_key(|(_, t)| **t).map(|(k, _)| *k) {
                self.msg1_seen.remove(&oldest);
            }
        }
        self.msg1_seen.insert(digest, now_ms);
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
        self.now_ms = self.now_ms.max(now_ms);
        let mut pt = [0u8; wire::MAX_PT + 16];
        let n = match s.rx.open(&wire::ad(&sid), rec, &mut pt, now_ms as i64) {
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
            Some(Msg::Caps(f)) => {
                // the device follows our epochs: rekey this direction from now on; tell it we follow too
                if f & wire::CAPS_REKEY != 0 {
                    if let Some(s) = self.sessions.get_mut(&sid) {
                        if !s.send.armed() {
                            self.stats.caps_rekey += 1;
                        }
                        s.send.arm();
                    }
                }
                self.seal(sid, &Msg::Caps(wire::CAPS_REKEY)).into_iter().collect()
            }
            Some(Msg::AddrReq) => {
                let a = Assign { inner: self.devices[dev].inner, plen: 32, dns: self.cfg.dns, mtu: self.cfg.mtu };
                self.seal(sid, &Msg::Assign(a)).into_iter().collect()
            }
            Some(Msg::Close(_)) => {
                if let Some(mut s) = self.sessions.remove(&sid) {
                    s.send.wipe();
                    s.rx.wipe();
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
        self.now_ms = self.now_ms.max(now_ms);
        for s in self.sessions.values_mut() {
            s.rx.tick(now_ms as i64); // retire a previous key epoch after its grace window
        }
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
                s.rx.wipe();
                if self.sid_by_dev.get(&s.dev) == Some(&sid) {
                    self.sid_by_dev.remove(&s.dev);
                }
            }
        }
        self.reasm.retain(|_, (_, t)| now_ms.saturating_sub(*t) <= REASM_TTL_MS);
        self.hs_budget.retain(|_, (t, _)| now_ms.saturating_sub(*t) <= HS_WINDOW_MS);
        self.msg2_cache.retain(|_, c| now_ms.saturating_sub(c.at_ms) <= HS_DUP_MS);
        self.msg1_seen.retain(|_, t| now_ms.saturating_sub(*t) <= SESSION_MAX_MS);
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
        let rl = s.send.seal(&wire::ad(&sid), &pt[..n], &mut dg[wire::HDR_LEN..], self.now_ms as i64)?;
        dg.truncate(wire::HDR_LEN + rl);
        Some(Out::Data(s.endpoint, dg))
    }
}
