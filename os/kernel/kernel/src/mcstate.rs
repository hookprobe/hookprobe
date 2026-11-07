//! On-device Mission Control STATE (ADR 0047 D2) — what the operator's UI reads from the device:
//! recent detections (fed from the ONE SOAR-ring drain), a windowed QSecBit-lite risk history,
//! per-source incident correlation, and datapath counters. Rendered as the JSON the Mission
//! Control UI already parses (the `crates/hookprobe-api` contract), so the unchanged UI works
//! against a device.
//!
//! Allocation-free by construction: heqk's heap is a bump allocator that never frees, so every
//! render writes into a caller-supplied fixed buffer (`JsonBuf`) and the stores are fixed rings.
//! Pure logic — no MMIO, clock passed in — so it is QEMU-testable (`[P-mc]`).

use crate::events;
use crate::rulecat;
use core::fmt::Write;

/// Fixed-buffer writer. On overflow it stops writing and sets `overflow` (the caller turns that
/// into a truncated-but-valid response by rendering fewer rows, never a half JSON document).
pub struct JsonBuf<'a> {
    buf: &'a mut [u8],
    pub len: usize,
    pub overflow: bool,
}

impl<'a> JsonBuf<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        JsonBuf { buf, len: 0, overflow: false }
    }
    pub fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
    pub fn raw(&mut self, s: &str) {
        let b = s.as_bytes();
        if self.len + b.len() > self.buf.len() {
            self.overflow = true;
            return;
        }
        self.buf[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
    }
    /// A JSON string literal with RFC 8259 escaping.
    pub fn string(&mut self, s: &str) {
        self.raw("\"");
        for c in s.chars() {
            match c {
                '"' => self.raw("\\\""),
                '\\' => self.raw("\\\\"),
                '\n' => self.raw("\\n"),
                '\r' => self.raw("\\r"),
                '\t' => self.raw("\\t"),
                c if (c as u32) < 0x20 => {
                    let _ = write!(self, "\\u{:04x}", c as u32);
                }
                c => {
                    let mut tmp = [0u8; 4];
                    self.raw(c.encode_utf8(&mut tmp));
                }
            }
        }
        self.raw("\"");
    }
    pub fn mark(&self) -> usize {
        self.len
    }
    pub fn rewind(&mut self, m: usize) {
        self.len = m;
        self.overflow = false;
    }
}

impl Write for JsonBuf<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.raw(s);
        if self.overflow { Err(core::fmt::Error) } else { Ok(()) }
    }
}

/// Epoch seconds with millisecond precision, as the UI's `ts` (a float).
fn ts(out: &mut JsonBuf, ms: u64) {
    let _ = write!(out, "{}.{:03}", ms / 1000, ms % 1000);
}

/// Dotted IPv4 into a small stack buffer.
fn ipv4(src: u32, tmp: &mut [u8; 16]) -> &str {
    let mut w = JsonBuf::new(&mut tmp[..]);
    let _ = write!(w, "{}.{}.{}.{}", src >> 24, (src >> 16) & 0xff, (src >> 8) & 0xff, src & 0xff);
    let n = w.len;
    core::str::from_utf8(&tmp[..n]).unwrap_or("")
}

pub const DET_CAP: usize = 256;
const QS_CAP: usize = 64;
/// Raw-score samples kept for the windowed risk (one per heartbeat, ~1 s apart).
const RAW_CAP: usize = 64;
/// Risk window: score points gained in the last `RISK_WINDOW_MS`.
const RISK_WINDOW_MS: u64 = 60_000;
/// Points-in-window at which risk reaches 0.5 (risk = p / (p + K)).
const RISK_HALF_POINTS: u64 = 20;
const MAX_INCIDENTS: usize = 32;

#[derive(Clone, Copy, Default)]
pub struct Det {
    pub seq: u64,
    pub ts_ms: u64,
    pub src: u32,
    pub rule_id: u16,
    pub sev_points: u8,
    pub verdict: u8,
    pub class: u8,
    /// Wall-clock-anchored row (restored from a prior boot): a clock step never moves it.
    pub abs: bool,
    pub dst: u32,
    pub dport: u16,
}

/// No real reply can predate this build era (2026-01-01T00:00:00Z): an older time is a forged or
/// unsynchronised server and is refused.
pub const NTP_FLOOR_UNIX: u64 = 1_767_225_600;

/// Validate one SNTP reply against our request: server mode (4), not "alarm" (LI 3), stratum
/// 1..=15, the Originate Timestamp equal to the nonce we sent (RFC 4330 §5 — an off-path
/// forger cannot guess it), a non-zero Transmit Timestamp, and a time at or after the build
/// floor. Returns the Transmit Timestamp in Unix milliseconds.
pub fn sntp_parse_strict(r: &[u8], nonce: u64) -> Option<u64> {
    if r.len() < 48 || nonce == 0 {
        return None;
    }
    let (li, mode, stratum) = (r[0] >> 6, r[0] & 7, r[1]);
    if mode != 4 || li == 3 || stratum == 0 || stratum > 15 {
        return None;
    }
    let orig = u64::from_be_bytes([r[24], r[25], r[26], r[27], r[28], r[29], r[30], r[31]]);
    if orig != nonce {
        return None;
    }
    let secs = u32::from_be_bytes([r[40], r[41], r[42], r[43]]) as u64;
    let frac = u32::from_be_bytes([r[44], r[45], r[46], r[47]]) as u64;
    let unix = secs.checked_sub(2_208_988_800)?;
    if unix < NTP_FLOOR_UNIX {
        return None;
    }
    Some(unix * 1000 + (frac * 1000 >> 32))
}

/// LAN hosts remembered for the "My Network" count (bounded; the oldest-seen is replaced).
pub const HOST_CAP: usize = 256;
/// A host counts as active if it was seen within this window.
pub const HOST_ACTIVE_MS: u64 = 600_000;

/// What the AP knows about its WAN, for the "Get Online" tile.
#[derive(Clone, Copy, Debug, Default)]
pub struct WanFacts {
    pub up: bool,
    pub ip: [u8; 4],
    /// 0 DHCP, 1 static, 2 PPPoE
    pub mode: u8,
    pub ipv6: bool,
    pub clients: u32,
    pub pkts_out: u64,
    pub pkts_in: u64,
    /// Client DNS queries the AP answered by forwarding them upstream through the IDS.
    pub dns_inspected: u64,
    /// Shield: client queries answered as blocked (blocklisted name) — they never left the device.
    pub dns_blocked: u64,
    /// Domains in the active blocklist (0 = Shield off: counting only).
    pub blocklist: u32,
}

/// The device's Mission Control state. One instance, owned by the serve loop.
pub struct McState {
    dets: [Det; DET_CAP],
    dhead: usize,
    dlen: usize,
    next_seq: u64,
    /// (epoch ms, risk in thousandths) — the QSecBit-lite history the Home orb plots.
    qs: [(u64, u32); QS_CAP],
    qhead: usize,
    qlen: usize,
    raw: [(u64, u32); RAW_CAP],
    rhead: usize,
    rlen: usize,
    boot_epoch_ms: u64,
    boot_ticks: u64,
    cntfrq: u64,
    pub seen: u64,
    pub dropped: u64,
    pub forwarded: u64,
    /// Bumps on every new detection or QSecBit sample — SSE clients compare against it.
    pub change: u64,
    /// Deployment mode truth for the UI badge: true only while the MSSP control-plane session is
    /// Established (set by the serve loop from `ControlPlane::established()`); otherwise standalone.
    pub cloud_linked: bool,
    /// True once a validated SNTP reply has set the wall clock (the UI shows "unsynced" otherwise).
    pub clock_synced: bool,
    /// The device's own WAN (the AP image): None on a passive sensor.
    pub wan: Option<WanFacts>,
    /// How many of the newest detections the device seals across a reboot (0 = none persisted).
    pub sealed_cap: u16,
    /// Passive inventory: (IPv4 host order, last seen epoch ms). 0 = empty slot.
    /// (ip, first seen, last seen) — epoch ms, or ms since the anchor before the clock syncs.
    hosts: [(u32, u64, u64); HOST_CAP],
}

/// A wall-clock re-sync larger than this is refused once the clock is synced (a forged reply can
/// not drag the timeline by days; the first sync has nothing better to compare against).
pub const MAX_RESYNC_STEP_MS: i64 = 3_600_000;

impl McState {
    pub const fn new() -> Self {
        McState {
            dets: [Det { seq: 0, ts_ms: 0, src: 0, rule_id: 0, sev_points: 0, verdict: 0, class: 0, abs: false, dst: 0, dport: 0 }; DET_CAP],
            dhead: 0,
            dlen: 0,
            next_seq: 0,
            qs: [(0, 0); QS_CAP],
            qhead: 0,
            qlen: 0,
            raw: [(0, 0); RAW_CAP],
            rhead: 0,
            rlen: 0,
            boot_epoch_ms: 0,
            boot_ticks: 0,
            cntfrq: 1,
            seen: 0,
            dropped: 0,
            forwarded: 0,
            change: 0,
            cloud_linked: false,
            clock_synced: false,
            wan: None,
            sealed_cap: 0,
            hosts: [(0, 0, 0); HOST_CAP],
        }
    }

    /// Anchor `cntpct` ticks to wall time: `boot_epoch_ms` is the epoch at `boot_ticks`.
    pub fn set_clock(&mut self, boot_epoch_ms: u64, boot_ticks: u64, cntfrq: u64) {
        self.boot_epoch_ms = boot_epoch_ms;
        self.boot_ticks = boot_ticks;
        self.cntfrq = cntfrq.max(1);
    }

    /// Set the wall clock from a validated time source: `epoch_ms` is true at `now_ticks`. Every
    /// timestamp already recorded (detections, QSecBit history) moves by the same step, so
    /// pre-sync rows land at their real time instead of 1970. Returns the step, or `None` when a
    /// re-sync would step more than `MAX_RESYNC_STEP_MS` (refused, clock unchanged).
    pub fn sync_clock(&mut self, epoch_ms: u64, now_ticks: u64) -> Option<i64> {
        let step = epoch_ms as i64 - self.epoch_ms(now_ticks) as i64;
        if self.clock_synced && step.abs() > MAX_RESYNC_STEP_MS {
            return None;
        }
        let mv = |t: u64| (t as i64).saturating_add(step).max(0) as u64;
        self.boot_epoch_ms = mv(self.boot_epoch_ms);
        for d in self.dets.iter_mut().filter(|d| !d.abs) {
            d.ts_ms = mv(d.ts_ms);
        }
        for q in self.qs.iter_mut() {
            q.0 = mv(q.0);
        }
        for r in self.raw.iter_mut() {
            r.0 = mv(r.0);
        }
        for h in self.hosts.iter_mut().filter(|h| h.0 != 0) {
            h.1 = mv(h.1);
            h.2 = mv(h.2);
        }
        self.clock_synced = true;
        self.change += 1;
        Some(step)
    }

    /// Wall time for a duration measured from the clock anchor (`boot_ticks`) — the serve loop's
    /// `now_ms` convention.
    pub fn epoch_at_ms(&self, ms_since_anchor: u64) -> u64 {
        self.boot_epoch_ms.saturating_add(ms_since_anchor)
    }

    /// The `cntpct` value at `ms_since_anchor` (the serve loop's `now_ms`).
    pub fn ticks_at_ms(&self, ms_since_anchor: u64) -> u64 {
        self.boot_ticks.saturating_add(ms_since_anchor.saturating_mul(self.cntfrq) / 1000)
    }

    pub fn epoch_ms(&self, ticks: u64) -> u64 {
        let dt = ticks.saturating_sub(self.boot_ticks);
        self.boot_epoch_ms + dt / self.cntfrq * 1000 + (dt % self.cntfrq) * 1000 / self.cntfrq
    }

    /// Record one drained SOAR event (the oldest is overwritten at capacity).
    pub fn push_event(&mut self, ev: &events::Event) {
        let ms = self.epoch_ms(ev.ts);
        self.push_at(ev, ms, false);
    }

    /// Restore one prior-boot detection at its persisted wall-clock time (D1: the UI's detection
    /// list survives a reboot). Call before live events so restored rows are the oldest.
    pub fn push_restored(&mut self, ev: &events::Event, epoch_ms: u64) {
        self.push_at(ev, epoch_ms, true);
    }

    fn push_at(&mut self, ev: &events::Event, ts_ms: u64, abs: bool) {
        let d = Det {
            seq: self.next_seq,
            ts_ms,
            src: ev.src,
            rule_id: ev.rule_id,
            sev_points: ev.severity,
            verdict: ev.verdict,
            class: ev.class,
            abs,
            dst: ev.dst,
            dport: ev.dport,
        };
        self.next_seq += 1;
        self.dets[(self.dhead + self.dlen) % DET_CAP] = d;
        if self.dlen < DET_CAP {
            self.dlen += 1;
        } else {
            self.dhead = (self.dhead + 1) % DET_CAP;
        }
        self.change += 1;
    }

    /// Remember a LAN source (open addressing, 8 probes; when all are taken the least recently
    /// seen of them is replaced — bounded memory, an honest "active" count).
    pub fn note_host(&mut self, ip: u32, now_ms: u64) {
        let h = (ip.wrapping_mul(0x9E37_79B1) >> 24) as usize % HOST_CAP;
        let mut victim = h;
        for k in 0..8 {
            let i = (h + k) % HOST_CAP;
            if self.hosts[i].0 == ip {
                self.hosts[i].2 = now_ms;
                return;
            }
            if self.hosts[i].0 == 0 {
                self.hosts[i] = (ip, now_ms, now_ms);
                return;
            }
            if self.hosts[i].2 < self.hosts[victim].2 {
                victim = i;
            }
        }
        self.hosts[victim] = (ip, now_ms, now_ms);
    }

    /// LAN hosts seen within `HOST_ACTIVE_MS` of `now_ms`.
    pub fn hosts_active(&self, now_ms: u64) -> usize {
        self.hosts.iter().filter(|&&(ip, _, t)| ip != 0 && now_ms.saturating_sub(t) <= HOST_ACTIVE_MS).count()
    }

    /// `GET /api/devices` → `{devices (most recently seen first), count}` — the LAN hosts this
    /// device has actually observed (IP only: heqk keeps no MAC per host, so `mac` is null rather
    /// than invented). Timestamps in epoch seconds, like `/api/detections`.
    pub fn render_devices(&self, limit: usize, out: &mut JsonBuf) {
        let mut idx = [0u16; HOST_CAP];
        let mut n = 0usize;
        for (i, h) in self.hosts.iter().enumerate() {
            if h.0 != 0 {
                idx[n] = i as u16;
                n += 1;
            }
        }
        // newest first (insertion sort: <= 256 rows, no allocator)
        for a in 1..n {
            let mut b = a;
            while b > 0 && self.hosts[idx[b - 1] as usize].2 < self.hosts[idx[b] as usize].2 {
                idx.swap(b - 1, b);
                b -= 1;
            }
        }
        out.raw("{\"devices\":[");
        let mut k = 0usize;
        for &i in idx[..n].iter().take(limit) {
            let (ip, first, last) = self.hosts[i as usize];
            let m = out.mark();
            if k > 0 {
                out.raw(",");
            }
            let [a, b, c, d] = ip.to_be_bytes();
            let _ = write!(out, "{{\"id\":\"host-{a}.{b}.{c}.{d}\",\"ip\":\"{a}.{b}.{c}.{d}\",\"mac\":null,\"first_seen\":{},\"last_seen\":{}}}", first / 1000, last / 1000);
            if out.overflow || out.len + 32 > out.buf.len() {
                out.rewind(m);
                break;
            }
            k += 1;
        }
        let _ = write!(out, "],\"count\":{}}}", k);
    }

    /// (detections kept, capacity, oldest kept timestamp in epoch ms).
    pub fn retention(&self) -> (usize, usize, u64) {
        let oldest = if self.dlen == 0 { 0 } else { self.dets[self.dhead].ts_ms };
        (self.dlen, DET_CAP, oldest)
    }

    /// The `i`-th newest detection's timestamp (epoch ms) — for the self-tests.
    pub fn health_ts(&self, i: usize) -> Option<u64> {
        self.newest(i).map(|d| d.ts_ms)
    }

    pub fn detections(&self) -> usize {
        self.dlen
    }

    /// The `i`-th NEWEST detection (0 = most recent).
    fn newest(&self, i: usize) -> Option<&Det> {
        if i >= self.dlen {
            return None;
        }
        Some(&self.dets[(self.dhead + self.dlen - 1 - i) % DET_CAP])
    }

    /// Sample the kernel's lifetime QSecBit-lite score (a saturating, never-decaying sum) and
    /// derive the CURRENT risk from its growth over the last minute: 0 on a quiet link, rising
    /// under attack, falling back on its own when the attack stops.
    pub fn sample_qsecbit(&mut self, now_ticks: u64, raw_score: u32) {
        let now = self.epoch_ms(now_ticks);
        self.raw[(self.rhead + self.rlen) % RAW_CAP] = (now, raw_score);
        if self.rlen < RAW_CAP {
            self.rlen += 1;
        } else {
            self.rhead = (self.rhead + 1) % RAW_CAP;
        }
        // Oldest sample still inside the window.
        let mut base = raw_score;
        for i in 0..self.rlen {
            let (t, s) = self.raw[(self.rhead + i) % RAW_CAP];
            if now.saturating_sub(t) <= RISK_WINDOW_MS {
                base = s;
                break;
            }
        }
        let p = raw_score.saturating_sub(base) as u64;
        let risk = (p * 1000 / (p + RISK_HALF_POINTS)) as u32;
        self.qs[(self.qhead + self.qlen) % QS_CAP] = (now, risk);
        if self.qlen < QS_CAP {
            self.qlen += 1;
        } else {
            self.qhead = (self.qhead + 1) % QS_CAP;
        }
        self.change += 1;
    }

    fn band(risk_milli: u32) -> &'static str {
        if risk_milli < 300 {
            "GREEN"
        } else if risk_milli < 700 {
            "AMBER"
        } else {
            "RED"
        }
    }

    fn qs_row(out: &mut JsonBuf, (t, r): (u64, u32)) {
        out.raw("{\"ts\":");
        ts(out, t);
        let _ = write!(out, ",\"score\":{}.{:03},\"band\":", r / 1000, r % 1000);
        out.string(Self::band(r));
        out.raw("}");
    }

    /// `GET /api/qsecbit` → `{latest, history (newest first), count}`.
    pub fn render_qsecbit(&self, limit: usize, out: &mut JsonBuf) {
        out.raw("{\"latest\":");
        if self.qlen == 0 {
            out.raw("null");
        } else {
            Self::qs_row(out, self.qs[(self.qhead + self.qlen - 1) % QS_CAP]);
        }
        out.raw(",\"history\":[");
        let n = limit.min(self.qlen);
        for i in 0..n {
            if i > 0 {
                out.raw(",");
            }
            Self::qs_row(out, self.qs[(self.qhead + self.qlen - 1 - i) % QS_CAP]);
        }
        let _ = write!(out, "],\"count\":{}}}", n);
    }

    fn class_confidence(class: u8) -> &'static str {
        match class {
            crate::verdict::CLASS_QUARANTINE | crate::verdict::CLASS_FRAMEDROP | crate::verdict::CLASS_RATELIMIT_OVER => "0.9",
            crate::verdict::CLASS_RATELIMIT_UNDER => "0.7",
            crate::verdict::CLASS_OBSERVE => "0.6",
            crate::verdict::CLASS_ALLOWLISTED => "0.3",
            _ => "0.5",
        }
    }

    fn class_name(class: u8) -> &'static str {
        match class {
            crate::verdict::CLASS_ALLOWLISTED => "allowlisted",
            crate::verdict::CLASS_OBSERVE => "observe",
            crate::verdict::CLASS_RATELIMIT_UNDER => "ratelimit",
            crate::verdict::CLASS_RATELIMIT_OVER => "ratelimit_enforced",
            crate::verdict::CLASS_FRAMEDROP => "framedrop",
            crate::verdict::CLASS_QUARANTINE => "quarantine",
            _ => "unknown",
        }
    }

    fn det_row(out: &mut JsonBuf, d: &Det) {
        let info = rulecat::lookup_or_generic(d.rule_id);
        let mut tmp = [0u8; 16];
        let src = if d.src == 0 || rulecat::src_is_mac_hash(d.rule_id) { "" } else { ipv4(d.src, &mut tmp) };
        let _ = write!(out, "{{\"id\":\"det:heqk:{}\",\"ts\":", d.seq);
        ts(out, d.ts_ms);
        let _ = write!(out, ",\"rule_id\":{},\"rule_msg\":", rulecat::HEQK_RULE_BAND + d.rule_id as u32);
        // "<message> (<wire action>, <class>)" — WHY it passed or dropped, in the list itself.
        let mut msg = [0u8; 128];
        let mut mw = JsonBuf::new(&mut msg[..]);
        let _ = write!(mw, "{} ({}, {})", info.msg, if d.verdict == 2 { "DROP" } else { "PASS" }, Self::class_name(d.class));
        let ml = mw.len;
        out.string(core::str::from_utf8(&msg[..ml]).unwrap_or(info.msg));
        out.raw(",\"category\":");
        out.string(info.category);
        let _ = write!(out, ",\"severity\":{},\"mitre\":", info.severity);
        out.string(info.mitre);
        out.raw(",\"src_ip\":");
        out.string(src);
        let mut tmp2 = [0u8; 16];
        let dst = if d.dst == 0 { "" } else { ipv4(d.dst, &mut tmp2) };
        out.raw(",\"dst_ip\":");
        out.string(dst);
        let _ = write!(out, ",\"dst_port\":{},\"confidence\":{}}}", d.dport, Self::class_confidence(d.class));
    }

    /// `GET /api/detections` → `{count, detections (newest first)}`. Rows that would overflow the
    /// buffer are dropped from the END, so the document is always valid JSON.
    pub fn render_detections(&self, limit: usize, out: &mut JsonBuf) {
        out.raw("{\"detections\":[");
        let mut n = 0usize;
        for i in 0..limit.min(self.dlen) {
            let Some(d) = self.newest(i) else { break };
            let m = out.mark();
            if n > 0 {
                out.raw(",");
            }
            Self::det_row(out, d);
            // keep room for the closing `],"count":N}`
            if out.overflow || out.len + 32 > out.buf.len() {
                out.rewind(m);
                break;
            }
            n += 1;
        }
        let _ = write!(out, "],\"count\":{}}}", n);
    }

    /// `GET /api/incidents` — one incident per attributed source (the "one traceable story"):
    /// worst canonical severity → priority + score, newest activity as ts. Computed on demand
    /// from the detection ring (bounded: ≤ DET_CAP rows, ≤ MAX_INCIDENTS sources).
    pub fn render_incidents(&self, limit: usize, out: &mut JsonBuf) {
        // (src, worst_sev, last_ts_ms, count, worst_rule)
        let mut inc: [(u32, u8, u64, u32, u16); MAX_INCIDENTS] = [(0, 0, 0, 0, 0); MAX_INCIDENTS];
        let mut ni = 0usize;
        for i in 0..self.dlen {
            let Some(d) = self.newest(i) else { break };
            if d.src == 0 || rulecat::src_is_mac_hash(d.rule_id) {
                continue;
            }
            let sev = rulecat::lookup_or_generic(d.rule_id).severity;
            match inc[..ni].iter_mut().find(|e| e.0 == d.src) {
                Some(e) => {
                    e.3 += 1;
                    if sev < e.1 {
                        e.1 = sev;
                        e.4 = d.rule_id;
                    }
                }
                None if ni < MAX_INCIDENTS => {
                    inc[ni] = (d.src, sev, d.ts_ms, 1, d.rule_id);
                    ni += 1;
                }
                None => {}
            }
        }
        out.raw("{\"incidents\":[");
        let n = ni.min(limit);
        for (k, e) in inc[..n].iter().enumerate() {
            if k > 0 {
                out.raw(",");
            }
            let mut tmp = [0u8; 16];
            let ip = ipv4(e.0, &mut tmp);
            out.raw("{\"id\":");
            let mut idb = [0u8; 32];
            let mut iw = JsonBuf::new(&mut idb[..]);
            let _ = write!(iw, "inc:heqk:{}", ip);
            let il = iw.len;
            out.string(core::str::from_utf8(&idb[..il]).unwrap_or("inc:heqk"));
            out.raw(",\"ts\":");
            ts(out, e.2);
            out.raw(",\"title\":");
            let mut tb = [0u8; 96];
            let mut tw = JsonBuf::new(&mut tb[..]);
            let _ = write!(tw, "{} from {} ({} detections)", rulecat::lookup_or_generic(e.4).msg, ip, e.3);
            let tl = tw.len;
            out.string(core::str::from_utf8(&tb[..tl]).unwrap_or("heqk incident"));
            out.raw(",\"device_ip\":");
            out.string(ip);
            // threat_score = (6 - worst severity) / 5, the evidence graph's formula.
            let worst = e.1.clamp(1, 5);
            let score = match worst { 1 => "1.0", 2 => "0.8", 3 => "0.6", 4 => "0.4", _ => "0.2" };
            let _ = write!(out, ",\"priority\":\"{}\",\"status\":\"open\",\"threat_score\":{}}}",
                if worst <= rulecat::SEV_HIGH { "High" } else { "Medium" }, score);
        }
        let _ = write!(out, "],\"count\":{}}}", n);
    }

    /// `GET /api/flows` → the AP's live translated flows (NAT table), most recent first. Empty on
    /// images without the AP data path (the passive sensor keeps no per-flow table).
    pub fn render_flows(&self, now_ticks: u64, limit: usize, out: &mut JsonBuf) {
        let mut v: [Option<arch_aarch64::nat::FlowView>; 256] = [None; 256];
        let mut n = 0usize;
        arch_aarch64::nat::for_each_flow(now_ticks, &mut |f| {
            if n < v.len() {
                v[n] = Some(*f);
                n += 1;
            }
        });
        let flows = &mut v[..n];
        flows.sort_unstable_by(|a, b| b.map(|x| x.last).cmp(&a.map(|x| x.last)));
        out.raw("{\"flows\":[");
        let mut k = 0usize;
        for f in flows.iter().take(limit).flatten() {
            let m = out.mark();
            if k > 0 {
                out.raw(",");
            }
            self.flow_row(out, f, now_ticks);
            if out.overflow || out.len + 32 > out.buf.len() {
                out.rewind(m);
                break;
            }
            k += 1;
        }
        let _ = write!(out, "],\"count\":{}}}", k);
    }

    fn flow_row(&self, out: &mut JsonBuf, f: &arch_aarch64::nat::FlowView, now_ticks: u64) {
        let (a, b) = (f.src, f.dst);
        let _ = write!(out, "{{\"id\":\"flow:heqk:{}:{}\",\"ts\":", f.slot, f.first);
        ts(out, self.epoch_ms(f.first));
        let idle = now_ticks.saturating_sub(f.last) > 30 * self.cntfrq;
        let _ = write!(out, ",\"src_ip\":\"{}.{}.{}.{}\",\"src_port\":{},\"dst_ip\":\"{}.{}.{}.{}\",\"dst_port\":{},\"proto\":\"{}\",\"conn_state\":\"{}\",\"orig_bytes\":{},\"resp_bytes\":{}}}",
            a[0], a[1], a[2], a[3], if f.proto == 1 { 0 } else { f.sport }, b[0], b[1], b[2], b[3], f.dport,
            match f.proto { 6 => "tcp", 17 => "udp", 1 => "icmp", _ => "ip" },
            if idle { "idle" } else { "active" }, f.bytes_out, f.bytes_in);
    }

    /// The incident for source `src` (as `/api/incidents` aggregates it): (worst severity, newest ts,
    /// detections, worst rule). None = no detections from that source.
    fn incident_of(&self, src: u32) -> Option<(u8, u64, u32, u16)> {
        let mut r: Option<(u8, u64, u32, u16)> = None;
        for i in 0..self.dlen {
            let Some(d) = self.newest(i) else { break };
            if d.src != src || rulecat::src_is_mac_hash(d.rule_id) {
                continue;
            }
            let sev = rulecat::lookup_or_generic(d.rule_id).severity;
            r = Some(match r {
                None => (sev, d.ts_ms, 1, d.rule_id),
                Some((w, t, c, rl)) => if sev < w { (sev, t, c + 1, d.rule_id) } else { (w, t, c + 1, rl) },
            });
        }
        r
    }

    /// `inc:heqk:a.b.c.d` (URL-decoded `:`) → the source address.
    pub fn parse_incident_id(id: &str) -> Option<u32> {
        let mut buf = [0u8; 40];
        let mut n = 0usize;
        let b = id.as_bytes();
        let mut i = 0usize;
        while i < b.len() {
            let c = if b[i] == b'%' && b.get(i + 1..i + 3).map_or(false, |h| h.eq_ignore_ascii_case(b"3A")) {
                i += 3;
                b':'
            } else {
                i += 1;
                b[i - 1]
            };
            if n >= buf.len() {
                return None;
            }
            buf[n] = c;
            n += 1;
        }
        let ip = core::str::from_utf8(&buf[..n]).ok()?.strip_prefix("inc:heqk:")?;
        let mut v = 0u32;
        let mut parts = 0;
        for p in ip.split('.') {
            if p.is_empty() || p.len() > 3 || !p.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let o: u32 = p.parse().ok()?;
            if o > 255 {
                return None;
            }
            v = (v << 8) | o;
            parts += 1;
        }
        if parts == 4 { Some(v) } else { None }
    }

    /// `GET /api/incidents/:id` — the incident with its explanation (deterministic: the rule
    /// matches on this device; no AI planner has run, so `model` is null) and its attack path
    /// (source → targets it touched, rules that fired). None = unknown incident (404).
    pub fn render_incident(&self, src: u32, out: &mut JsonBuf) -> bool {
        let Some((worst, last, count, rule)) = self.incident_of(src) else { return false };
        let mut tmp = [0u8; 16];
        let ip = ipv4(src, &mut tmp);
        let worst = worst.clamp(1, 5);
        let score = match worst { 1 => "1.0", 2 => "0.8", 3 => "0.6", 4 => "0.4", _ => "0.2" };
        let _ = write!(out, "{{\"id\":\"inc:heqk:{}\",\"ts\":", ip);
        ts(out, last);
        out.raw(",\"title\":");
        let mut tb = [0u8; 96];
        let mut tw = JsonBuf::new(&mut tb[..]);
        let _ = write!(tw, "{} from {} ({} detections)", rulecat::lookup_or_generic(rule).msg, ip, count);
        let tl = tw.len;
        out.string(core::str::from_utf8(&tb[..tl]).unwrap_or("heqk incident"));
        let _ = write!(out, ",\"device_ip\":\"{}\",\"priority\":\"{}\",\"status\":\"open\",\"threat_score\":{}", ip,
            if worst <= rulecat::SEV_HIGH { "High" } else { "Medium" }, score);
        // distinct rules + targets, newest first (bounded)
        let mut rules: [u16; 8] = [0; 8];
        let mut nr = 0usize;
        let mut tgts: [(u32, u16); 8] = [(0, 0); 8];
        let mut nt = 0usize;
        let mut conf = "0.5";
        for i in 0..self.dlen {
            let Some(d) = self.newest(i) else { break };
            if d.src != src || rulecat::src_is_mac_hash(d.rule_id) {
                continue;
            }
            if nr < rules.len() && !rules[..nr].contains(&d.rule_id) {
                rules[nr] = d.rule_id;
                nr += 1;
            }
            if d.dst != 0 && nt < tgts.len() && !tgts[..nt].contains(&(d.dst, d.dport)) {
                tgts[nt] = (d.dst, d.dport);
                nt += 1;
            }
            if Self::class_confidence(d.class) == "0.9" {
                conf = "0.9";
            }
        }
        out.raw(",\"explanation\":{\"why\":");
        let mut wb = [0u8; 320];
        let mut ww = JsonBuf::new(&mut wb[..]);
        let _ = write!(ww, "{} detection(s) from {} matched {} rule(s) on this device:", count, ip, nr);
        for (k, r) in rules[..nr].iter().enumerate().take(3) {
            let _ = write!(ww, "{} {}", if k > 0 { ";" } else { "" }, rulecat::lookup_or_generic(*r).msg);
        }
        let _ = write!(ww, ". Deterministic rule match (no AI planner run).");
        let wl = ww.len;
        out.string(core::str::from_utf8(&wb[..wl]).unwrap_or("rule match"));
        let _ = write!(out, ",\"confidence\":{},\"evidence\":{},\"model\":null,\"related_events\":[", conf, count);
        let mut k = 0;
        for i in 0..self.dlen {
            let Some(d) = self.newest(i) else { break };
            if d.src == src && !rulecat::src_is_mac_hash(d.rule_id) && k < 10 {
                let _ = write!(out, "{}\"det:heqk:{}\"", if k > 0 { "," } else { "" }, d.seq);
                k += 1;
            }
        }
        // attack path: source -> each target; each rule -> source
        let _ = write!(out, "]}},\"attack_path\":{{\"incident\":\"inc:heqk:{}\",\"node_count\":{},\"edge_count\":{},\"nodes\":[", ip, 1 + nt + nr, nt + nr);
        let _ = write!(out, "{{\"id\":\"ip:{}\",\"type\":\"Device\",\"label\":\"{}\"}}", ip, ip);
        for &(d, p) in &tgts[..nt] {
            let mut t2 = [0u8; 16];
            let dip = ipv4(d, &mut t2);
            let _ = write!(out, ",{{\"id\":\"conn:{}:{}\",\"type\":\"Connection\",\"label\":\"{}:{}\"}}", dip, p, dip, p);
        }
        for &r in &rules[..nr] {
            let _ = write!(out, ",{{\"id\":\"rule:{}\",\"type\":\"Threat\",\"label\":", rulecat::HEQK_RULE_BAND + r as u32);
            out.string(rulecat::lookup_or_generic(r).msg);
            out.raw("}");
        }
        out.raw("],\"edges\":[");
        let mut e = 0;
        for &(d, p) in &tgts[..nt] {
            let mut t2 = [0u8; 16];
            let dip = ipv4(d, &mut t2);
            let _ = write!(out, "{}{{\"src\":\"ip:{}\",\"type\":\"connected_to\",\"dst\":\"conn:{}:{}\"}}", if e > 0 { "," } else { "" }, ip, dip, p);
            e += 1;
        }
        for &r in &rules[..nr] {
            let _ = write!(out, "{}{{\"src\":\"rule:{}\",\"type\":\"detected_on\",\"dst\":\"ip:{}\"}}", if e > 0 { "," } else { "" }, rulecat::HEQK_RULE_BAND + r as u32, ip);
            e += 1;
        }
        out.raw("]}}");
        !out.overflow
    }

    /// `GET /api/incidents/:id/timeline` — the source's detections and its live flows, oldest first.
    pub fn render_timeline(&self, src: u32, now_ticks: u64, out: &mut JsonBuf) {
        let found = self.incident_of(src).is_some();
        let mut tmp = [0u8; 16];
        let ip = ipv4(src, &mut tmp);
        let _ = write!(out, "{{\"incident\":\"inc:heqk:{}\",\"found\":{},\"events\":[", ip, found);
        // (ts_ms, is_flow, index)
        let mut ev: [(u64, bool, u16); 96] = [(0, false, 0); 96];
        let mut n = 0usize;
        if found {
            for i in (0..self.dlen).rev() {
                let Some(d) = self.newest(i) else { continue };
                if d.src == src && !rulecat::src_is_mac_hash(d.rule_id) && n < 64 {
                    ev[n] = (d.ts_ms, false, i as u16);
                    n += 1;
                }
            }
            let srcb = src.to_be_bytes();
            let mut fl: [Option<arch_aarch64::nat::FlowView>; 32] = [None; 32];
            let mut nf = 0usize;
            arch_aarch64::nat::for_each_flow(now_ticks, &mut |f| {
                if (f.src == srcb || f.dst == srcb) && nf < fl.len() {
                    fl[nf] = Some(*f);
                    nf += 1;
                }
            });
            for (j, f) in fl[..nf].iter().flatten().enumerate() {
                if n < ev.len() {
                    ev[n] = (self.epoch_ms(f.first), true, j as u16);
                    n += 1;
                }
            }
            ev[..n].sort_unstable_by_key(|e| e.0);
            for (k, &(t, is_flow, idx)) in ev[..n].iter().enumerate() {
                let m = out.mark();
                if k > 0 {
                    out.raw(",");
                }
                if is_flow {
                    let f = fl[idx as usize].unwrap();
                    let _ = write!(out, "{{\"id\":\"flow:heqk:{}:{}\",\"ts\":", f.slot, f.first);
                    ts(out, t);
                    let _ = write!(out, ",\"kind\":\"flow\",\"label\":\"{} {}.{}.{}.{} -> {}.{}.{}.{}:{} ({} B out / {} B in)\"}}",
                        match f.proto { 6 => "TCP", 17 => "UDP", 1 => "ICMP", _ => "IP" },
                        f.src[0], f.src[1], f.src[2], f.src[3], f.dst[0], f.dst[1], f.dst[2], f.dst[3], f.dport, f.bytes_out, f.bytes_in);
                } else {
                    let Some(d) = self.newest(idx as usize) else { continue };
                    let _ = write!(out, "{{\"id\":\"det:heqk:{}\",\"ts\":", d.seq);
                    ts(out, t);
                    out.raw(",\"kind\":\"detection\",\"label\":");
                    let mut lb = [0u8; 160];
                    let mut lw = JsonBuf::new(&mut lb[..]);
                    let mut t2 = [0u8; 16];
                    let _ = write!(lw, "{} ({}, {})", rulecat::lookup_or_generic(d.rule_id).msg, if d.verdict == 2 { "DROP" } else { "PASS" }, Self::class_name(d.class));
                    if d.dst != 0 {
                        let _ = write!(lw, " -> {}:{}", ipv4(d.dst, &mut t2), d.dport);
                    }
                    let ll = lw.len;
                    out.string(core::str::from_utf8(&lb[..ll]).unwrap_or("detection"));
                    out.raw("}");
                }
                if out.overflow || out.len + 32 > out.buf.len() {
                    out.rewind(m);
                    n = k;
                    break;
                }
            }
        }
        let _ = write!(out, "],\"count\":{}}}", n);
    }

    /// SSE `update` payload: the newest detections since `since_change` was observed is not
    /// tracked per row, so clients treat it as "something changed, re-fetch" (the UI contract):
    /// carry the newest few detections + the latest QSecBit sample.
    pub fn render_update(&self, out: &mut JsonBuf) {
        out.raw("{\"detections\":");
        let m = out.mark();
        let mut inner = [0u8; 2048];
        let mut iw = JsonBuf::new(&mut inner[..]);
        self.render_detections(5, &mut iw);
        // render_detections emits {"detections":[...],"count":n}; reuse just the array.
        let b = iw.bytes();
        let start = b.iter().position(|&c| c == b'[').unwrap_or(0);
        let end = b.iter().rposition(|&c| c == b']').map(|e| e + 1).unwrap_or(b.len());
        out.raw(core::str::from_utf8(&b[start..end]).unwrap_or("[]"));
        if out.overflow {
            out.rewind(m);
            out.raw("[]");
        }
        out.raw(",\"incidents\":[],\"qsecbit\":[");
        if self.qlen > 0 {
            Self::qs_row(out, self.qs[(self.qhead + self.qlen - 1) % QS_CAP]);
        }
        out.raw("]}");
    }
}
