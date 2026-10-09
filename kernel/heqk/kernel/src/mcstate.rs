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
}

impl McState {
    pub const fn new() -> Self {
        McState {
            dets: [Det { seq: 0, ts_ms: 0, src: 0, rule_id: 0, sev_points: 0, verdict: 0, class: 0 }; DET_CAP],
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
        }
    }

    /// Anchor `cntpct` ticks to wall time: `boot_epoch_ms` is the epoch at `boot_ticks`.
    pub fn set_clock(&mut self, boot_epoch_ms: u64, boot_ticks: u64, cntfrq: u64) {
        self.boot_epoch_ms = boot_epoch_ms;
        self.boot_ticks = boot_ticks;
        self.cntfrq = cntfrq.max(1);
    }

    pub fn epoch_ms(&self, ticks: u64) -> u64 {
        let dt = ticks.saturating_sub(self.boot_ticks);
        self.boot_epoch_ms + dt / self.cntfrq * 1000 + (dt % self.cntfrq) * 1000 / self.cntfrq
    }

    /// Record one drained SOAR event (the oldest is overwritten at capacity).
    pub fn push_event(&mut self, ev: &events::Event) {
        let d = Det {
            seq: self.next_seq,
            ts_ms: self.epoch_ms(ev.ts),
            src: ev.src,
            rule_id: ev.rule_id,
            sev_points: ev.severity,
            verdict: ev.verdict,
            class: ev.class,
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
        let _ = write!(out, ",\"dst_ip\":\"\",\"dst_port\":0,\"confidence\":{}}}", Self::class_confidence(d.class));
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
