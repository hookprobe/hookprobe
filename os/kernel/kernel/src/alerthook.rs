//! Owner alert delivery (operator decision 2026-11-10): a signed webhook, ntfy / Gotify compatible, local-first —
//! no HookProbe cloud. The owner points it at their own server (e.g. a self-hosted ntfy or Gotify on the LAN or the
//! management network; their phone app subscribes there). The in-UI feed and the SIEM syslog export are unchanged.
//!
//! * Configuration: an owner-authenticated setting (`POST /api/alert-hook`, re-auth like every owner write), stored
//!   as a sealed owner-journal record (`Kind::AlertHook`): target IPv4 + port, format, minimum severity, the path /
//!   topic, and the HMAC key = sha256(owner's signing secret). The secret itself is never stored.
//! * Every POST carries `X-HQ-Signature: sha256=<hex HMAC-SHA256(key, body)>` and `X-HQ-Seq`.
//! * No alert storms: one alert per (rule, device) per hour, at most `MAX_PER_HOUR` alerts an hour in total; what
//!   is held back is counted and named in the next alert ("+N more held back").
//! * v1 transport: plain HTTP/1.1 over the Mission Control TCP stack — the target must be reachable from it (LAN or
//!   management network). HTTPS to a public endpoint needs a TLS client (not built).

pub const FMT_NTFY: u8 = 0;
pub const FMT_GOTIFY: u8 = 1;
pub const FMT_JSON: u8 = 2;
pub const PATH_MAX: usize = 96;
/// Journal target layout: ip 4 | port 2 | fmt 1 | min_sev 1 | key 32.
pub const TARGET_LEN: usize = 40;
const DEDUPE_MS: u64 = 3_600_000;
pub const MAX_PER_HOUR: u32 = 12;
const SLOTS: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Hook {
    pub ip: [u8; 4],
    pub port: u16,
    pub fmt: u8,
    /// Alert on severity <= this (rulecat: 1 critical, 2 high, 3 medium, 4 low).
    pub min_sev: u8,
    pub key: [u8; 32],
    pub path: [u8; PATH_MAX],
    pub plen: u8,
}

impl Hook {
    pub fn path(&self) -> &str {
        core::str::from_utf8(&self.path[..self.plen as usize]).unwrap_or("/")
    }
    pub fn fmt_name(&self) -> &'static str {
        match self.fmt {
            FMT_NTFY => "ntfy",
            FMT_GOTIFY => "gotify",
            _ => "json",
        }
    }
    pub fn encode(&self) -> [u8; TARGET_LEN] {
        let mut t = [0u8; TARGET_LEN];
        t[..4].copy_from_slice(&self.ip);
        t[4..6].copy_from_slice(&self.port.to_be_bytes());
        t[6] = self.fmt;
        t[7] = self.min_sev;
        t[8..40].copy_from_slice(&self.key);
        t
    }
    pub fn decode(t: &[u8], path: &[u8]) -> Option<Hook> {
        if t.len() != TARGET_LEN || path.is_empty() || path.len() > PATH_MAX || path[0] != b'/' || t[6] > FMT_JSON || !(1..=4).contains(&t[7]) {
            return None;
        }
        if !path.iter().all(|&c| c.is_ascii_graphic()) {
            return None;
        }
        let mut h = Hook { ip: [t[0], t[1], t[2], t[3]], port: u16::from_be_bytes([t[4], t[5]]), fmt: t[6], min_sev: t[7], key: [0; 32], path: [0; PATH_MAX], plen: path.len() as u8 };
        h.key.copy_from_slice(&t[8..40]);
        h.path[..path.len()].copy_from_slice(path);
        (h.port != 0 && h.ip != [0; 4]).then_some(h)
    }
}

static mut HOOK: Option<Hook> = None;

pub fn set(h: Option<Hook>) {
    unsafe { *core::ptr::addr_of_mut!(HOOK) = h };
}
pub fn get() -> Option<Hook> {
    unsafe { *core::ptr::addr_of!(HOOK) }
}

/// Counters for `/api/alert-hook` and the heartbeat.
#[derive(Clone, Copy, Default)]
pub struct Stats {
    pub queued: u32,
    pub sent: u32,
    pub failed: u32,
    pub held_back: u32,
    pub last_status: u16,
}
static mut STATS: Stats = Stats { queued: 0, sent: 0, failed: 0, held_back: 0, last_status: 0 };
pub fn stats() -> Stats {
    let mut s = unsafe { *core::ptr::addr_of!(STATS) };
    s.held_back = unsafe { STATS_HELD };
    s
}
/// Held back by the storm gate (also counted inside the gate for the next alert's text).
pub static mut STATS_HELD: u32 = 0;
pub fn note_queued() {
    unsafe { (*core::ptr::addr_of_mut!(STATS)).queued += 1 };
}
pub fn note_result(status: u16) {
    let s = unsafe { &mut *core::ptr::addr_of_mut!(STATS) };
    s.last_status = status;
    if (200..300).contains(&status) {
        s.sent += 1;
    } else {
        s.failed += 1;
    }
}

/// The storm gate: per (rule, device) once an hour, at most MAX_PER_HOUR an hour overall.
pub struct Gate {
    keys: [(u32, u64); SLOTS],
    hour_start: u64,
    in_hour: u32,
    held: u32,
}
impl Gate {
    pub const fn new() -> Gate {
        Gate { keys: [(0, 0); SLOTS], hour_start: 0, in_hour: 0, held: 0 }
    }
    /// Some(held_back_since_last_alert) when this detection may alert now.
    pub fn admit(&mut self, rule: u16, src: u32, now_ms: u64) -> Option<u32> {
        let k = ((rule as u32) << 16 ^ src.rotate_left(7) ^ src) | 1;
        if now_ms.saturating_sub(self.hour_start) >= DEDUPE_MS || self.hour_start == 0 {
            self.hour_start = now_ms.max(1);
            self.in_hour = 0;
        }
        if let Some(e) = self.keys.iter().find(|e| e.0 == k) {
            if now_ms.saturating_sub(e.1) < DEDUPE_MS {
                self.held += 1;
                return None;
            }
        }
        if self.in_hour >= MAX_PER_HOUR {
            self.held += 1;
            return None;
        }
        let i = self.keys.iter().position(|e| e.0 == k).unwrap_or_else(|| (0..SLOTS).min_by_key(|&i| self.keys[i].1).unwrap_or(0));
        self.keys[i] = (k, now_ms.max(1));
        self.in_hour += 1;
        let h = self.held;
        self.held = 0;
        Some(h)
    }
    pub fn held(&self) -> u32 {
        self.held
    }
}

struct W<'a> {
    b: &'a mut [u8],
    n: usize,
    ok: bool,
}
impl core::fmt::Write for W<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bs = s.as_bytes();
        if self.n + bs.len() > self.b.len() {
            self.ok = false;
            return Err(core::fmt::Error);
        }
        self.b[self.n..self.n + bs.len()].copy_from_slice(bs);
        self.n += bs.len();
        Ok(())
    }
}

/// One alert, already gated.
pub struct Alert<'a> {
    pub seq: u64,
    pub rule_id: u32,
    pub msg: &'a str,
    pub severity: u8,
    pub src: u32,
    pub dst: u32,
    pub dport: u16,
    pub action: &'a str,
    pub held_back: u32,
}

fn ip(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

/// The request body for `hook`'s format. JSON-safe: messages come from the rule catalogue (fixed ASCII).
pub fn body(h: &Hook, a: &Alert, out: &mut [u8]) -> usize {
    use core::fmt::Write;
    let (s, d) = (ip(a.src), ip(a.dst));
    let more = if a.held_back > 0 { " (+more held back)" } else { "" };
    let mut w = W { b: out, n: 0, ok: true };
    let _ = match h.fmt {
        FMT_NTFY => write!(w, "{} — device {}.{}.{}.{} -> {}.{}.{}.{}:{} ({}){} [rule {}]", a.msg, s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3], a.dport, a.action, more, a.rule_id),
        FMT_GOTIFY => write!(w, "{{\"title\":\"HookProbe: {}\",\"message\":\"device {}.{}.{}.{} -> {}.{}.{}.{}:{} ({}), rule {}, {} held back\",\"priority\":{}}}",
            a.msg, s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3], a.dport, a.action, a.rule_id, a.held_back, priority(a.severity) * 2),
        _ => write!(w, "{{\"source\":\"heqk\",\"seq\":{},\"rule_id\":{},\"message\":\"{}\",\"severity\":{},\"src\":\"{}.{}.{}.{}\",\"dst\":\"{}.{}.{}.{}\",\"dport\":{},\"action\":\"{}\",\"held_back\":{}}}",
            a.seq, a.rule_id, a.msg, a.severity, s[0], s[1], s[2], s[3], d[0], d[1], d[2], d[3], a.dport, a.action, a.held_back),
    };
    if w.ok { w.n } else { 0 }
}

/// ntfy priority 1..5 from the catalogue severity (1 critical .. 4 low).
fn priority(sev: u8) -> u8 {
    match sev {
        1 => 5,
        2 => 4,
        3 => 3,
        _ => 2,
    }
}

/// The full HTTP/1.1 request (headers + body) into `out`; 0 when it does not fit.
pub fn request(h: &Hook, a: &Alert, out: &mut [u8]) -> usize {
    use core::fmt::Write;
    let mut b = [0u8; 600];
    let n = body(h, a, &mut b);
    if n == 0 {
        return 0;
    }
    let mac = boot_abi::kdf::hmac_sha256(&h.key, &b[..n]);
    let mut hex = [0u8; 64];
    for (i, x) in mac.iter().enumerate() {
        const H: &[u8; 16] = b"0123456789abcdef";
        hex[2 * i] = H[(x >> 4) as usize];
        hex[2 * i + 1] = H[(x & 15) as usize];
    }
    let ctype = if h.fmt == FMT_NTFY { "text/plain; charset=utf-8" } else { "application/json" };
    let mut w = W { b: out, n: 0, ok: true };
    let _ = write!(w, "POST {} HTTP/1.1\r\nHost: {}.{}.{}.{}:{}\r\nContent-Type: {}\r\nContent-Length: {}\r\nX-HQ-Seq: {}\r\nX-HQ-Signature: sha256={}\r\nConnection: close\r\n",
        h.path(), h.ip[0], h.ip[1], h.ip[2], h.ip[3], h.port, ctype, n, a.seq, core::str::from_utf8(&hex).unwrap_or(""));
    if h.fmt == FMT_NTFY {
        let _ = write!(w, "Title: HookProbe alert\r\nPriority: {}\r\nTags: warning,shield\r\n", priority(a.severity));
    }
    let _ = write!(w, "\r\n");
    if !w.ok || w.n + n > w.b.len() {
        return 0;
    }
    w.b[w.n..w.n + n].copy_from_slice(&b[..n]);
    w.n + n
}

/// The status code of an HTTP response head (`HTTP/1.x NNN`), or 0.
pub fn status(resp: &[u8]) -> u16 {
    if resp.len() < 12 || !resp.starts_with(b"HTTP/1.") || resp[8] != b' ' {
        return 0;
    }
    let d = &resp[9..12];
    if !d.iter().all(|c| c.is_ascii_digit()) {
        return 0;
    }
    (d[0] - b'0') as u16 * 100 + (d[1] - b'0') as u16 * 10 + (d[2] - b'0') as u16
}

/// `[P-alerthook]`: config round trip + refusals, the storm gate, the three formats, the signature.
pub fn selftest() -> bool {
    let mut h = Hook { ip: [10, 99, 0, 20], port: 8080, fmt: FMT_NTFY, min_sev: 2, key: boot_abi::sha256::digest(b"owner-signing-secret"), path: [0; PATH_MAX], plen: 0 };
    let p = b"/heqk-alerts";
    h.path[..p.len()].copy_from_slice(p);
    h.plen = p.len() as u8;
    let rt = Hook::decode(&h.encode(), p) == Some(h);
    let refused = Hook::decode(&h.encode(), b"no-slash").is_none() && Hook::decode(&h.encode(), b"/a b").is_none() && Hook::decode(&[0; TARGET_LEN], p).is_none();
    // storm gate: same (rule, device) once an hour; 12 an hour overall; held-back count carried
    let mut g = Gate::new();
    let t = 10_000u64;
    let first = g.admit(124, 0x0a63_000a, t) == Some(0);
    let dup = g.admit(124, 0x0a63_000a, t + 1_000).is_none();
    let other_dev = g.admit(124, 0x0a63_000b, t + 2_000) == Some(1);
    let mut capped = true;
    for k in 0..10u32 {
        capped &= g.admit(200 + k as u16, 0x0a63_0001, t + 3_000).is_some();
    }
    let over = g.admit(250, 0x0a63_0001, t + 4_000).is_none(); // the 13th in the hour
    let next_hour = g.admit(250, 0x0a63_0001, t + DEDUPE_MS + 5_000) == Some(1); // the one held back by the cap
    let gate = first && dup && other_dev && capped && over && next_hour;
    // formats + signature
    let a = Alert { seq: 7, rule_id: 1_000_124, msg: "Brute force on an admin service", severity: 2, src: 0x0a63_000a, dst: 0x0a64_0001, dport: 22, action: "observed", held_back: 0 };
    let mut out = [0u8; 1100];
    let n = request(&h, &a, &mut out);
    let r = core::str::from_utf8(&out[..n]).unwrap_or("");
    let ntfy = r.starts_with("POST /heqk-alerts HTTP/1.1\r\n") && r.contains("Title: HookProbe alert\r\n") && r.contains("Priority: 4\r\n") && r.ends_with("[rule 1000124]");
    let mut body_b = [0u8; 600];
    let bn = body(&h, &a, &mut body_b);
    let mac = boot_abi::kdf::hmac_sha256(&h.key, &body_b[..bn]);
    let signed = r.contains("X-HQ-Signature: sha256=") && {
        let i = r.find("sha256=").unwrap_or(0) + 7;
        r.len() > i + 2 && u8::from_str_radix(&r[i..i + 2], 16).ok() == Some(mac[0])
    };
    h.fmt = FMT_GOTIFY;
    let n = request(&h, &a, &mut out);
    let gotify = core::str::from_utf8(&out[..n]).is_ok_and(|r| r.contains("\"priority\":8") && r.contains("application/json"));
    h.fmt = FMT_JSON;
    let n = request(&h, &a, &mut out);
    let json = core::str::from_utf8(&out[..n]).is_ok_and(|r| r.contains("\"rule_id\":1000124") && r.contains("\"src\":\"10.99.0.10\""));
    let st = status(b"HTTP/1.1 200 OK\r\n") == 200 && status(b"HTTP/1.0 403 Forbidden") == 403 && status(b"garbage") == 0;
    let pass = rt && refused && gate && ntfy && signed && gotify && json && st;
    arch_aarch64::_print(format_args!(
        " [P-alerthook] {} — owner alert webhook (operator 2026-11-10; ntfy / Gotify / JSON, signed): config round trip={} bad path / empty target refused={} storm gate (per device+rule hourly, {} an hour, held-back count carried)={} ntfy request={} HMAC signature={} gotify={} json={} response status parse={}\n",
        if pass { "PASS" } else { "FAIL" }, rt, refused, MAX_PER_HOUR, gate, ntfy, signed, gotify, json, st));
    pass
}
