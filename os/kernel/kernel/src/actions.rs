//! Operator actions from Mission Control (ADR 0053, accepted with safeguards 2026-11-08).
//!
//! Only reversible, time-bounded operations. Limits are enforced here, not in the UI. Actions are kept
//! in RAM on the monotonic clock: they expire by themselves and a reboot clears them, so recovery never
//! depends on Mission Control. Nothing here writes a signed file or changes WAN, firewall or trust
//! configuration.

/// Longest allowed lifetime of any action (kernel-enforced).
pub const MAX_TTL_S: u64 = 24 * 3600;
/// Shortest allowed lifetime.
pub const MIN_TTL_S: u64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Mark an incident as acknowledged (no enforcement).
    Ack = 0,
    /// Hold traffic from/to one IPv4 address for a while.
    HoldIp = 1,
    /// Put one device (by MAC) into the quarantine policy for a while.
    Isolate = 2,
    /// Let one domain through Shield for a while.
    ShieldAllow = 3,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Kind> {
        match s {
            "ack" => Some(Kind::Ack),
            "hold_ip" => Some(Kind::HoldIp),
            "isolate" => Some(Kind::Isolate),
            "shield_allow" => Some(Kind::ShieldAllow),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Kind::Ack => "ack",
            Kind::HoldIp => "hold_ip",
            Kind::Isolate => "isolate",
            Kind::ShieldAllow => "shield_allow",
        }
    }

    /// Kinds that need the owner key entered again (re-authentication).
    pub fn needs_reauth(self) -> bool {
        matches!(self, Kind::Isolate | Kind::ShieldAllow)
    }

    /// Kinds that carry a lifetime (an ack does not expire).
    pub fn has_ttl(self) -> bool {
        !matches!(self, Kind::Ack)
    }
}

/// Clamp a requested lifetime into the kernel's bounds.
pub fn clamp_ttl(req_s: u64) -> u64 {
    req_s.clamp(MIN_TTL_S, MAX_TTL_S)
}

/// What an action applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Incident(u32),
    Ip(u32),
    Mac([u8; 6]),
    /// Domain: hash of the lowercase name.
    Domain(u64),
}

#[derive(Clone, Copy)]
pub struct Entry {
    pub id: u32,
    pub kind: Kind,
    pub target: Target,
    pub created_ms: u64,
    /// 0 = does not expire (ack).
    pub expires_ms: u64,
    pub live: bool,
}

const SLOTS: usize = 64;
const EMPTY: Entry = Entry { id: 0, kind: Kind::Ack, target: Target::Incident(0), created_ms: 0, expires_ms: 0, live: false };

struct Store {
    e: [Entry; SLOTS],
    next_id: u32,
    now_ms: u64,
}

// All-zero initializer on purpose: the store lives in .bss and costs no image bytes.
static mut STORE: Store = Store { e: [EMPTY; SLOTS], next_id: 0, now_ms: 0 };

fn store() -> &'static mut Store {
    unsafe { &mut *core::ptr::addr_of_mut!(STORE) }
}

/// Advance the monotonic clock (ms since the anchor) and drop expired entries.
pub fn tick(now_ms: u64) {
    let s = store();
    s.now_ms = now_ms;
    for e in s.e.iter_mut() {
        if e.live && e.expires_ms != 0 && now_ms >= e.expires_ms {
            e.live = false;
        }
    }
}

fn active(e: &Entry, now: u64) -> bool {
    e.live && (e.expires_ms == 0 || now < e.expires_ms)
}

/// Add an action. Returns its id, or None when the store is full.
pub fn add(kind: Kind, target: Target, ttl_s: u64) -> Option<u32> {
    let s = store();
    let now = s.now_ms;
    let slot = s.e.iter().position(|e| !active(e, now))?;
    s.next_id = s.next_id.wrapping_add(1).max(1);
    let id = s.next_id;
    let expires_ms = if kind.has_ttl() { now + clamp_ttl(ttl_s) * 1000 } else { 0 };
    s.e[slot] = Entry { id, kind, target, created_ms: now, expires_ms, live: true };
    Some(id)
}

/// End an action early. Returns whether it was active.
pub fn revoke(id: u32) -> bool {
    let s = store();
    let now = s.now_ms;
    match s.e.iter_mut().find(|e| e.id == id && active(e, now)) {
        Some(e) => {
            e.live = false;
            true
        }
        None => false,
    }
}

fn any(f: impl Fn(&Entry) -> bool) -> bool {
    let s = store();
    let now = s.now_ms;
    s.e.iter().any(|e| active(e, now) && f(e))
}

/// Is traffic from/to this IPv4 address held right now?
pub fn ip_held(ip: u32) -> bool {
    // Defence in depth: the management floor is never held, whatever is in the store.
    ip != 0 && !crate::verdict::is_allowlisted(ip) && any(|e| e.kind == Kind::HoldIp && e.target == Target::Ip(ip))
}

/// Is this device isolated right now?
pub fn isolated(mac: &[u8; 6]) -> bool {
    any(|e| e.kind == Kind::Isolate && e.target == Target::Mac(*mac))
}

/// Is this domain hash allowed through Shield right now?
pub fn shield_allowed(hash: u64) -> bool {
    any(|e| e.kind == Kind::ShieldAllow && e.target == Target::Domain(hash))
}

/// Has this incident (keyed by source address) been acknowledged?
pub fn acked(src: u32) -> bool {
    any(|e| e.kind == Kind::Ack && e.target == Target::Incident(src))
}

/// Visit every active entry.
pub fn for_each(f: &mut dyn FnMut(&Entry, u64)) {
    let s = store();
    let now = s.now_ms;
    for e in s.e.iter().filter(|e| active(e, now)) {
        f(e, now);
    }
}

/// Clear everything (tests).
pub fn reset() {
    let s = store();
    s.e = [EMPTY; SLOTS];
    s.next_id = 0;
}

// ---- audit log: every attempt, accepted or refused ----

#[derive(Clone, Copy)]
pub struct Audit {
    pub ms: u64,
    pub session: [u8; 4],
    pub kind: Kind,
    pub target: Target,
    pub ttl_s: u64,
    pub ok: bool,
    /// why it was refused (None when accepted). An Option so the static log is all-zero (.bss, not image bytes).
    pub refusal: Option<&'static str>,
    pub reason: [u8; 64],
    pub rlen: u8,
}

const LOG: usize = 128;
const A0: Audit = Audit { ms: 0, session: [0; 4], kind: Kind::Ack, target: Target::Incident(0), ttl_s: 0, ok: false, refusal: None, reason: [0; 64], rlen: 0 };

struct Log {
    e: [Audit; LOG],
    head: usize,
    len: usize,
}

static mut AUDIT_LOG: Log = Log { e: [A0; LOG], head: 0, len: 0 };

/// Record one attempt. `reason` is the operator's text (printable ASCII kept, ≤ 64 bytes).
pub fn audit(session: [u8; 4], kind: Kind, target: Target, ttl_s: u64, ok: bool, refusal: &'static str, reason: &[u8]) {
    let l = unsafe { &mut *core::ptr::addr_of_mut!(AUDIT_LOG) };
    let mut a = Audit { ms: store().now_ms, session, kind, target, ttl_s, ok, refusal: if ok { None } else { Some(refusal) }, reason: [0; 64], rlen: 0 };
    let mut n = 0;
    for &c in reason {
        if n >= a.reason.len() {
            break;
        }
        if (0x20..0x7f).contains(&c) && c != b'"' && c != b'\\' {
            a.reason[n] = c;
            n += 1;
        }
    }
    a.rlen = n as u8;
    l.e[(l.head + l.len) % LOG] = a;
    if l.len < LOG {
        l.len += 1;
    } else {
        l.head = (l.head + 1) % LOG;
    }
}

/// Visit the audit log, newest first.
pub fn for_each_audit(f: &mut dyn FnMut(&Audit)) {
    let l = unsafe { &*core::ptr::addr_of!(AUDIT_LOG) };
    for i in 0..l.len {
        f(&l.e[(l.head + l.len - 1 - i) % LOG]);
    }
}

/// Clear the audit log (tests).
pub fn reset_audit() {
    let l = unsafe { &mut *core::ptr::addr_of_mut!(AUDIT_LOG) };
    l.head = 0;
    l.len = 0;
}

// ---- replay guard: a strictly increasing sequence number per session ----

static mut SEQS: [([u8; 4], u64); 8] = [([0; 4], 0); 8];

/// Accept `seq` for this session only if it is greater than the last accepted one.
pub fn accept_seq(session: [u8; 4], seq: u64) -> bool {
    let t = unsafe { &mut *core::ptr::addr_of_mut!(SEQS) };
    if seq == 0 {
        return false;
    }
    if let Some(e) = t.iter_mut().find(|e| e.0 == session) {
        if seq <= e.1 {
            return false;
        }
        e.1 = seq;
        return true;
    }
    // new session: take the slot with the lowest seq (oldest)
    let i = (0..t.len()).min_by_key(|&i| t[i].1).unwrap_or(0);
    t[i] = (session, seq);
    true
}

/// The last accepted sequence number for a session (0 if none) — the UI starts above it.
pub fn last_seq(session: [u8; 4]) -> u64 {
    let t = unsafe { &*core::ptr::addr_of!(SEQS) };
    t.iter().find(|e| e.0 == session).map_or(0, |e| e.1)
}
