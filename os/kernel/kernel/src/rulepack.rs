//! Field-updatable detection rules (parity gap G6) — `RULES.BIN` on the boot partition.
//!
//! heqk shipped 3 signature rules against NAPSE's set; new detections meant a new kernel. A rule pack is
//! compiled OFF-device (`tools/rulepack.py`, same RFC 9669 encoding as `bpf.rs`), signed with the operator
//! key (`RULES.SIG`, magic HQRSIG1 / tag HQRUL1 — its own signature domain), and loaded at boot:
//!   1. the pack signature is verified before a byte is parsed (authority + integrity, incl. each rule's
//!      id / tier / class / severity — an attacker cannot turn an observe rule into a dropping one);
//!   2. every program then passes `bpf::verify_prevail` (memory safety, min_len) and is JIT-compiled
//!      exactly like the built-in corpus; a rule that fails is skipped and counted, never armed;
//!   3. ids live in a dedicated band (1000..=1999) so they never collide with the catalogue.
//! Pack layout: "HQRULES1" | n u16 LE | reserved u16 | n × { id u16 | tier u8 | class u8 | severity u8 |
//! name_len u8 | n_insn u16 | name | n_insn × u64 LE }.
//! Tiers: 0 L4 header (R1 = TCP/UDP header), 1 L2 frame, 2 TCP header (TCP only), 3 flow (frame, helpers).
//! Classes: 0 signature (may drop, as the built-in port rules), 1 scan_shape, 2 malformed_frame,
//! 3 reputation (observe), 4 spoof (observe), 5 behavioral (observe — the safe default for content rules).

use crate::rules::{Rule, RState};
use crate::verdict::FindingClass;

pub const ID_MIN: u16 = 1000;
pub const ID_MAX: u16 = 1999;
pub const DYN_MAX: usize = 64;
/// Heap left untouched by the rule-pack JIT (everything else that allocates keeps working).
const JIT_HEAP_MARGIN: usize = 64 * 1024;
const POOL: usize = 8192;
const NAMES: usize = 2048;

static mut INSN: [u64; POOL] = [0; POOL];
static mut INSN_N: usize = 0;
static mut NAME: [u8; NAMES] = [0; NAMES];
static mut NAME_N: usize = 0;
// Zeroed, not `[Rule; N]` literals: a Rule holds &str/&[] (non-null), which would put the whole table in
// .data (10 KiB of image). Only slots below DYN_N[t] are ever written and read, via raw pointers (dyn_slot).
pub(crate) static mut DYN: core::mem::MaybeUninit<[[Rule; DYN_MAX]; 4]> = core::mem::MaybeUninit::zeroed();

#[inline]
fn dyn_slot(t: usize, i: usize) -> *mut Rule {
    debug_assert!(t < 4 && i < DYN_MAX);
    unsafe { (core::ptr::addr_of_mut!(DYN) as *mut Rule).add(t * DYN_MAX + i) }
}

/// The armed rules of tier `t` (only the written prefix).
fn dyn_rules(t: usize, n: usize) -> &'static [Rule] {
    unsafe { core::slice::from_raw_parts(dyn_slot(t, 0) as *const Rule, n.min(DYN_MAX)) }
}
pub(crate) static mut DYN_N: [usize; 4] = [0; 4];
pub(crate) static mut DYN_STATE: [[RState; DYN_MAX]; 4] = [[RState::EMPTY; DYN_MAX]; 4];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PackInfo {
    pub loaded: u16,
    pub refused_verify: u16,
    pub refused_meta: u16,
    pub generation: u64,
    pub signed: bool,
    /// 0 none, 1 loaded, 2 refused (signature / format)
    pub file: u8,
    /// Armed on the interpreter because the heap had no JIT margin left.
    pub interp_only: u16,
    /// Not armed: the heap had no margin left for the verifier.
    pub refused_heap: u16,
}
static mut INFO: PackInfo = PackInfo { loaded: 0, refused_verify: 0, refused_meta: 0, generation: 0, signed: false, file: 0, interp_only: 0, refused_heap: 0 };

pub fn info() -> PackInfo {
    unsafe { INFO }
}

fn class_of(b: u8) -> Option<FindingClass> {
    Some(match b {
        0 => FindingClass::Signature,
        1 => FindingClass::ScanShape,
        2 => FindingClass::MalformedFrame,
        3 => FindingClass::IdentityReputation,
        4 => FindingClass::IdentitySpoof,
        5 => FindingClass::Behavioral,
        _ => return None,
    })
}

/// Name + severity of a dynamic rule (for the detection list / catalogue fallback).
pub fn lookup(id: u16) -> Option<(&'static str, u32)> {
    if !(ID_MIN..=ID_MAX).contains(&id) {
        return None;
    }
    for t in 0..4 {
        let n = unsafe { DYN_N[t] };
        for r in dyn_rules(t, n) {
            if r.id == id {
                return Some((r.name, r.severity));
            }
        }
    }
    None
}

fn reset() {
    unsafe {
        INSN_N = 0;
        NAME_N = 0;
        DYN_N = [0; 4];
    }
}

/// Parse + verify + arm the rules of an (already signature-checked) pack body. Whole-pack format
/// errors refuse everything; a single rule failing its metadata or verifier checks is skipped.
pub fn load_body(body: &[u8]) -> Result<PackInfo, &'static str> {
    load_body_jit(body, true, true)
}

/// `jit = false`: interpreter only. The JIT allocates code from the never-freeing kernel heap, so a
/// repeated parse (the truncation sweep in the selftest) must not compile — a pack loads once at boot.
fn load_body_jit(body: &[u8], jit: bool, arm: bool) -> Result<PackInfo, &'static str> {
    reset();
    if body.len() < 12 || &body[..8] != b"HQRULES1" {
        return Err("bad magic");
    }
    let n = u16::from_le_bytes([body[8], body[9]]) as usize;
    let mut p = 12usize;
    let mut info = PackInfo::default();
    let mut seen = [0u16; DYN_MAX * 4];
    let mut ns = 0;
    for _ in 0..n {
        let h = body.get(p..p + 8).ok_or("truncated header")?;
        let (id, tier, class, sev, nl, ni) = (u16::from_le_bytes([h[0], h[1]]), h[2], h[3], h[4], h[5] as usize, u16::from_le_bytes([h[6], h[7]]) as usize);
        let name = body.get(p + 8..p + 8 + nl).ok_or("truncated name")?;
        let ib = body.get(p + 8 + nl..p + 8 + nl + ni * 8).ok_or("truncated program")?;
        p += 8 + nl + ni * 8;
        let meta_ok = (ID_MIN..=ID_MAX).contains(&id) && tier < 4 && class_of(class).is_some() && (1..=7).contains(&sev)
            && ni > 0 && ni <= 512 && !seen[..ns].contains(&id) && name.iter().all(|&c| c.is_ascii_graphic() || c == b' ')
            && unsafe { DYN_N[tier as usize] } < DYN_MAX;
        if !meta_ok || unsafe { INSN_N + ni > POOL || NAME_N + nl > NAMES } {
            info.refused_meta += 1;
            continue;
        }
        if ns < seen.len() {
            seen[ns] = id;
            ns += 1;
        }
        let prog: &'static [u64] = unsafe {
            let pool = &mut *core::ptr::addr_of_mut!(INSN);
            for k in 0..ni {
                pool[INSN_N + k] = u64::from_le_bytes(ib[k * 8..k * 8 + 8].try_into().unwrap());
            }
            let s = core::slice::from_raw_parts(pool.as_ptr().add(INSN_N), ni);
            INSN_N += ni;
            s
        };
        if !arm {
            info.loaded += 1; // parse-only (selftest truncation sweep): the verifier also allocates
            continue;
        }
        // the verifier allocates (~4 KiB per rule) from the never-freeing heap: keep the margin
        if crate::heap::remaining() < JIT_HEAP_MARGIN + 8 * 1024 {
            info.refused_heap += 1;
            continue;
        }
        let st = match crate::bpf::verify_prevail(prog) {
            Ok(min_len) => {
                // The JIT allocates from the never-freeing heap and an allocation failure panics: compile
                // only with a safe margin left (64 KiB), else arm the rule on the interpreter (same
                // verdicts, slower) — a big pack must never take the kernel down at boot.
                let room = crate::heap::remaining() > JIT_HEAP_MARGIN + ni * 64;
                let j = if jit && room { arch_aarch64::bpf_jit::compile(prog).unwrap_or(0) } else { 0 };
                if jit && !room {
                    info.interp_only += 1;
                }
                RState { verified: true, min_len, jit: j }
            }
            Err(_) => {
                info.refused_verify += 1;
                continue;
            }
        };
        let nm: &'static str = unsafe {
            let names = &mut *core::ptr::addr_of_mut!(NAME);
            names[NAME_N..NAME_N + nl].copy_from_slice(name);
            let s = core::str::from_utf8(core::slice::from_raw_parts(names.as_ptr().add(NAME_N), nl)).unwrap_or("rule");
            NAME_N += nl;
            s
        };
        unsafe {
            let t = tier as usize;
            let i = DYN_N[t];
            dyn_slot(t, i).write(Rule { id, name: nm, prog, severity: sev as u32, class: class_of(class).unwrap() });
            (*core::ptr::addr_of_mut!(DYN_STATE))[t][i] = st;
            DYN_N[t] += 1;
        }
        info.loaded += 1;
    }
    Ok(info)
}

fn signed_message(gen: u64, len: u64, digest: &[u8; 32]) -> [u8; 54] {
    let mut m = [0u8; 54];
    m[..6].copy_from_slice(b"HQRUL1");
    m[6..14].copy_from_slice(&gen.to_le_bytes());
    m[14..22].copy_from_slice(&len.to_le_bytes());
    m[22..].copy_from_slice(digest);
    m
}

fn check_sig(sig: &[u8], key: &[u8; 32], body: &[u8]) -> Option<(u64, usize)> {
    if sig.len() < 120 || &sig[..8] != b"HQRSIG1\0" {
        return None;
    }
    let gen = u64::from_le_bytes(sig[8..16].try_into().ok()?);
    let len = u64::from_le_bytes(sig[16..24].try_into().ok()?) as usize;
    if len > body.len() {
        return None;
    }
    let d = boot_abi::sha256::digest(&body[..len]);
    if d[..] != sig[24..56] {
        return None;
    }
    let pk = ed25519_compact::PublicKey::from_slice(key).ok()?;
    let s = ed25519_compact::Signature::from_slice(&sig[56..120]).ok()?;
    pk.verify(&signed_message(gen, len as u64, &d)[..], &s).ok()?;
    Some((gen, len))
}

/// Boot: RULES.BIN (≤ 64 KiB) [+ RULES.SIG with an operator key]. Call after `rules::init`.
pub fn load<D: hal::BlockDev>(dev: &D) -> PackInfo {
    reset();
    let mut info = PackInfo::default();
    let mut sec = [0u8; 512];
    let p1 = if dev.read_block(0, &mut sec).is_ok() { crate::store::parse_mbr(&sec)[0].start } else { 0 };
    let Some((lba, nsec)) = (p1 != 0).then(|| crate::fat::locate_contiguous(dev, p1, b"RULES   BIN")).flatten() else {
        unsafe { INFO = info };
        return info;
    };
    static mut BUF: [u8; 65536] = [0; 65536];
    let buf = unsafe { &mut *core::ptr::addr_of_mut!(BUF) };
    let n = ((nsec as usize) * 512).min(buf.len());
    for k in 0..n / 512 {
        if dev.read_block(lba + k as u64, &mut sec).is_err() {
            info.file = 2;
            unsafe { INFO = info };
            return info;
        }
        buf[k * 512..k * 512 + 512].copy_from_slice(&sec);
    }
    let mut body_len = n;
    if let Some(key) = crate::policysig::POLICY_PUBKEY {
        let mut sig = [0u8; 512];
        match crate::fat::locate_contiguous(dev, p1, b"RULES   SIG").and_then(|(l, _)| dev.read_block(l, &mut sig).ok()).and_then(|_| check_sig(&sig, &key, &buf[..n])) {
            Some((g, l)) => {
                info.signed = true;
                info.generation = g;
                body_len = l;
            }
            None => {
                info.file = 2;
                unsafe { INFO = info };
                return info;
            }
        }
    }
    match load_body(&buf[..body_len]) {
        Ok(i) => info = PackInfo { file: 1, signed: info.signed, generation: info.generation, ..i },
        Err(_) => info.file = 2,
    }
    unsafe { INFO = info };
    info
}

/// Run one tier's dynamic rules (after the built-in set found nothing).
pub fn verdict(tier: usize, pkt: &[u8], src: u32, decide_fn: fn(FindingClass, crate::verdict::DecideCtx) -> crate::verdict::Verdict) -> Option<crate::verdict::Verdict> {
    let n = unsafe { DYN_N[tier] };
    if n == 0 {
        return None;
    }
    let rules = dyn_rules(tier, n);
    let st = unsafe { core::ptr::addr_of_mut!(DYN_STATE).cast::<[RState; DYN_MAX]>().add(tier).cast::<RState>() };
    crate::rules::run_set_verdict_pub(rules, st, n, pkt, src, decide_fn)
}

/// `[P-rulepack]`
pub fn selftest() -> bool {
    use crate::bpf::port_block_rule;
    // a pack: (1) dport 6667 IRC as signature, (2) dport 3389 RDP as behavioral (observe),
    // (3) a program that fails the verifier (jump out of range), (4) an id outside the band,
    // (5) a duplicate id
    let mut pk = [0u8; 2048];
    pk[..8].copy_from_slice(b"HQRULES1");
    let mut p = 12;
    let mut n = 0u16;
    let mut add = |pk: &mut [u8; 2048], p: &mut usize, id: u16, tier: u8, class: u8, sev: u8, name: &[u8], prog: &[u64]| {
        pk[*p..*p + 2].copy_from_slice(&id.to_le_bytes());
        pk[*p + 2] = tier;
        pk[*p + 3] = class;
        pk[*p + 4] = sev;
        pk[*p + 5] = name.len() as u8;
        pk[*p + 6..*p + 8].copy_from_slice(&(prog.len() as u16).to_le_bytes());
        pk[*p + 8..*p + 8 + name.len()].copy_from_slice(name);
        let mut q = *p + 8 + name.len();
        for i in prog {
            pk[q..q + 8].copy_from_slice(&i.to_le_bytes());
            q += 8;
        }
        *p = q;
    };
    let irc = port_block_rule(6667);
    let rdp = port_block_rule(3389);
    let bad: [u64; 2] = [0x0000_0000_0063_0005, 0x95]; // ja +99: out of range -> verifier refuses
    // the EXACT words tools/rulepack.py emits for `dport-range 3333-3334` (tool <-> device contract)
    let range: [u64; 10] = [0x21271, 0x800000267, 0x31371, 0x324f, 0xd0600010225, 0xd0500020235, 0x1000000b7, 0x95, 0x2000000b7, 0x95];
    add(&mut pk, &mut p, 1001, 0, 0, 5, b"IRC C2 port 6667", &irc); n += 1;
    add(&mut pk, &mut p, 1004, 0, 5, 5, b"Mining stratum 3333-3334", &range); n += 1;
    add(&mut pk, &mut p, 1002, 0, 5, 3, b"RDP exposure 3389", &rdp); n += 1;
    add(&mut pk, &mut p, 1003, 0, 0, 5, b"broken", &bad); n += 1;
    add(&mut pk, &mut p, 42, 0, 0, 5, b"out of band", &irc); n += 1;
    add(&mut pk, &mut p, 1001, 0, 0, 5, b"duplicate", &irc); n += 1;
    pk[8..10].copy_from_slice(&n.to_le_bytes());
    let r = load_body(&pk[..p]);
    let parsed = r.map_or(false, |i| i.loaded == 3 && i.refused_verify == 1 && i.refused_meta == 2);
    let l4 = |port: u16| { let mut h = [0u8; 8]; h[2..4].copy_from_slice(&port.to_be_bytes()); h };
    let fires = verdict(0, &l4(6667), 0x0A00_0001, crate::verdict::decide).is_some()
        && verdict(0, &l4(3389), 0x0A00_0001, crate::verdict::decide).map_or(false, |v| v.to_wire() == crate::packet::PASS) // behavioral = observe
        && verdict(0, &l4(443), 0x0A00_0001, crate::verdict::decide).is_none()
        && verdict(0, &l4(3333), 1, crate::verdict::decide).is_some() && verdict(0, &l4(3334), 1, crate::verdict::decide).is_some()
        && verdict(0, &l4(3332), 1, crate::verdict::decide).is_none() && verdict(0, &l4(3335), 1, crate::verdict::decide).is_none();
    let names = lookup(1001) == Some(("IRC C2 port 6667", 5)) && lookup(1003).is_none() && lookup(42).is_none();
    let trunc = (0..p).all(|l| load_body_jit(&pk[..l], false, false).map_or(true, |i| i.loaded <= 4));
    let magic = load_body_jit(b"HQRULES0\0\0\0\0", false, false).is_err();
    reset();
    let empty = verdict(0, &l4(6667), 1, crate::verdict::decide).is_none();
    let pass = parsed && fires && names && trunc && magic && empty;
    arch_aarch64::_print(format_args!(
        " [P-rulepack] {} — signed field-updatable rule pack (parity G6): 6-rule pack -> 3 armed (incl. the tool's exact range program), verifier refused 1 (out-of-range jump), metadata refused 2 (id outside 1000..1999, duplicate)={} | armed rules fire through the same decide() (signature rule matches, behavioral rule observe-only PASS, other ports clean)={} names in the catalogue fallback={} every truncation safe={} bad magic refused={} empty pack inert={}\n",
        if pass { "PASS" } else { "FAIL" }, parsed, fires, names, trunc, magic, empty
    ));
    pass
}
