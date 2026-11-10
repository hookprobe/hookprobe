//! G32: JA4 as a device identity signal. Every TLS ClientHello a LAN device sends is already fingerprinted (`ja4.rs`);
//! here the DISTINCT fingerprints are kept per MAC (up to `PER`), so a phone that rotates its private MAC can be
//! linked to the MAC it had before.
//!
//! Honest limits, built into the rule: a JA4 names a TLS client STACK, not a device — every iPhone on the same iOS
//! shares fingerprints. So the result is a HINT shown to the owner (`likely_same_as`), never an identity merge, and
//! no enforcement keys on it. A hint needs all of:
//!   * the new MAC is private (locally administered — what a rotation produces);
//!   * ≥ 2 fingerprints in common and a Jaccard overlap ≥ 50 % (one shared library is not enough);
//!   * the earlier MAC went quiet before the new one appeared (`GRACE_MS` of overlap at most — two devices active at
//!     the same time are two devices);
//!   * exactly ONE earlier MAC qualifies (two candidates = the fingerprints are generic: no hint).

pub const PER: usize = 8;
const N: usize = 64;
/// A rotating phone may still finish a few old-MAC flows after it joined with the new one.
pub const GRACE_MS: u64 = 60_000;

#[derive(Clone, Copy)]
struct Dev {
    mac: [u8; 6],
    fp: [u64; PER],
    n: u8,
    first_ms: u64,
    last_ms: u64,
}
const D0: Dev = Dev { mac: [0; 6], fp: [0; PER], n: 0, first_ms: 0, last_ms: 0 };
static mut TAB: [Dev; N] = [D0; N];

/// FNV-1a 64 of the 36-byte JA4 string (a set key; the string itself stays in `ja4.rs`'s ring).
pub fn fp_of(ja4: &[u8; 36]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in ja4 {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h | 1 // never 0 (0 = empty slot)
}

fn private(mac: &[u8; 6]) -> bool {
    mac[0] & 0x02 != 0
}

/// (common fingerprints, Jaccard × 100) of two sets.
pub fn overlap(a: &[u64], b: &[u64]) -> (usize, u32) {
    let common = a.iter().filter(|x| b.contains(x)).count();
    let union = a.len() + b.len() - common;
    (common, if union == 0 { 0 } else { (common * 100 / union) as u32 })
}

/// Record that `mac` sent a ClientHello with `ja4` at `now_ms`.
pub fn note(mac: &[u8; 6], ja4: &[u8; 36], now_ms: u64) {
    let now = now_ms.max(1);
    let t = unsafe { &mut *core::ptr::addr_of_mut!(TAB) };
    let i = t.iter().position(|d| d.last_ms != 0 && d.mac == *mac)
        .or_else(|| t.iter().position(|d| d.last_ms == 0))
        .unwrap_or_else(|| (0..N).min_by_key(|&i| t[i].last_ms).unwrap_or(0));
    if t[i].last_ms == 0 || t[i].mac != *mac {
        t[i] = Dev { mac: *mac, first_ms: now, ..D0 };
    }
    let d = &mut t[i];
    d.last_ms = now;
    let f = fp_of(ja4);
    if !d.fp[..d.n as usize].contains(&f) && (d.n as usize) < PER {
        d.fp[d.n as usize] = f;
        d.n += 1;
    }
}

/// Distinct fingerprints seen from `mac`.
pub fn count(mac: &[u8; 6]) -> usize {
    let t = unsafe { &*core::ptr::addr_of!(TAB) };
    t.iter().find(|d| d.last_ms != 0 && d.mac == *mac).map_or(0, |d| d.n as usize)
}

/// The earlier MAC this private MAC most likely rotated from: (mac, common fingerprints, Jaccard × 100).
pub fn likely_same_as(mac: &[u8; 6]) -> Option<([u8; 6], usize, u32)> {
    if !private(mac) {
        return None;
    }
    let t = unsafe { &*core::ptr::addr_of!(TAB) };
    let me = t.iter().find(|d| d.last_ms != 0 && d.mac == *mac)?;
    if me.n < 2 {
        return None;
    }
    let mut best: Option<([u8; 6], usize, u32)> = None;
    let mut qualifying = 0;
    for d in t.iter() {
        if d.last_ms == 0 || d.mac == *mac || d.n < 2 || d.last_ms > me.first_ms.saturating_add(GRACE_MS) {
            continue; // empty, itself, too little evidence, or still active alongside me (a different device)
        }
        let (c, j) = overlap(&me.fp[..me.n as usize], &d.fp[..d.n as usize]);
        if c >= 2 && j >= 50 {
            qualifying += 1;
            best = Some((d.mac, c, j));
        }
    }
    if qualifying == 1 { best } else { None }
}

/// Test hook.
pub fn clear() {
    unsafe { *core::ptr::addr_of_mut!(TAB) = [D0; N] };
}

/// [P-ja4id]
pub fn selftest() -> bool {
    clear();
    let j = |k: u8| {
        let mut s = [b'a'; 36];
        s[35] = b'0' + k;
        s
    };
    let old = [0x10, 1, 1, 1, 1, 1]; // the phone's previous MAC (could be either kind)
    let new = [0x12, 2, 2, 2, 2, 2]; // locally administered (private) — a rotation
    for k in [1, 2, 3] {
        note(&old, &j(k), 1_000);
    }
    for k in [1, 2, 4] {
        note(&new, &j(k), 200_000);
    }
    let rotated = likely_same_as(&new).is_some_and(|(m, c, jac)| m == old && c == 2 && jac == 50);
    // a universally administered MAC never gets a hint; nor does a private MAC with one fingerprint
    let fixed = [0x00, 3, 3, 3, 3, 3];
    for k in [1, 2] {
        note(&fixed, &j(k), 300_000);
    }
    let lone = [0x16, 4, 4, 4, 4, 4];
    note(&lone, &j(1), 300_000);
    let no_hint = likely_same_as(&fixed).is_none() && likely_same_as(&lone).is_none();
    // two devices ACTIVE AT THE SAME TIME with the same OS stack are two devices
    clear();
    let a = [0x12, 5, 5, 5, 5, 5];
    let b = [0x12, 6, 6, 6, 6, 6];
    for k in [1, 2, 3] {
        note(&a, &j(k), 1_000);
        note(&b, &j(k), 1_500);
    }
    note(&a, &j(1), 500_000); // a keeps talking long after b appeared
    let concurrent = likely_same_as(&b).is_none();
    // two quiet earlier MACs both match: the fingerprints are generic -> no hint
    clear();
    let (p, q, r) = ([0x10, 7, 7, 7, 7, 7], [0x10, 8, 8, 8, 8, 8], [0x12, 9, 9, 9, 9, 9]);
    for k in [1, 2, 3] {
        note(&p, &j(k), 1_000);
        note(&q, &j(k), 2_000);
        note(&r, &j(k), 400_000);
    }
    let ambiguous = likely_same_as(&r).is_none();
    // bounded set, duplicate fingerprints counted once
    clear();
    for k in 0..12 {
        note(&a, &j(k % 10), 1_000);
        note(&a, &j(k % 10), 1_000);
    }
    let bounded = count(&a) == PER;
    clear();
    let pass = rotated && no_hint && concurrent && ambiguous && bounded;
    arch_aarch64::_print(format_args!(
        " [P-ja4id] {} — G32 JA4 as an identity HINT: a private MAC that appears after an earlier MAC went quiet, sharing >= 2 fingerprints at >= 50 % Jaccard, is linked (likely_same_as)={} | no hint for a universal MAC or a single fingerprint={} | two devices active at once with the same stack stay two devices={} | two equally good candidates = generic fingerprints, no hint={} | per-MAC set bounded at {}, duplicates once={}\n",
        if pass { "PASS" } else { "FAIL" }, rotated, no_hint, concurrent, ambiguous, PER, bounded
    ));
    pass
}
