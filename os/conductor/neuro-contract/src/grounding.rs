// SPDX-License-Identifier: AGPL-3.0-only
//! Grounding: guard G and the grounding checks, mirroring Neuro's `tools/neuro-research/guard_ground.py` and
//! `tools/neuro-research/eval/grounding.py` (Neuro's answers to the Conductor, 2026-11-24).
//!
//! - [`guard_g`] is a deterministic output filter that can only DELETE. It removes, from the answer's prose, every
//!   technique-like token that is not a real ATT&CK id, and every CVE id the context does not contain (that is,
//!   one no `lookup_exposure` result supplied), with the brackets or quotes around it. Verdict, evidence,
//!   entities and tool calls are never touched.
//! - [`technique_check`] and [`service_check`] are the checks the verifier applies after G (Neuro's suggested
//!   severities: an invented technique or an unreturned CVE is REJECTED, which can only happen if G did not run;
//!   a service named without its port on the cards is UNVERIFIED, which no filter can fix).
//!
//! The ATT&CK list is [`crate::attack_ids::ATTACK_IDS`], generated from Neuro's `data/attack-ids.json`;
//! `tests/grounding.rs` is its drift gate. The text operations reproduce Python's `re` behaviour on these exact
//! patterns, verified against vectors produced by Neuro's own functions. Known differences, as for the contract:
//! `\d` and `\s` are ASCII here (Python's are Unicode), and upper/lower case is ASCII.
//!
//! `no_std`, no allocation, no unsafe. Edits happen in place: every step only shortens the text.

use crate::attack_ids::ATTACK_IDS;

const STALE: u32 = 1 << 31;

fn is_alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

/// Python's `\s` (and `str.isspace`) restricted to ASCII: space, \t \n \v \f \r and \x1c–\x1f.
pub(crate) fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | 0x1c..=0x1f)
}

fn at(t: &[u8], i: usize) -> Option<u8> {
    t.get(i).copied()
}

fn digits(t: &[u8], i: usize) -> usize {
    t.get(i..).map_or(0, |s| s.iter().take_while(|b| b.is_ascii_digit()).count())
}

fn num(s: &[u8]) -> u32 {
    s.iter().fold(0u32, |a, &d| a.saturating_mul(10).saturating_add(u32::from(d.wrapping_sub(b'0'))))
}

/// ATT&CK lookup: `Some(stale)` if `tok` is exactly a key of `attack-ids.json`. Every key there is `T` + 4 digits,
/// optionally `.` + 3 digits (the drift gate checks this), so only those shapes can match.
pub fn attack_id(tok: &[u8]) -> Option<bool> {
    let key = match tok {
        [b'T', a @ ..] if a.len() == 4 && a.iter().all(u8::is_ascii_digit) => num(a).checked_mul(1000)?,
        [b'T', a @ .., b'.', x, y, z] if a.len() == 4 && a.iter().chain([x, y, z]).all(u8::is_ascii_digit) => {
            let sub = num(&[*x, *y, *z]);
            if sub == 0 {
                return None;
            }
            num(a).checked_mul(1000)?.checked_add(sub)?
        }
        _ => return None,
    };
    let i = ATTACK_IDS.binary_search_by_key(&key, |v| v & !STALE).ok()?;
    ATTACK_IDS.get(i).map(|v| v & STALE != 0)
}

/// `(?<![A-Za-z0-9])T\d{1,5}(?:\.\d{1,3})?(?![A-Za-z0-9])` at `i`: the end of the match, if any.
fn tech_at(t: &[u8], i: usize) -> Option<usize> {
    if at(t, i) != Some(b'T') || i.checked_sub(1).and_then(|p| at(t, p)).is_some_and(is_alnum) {
        return None;
    }
    let ok = |e: usize| !at(t, e).is_some_and(is_alnum);
    let nd = digits(t, i + 1).min(5);
    // Backtracking over the digit count: only the longest run can be followed by '.' or a non-alnum.
    for d in (1..=nd).rev() {
        let p = i + 1 + d;
        if at(t, p) == Some(b'.') {
            let ns = digits(t, p + 1).min(3);
            for s in (1..=ns).rev() {
                if ok(p + 1 + s) {
                    return Some(p + 1 + s);
                }
            }
        }
        if ok(p) {
            return Some(p);
        }
    }
    None
}

/// `CVE-\d{4}-\d{4,7}` (case-insensitive) at `i`.
fn cve_at(t: &[u8], i: usize) -> Option<usize> {
    let head = t.get(i..i + 4)?;
    if !head.eq_ignore_ascii_case(b"CVE-") || digits(t, i + 4) < 4 || at(t, i + 8) != Some(b'-') {
        return None;
    }
    let n = digits(t, i + 9).min(7);
    (n >= 4).then_some(i + 9 + n)
}

/// Non-overlapping, leftmost matches of `m` over `t` (Python's `findall` / `finditer`).
fn each(t: &[u8], m: fn(&[u8], usize) -> Option<usize>, mut f: impl FnMut(usize, usize)) {
    let mut i = 0;
    while i < t.len() {
        match m(t, i) {
            Some(e) => {
                f(i, e);
                i = e.max(i + 1);
            }
            None => i += 1,
        }
    }
}

fn contains_ignore_case(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
}

/// The context the provider was shown, in parts (on the device: the evidence cards, then the earlier tool
/// results). Neuro's checks read `case["context"]`, which holds exactly these.
pub type Context<'a> = &'a [&'a [u8]];

fn ctx_contains(ctx: Context, needle: &[u8]) -> bool {
    ctx.iter().any(|h| contains_ignore_case(h, needle))
}

/// Up to this many distinct removed tokens are tracked per answer; more is refused (see [`GuardG::overflow`]).
pub const MAX_REMOVED: usize = 16;
const TOK_MAX: usize = 24;

/// What guard G did to one prose field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardG {
    /// Distinct tokens removed (unknown technique ids and ungrounded CVE ids).
    pub removed: usize,
    /// More distinct bad tokens than [`MAX_REMOVED`]: the text was left as it was and must be rejected.
    pub overflow: bool,
    /// New length of the text.
    pub len: usize,
}

struct Toks {
    t: [[u8; TOK_MAX]; MAX_REMOVED],
    n: [usize; MAX_REMOVED],
    k: usize,
    overflow: bool,
}

impl Toks {
    fn add(&mut self, s: &[u8]) {
        if s.len() > TOK_MAX {
            self.overflow = true;
            return;
        }
        if (0..self.k).any(|j| self.get(j) == Some(s)) {
            return;
        }
        match (self.t.get_mut(self.k), self.n.get_mut(self.k)) {
            (Some(d), Some(n)) => {
                if let Some(dst) = d.get_mut(..s.len()) {
                    dst.copy_from_slice(s);
                }
                *n = s.len();
                self.k += 1;
            }
            _ => self.overflow = true,
        }
    }
    fn get(&self, j: usize) -> Option<&[u8]> {
        self.t.get(j)?.get(..*self.n.get(j)?)
    }
}

/// One in-place `re.sub(pattern, "")`-style pass: `m(text, i)` returns the end of a match at `i` and the byte to
/// keep in its place (or none). Leftmost, non-overlapping, as Python's `re.sub`.
fn sub(t: &mut [u8], len: usize, m: impl Fn(&[u8], usize) -> Option<(usize, Option<u8>)>) -> usize {
    let (mut r, mut w) = (0, 0);
    while r < len {
        let hit = t.get(..len).and_then(|s| m(s, r));
        match hit {
            Some((e, keep)) if e > r => {
                if let Some(b) = keep {
                    if let Some(x) = t.get_mut(w) {
                        *x = b;
                    }
                    w += 1;
                }
                r = e;
            }
            _ => {
                if let Some(&b) = t.get(r) {
                    if let Some(x) = t.get_mut(w) {
                        *x = b;
                    }
                }
                w += 1;
                r += 1;
            }
        }
    }
    w
}

fn skip_ws(t: &[u8], mut i: usize) -> usize {
    while at(t, i).is_some_and(is_space) {
        i += 1;
    }
    i
}

fn starts(t: &[u8], i: usize, tok: &[u8]) -> bool {
    t.get(i..i + tok.len()) == Some(tok)
}

/// Neuro's `_strip(text, bad)`, in place.
fn strip(t: &mut [u8], mut len: usize, toks: &Toks) -> usize {
    // Longest first, ties in lexicographic order. (Neuro's `sorted(set(bad), key=len, reverse=True)` leaves ties in
    // set order, which changes with PYTHONHASHSEED; the device fixes it, and the same fix is proposed to Neuro.)
    let mut order = [0usize; MAX_REMOVED];
    for (j, o) in order.iter_mut().enumerate().take(toks.k) {
        *o = j;
    }
    let ord = order.get_mut(..toks.k).unwrap_or(&mut []);
    ord.sort_unstable_by(|&a, &b| {
        let (x, y) = (toks.get(a).unwrap_or(&[]), toks.get(b).unwrap_or(&[]));
        y.len().cmp(&x.len()).then(x.cmp(y))
    });
    for &j in ord.iter() {
        let Some(tok) = toks.get(j) else { continue };
        let mut tk = [0u8; TOK_MAX];
        let tl = tok.len();
        if let Some(d) = tk.get_mut(..tl) {
            d.copy_from_slice(tok);
        }
        let tok = tk.get(..tl).unwrap_or(&[]);
        // \s*[\(\[]\s*TOK\s*[\)\]]
        len = sub(t, len, |s, i| {
            let k = skip_ws(s, i);
            if !matches!(at(s, k), Some(b'(' | b'[')) {
                return None;
            }
            let m = skip_ws(s, k + 1);
            if !starts(s, m, tok) {
                return None;
            }
            let n = skip_ws(s, m + tok.len());
            matches!(at(s, n), Some(b')' | b']')).then_some((n + 1, None))
        });
        // (?<![A-Za-z0-9])['"]?TOK['"]?(?![A-Za-z0-9])
        len = sub(t, len, |s, i| {
            if i.checked_sub(1).and_then(|p| at(s, p)).is_some_and(is_alnum) {
                return None;
            }
            let q = |p: usize| matches!(at(s, p), Some(b'\'' | b'"'));
            for q1 in [true, false] {
                if q1 && !q(i) {
                    continue;
                }
                let b = i + usize::from(q1);
                if !starts(s, b, tok) {
                    continue;
                }
                let e = b + tok.len();
                for q2 in [true, false] {
                    if q2 && !q(e) {
                        continue;
                    }
                    let end = e + usize::from(q2);
                    if !at(s, end).is_some_and(is_alnum) {
                        return Some((end, None));
                    }
                }
            }
            None
        });
    }
    // \s+([.,;:]) -> \1
    len = sub(t, len, |s, i| {
        if !at(s, i).is_some_and(is_space) {
            return None;
        }
        let k = skip_ws(s, i);
        match at(s, k) {
            Some(c @ (b'.' | b',' | b';' | b':')) => Some((k + 1, Some(c))),
            _ => None,
        }
    });
    // \(\s*\)|\[\s*\]
    len = sub(t, len, |s, i| {
        let close = match at(s, i)? {
            b'(' => b')',
            b'[' => b']',
            _ => return None,
        };
        let k = skip_ws(s, i + 1);
        (at(s, k) == Some(close)).then_some((k + 1, None))
    });
    // [ \t]{2,} -> " "
    len = sub(t, len, |s, i| {
        let n = s.get(i..).map_or(0, |r| r.iter().take_while(|&&b| b == b' ' || b == b'\t').count());
        (n >= 2).then_some((i + n, Some(b' ')))
    });
    // .strip()
    let body = t.get(..len).unwrap_or(&[]);
    let a = body.iter().take_while(|&&b| is_space(b)).count();
    let z = body.iter().rev().take_while(|&&b| is_space(b)).count();
    let keep = len.saturating_sub(a).saturating_sub(z);
    t.copy_within(a..a + keep, 0);
    keep
}

/// Guard G on one prose field (`text[..len]`, edited in place), against the context the provider was shown.
pub fn guard_g(text: &mut [u8], len: usize, context: Context) -> GuardG {
    let len = len.min(text.len());
    let mut toks = Toks { t: [[0; TOK_MAX]; MAX_REMOVED], n: [0; MAX_REMOVED], k: 0, overflow: false };
    {
        let t = text.get(..len).unwrap_or(&[]);
        // Python order: technique tokens, then CVE tokens.
        each(t, tech_at, |a, b| {
            if let Some(s) = t.get(a..b) {
                if attack_id(s).is_none() {
                    toks.add(s);
                }
            }
        });
        each(t, cve_at, |a, b| {
            if let Some(s) = t.get(a..b) {
                if !ctx_contains(context, s) {
                    toks.add(s);
                }
            }
        });
    }
    if toks.overflow {
        return GuardG { removed: 0, overflow: true, len };
    }
    if toks.k == 0 {
        return GuardG { removed: 0, overflow: false, len };
    }
    let n = strip(text, len, &toks);
    GuardG { removed: toks.k, overflow: false, len: n }
}

/// `grounding.technique_check`, the failing part: how many technique tokens are not real ATT&CK ids, and how many
/// are revoked or deprecated (reported, not failing). Off-category ids are not computed on the device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Techniques {
    pub found: usize,
    pub unknown: usize,
    pub stale: usize,
}

pub fn technique_check(text: &[u8]) -> Techniques {
    let mut r = Techniques::default();
    each(text, tech_at, |a, b| {
        r.found += 1;
        match text.get(a..b).and_then(attack_id) {
            None => r.unknown += 1,
            Some(true) => r.stale += 1,
            Some(false) => {}
        }
    });
    r
}

/// CVE ids in `text` that `context` does not contain (an unreturned CVE).
pub fn ungrounded_cves(text: &[u8], context: Context) -> usize {
    let mut n = 0;
    each(text, cve_at, |a, b| n += usize::from(!text.get(a..b).is_some_and(|s| ctx_contains(context, s))));
    n
}

/// Neuro's `SERVICE` table, in its order.
pub const SERVICES: [(&str, &[u32]); 14] = [
    ("ssh", &[22]),
    ("telnet", &[23, 2323]),
    ("rdp", &[3389]),
    ("ntp", &[123]),
    ("dns", &[53, 853]),
    ("smb", &[445, 139]),
    ("smtp", &[25, 465, 587]),
    ("http", &[80, 8080, 8000]),
    ("https", &[443, 8443]),
    ("mqtt", &[1883, 8883]),
    ("snmp", &[161, 162]),
    ("ftp", &[20, 21]),
    ("ssdp", &[1900]),
    ("upnp", &[1900]),
];

/// `(?<![a-z])NAME(?![a-z])` on ASCII-lowercased text.
fn names(t: &[u8], name: &[u8]) -> bool {
    let low = |b: u8| b.to_ascii_lowercase().is_ascii_lowercase();
    (0..t.len()).any(|i| {
        let pre = i.checked_sub(1).and_then(|p| at(t, p)).is_some_and(low);
        !pre && t.get(i..i + name.len()).is_some_and(|w| w.eq_ignore_ascii_case(name)) && !at(t, i + name.len()).is_some_and(low)
    })
}

/// Whether port `p` is on the cards: Python's `ports_on_cards` membership, over `:((?:\d+,)*\d+)(?:-(\d+))?`
/// (every number of group 1, plus the range from its last number to group 2).
fn port_on_cards(ctx: &[u8], p: u64) -> bool {
    let n = |s: &[u8]| s.iter().fold(0u64, |a, &d| a.saturating_mul(10).saturating_add(u64::from(d.wrapping_sub(b'0'))));
    let mut i = 0;
    while i < ctx.len() {
        if at(ctx, i) != Some(b':') || digits(ctx, i + 1) == 0 {
            i += 1;
            continue;
        }
        // Group 1: a number, then greedily ',' + number; a comma without a number after it ends the group.
        let mut s = i + 1;
        let mut e = s + digits(ctx, s);
        let mut hit = false;
        loop {
            hit |= ctx.get(s..e).is_some_and(|x| n(x) == p);
            if at(ctx, e) == Some(b',') && digits(ctx, e + 1) > 0 {
                s = e + 1;
                e = s + digits(ctx, s);
            } else {
                break;
            }
        }
        if at(ctx, e) == Some(b'-') && digits(ctx, e + 1) > 0 {
            let lo = ctx.get(s..e).map_or(0, n);
            let h_end = e + 1 + digits(ctx, e + 1);
            let hi = ctx.get(e + 1..h_end).map_or(0, n);
            let span = i128::from(hi) - i128::from(lo);
            if span < 70_000 {
                hit |= if span < 2_000 { lo <= p && p <= hi } else { p == lo || p == hi };
            }
            e = h_end;
        }
        if hit {
            return true;
        }
        i = e;
    }
    false
}

/// `grounding.service_check`: how many services the text names whose ports are not on the cards (and whose name
/// the cards do not show either).
pub fn services_without_port(text: &[u8], context: Context) -> usize {
    SERVICES
        .iter()
        .filter(|(s, ports)| {
            let s = s.as_bytes();
            names(text, s)
                && !ports.iter().any(|&p| context.iter().any(|c| port_on_cards(c, u64::from(p))))
                && !context.iter().any(|c| names(c, s))
                && !(s == b"dns" && ctx_contains(context, b" dns "))
        })
        .count()
}
