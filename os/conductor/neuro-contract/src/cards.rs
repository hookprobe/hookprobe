// SPDX-License-Identifier: AGPL-3.0-only
//! Evidence cards: the text a window of flows and detections becomes before a model sees it.
//!
//! Upstream truth is Neuro's `tools/neuro-research/semantic_compression.py` (`rep_cards`, `fill`, `Interner`,
//! `kind_of`, `Tok.count` in its estimate mode) and the rule of `e2e_neuro.py` that a context always ends with
//! the `REST` line. [`build_context`] gives the same bytes for the same window. `tests/cards.rs` checks it
//! against vectors made by Neuro's own functions and reads the constants back from Neuro's sources.
//!
//! What is mirrored: flow events and detection events. Neuro's builder also takes DNS and behaviour events;
//! this function has no input for them, so a window that needs them cannot be built here yet.
//!
//! How the arithmetic differs. Python computes with floats; this module has none. Every comparison and every
//! printed number is computed exactly from integers (milliseconds, bytes, counts), which gives Python's result
//! except where Python's own float rounding decides the outcome:
//! - a coefficient of variation of exactly 0.1, or exactly on a `%.2f` rounding boundary (Python's gaps are
//!   differences of floats and carry their error);
//! - a budget met exactly by the estimate in `fill` (Python sums floats);
//! - two cards whose scores are equal as fractions but are reached by different float additions (possible only
//!   with a severity-5 detection, weight 0.2).
//!   Two float results are reproduced exactly, because real traffic meets them: the mean gap (a device polling
//!   every 5.000 s has a float mean just under 5 and is not periodic for Python), computed here as the double
//!   Python holds, bit for bit, in integers; and the `out=…GB` figure, where a half-way value is rounded the way
//!   the nearest double falls.
//!
//! Memory is the caller's: the flows are sorted in place, and [`Scratch`] holds the cards, fan-outs and aliases.
//! A window that does not fit is an error ([`ContractError::Space`]), never a shortened context.
//!
//! Two behaviours of the Python are kept because the model was measured with them:
//! - the port a detection is matched on, for a pair with two or three ports, is the first element of a Python
//!   `set` of those ports (CPython's small-table order), reproduced by [`first_of_set`];
//! - when exactly one card is dropped, `e2e_neuro.py` appends a second `REST` line after `fill`'s own.

use crate::{ContractError, Sink};

/// Neuro's budget for a context, in its estimated tokens (bytes / 4).
pub const BUDGET: u32 = 512;
/// Destination hosts on one source and port from which a fan-out card is written.
pub const FANOUT_HOSTS: u32 = 50;
/// Destination ports on one pair from which `fanout_ports` is flagged.
pub const FANOUT_PORTS: u32 = 50;
/// Flows from which a pair is tested for periodicity, and the smallest mean gap (seconds) that counts.
pub const PERIODIC_MIN_FLOWS: u32 = 8;
pub const PERIODIC_MIN_GAP_S: u32 = 5;
/// Bytes sent from which `out=` is flagged.
pub const OUT_MIN_BYTES: u64 = 100_000_000;
/// A pair with no flag, no detection and fewer flows than this is not a card.
pub const ORDINARY_MAX_FLOWS: u32 = 30;
/// Lines `Tok.ratio` samples.
pub const RATIO_SAMPLE_LINES: usize = 600;
/// The longest line this module writes; inputs that would exceed it are refused.
pub const LINE_MAX: usize = 512;
/// Detections per window (a bit mask tracks which a card has claimed).
pub const MAX_DETECTIONS: usize = 64;

const SCALE: u32 = 1000;

/// `SEV_WEIGHT`, times 1000.
fn sev_weight(sev: u32) -> u32 {
    match sev {
        1 => 8000,
        2 => 6000,
        3 => 3000,
        4 => 1000,
        5 => 200,
        _ => 1000,
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Flow<'a> {
    /// Time of day in milliseconds (`ts[11:23]` of the event).
    pub t_ms: u32,
    pub src: &'a str,
    pub dst: &'a str,
    pub port: u32,
    pub bytes_out: u64,
    /// The compressor's state is `rst` (no reply and reset both count).
    pub rst: bool,
    seq: u32,
    grp: u32,
}

impl<'a> Flow<'a> {
    pub const fn new(t_ms: u32, src: &'a str, dst: &'a str, port: u32, bytes_out: u64, rst: bool) -> Self {
        Self { t_ms, src, dst, port, bytes_out, rst, seq: 0, grp: 0 }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Detection<'a> {
    pub id: &'a str,
    pub src: &'a str,
    /// Empty when the detection names no destination.
    pub dst: &'a str,
    pub port: u32,
    pub category: &'a str,
    /// Empty when there is none (written `-`).
    pub mitre: &'a str,
    pub severity: u32,
    pub rule_msg: &'a str,
}

/// One ranked card, before it is written.
#[derive(Clone, Copy, Debug)]
pub struct Card {
    score: u32,
    /// 0 fan-out, 1 pair, 2 a detection no card claimed; with `k1`, `k2` this is Python's insertion order.
    phase: u8,
    k1: u32,
    k2: u32,
    /// Fan-out: index into the fan-outs. Pair: index of one of its flows. Detection: its index.
    at: u32,
    n: u32,
    nports: u32,
    ports: [u32; 3],
    flags: u8,
    period_s: u32,
    cv: u8,
    out_tenths: u64,
    rst_pct: u8,
    novel: bool,
    /// Index + 1 of the detection in the card's note; 0 for none.
    det: u8,
    len: u32,
}

impl Card {
    pub const EMPTY: Self =
        Self { score: 0, phase: 0, k1: 0, k2: 0, at: 0, n: 0, nports: 0, ports: [0; 3], flags: 0, period_s: 0, cv: 0, out_tenths: 0, rst_pct: 0, novel: false, det: 0, len: 0 };
}

const F_PORTS: u8 = 1;
const F_PERIODIC: u8 = 2;
const F_OUT: u8 = 4;
const F_RST: u8 = 8;

#[derive(Clone, Copy, Debug)]
pub struct Fan<'a> {
    src: &'a str,
    port: u32,
    n: u32,
    hosts: u32,
    fails: u32,
    k1: u32,
    k2: u32,
}

impl Fan<'_> {
    pub const EMPTY: Self = Self { src: "", port: 0, n: 0, hosts: 0, fails: 0, k1: 0, k2: 0 };
}

#[derive(Clone, Copy, Debug)]
pub struct Alias<'a> {
    ent: &'a str,
    num: u32,
}

impl Alias<'_> {
    pub const EMPTY: Self = Self { ent: "", num: 0 };
}

/// Working memory. `cards` bounds the cards of a window, `fans` its fan-outs, `aliases` its distinct entities.
pub struct Scratch<'s, 'a> {
    pub cards: &'s mut [Card],
    pub fans: &'s mut [Fan<'a>],
    pub aliases: &'s mut [Alias<'a>],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Built {
    /// Cards the window has, and how many of them are in the context.
    pub cards: u32,
    pub kept: u32,
    /// Ordinary pairs counted in the `REST` line.
    pub ordinary_pairs: u32,
}

/// `kind_of`: `H` for an RFC 1918 address, by its text.
pub fn is_site(ip: &str) -> bool {
    if ip.starts_with("10.") || ip.starts_with("192.168.") {
        return true;
    }
    let Some(rest) = ip.strip_prefix("172.") else { return false };
    let b = rest.as_bytes();
    matches!(
        (b.first(), b.get(1), b.get(2)),
        (Some(b'1'), Some(b'6'..=b'9'), Some(b'.')) | (Some(b'2'), Some(b'0'..=b'9'), Some(b'.')) | (Some(b'3'), Some(b'0' | b'1'), Some(b'.'))
    )
}

/// The first element CPython yields from a `set` of at most three small non-negative integers inserted in
/// this order (an 8-slot table; slot `h & 7`, then `i = (5 i + 1 + perturb) & 7` with `perturb >>= 5`).
pub fn first_of_set(ports: &[u32]) -> Option<u32> {
    let mut table: [Option<u32>; 8] = [None; 8];
    for &h in ports {
        let mut i = (h & 7) as usize;
        let mut perturb = h;
        for _ in 0..64 {
            match table.get(i).copied().flatten() {
                None => {
                    if let Some(slot) = table.get_mut(i) {
                        *slot = Some(h);
                    }
                    break;
                }
                Some(x) if x == h => break,
                Some(_) => {
                    perturb >>= 5;
                    i = (i.wrapping_mul(5).wrapping_add(1).wrapping_add(perturb as usize)) & 7;
                }
            }
        }
    }
    table.iter().flatten().next().copied()
}

/// `"%.1f" % (bytes / 1e9)` as tenths of a gigabyte. A half-way value goes the way the double nearest to it
/// lies, as Python's float does; one that a double holds exactly rounds half to even.
fn gb_tenths(bytes: u64) -> u64 {
    const UNIT: u64 = 100_000_000;
    let (base, rem) = (bytes / UNIT, bytes % UNIT);
    match (rem.saturating_mul(2)).cmp(&UNIT) {
        core::cmp::Ordering::Less => base,
        core::cmp::Ordering::Greater => base.saturating_add(1),
        core::cmp::Ordering::Equal => {
            // The value is p / 20 with p odd.
            let p = u128::from(base).saturating_mul(2).saturating_add(1);
            let up = if p.is_multiple_of(5) {
                base % 2 == 1
            } else {
                let mut e = 0u32;
                while e < 80 && (p << e) / 20 < (1u128 << 52) {
                    e = e.saturating_add(1);
                }
                let num = p << e;
                let (mut m, r) = (num / 20, num % 20);
                if r > 10 || (r == 10 && m % 2 == 1) {
                    m = m.saturating_add(1);
                }
                m.saturating_mul(20) > num
            };
            if up {
                base.saturating_add(1)
            } else {
                base
            }
        }
    }
}

/// Scale of the exact values below: units of 2^-70 seconds.
const FRAC: u32 = 70;

/// Round a non-negative value (in 2^-70 units, `sticky` when bits were lost below it) to 53 significant bits,
/// half to even: the double Python holds.
fn round53(q: u128, sticky: bool) -> u128 {
    let bits = 128u32.saturating_sub(q.leading_zeros());
    if bits <= 53 {
        return q;
    }
    let shift = bits.saturating_sub(53);
    let half = 1u128 << shift.saturating_sub(1);
    let low = q & ((1u128 << shift).saturating_sub(1));
    let floor = q >> shift;
    let up = low > half || (low == half && (sticky || floor & 1 == 1));
    floor.saturating_add(u128::from(up)) << shift
}

/// `t_of`: `int(hh) * 3600 + int(mm) * 60 + float("SS.mmm")` as the double Python computes, for a time of day
/// in milliseconds.
fn t_double(t_ms: u32) -> u128 {
    let (whole, part) = (u128::from(t_ms / 60_000) * 60, u128::from(t_ms % 60_000));
    let num = part << FRAC;
    let secs = round53(num / 1000, !num.is_multiple_of(1000));
    round53((whole << FRAC).saturating_add(secs), false)
}

fn printable(s: &str, max: usize) -> Result<(), ContractError> {
    if s.len() > max || !s.bytes().all(|b| (0x20..0x7f).contains(&b)) {
        return Err(ContractError::Invalid);
    }
    Ok(())
}

/// One line being written.
struct Line {
    buf: [u8; LINE_MAX],
    n: usize,
}

impl Line {
    fn new() -> Self {
        Self { buf: [0; LINE_MAX], n: 0 }
    }
    fn put(&mut self, s: &[u8]) -> Result<(), ContractError> {
        let end = self.n.checked_add(s.len()).ok_or(ContractError::Space)?;
        self.buf.get_mut(self.n..end).ok_or(ContractError::Space)?.copy_from_slice(s);
        self.n = end;
        Ok(())
    }
    fn s(&mut self, s: &str) -> Result<(), ContractError> {
        self.put(s.as_bytes())
    }
    fn dec(&mut self, mut v: u64) -> Result<(), ContractError> {
        let mut d = [0u8; 20];
        let mut i = d.len();
        loop {
            i = i.saturating_sub(1);
            if let Some(slot) = d.get_mut(i) {
                *slot = b'0'.saturating_add(u8::try_from(v % 10).unwrap_or(0));
            }
            v /= 10;
            if v == 0 || i == 0 {
                break;
            }
        }
        self.put(d.get(i..).unwrap_or(&[]))
    }
    fn bytes(&self) -> &[u8] {
        self.buf.get(..self.n).unwrap_or(&[])
    }
}

/// `Interner.materialize`: an entity is written `H1=<entity>` the first time and `H1` after that.
struct Aliases<'s, 'a> {
    tab: &'s mut [Alias<'a>],
    n: usize,
    hosts: u32,
    remotes: u32,
    /// Write the entity itself and keep no table (for text that is only scanned).
    plain: bool,
}

impl<'a> Aliases<'_, 'a> {
    fn write(&mut self, ent: &'a str, l: &mut Line) -> Result<(), ContractError> {
        if ent.is_empty() {
            return l.s("-");
        }
        if self.plain {
            return l.s(ent);
        }
        let host = is_site(ent);
        let known = self.tab.get(..self.n).unwrap_or(&[]).iter().find(|a| a.ent == ent).map(|a| a.num);
        l.s(if host { "H" } else { "R" })?;
        match known {
            Some(num) => l.dec(u64::from(num)),
            None => {
                let c = if host { &mut self.hosts } else { &mut self.remotes };
                *c = c.saturating_add(1);
                let num = *c;
                *self.tab.get_mut(self.n).ok_or(ContractError::Space)? = Alias { ent, num };
                self.n = self.n.saturating_add(1);
                l.dec(u64::from(num))?;
                l.s("=")?;
                l.s(ent)
            }
        }
    }
}

/// ` det=<category>[<mitre or ->,sev<n>,<text after the rule's last "(", without closing brackets>]`.
fn det_note(d: &Detection, l: &mut Line) -> Result<(), ContractError> {
    l.s("det=")?;
    l.s(d.category)?;
    l.s("[")?;
    l.s(if d.mitre.is_empty() { "-" } else { d.mitre })?;
    l.s(",sev")?;
    l.dec(u64::from(d.severity))?;
    l.s(",")?;
    let tail = d.rule_msg.rsplit('(').next().unwrap_or("");
    l.s(tail.trim_end_matches(')'))?;
    l.s("]")
}

fn write_line<'a>(i: usize, c: &Card, flows: &[Flow<'a>], dets: &[Detection<'a>], fans: &[Fan<'a>], al: &mut Aliases<'_, 'a>, l: &mut Line) -> Result<(), ContractError> {
    l.n = 0;
    l.s("F")?;
    l.dec(u64::try_from(i).unwrap_or(u64::MAX).saturating_add(1))?;
    l.s(" ")?;
    let det = usize::from(c.det).checked_sub(1).and_then(|k| dets.get(k));
    match c.phase {
        0 => {
            let f = fans.get(c.at as usize).ok_or(ContractError::Invalid)?;
            al.write(f.src, l)?;
            l.s("->*:")?;
            l.dec(u64::from(f.port))?;
            l.s(" n=")?;
            l.dec(u64::from(f.n))?;
            l.s(" fanout_hosts=")?;
            l.dec(u64::from(f.hosts))?;
            l.s(" fail=")?;
            l.dec(u64::from(f.fails).saturating_mul(100) / u64::from(f.n.max(1)))?;
            l.s("%")?;
            if let Some(d) = det {
                l.s(" ")?;
                det_note(d, l)?;
            }
        }
        1 => {
            let f = flows.get(c.at as usize).ok_or(ContractError::Invalid)?;
            al.write(f.src, l)?;
            l.s("->")?;
            al.write(f.dst, l)?;
            l.s(":")?;
            if c.nports > 3 {
                l.dec(u64::from(c.nports))?;
                l.s(" ports")?;
            } else {
                let mut p = c.ports;
                let p = p.get_mut(..c.nports as usize).ok_or(ContractError::Invalid)?;
                p.sort_unstable();
                for (k, x) in p.iter().enumerate() {
                    if k > 0 {
                        l.s(",")?;
                    }
                    l.dec(u64::from(*x))?;
                }
            }
            l.s(" n=")?;
            l.dec(u64::from(c.n))?;
            l.s(" ")?;
            let mut first = true;
            let mut sep = |l: &mut Line| -> Result<(), ContractError> {
                if !first {
                    l.s(" ")?;
                }
                first = false;
                Ok(())
            };
            if c.flags & F_PORTS != 0 {
                sep(l)?;
                l.s("fanout_ports=")?;
                l.dec(u64::from(c.nports))?;
            }
            if c.flags & F_PERIODIC != 0 {
                sep(l)?;
                l.s("periodic=")?;
                l.dec(u64::from(c.period_s))?;
                l.s("s cv=0.")?;
                l.dec(u64::from(c.cv / 10))?;
                l.dec(u64::from(c.cv % 10))?;
            }
            if c.flags & F_OUT != 0 {
                sep(l)?;
                l.s("out=")?;
                l.dec(c.out_tenths / 10)?;
                l.s(".")?;
                l.dec(c.out_tenths % 10)?;
                l.s("GB")?;
            }
            if c.flags & F_RST != 0 {
                sep(l)?;
                l.s("rst=")?;
                l.dec(u64::from(c.rst_pct))?;
                l.s("%")?;
            }
            if c.novel {
                l.s(" novel")?;
            }
            if let Some(d) = det {
                l.s(" ")?;
                det_note(d, l)?;
            }
        }
        _ => {
            let d = dets.get(c.at as usize).ok_or(ContractError::Invalid)?;
            al.write(d.src, l)?;
            l.s("->")?;
            al.write(d.dst, l)?;
            l.s(":")?;
            l.dec(u64::from(d.port))?;
            l.s(" ")?;
            det_note(d, l)?;
        }
    }
    Ok(())
}

const CATS: usize = 16;
const CAT_MAX: usize = 48;

/// `collections.Counter` over `re.findall(r"det=(\w+)", line)` of the dropped lines.
struct Cats {
    names: [[u8; CAT_MAX]; CATS],
    lens: [u8; CATS],
    counts: [u32; CATS],
    n: usize,
}

impl Cats {
    fn new() -> Self {
        Self { names: [[0; CAT_MAX]; CATS], lens: [0; CATS], counts: [0; CATS], n: 0 }
    }
    fn name(&self, i: usize) -> &[u8] {
        let l = usize::from(self.lens.get(i).copied().unwrap_or(0));
        self.names.get(i).and_then(|n| n.get(..l)).unwrap_or(&[])
    }
    fn add(&mut self, w: &[u8]) -> Result<(), ContractError> {
        for i in 0..self.n {
            if self.name(i) == w {
                if let Some(c) = self.counts.get_mut(i) {
                    *c = c.saturating_add(1);
                }
                return Ok(());
            }
        }
        let i = self.n;
        self.names.get_mut(i).and_then(|n| n.get_mut(..w.len())).ok_or(ContractError::Space)?.copy_from_slice(w);
        *self.lens.get_mut(i).ok_or(ContractError::Space)? = u8::try_from(w.len()).map_err(|_| ContractError::Space)?;
        *self.counts.get_mut(i).ok_or(ContractError::Space)? = 1;
        self.n = i.saturating_add(1);
        Ok(())
    }
    fn scan(&mut self, text: &[u8]) -> Result<(), ContractError> {
        let mut i = 0usize;
        while let Some(rest) = text.get(i..) {
            let Some(at) = rest.windows(4).position(|w| w == b"det=") else { break };
            let start = i.saturating_add(at).saturating_add(4);
            let word = text.get(start..).unwrap_or(&[]);
            let len = word.iter().take_while(|b| b.is_ascii_alphanumeric() || **b == b'_').count();
            if len > 0 {
                self.add(word.get(..len).unwrap_or(&[]))?;
            }
            i = start.saturating_add(len);
        }
        Ok(())
    }
}

/// The `REST` line for `dropped` omitted cards whose detections are in `cats`.
fn rest_line(dropped: usize, cats: &Cats, ordinary_pairs: u32, l: &mut Line) -> Result<(), ContractError> {
    l.n = 0;
    l.s("REST ")?;
    l.dec(u64::try_from(dropped).unwrap_or(u64::MAX))?;
    l.s(" more cards omitted")?;
    if cats.n == 0 {
        l.s("; omitted cards carry no detections")?;
    } else {
        l.s("; omitted cards carry detections: ")?;
        // `most_common`: by count, first seen first among equals.
        let mut done = [false; CATS];
        for k in 0..cats.n {
            let mut best: Option<usize> = None;
            for i in 0..cats.n {
                let (ci, taken) = (cats.counts.get(i).copied().unwrap_or(0), done.get(i).copied().unwrap_or(true));
                if !taken && best.is_none_or(|b| ci > cats.counts.get(b).copied().unwrap_or(0)) {
                    best = Some(i);
                }
            }
            let Some(b) = best else { break };
            if let Some(d) = done.get_mut(b) {
                *d = true;
            }
            if k > 0 {
                l.s(", ")?;
            }
            l.put(cats.name(b))?;
            l.s(" x")?;
            l.dec(u64::from(cats.counts.get(b).copied().unwrap_or(0)))?;
        }
    }
    l.s("; plus ")?;
    l.dec(u64::from(ordinary_pairs))?;
    l.s(" ordinary flow pairs and 0 ordinary dns groups with no detections")
}

/// `Tok.count` in estimate mode: 0 for no text, else at least 1.
fn tokens(bytes: usize) -> u64 {
    if bytes == 0 {
        0
    } else {
        u64::try_from(bytes / 4).unwrap_or(u64::MAX).max(1)
    }
}

/// The first detection of lowest severity among those `pick` accepts, and a mask of all it accepts.
fn best_hit(dets: &[Detection], pick: impl Fn(&Detection) -> bool) -> (Option<usize>, u64) {
    let (mut best, mut mask) = (None::<usize>, 0u64);
    for (i, d) in dets.iter().enumerate() {
        if pick(d) {
            mask |= 1u64.checked_shl(u32::try_from(i).unwrap_or(64)).unwrap_or(0);
            if best.and_then(|b| dets.get(b)).is_none_or(|b| d.severity < b.severity) {
                best = Some(i);
            }
        }
    }
    (best, mask)
}

/// Mark every detection sharing an id with one in `mask` (`used_dets` holds ids).
fn mark_ids(dets: &[Detection], mask: u64, used: &mut u64) {
    for (i, d) in dets.iter().enumerate() {
        if mask >> i & 1 == 1 {
            for (j, e) in dets.iter().enumerate() {
                if e.id == d.id {
                    *used |= 1u64.checked_shl(u32::try_from(j).unwrap_or(64)).unwrap_or(0);
                }
            }
        }
    }
}

fn push_card(cards: &mut [Card], n: &mut usize, c: Card) -> Result<(), ContractError> {
    *cards.get_mut(*n).ok_or(ContractError::Space)? = c;
    *n = n.saturating_add(1);
    Ok(())
}

fn emit(out: &mut (impl Sink + ?Sized), wrote: &mut bool, line: &[u8]) -> Result<(), ContractError> {
    if *wrote {
        out.put(b"\n")?;
    }
    *wrote = true;
    out.put(line)
}

fn det_ref(i: Option<usize>) -> u8 {
    i.and_then(|i| u8::try_from(i.saturating_add(1)).ok()).unwrap_or(0)
}

/// Build the context of one window: ranked cards within `budget`, then the `REST` line, joined by newlines.
/// `flows` is reordered. `baseline` holds the (source, destination) pairs the device has seen before.
pub fn build_context<'a>(
    flows: &mut [Flow<'a>],
    dets: &[Detection<'a>],
    baseline: &[(&str, &str)],
    budget: u32,
    scratch: &mut Scratch<'_, 'a>,
    out: &mut (impl Sink + ?Sized),
) -> Result<Built, ContractError> {
    if dets.len() > MAX_DETECTIONS || u32::try_from(flows.len()).is_err() {
        return Err(ContractError::Space);
    }
    for f in flows.iter() {
        printable(f.src, 45)?;
        printable(f.dst, 45)?;
        if f.src.is_empty() || f.dst.is_empty() || f.bytes_out >= 1 << 53 {
            return Err(ContractError::Invalid);
        }
    }
    for d in dets {
        printable(d.id, 48)?;
        printable(d.src, 45)?;
        printable(d.dst, 45)?;
        printable(d.category, CAT_MAX)?;
        printable(d.mitre, 24)?;
        printable(d.rule_msg, 200)?;
    }

    // Python's dictionaries keep insertion order. `seq` is a flow's place among the events, `grp` the place of
    // the first flow of its pair: a pair's cards come in `grp` order.
    for (i, f) in flows.iter_mut().enumerate() {
        f.seq = u32::try_from(i).unwrap_or(u32::MAX);
    }
    flows.sort_unstable_by(|a, b| (a.src, a.dst, a.seq).cmp(&(b.src, b.dst, b.seq)));
    let mut first = 0u32;
    let mut prev: Option<(&str, &str)> = None;
    for f in flows.iter_mut() {
        if prev != Some((f.src, f.dst)) {
            first = f.seq;
            prev = Some((f.src, f.dst));
        }
        f.grp = first;
    }

    // Fan-outs: one source and port reaching many hosts. `by_sport` is filled pair by pair, flow by flow, so a
    // fan-out's place is that of its first flow in that order.
    flows.sort_unstable_by(|a, b| (a.src, a.port, a.dst).cmp(&(b.src, b.port, b.dst)));
    let mut n_fans = 0usize;
    {
        let mut i = 0usize;
        while let Some(head) = flows.get(i).copied() {
            let (mut j, mut hosts, mut fails) = (i, 0u32, 0u32);
            let (mut k, mut last_dst) = ((u32::MAX, u32::MAX), None::<&str>);
            while let Some(f) = flows.get(j).filter(|f| f.src == head.src && f.port == head.port) {
                if last_dst != Some(f.dst) {
                    hosts = hosts.saturating_add(1);
                    last_dst = Some(f.dst);
                }
                fails = fails.saturating_add(u32::from(f.rst));
                k = k.min((f.grp, f.seq));
                j = j.saturating_add(1);
            }
            if hosts >= FANOUT_HOSTS {
                let n = u32::try_from(j.saturating_sub(i)).unwrap_or(u32::MAX);
                *scratch.fans.get_mut(n_fans).ok_or(ContractError::Space)? = Fan { src: head.src, port: head.port, n, hosts, fails, k1: k.0, k2: k.1 };
                n_fans = n_fans.saturating_add(1);
            }
            i = j;
        }
    }
    let fans = scratch.fans.get_mut(..n_fans).ok_or(ContractError::Space)?;
    fans.sort_unstable_by_key(|f| (f.k1, f.k2));
    let fans: &[Fan<'a>] = fans;

    let cards = &mut *scratch.cards;
    let mut n_cards = 0usize;
    let mut used = 0u64;
    for (fi, f) in fans.iter().enumerate() {
        let (best, mask) = best_hit(dets, |d| d.src == f.src && (d.port == 0 || d.port == f.port));
        mark_ids(dets, mask, &mut used);
        let dw = best.and_then(|b| dets.get(b)).map_or(0, |d| sev_weight(d.severity));
        // 4.0 + dw + min(3.0, hosts / 500.0)
        let score = (4 * SCALE).saturating_add(dw).saturating_add(f.hosts.saturating_mul(2).min(3 * SCALE));
        push_card(cards, &mut n_cards, Card { score, phase: 0, k1: f.k1, k2: f.k2, at: u32::try_from(fi).unwrap_or(u32::MAX), det: det_ref(best), ..Card::EMPTY })?;
    }

    // Pairs, each in time order.
    flows.sort_unstable_by(|a, b| (a.src, a.dst, a.t_ms, a.port).cmp(&(b.src, b.dst, b.t_ms, b.port)));
    let mut ordinary = 0u32;
    let mut i = 0usize;
    while let Some(head) = flows.get(i).copied() {
        let mut j = i;
        let mut all_fanned = true;
        let (mut out_b, mut rst, mut sum_sq) = (0u64, 0u32, 0u128);
        // Python's gaps are differences of doubles; their exact sum decides the mean it compares and prints.
        let (mut last_d, mut gap_sum) = (t_double(head.t_ms), 0u128);
        let (mut seen, mut n_seen) = ([0u32; 4], 0usize);
        let mut last_t = head.t_ms;
        while let Some(f) = flows.get(j).filter(|f| f.src == head.src && f.dst == head.dst) {
            all_fanned &= fans.iter().any(|x| x.src == f.src && x.port == f.port);
            out_b = out_b.saturating_add(f.bytes_out);
            rst = rst.saturating_add(u32::from(f.rst));
            let g = u128::from(f.t_ms.saturating_sub(last_t));
            sum_sq = sum_sq.saturating_add(g.saturating_mul(g));
            last_t = f.t_ms;
            let td = t_double(f.t_ms);
            gap_sum = gap_sum.saturating_add(round53(td.saturating_sub(last_d), false));
            last_d = td;
            if n_seen < 4 && !seen.get(..n_seen).unwrap_or(&[]).contains(&f.port) {
                if let Some(s) = seen.get_mut(n_seen) {
                    *s = f.port;
                }
                n_seen = n_seen.saturating_add(1);
            }
            j = j.saturating_add(1);
        }
        let n = u32::try_from(j.saturating_sub(i)).unwrap_or(u32::MAX);
        let (at, span) = (u32::try_from(i).unwrap_or(u32::MAX), u128::from(last_t.saturating_sub(head.t_ms)));
        let range = i..j;
        i = j;
        if all_fanned {
            ordinary = ordinary.saturating_add(1);
            continue;
        }
        // More than three ports: only their number matters. The time statistics are already taken.
        let nports = if n_seen <= 3 {
            u32::try_from(n_seen).unwrap_or(0)
        } else {
            let g = flows.get_mut(range).ok_or(ContractError::Invalid)?;
            g.sort_unstable_by_key(|f| f.port);
            let (mut c, mut last) = (0u32, None::<u32>);
            for f in g.iter() {
                if last != Some(f.port) {
                    c = c.saturating_add(1);
                    last = Some(f.port);
                }
            }
            c
        };
        let mut c = Card { phase: 1, k1: head.grp, at, n, nports, ..Card::EMPTY };
        let mut w = 0u32;
        if nports >= FANOUT_PORTS {
            c.flags |= F_PORTS;
            w = w.saturating_add(4 * SCALE);
        }
        if n >= PERIODIC_MIN_FLOWS {
            // The mean gap as Python's double: >= 5 s, and printed with round(), half to even.
            let m = u128::from(n.saturating_sub(1));
            let mu = round53(gap_sum / m.max(1), !gap_sum.is_multiple_of(m.max(1)));
            // cv = pstdev / mean < 0.1, from the gaps in ms: m of them, sum `span`, sum of squares `sum_sq`.
            let d = m.saturating_mul(sum_sq).saturating_sub(span.saturating_mul(span));
            let s2 = span.saturating_mul(span);
            if mu >= u128::from(PERIODIC_MIN_GAP_S) << FRAC && d.saturating_mul(100) < s2 {
                c.flags |= F_PERIODIC;
                w = w.saturating_add(3 * SCALE);
                let (q, r, half) = (mu >> FRAC, mu & ((1u128 << FRAC) - 1), 1u128 << (FRAC - 1));
                let up = r > half || (r == half && q % 2 == 1);
                c.period_s = u32::try_from(q.saturating_add(u128::from(up))).unwrap_or(u32::MAX);
                // "%.2f" % cv: the hundredth k with (k - 0.5)^2 <= 10^4 cv^2 < (k + 0.5)^2
                let mut k = 0u8;
                while k < 10 && d.saturating_mul(40_000) >= s2.saturating_mul(u128::from((2 * u32::from(k) + 1).pow(2))) {
                    k = k.saturating_add(1);
                }
                c.cv = k;
            }
        }
        if out_b >= OUT_MIN_BYTES {
            c.flags |= F_OUT;
            c.out_tenths = gb_tenths(out_b);
            w = w.saturating_add(4 * SCALE);
        }
        if rst.saturating_mul(2) > n && n > 20 {
            c.flags |= F_RST;
            c.rst_pct = u8::try_from(u64::from(rst).saturating_mul(100) / u64::from(n.max(1))).unwrap_or(100);
        }
        c.novel = !baseline.iter().any(|(s, d)| *s == head.src && *d == head.dst);
        if nports <= 3 {
            c.ports = [seen.first().copied().unwrap_or(0), seen.get(1).copied().unwrap_or(0), seen.get(2).copied().unwrap_or(0)];
        }
        let port = if nports > 3 { None } else { first_of_set(seen.get(..n_seen).unwrap_or(&[])) };
        let (best, mask) = best_hit(dets, |d| d.src == head.src && d.dst == head.dst && port.is_none_or(|p| d.port == 0 || d.port == p || d.port == 53));
        mark_ids(dets, mask, &mut used);
        c.det = det_ref(best);
        w = w.saturating_add(best.and_then(|b| dets.get(b)).map_or(0, |d| sev_weight(d.severity))).saturating_add(if c.novel { SCALE } else { 0 });
        if c.flags == 0 && best.is_none() && n < ORDINARY_MAX_FLOWS {
            ordinary = ordinary.saturating_add(1);
            continue;
        }
        c.score = w;
        push_card(cards, &mut n_cards, c)?;
    }

    // Detections no card claimed, visited as `dets.items()` is: source by source in order of each source's
    // first detection, then in order. The visiting order decides which of two detections with one id is kept.
    for (si, head) in dets.iter().enumerate() {
        if dets.iter().position(|e| e.src == head.src) != Some(si) {
            continue;
        }
        for (di, d) in dets.iter().enumerate().filter(|(_, d)| d.src == head.src) {
            if used >> di & 1 == 1 {
                continue;
            }
            mark_ids(dets, 1u64.checked_shl(u32::try_from(di).unwrap_or(64)).unwrap_or(0), &mut used);
            let score = sev_weight(d.severity).saturating_add(if d.category == "ioc_match" { 2 * SCALE } else { 0 });
            let (k1, k2) = (u32::try_from(si).unwrap_or(u32::MAX), u32::try_from(di).unwrap_or(u32::MAX));
            push_card(cards, &mut n_cards, Card { score, phase: 2, k1, k2, at: k2, ..Card::EMPTY })?;
        }
    }
    let cards = cards.get_mut(..n_cards).ok_or(ContractError::Space)?;
    cards.sort_unstable_by_key(|c| (core::cmp::Reverse(c.score), c.phase, c.k1, c.k2));

    // Line lengths, with the aliases as they will be written.
    let mut line = Line::new();
    {
        let mut al = Aliases { tab: &mut *scratch.aliases, n: 0, hosts: 0, remotes: 0, plain: false };
        for (k, c) in cards.iter_mut().enumerate() {
            let snapshot = *c;
            write_line(k, &snapshot, flows, dets, fans, &mut al, &mut line)?;
            c.len = u32::try_from(line.n).unwrap_or(u32::MAX);
        }
    }
    let cards: &[Card] = cards;

    // `fill`: lines are added while (bytes x ratio + 1) per line stays within the budget; the ratio is the
    // estimate's tokens per byte on the first 600 lines joined.
    let m = n_cards.min(RATIO_SAMPLE_LINES);
    let sample: u64 = cards.iter().take(m).map(|c| u64::from(c.len)).sum::<u64>().saturating_add(u64::try_from(m.saturating_sub(1)).unwrap_or(0));
    let (q, big_l) = (u128::from(tokens(usize::try_from(sample).unwrap_or(usize::MAX))), u128::from(sample.max(1)));
    let mut kept = 0usize;
    let mut bytes = 0u128;
    for c in cards {
        let b = bytes.saturating_add(u128::from(c.len));
        let k = u128::try_from(kept).unwrap_or(u128::MAX).saturating_add(1);
        if q.saturating_mul(b).saturating_add(k.saturating_mul(big_l)) > u128::from(budget).saturating_mul(big_l) {
            break;
        }
        bytes = b;
        kept = kept.saturating_add(1);
    }
    // The joined text is counted and lines are removed until it fits. A `REST` line stands for what was dropped.
    let rest_for = |kept: usize, line: &mut Line| -> Result<(), ContractError> {
        let mut cats = Cats::new();
        let mut plain = Aliases { tab: &mut [], n: 0, hosts: 0, remotes: 0, plain: true };
        for (k, c) in cards.iter().enumerate().skip(kept) {
            write_line(k, c, flows, dets, fans, &mut plain, line)?;
            cats.scan(line.bytes())?;
        }
        rest_line(n_cards.saturating_sub(kept), &cats, ordinary, line)
    };
    let size = |kept: usize, line: &mut Line| -> Result<usize, ContractError> {
        let mut b: usize = cards.iter().take(kept).map(|c| c.len as usize).sum::<usize>().saturating_add(kept.saturating_sub(1));
        if kept < n_cards {
            rest_for(kept, line)?;
            b = b.saturating_add(line.n).saturating_add(usize::from(kept > 0));
        }
        Ok(b)
    };
    let mut n_tok = tokens(size(kept, &mut line)?);
    while n_tok > u64::from(budget) && kept > 0 {
        kept = kept.saturating_sub(1);
        n_tok = tokens(size(kept, &mut line)?);
    }
    let empty = n_tok > u64::from(budget);

    // Write. `e2e_neuro.py` adds the `REST` line when `fill` returned as many lines as there are cards.
    let lines_from_fill = if empty { 0 } else { kept.saturating_add(usize::from(kept < n_cards)) };
    let mut wrote = false;
    if !empty {
        let mut al = Aliases { tab: &mut *scratch.aliases, n: 0, hosts: 0, remotes: 0, plain: false };
        for (k, c) in cards.iter().enumerate().take(kept) {
            write_line(k, c, flows, dets, fans, &mut al, &mut line)?;
            emit(out, &mut wrote, line.bytes())?;
        }
        if kept < n_cards {
            rest_for(kept, &mut line)?;
            emit(out, &mut wrote, line.bytes())?;
        }
    }
    if lines_from_fill == n_cards {
        rest_line(0, &Cats::new(), ordinary, &mut line)?;
        emit(out, &mut wrote, line.bytes())?;
    }
    Ok(Built { cards: u32::try_from(n_cards).unwrap_or(u32::MAX), kept: if empty { 0 } else { u32::try_from(kept).unwrap_or(u32::MAX) }, ordinary_pairs: ordinary })
}
