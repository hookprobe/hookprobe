// SPDX-License-Identifier: AGPL-3.0-only
//! Guards A and E, mirroring Neuro's `tools/neuro-research/guard.py` (docs 24 and 25), and the Level-0 template
//! summary guard E falls back to (`run_eval.py` `template_backend`). Neuro's answers to the Conductor
//! (2026-11-24): guards A, E and G are deterministic and run on the device.
//!
//! - [`guard_a`] is the input guard (`redact_all`, default-deny). Every quoted value in the context is replaced
//!   by a description of it: `"<untrusted text withheld: N chars, K words, instruction-like: yes|no>"`. The
//!   model never reads attacker-controlled text.
//! - [`echoes`] is the test of the output guard E: does the answer's prose contain any 8-character substring of
//!   any quoted value of the ORIGINAL context, ignoring case?
//! - [`template_summary`] is what E puts in place of an echoing summary: the deterministic template sentence,
//!   built from the detections on the cards. Verdict, evidence, entities and next step are kept as the model
//!   gave them.
//!
//! Order on the device, as in Neuro's pipeline: A on the way in; on the way out E, then G, then the verifier.
//!
//! The text operations reproduce Python's `re` and `str` behaviour on these exact patterns, verified against
//! vectors produced by Neuro's own functions (`tests/guard.rs`). Known differences, all outside what the card
//! writer emits:
//! - `\S`, `\d`, `\w` and `str.strip` are ASCII here (Python's are Unicode);
//! - a context that is not valid UTF-8 is refused by [`guard_a`] and [`template_summary`], and makes [`echoes`]
//!   answer `true`;
//! - lower-casing is per character, so Greek final sigma is not contextual. Both sigmas compare equal here, which
//!   can only report an echo Python would not, never miss one.
//!
//! `no_std`, no allocation, no unsafe.

use crate::grounding::is_space;
use crate::{ContractError, Lang, Sink, SinkExt};

/// `guard.N`: the shortest echoed run that counts, in characters.
pub const ECHO_MIN_CHARS: usize = 8;

/// `semantic_compression.INSTRUCTION_LIKE`, the one detector: any of these, ignoring case.
pub const INSTRUCTION_LIKE: [&str; 8] = ["ignore", "disregard", "previous", "instruction", "system prompt", "classify", "you are", "assistant"];

pub const WITHHELD_HEAD: &str = "<untrusted text withheld: ";
pub const WITHHELD_CHARS: &str = " chars, ";
pub const WITHHELD_WORDS: &str = " words, instruction-like: ";
pub const WITHHELD_TAIL: &str = ">";

/// The marker the compressor puts on a card whose quoted value looks like an instruction.
pub const INSTR_MARKER: &str = "!instr-like";

pub const NO_DETECTION_EN: &str = "No detection in this window.";
pub const NO_DETECTION_RO: &str = "Nicio detecție în această fereastră.";
pub const INSTR_NOTE_EN: &str = " Telemetry contains instruction-like text (possible prompt injection).";
pub const INSTR_NOTE_RO: &str = " Telemetria conține text care seamănă cu instrucțiuni (posibilă injecție de prompt).";

/// `run_eval.TEMPL`, split at its fields: `{n}`, `{cat}`, `{mitre}`, `{src}`, `{dst}`, `{wire}`, `{step}`.
pub const TEMPL_EN: [&str; 8] = ["", " finding(s). Highest: ", " (", ") from ", " to ", ". The device recorded it as ", ". Recommended: ", "."];
pub const TEMPL_RO: [&str; 8] =
    ["", " constatare(i). Cea mai importantă: ", " (", ") de la ", " către ", ". Dispozitivul a înregistrat-o ca ", ". Recomandare: ", "."];

/// Categories whose template step is `isolate_review`; every other category gives `investigate`.
pub const ISOLATE_CATS: [&str; 2] = ["exfiltration", "dns_dga"];

fn at(t: &[u8], i: usize) -> Option<u8> {
    t.get(i).copied()
}

fn sub(t: &[u8], a: usize, b: usize) -> &[u8] {
    t.get(a..b).unwrap_or(&[])
}

// ------------------------------------------------------------------------------------------- quoted values

/// `QUOTED = re.compile(r'"([^"\n]*)"')`, left to right without overlap: the next match at or after `from`, as
/// `(index of the opening quote, index of the closing quote)`.
fn next_quoted(t: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut i = from;
    while i < t.len() {
        if at(t, i) == Some(b'"') {
            let rest = t.get(i + 1..)?;
            let j = i + 1 + rest.iter().position(|&b| b == b'"' || b == b'\n')?;
            if at(t, j) == Some(b'"') {
                return Some((i, j));
            }
            // A newline came first: no match starts in i..=j.
            i = j;
        }
        i += 1;
    }
    None
}

/// Python's `re.I` on these keywords: ASCII case, plus the three characters `sre` also folds onto `i` and `s`.
fn eq_ci(pat: u8, c: char) -> bool {
    if c.is_ascii() {
        return (c as u8).to_ascii_lowercase() == pat;
    }
    (pat == b'i' && (c == '\u{130}' || c == '\u{131}')) || (pat == b's' && c == '\u{17f}')
}

/// `INSTRUCTION_LIKE.search(value)`.
pub fn instruction_like(value: &str) -> bool {
    let mut it = value.chars();
    loop {
        let here = it.clone();
        if INSTRUCTION_LIKE.iter().any(|k| {
            let mut v = here.clone();
            k.bytes().all(|p| v.next().is_some_and(|c| eq_ci(p, c)))
        }) {
            return true;
        }
        if it.next().is_none() {
            return false;
        }
    }
}

/// `len(re.findall(r"[A-Za-z]{2,}", value))`: runs of two or more ASCII letters.
fn words(value: &[u8]) -> u32 {
    let (mut n, mut run) = (0u32, 0u32);
    for &b in value.iter().chain(core::iter::once(&0)) {
        if b.is_ascii_alphabetic() {
            run += 1;
        } else {
            n += u32::from(run >= 2);
            run = 0;
        }
    }
    n
}

/// `guard.describe(value)`: a structured description of an untrusted value, never its content.
fn describe(value: &str, out: &mut (impl Sink + ?Sized)) -> Result<(), ContractError> {
    out.put(WITHHELD_HEAD.as_bytes())?;
    out.dec(u32::try_from(value.chars().count()).map_err(|_| ContractError::Overflow)?)?;
    out.put(WITHHELD_CHARS.as_bytes())?;
    out.dec(words(value.as_bytes()))?;
    out.put(WITHHELD_WORDS.as_bytes())?;
    out.put(if instruction_like(value) { b"yes" } else { b"no" })?;
    out.put(WITHHELD_TAIL.as_bytes())
}

/// Guard A, `guard.redact_all(context)`: the context with every quoted value replaced by its description. The
/// result is what the model is shown; guard E and the template keep using the original.
pub fn guard_a(context: &[u8], out: &mut (impl Sink + ?Sized)) -> Result<(), ContractError> {
    core::str::from_utf8(context).map_err(|_| ContractError::Invalid)?;
    let mut done = 0usize;
    while let Some((open, close)) = next_quoted(context, done) {
        out.put(sub(context, done, open + 1))?;
        // Quote bytes are ASCII, so the value between two of them is valid UTF-8 whenever the context is.
        let value = core::str::from_utf8(sub(context, open + 1, close)).map_err(|_| ContractError::Invalid)?;
        describe(value, out)?;
        out.put(b"\"")?;
        done = close + 1;
    }
    out.put(sub(context, done, context.len()))
}

// ------------------------------------------------------------------------------------------- guard E

fn fold_sigma(c: char) -> char {
    if c == '\u{3c2}' {
        '\u{3c3}'
    } else {
        c
    }
}

/// `s.lower()` as a stream of characters (see the module note on final sigma).
fn lowered(s: &str) -> impl Iterator<Item = char> + Clone + '_ {
    s.chars().flat_map(char::to_lowercase).map(fold_sigma)
}

/// Does `hay` contain the first `n` characters of `needle` as a contiguous run? `needle` has at least `n`.
fn contains_window(hay: impl Iterator<Item = char> + Clone, needle: impl Iterator<Item = char> + Clone, n: usize) -> bool {
    let mut h = hay;
    loop {
        if h.clone().zip(needle.clone().take(n)).filter(|(a, b)| a == b).count() == n {
            return true;
        }
        if h.next().is_none() {
            return false;
        }
    }
}

/// Guard E's test, `guard.echoes(context, text)`: `true` if `text` contains, ignoring case, any run of
/// [`ECHO_MIN_CHARS`] characters taken from a quoted value of `context`. `context` is the ORIGINAL context, not
/// the one guard A produced. Text or context that is not valid UTF-8 answers `true`.
pub fn echoes(context: &[u8], text: &[u8]) -> bool {
    let (Ok(_), Ok(text)) = (core::str::from_utf8(context), core::str::from_utf8(text)) else {
        return true;
    };
    let mut from = 0usize;
    while let Some((open, close)) = next_quoted(context, from) {
        from = close + 1;
        let Ok(value) = core::str::from_utf8(sub(context, open + 1, close)) else {
            return true;
        };
        if value.chars().count() < ECHO_MIN_CHARS {
            continue;
        }
        let mut window = lowered(value);
        // One window per start position that still has ECHO_MIN_CHARS characters after it.
        while window.clone().take(ECHO_MIN_CHARS).count() == ECHO_MIN_CHARS {
            if contains_window(lowered(text), window.clone(), ECHO_MIN_CHARS) {
                return true;
            }
            window.next();
        }
    }
    false
}

// ------------------------------------------------------------------------------------------- template summary

/// One detection row of `template_backend`: the fields its summary uses.
#[derive(Clone, Copy)]
struct Row<'a> {
    src: &'a [u8],
    dst: &'a [u8],
    cat: &'a [u8],
    mitre: &'a [u8],
    sev: u8,
    wire: &'a [u8],
}

fn run_while(t: &[u8], i: usize, f: impl Fn(u8) -> bool) -> usize {
    t.get(i..).map_or(0, |s| s.iter().take_while(|&&b| f(b)).count())
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// What the detection part of a row matched, and where the match ends.
struct Det<'a> {
    cat: &'a [u8],
    mitre: &'a [u8],
    sev: u8,
    wire: &'a [u8],
    end: usize,
}

/// A row pattern tried at one line start: the row and the end of the match.
type RowAt<'a> = fn(&'a [u8], usize) -> Option<(Row<'a>, usize)>;

/// ` .*?det=(\w+)\[([^,\]]*),sev(\d),([^\]]*)\]` from `p` (the byte after the run that precedes it).
fn det_tail(t: &[u8], p: usize) -> Option<Det<'_>> {
    if at(t, p) != Some(b' ') {
        return None;
    }
    let line_end = p + run_while(t, p, |b| b != b'\n');
    // `.*?` is lazy and stays on the line: the first `det=` on it from which the rest matches.
    let mut k = p + 1;
    while k + 4 <= line_end {
        if sub(t, k, k + 4) == b"det=" {
            let c0 = k + 4;
            let c1 = c0 + run_while(t, c0, is_word);
            let m0 = c1 + 1;
            let m1 = m0 + run_while(t, m0, |b| b != b',' && b != b']');
            let d = m1 + 4;
            let w0 = d + 2;
            let w1 = w0 + run_while(t, w0, |b| b != b']');
            let sev = at(t, d).filter(u8::is_ascii_digit);
            if c1 > c0 && at(t, c1) == Some(b'[') && sub(t, m1, d) == b",sev" && at(t, d + 1) == Some(b',') && at(t, w1) == Some(b']') {
                if let Some(sev) = sev {
                    return Some(Det { cat: sub(t, c0, c1), mitre: sub(t, m0, m1), sev: sev - b'0', wire: sub(t, w0, w1), end: w1 + 1 });
                }
            }
        }
        k += 1;
    }
    None
}

/// `(F\d+) ` at `s`: the index after the space.
fn fact_head(t: &[u8], s: usize) -> Option<usize> {
    if at(t, s) != Some(b'F') {
        return None;
    }
    let nd = run_while(t, s + 1, |b| b.is_ascii_digit());
    (nd > 0 && at(t, s + 1 + nd) == Some(b' ')).then_some(s + 2 + nd)
}

/// `^(F\d+) (\S+?)->(\S+?):\S+ .*?det=(\w+)\[([^,\]]*),sev(\d),([^\]]*)\]` at line start `s`.
fn flow_row(t: &[u8], s: usize) -> Option<(Row<'_>, usize)> {
    let a = fact_head(t, s)?;
    // source, arrow, destination, colon and port all lie in one run without whitespace.
    let run = sub(t, a, a + run_while(t, a, |b| !is_space(b)));
    // Lazy source: the first arrow after at least one character. A later arrow cannot succeed where it fails.
    let q = 1 + run.get(1..)?.windows(2).position(|w| w == b"->")?;
    // Lazy destination: the first colon after at least one character, with at least one character after it.
    let d0 = q + 2;
    let colon = (d0 + 1..run.len().saturating_sub(1)).find(|&i| run.get(i) == Some(&b':'))?;
    let d = det_tail(t, a + run.len())?;
    Some((Row { src: run.get(..q)?, dst: run.get(d0..colon)?, cat: d.cat, mitre: d.mitre, sev: d.sev, wire: d.wire }, d.end))
}

/// `^(F\d+) (\S+) dns (\S+) .*?det=(\w+)\[([^,\]]*),sev(\d),([^\]]*)\]` at line start `s`.
fn dns_row(t: &[u8], s: usize) -> Option<(Row<'_>, usize)> {
    let a = fact_head(t, s)?;
    let b = a + run_while(t, a, |b| !is_space(b));
    if b == a || sub(t, b, b + 5) != b" dns " {
        return None;
    }
    let c = b + 5;
    let e = c + run_while(t, c, |b| !is_space(b));
    if e == c {
        return None;
    }
    let d = det_tail(t, e)?;
    Some((Row { src: sub(t, a, b), dst: sub(t, c, e), cat: d.cat, mitre: d.mitre, sev: d.sev, wire: d.wire }, d.end))
}

/// `re.findall(pattern, ctx, re.M)`: every match that starts at a line start, left to right without overlap.
/// Counts the rows into `n` and keeps the first one with the lowest severity digit in `worst`.
fn each_row<'a>(t: &'a [u8], row: RowAt<'a>, n: &mut u32, worst: &mut Option<Row<'a>>) {
    let mut s = 0usize;
    while s < t.len() {
        match row(t, s) {
            Some((r, end)) => {
                *n = n.saturating_add(1);
                // `min(rows, key=sev)`: the first row with the lowest severity digit.
                if worst.is_none_or(|w| r.sev < w.sev) {
                    *worst = Some(r);
                }
                // The next match starts at the first line start at or after `end`.
                s = if end > 0 && at(t, end - 1) == Some(b'\n') { end } else { end + run_while(t, end, |b| b != b'\n') + 1 };
            }
            None => s += run_while(t, s, |b| b != b'\n') + 1,
        }
    }
}

fn strip(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if !is_space(*first) {
            break;
        }
        s = rest;
    }
    while let [rest @ .., last] = s {
        if !is_space(*last) {
            break;
        }
        s = rest;
    }
    s
}

/// `e.split("=")[0]`: an entity's alias without its inline definition.
fn alias(e: &[u8]) -> &[u8] {
    e.split(|&b| b == b'=').next().unwrap_or(e)
}

fn has(t: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && t.windows(needle.len()).any(|w| w == needle)
}

/// The summary guard E substitutes: `template_backend(case)["summary"]` for a triage or injection case, from the
/// ORIGINAL context. It names the number of detections and the most severe one; with no detection it says so.
pub fn template_summary(context: &[u8], lang: Lang, out: &mut (impl Sink + ?Sized)) -> Result<(), ContractError> {
    core::str::from_utf8(context).map_err(|_| ContractError::Invalid)?;
    let (mut n, mut worst): (u32, Option<Row<'_>>) = (0, None);
    each_row(context, flow_row, &mut n, &mut worst);
    each_row(context, dns_row, &mut n, &mut worst);
    let Some(w) = worst else {
        return out.put(match lang {
            Lang::En => NO_DETECTION_EN.as_bytes(),
            Lang::Ro => NO_DETECTION_RO.as_bytes(),
        });
    };
    let step: &[u8] = if ISOLATE_CATS.iter().any(|c| c.as_bytes() == w.cat) { b"isolate_review" } else { b"investigate" };
    let mitre: &[u8] = if w.mitre.is_empty() { b"-" } else { w.mitre };
    let fields: [&[u8]; 6] = [w.cat, mitre, alias(w.src), alias(w.dst), strip(w.wire), step];
    let templ = match lang {
        Lang::En => TEMPL_EN,
        Lang::Ro => TEMPL_RO,
    };
    let mut parts = templ.iter();
    out.put(parts.next().map_or(&[][..], |p| p.as_bytes()))?;
    out.dec(n)?;
    for (part, field) in parts.zip(fields.iter().map(Some).chain(core::iter::once(None))) {
        out.put(part.as_bytes())?;
        if let Some(field) = field {
            out.put(field)?;
        }
    }
    if has(context, INSTR_MARKER.as_bytes()) {
        out.put(match lang {
            Lang::En => INSTR_NOTE_EN.as_bytes(),
            Lang::Ro => INSTR_NOTE_RO.as_bytes(),
        })?;
    }
    Ok(())
}
