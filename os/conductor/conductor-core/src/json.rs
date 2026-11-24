// SPDX-License-Identifier: AGPL-3.0-only
//! A strict parser for the model's reply. It accepts exactly two shapes:
//!
//! - **the explainer's answer**, in the language of `neuro_contract` (Neuro's triage schema, closed over the
//!   fact ids and aliases of this job's context) and parsed by that crate's automaton, the same one the
//!   engine decodes with. Nothing here redefines it;
//! - **a tool call** (a Conductor extension, keys in this order):
//!
//! ```text
//! {"tool":"evidence.get","args":{"id":"ev:N"}}
//! {"tool":"flows.count","args":{"ev":"ev:N","hours":H}}
//! ```
//!
//! Citations `F<n>` name evidence `n` (canonical decimal only). The summary is unescaped and must be inert
//! text. In tool calls, anything else is an error: unknown or duplicate keys
//! (a duplicate necessarily breaks the fixed order), other escapes than \" \\ \/ \n, raw control
//! characters, numbers with signs, leading zeros or fractions, nesting beyond the schema, trailing bytes.
//! Strings are bounded and must be inert text. No allocation, no recursion.

use crate::buf::Buf;
use crate::job::{inert_text, Verdict};
use crate::limits::{MAX_CITES, MAX_SUMMARY};
use neuro_contract::{IdList, Sink};
use crate::tools::ToolCall;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JsonError {
    Syntax,
    Schema,
    Encoding,
    TooLong,
    Trailing,
}

pub struct Answer {
    pub verdict: Option<Verdict>,
    /// Index into `neuro_contract::SEVERITIES` / `NEXT_STEPS`.
    pub severity: u8,
    pub next_step: u8,
    pub confidence: u8,
    pub n_entities: u8,
    pub cites: [u16; MAX_CITES],
    pub n_cites: usize,
    /// Bytes of the decoded summary (the text itself is written to the caller's buffer).
    pub summary_len: usize,
}

struct BufSink<'b, const N: usize>(&'b mut Buf<N>);
impl<const N: usize> Sink for BufSink<'_, N> {
    fn put(&mut self, s: &[u8]) -> Result<(), neuro_contract::ContractError> {
        self.0.push(s).ok_or(neuro_contract::ContractError::Space)
    }
}

/// `F<n>`, canonical decimal (no leading zero), n ≤ 65535.
fn fact_number(id: &[u8]) -> Option<u16> {
    let digits = id.strip_prefix(b"F")?;
    if digits.is_empty() || (digits.len() > 1 && digits.first() == Some(&b'0')) || digits.len() > 5 {
        return None;
    }
    let v = digits.iter().try_fold(0u32, |a, &d| if d.is_ascii_digit() { a.checked_mul(10)?.checked_add(u32::from(d.wrapping_sub(b'0'))) } else { None })?;
    u16::try_from(v).ok()
}

/// The explainer's answer, through the contract.
fn answer(b: &[u8], facts: &IdList, ents: &IdList, summary: &mut Buf<MAX_SUMMARY>) -> R<Answer> {
    let c = neuro_contract::parse(b, facts, ents).map_err(|_| JsonError::Schema)?;
    let mut a = Answer { verdict: None, severity: c.severity, next_step: c.next_step, confidence: c.confidence, n_entities: u8::try_from(c.entities().len()).unwrap_or(u8::MAX), cites: [0; MAX_CITES], n_cites: 0, summary_len: 0 };
    a.verdict = Some(Verdict::parse_name(c.verdict_name().as_bytes()).ok_or(JsonError::Schema)?);
    for &i in c.evidence() {
        let id = facts.get(usize::from(i)).and_then(fact_number).ok_or(JsonError::Schema)?;
        *a.cites.get_mut(a.n_cites).ok_or(JsonError::TooLong)? = id;
        a.n_cites = a.n_cites.saturating_add(1);
    }
    summary.clear();
    neuro_contract::unescape(c.summary(b), &mut BufSink(summary)).map_err(|e| if e == neuro_contract::ContractError::Space { JsonError::TooLong } else { JsonError::Encoding })?;
    if !inert_text(summary.as_slice()) {
        return Err(JsonError::Encoding);
    }
    a.summary_len = summary.len();
    Ok(a)
}

impl Answer {
    pub fn cites(&self) -> &[u16] {
        self.cites.get(..self.n_cites).unwrap_or(&[])
    }
}

// Answer is ~1 KiB and lives inside the harness's own frame; no allocator to box it.
#[allow(clippy::large_enum_variant)]
pub enum ModelOutput {
    Tool(ToolCall),
    Answer(Answer),
}

struct Cur<'a> {
    b: &'a [u8],
    i: usize,
}

type R<T> = Result<T, JsonError>;

impl<'a> Cur<'a> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn bump(&mut self) -> R<u8> {
        let c = self.peek().ok_or(JsonError::Syntax)?;
        self.i = self.i.checked_add(1).ok_or(JsonError::Syntax)?;
        Ok(c)
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.i = self.i.saturating_add(1);
        }
    }
    fn expect(&mut self, c: u8) -> R<()> {
        self.ws();
        if self.bump()? == c {
            Ok(())
        } else {
            Err(JsonError::Syntax)
        }
    }
    /// A string, decoded into `out`, required to be inert text.
    fn string<const N: usize>(&mut self, out: &mut Buf<N>) -> R<()> {
        out.clear();
        self.expect(b'"')?;
        loop {
            let c = self.bump()?;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.bump()?;
                    let v = match e {
                        b'"' => b'"',
                        b'\\' => b'\\',
                        b'/' => b'/',
                        b'n' => b'\n',
                        _ => return Err(JsonError::Encoding),
                    };
                    out.push(&[v]).ok_or(JsonError::TooLong)?;
                }
                0..=0x1f => return Err(JsonError::Encoding),
                _ => out.push(&[c]).ok_or(JsonError::TooLong)?,
            }
        }
        if inert_text(out.as_slice()) {
            Ok(())
        } else {
            Err(JsonError::Encoding)
        }
    }
    fn key(&mut self, want: &[u8]) -> R<()> {
        let mut k: Buf<24> = Buf::new();
        self.string(&mut k).map_err(|_| JsonError::Schema)?;
        if k.as_slice() != want {
            return Err(JsonError::Schema);
        }
        self.expect(b':')
    }
    fn uint(&mut self, max: u32) -> R<u32> {
        self.ws();
        let start = self.i;
        let mut v: u32 = 0;
        while let Some(d @ b'0'..=b'9') = self.peek() {
            v = v.checked_mul(10).and_then(|x| x.checked_add(u32::from(d.wrapping_sub(b'0')))).ok_or(JsonError::Schema)?;
            self.i = self.i.saturating_add(1);
        }
        let n = self.i.saturating_sub(start);
        let lead_zero = n > 1 && self.b.get(start) == Some(&b'0');
        if n == 0 || lead_zero || v > max {
            return Err(JsonError::Schema);
        }
        Ok(v)
    }
    /// "ev:N" with 0 <= N <= 65535, no leading zeros.
    fn ev_ref(&mut self) -> R<u16> {
        let mut s: Buf<12> = Buf::new();
        self.string(&mut s).map_err(|_| JsonError::Schema)?;
        let d = s.as_slice().strip_prefix(b"ev:").ok_or(JsonError::Schema)?;
        if d.is_empty() || d.len() > 5 || (d.len() > 1 && d.first() == Some(&b'0')) {
            return Err(JsonError::Schema);
        }
        let mut v: u32 = 0;
        for &c in d {
            if !c.is_ascii_digit() {
                return Err(JsonError::Schema);
            }
            v = v.checked_mul(10).and_then(|x| x.checked_add(u32::from(c.wrapping_sub(b'0')))).ok_or(JsonError::Schema)?;
        }
        u16::try_from(v).map_err(|_| JsonError::Schema)
    }
}

/// Parse a reply. `facts` and `ents` are the ids of the context the model was shown (the closed enums); an
/// answer's decoded summary goes to `summary`.
pub fn parse(b: &[u8], facts: &IdList, ents: &IdList, summary: &mut Buf<MAX_SUMMARY>) -> R<ModelOutput> {
    let c = &mut Cur { b, i: 0 };
    c.expect(b'{')?;
    let mut top: Buf<24> = Buf::new();
    c.string(&mut top).map_err(|_| JsonError::Schema)?;
    c.expect(b':')?;
    if top.as_slice() != b"tool" {
        return Ok(ModelOutput::Answer(answer(b, facts, ents, summary)?));
    }
    let out = ModelOutput::Tool(tool(c)?);
    c.expect(b'}')?;
    c.ws();
    if c.i != b.len() {
        return Err(JsonError::Trailing);
    }
    Ok(out)
}

fn tool(c: &mut Cur) -> R<ToolCall> {
    let mut name: Buf<24> = Buf::new();
    c.string(&mut name).map_err(|_| JsonError::Schema)?;
    c.expect(b',')?;
    c.key(b"args")?;
    c.expect(b'{')?;
    let call = match name.as_slice() {
        b"evidence.get" => {
            c.key(b"id")?;
            ToolCall::EvidenceGet { ev: c.ev_ref()? }
        }
        b"flows.count" => {
            c.key(b"ev")?;
            let ev = c.ev_ref()?;
            c.expect(b',')?;
            c.key(b"hours")?;
            let h = c.uint(u32::from(u8::MAX))?;
            ToolCall::FlowCount { ev, hours: u8::try_from(h).map_err(|_| JsonError::Schema)? }
        }
        _ => return Err(JsonError::Schema),
    };
    c.expect(b'}')?;
    Ok(call)
}

