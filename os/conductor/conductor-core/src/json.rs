// SPDX-License-Identifier: AGPL-3.0-only
//! A strict parser for the model's reply. It accepts exactly two shapes, with keys in this order:
//!
//! ```text
//! {"tool":"evidence.get","args":{"id":"ev:N"}}
//! {"tool":"flows.count","args":{"ev":"ev:N","hours":H}}
//! {"answer":{"verdict":"benign|suspicious|malicious|insufficient_evidence","cites":["ev:N",...],"summary":"..."}}
//! ```
//!
//! `verdict` may be omitted (a descriptive answer). Anything else is an error: unknown or duplicate keys
//! (a duplicate necessarily breaks the fixed order), other escapes than \" \\ \/ \n, raw control
//! characters, numbers with signs, leading zeros or fractions, nesting beyond the schema, trailing bytes.
//! Strings are bounded and must be inert text. No allocation, no recursion.

use crate::buf::Buf;
use crate::job::{inert_text, Verdict};
use crate::limits::{MAX_CITES, MAX_SUMMARY};
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
    pub cites: [u16; MAX_CITES],
    pub n_cites: usize,
    pub summary: Buf<MAX_SUMMARY>,
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
    fn comma_or(&mut self, end: u8) -> R<bool> {
        self.ws();
        match self.bump()? {
            b',' => Ok(true),
            c if c == end => Ok(false),
            _ => Err(JsonError::Syntax),
        }
    }
}

pub fn parse(b: &[u8]) -> R<ModelOutput> {
    let c = &mut Cur { b, i: 0 };
    c.expect(b'{')?;
    let mut top: Buf<24> = Buf::new();
    c.string(&mut top).map_err(|_| JsonError::Schema)?;
    c.expect(b':')?;
    let out = match top.as_slice() {
        b"tool" => ModelOutput::Tool(tool(c)?),
        b"answer" => ModelOutput::Answer(answer(c)?),
        _ => return Err(JsonError::Schema),
    };
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

fn answer(c: &mut Cur) -> R<Answer> {
    let mut a = Answer { verdict: None, cites: [0; MAX_CITES], n_cites: 0, summary: Buf::new() };
    c.expect(b'{')?;
    let mut k: Buf<24> = Buf::new();
    c.string(&mut k).map_err(|_| JsonError::Schema)?;
    c.expect(b':')?;
    if k.as_slice() == b"verdict" {
        let mut v: Buf<24> = Buf::new();
        c.string(&mut v).map_err(|_| JsonError::Schema)?;
        a.verdict = Some(Verdict::parse_name(v.as_slice()).ok_or(JsonError::Schema)?);
        c.expect(b',')?;
        c.key(b"cites")?;
    } else if k.as_slice() != b"cites" {
        return Err(JsonError::Schema);
    }
    c.expect(b'[')?;
    c.ws();
    if c.peek() == Some(b']') {
        c.i = c.i.saturating_add(1);
    } else {
        loop {
            let id = c.ev_ref()?;
            let slot = a.cites.get_mut(a.n_cites).ok_or(JsonError::TooLong)?;
            *slot = id;
            a.n_cites = a.n_cites.saturating_add(1);
            if !c.comma_or(b']')? {
                break;
            }
        }
    }
    c.expect(b',')?;
    c.key(b"summary")?;
    c.string(&mut a.summary)?;
    c.expect(b'}')?;
    Ok(a)
}
