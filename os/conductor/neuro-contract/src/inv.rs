// SPDX-License-Identifier: AGPL-3.0-only
//! The investigation turn: the request Neuro's investigation adapter (ftM, docs 39, 43 and 44) is given, and the
//! device's reading of its answer.
//!
//! Upstream truth is `tools/neuro-research/inv_contract.json`, which Neuro generates from the code that sends the
//! request (`inv_eval.py` → `run_eval.openai_backend`). `tests/inv.rs` reads that file and fails on any
//! difference, test vectors included.
//!
//! **The request.** The same system prompt and user framing as the explainer, without the answer schema, and with
//! Neuro's five tools. llama-server (`--jinja --reasoning off`) renders them with the model's own chat template;
//! [`write_prompt`] writes those bytes. The context must already have passed guard A.
//!
//! **The answer.** Either free text (no check is needed) or ONE tool call:
//!
//! ```text
//! <tool_call>
//! {"name": "lookup_reputation", "arguments": {"entity": "R1"}}
//! </tool_call>
//! ```
//!
//! [`parse_answer`] is the device's own strict reading of that form, not a mirror of llama.cpp's tool-call
//! grammar: the name must be one of the five tools, the arguments exactly that tool's (typed, no extras), and
//! the entity an alias of the context. Anything else after `<tool_call>` is `Invalid`. A model never enforces:
//! `propose_policy_change` is a proposal the owner reviews.
//!
//! Not here yet: constrained decoding of the tool call in the engine (it needs the grammar llama.cpp derives
//! from the tools), and the mapping of these tools onto the Conductor's typed, per-call authorised tools.
//!
//! `no_std`, no allocation, no unsafe.

use crate::{system_prompt, ContractError, IdList, Lang, Sink, CHAT_ASSISTANT, CHAT_SYSTEM, CHAT_USER, USER_HEAD, USER_MID};

/// Neuro's request settings (`inv_contract.json`).
pub const MAX_TOKENS: u32 = 300;

/// One tool as the request carries it. `json` is `json.dumps({"type": "function", "function": {...}})` with
/// Python's default separators, which is also the line the chat template writes into the system prompt.
#[derive(Clone, Copy, Debug)]
pub struct Tool {
    pub name: &'static str,
    /// An optional integer `minutes`.
    pub minutes: bool,
    /// A required `policy`, one of [`POLICIES`].
    pub policy: bool,
    pub json: &'static str,
}

pub const POLICIES: [&str; 4] = ["isolated", "internet_only", "lan_only", "full_access"];

/// `run_eval.TOOLS + [LOOKUP_TOOL]`, in request order. Every tool takes a required `entity`.
pub const TOOLS: [Tool; 5] = [
    Tool {
        name: "lookup_reputation",
        minutes: false,
        policy: false,
        json: r#"{"type": "function", "function": {"name": "lookup_reputation", "description": "Threat-intel reputation of an entity alias", "parameters": {"type": "object", "properties": {"entity": {"type": "string"}}, "required": ["entity"]}}}"#,
    },
    Tool {
        name: "query_flows",
        minutes: true,
        policy: false,
        json: r#"{"type": "function", "function": {"name": "query_flows", "description": "Recent flows of an entity alias", "parameters": {"type": "object", "properties": {"entity": {"type": "string"}, "minutes": {"type": "integer"}}, "required": ["entity"]}}}"#,
    },
    Tool {
        name: "query_dns",
        minutes: true,
        policy: false,
        json: r#"{"type": "function", "function": {"name": "query_dns", "description": "Recent DNS queries of an entity alias", "parameters": {"type": "object", "properties": {"entity": {"type": "string"}, "minutes": {"type": "integer"}}, "required": ["entity"]}}}"#,
    },
    Tool {
        name: "propose_policy_change",
        minutes: false,
        policy: true,
        json: r#"{"type": "function", "function": {"name": "propose_policy_change", "description": "PROPOSE (never apply) a device policy for owner approval", "parameters": {"type": "object", "properties": {"entity": {"type": "string"}, "policy": {"type": "string", "enum": ["isolated", "internet_only", "lan_only", "full_access"]}}, "required": ["entity", "policy"]}}}"#,
    },
    Tool {
        name: "lookup_exposure",
        minutes: false,
        policy: false,
        json: r#"{"type": "function", "function": {"name": "lookup_exposure", "description": "Known-exploited weaknesses for a device's class (and product, when known): counts, usual entry technique, and CVE ids that match the product. Read-only.", "parameters": {"type": "object", "properties": {"entity": {"type": "string"}}, "required": ["entity"]}}}"#,
    },
];

/// What Qwen3's chat template puts between the system text and the tool lines, and after them.
pub const TOOLS_HEAD: &str = "\n\n# Tools\n\nYou may call one or more functions to assist with the user query.\n\nYou are provided with function signatures within <tools></tools> XML tags:\n<tools>";
pub const TOOLS_TAIL: &str = "\n</tools>\n\nFor each function call, return a json object with function name and arguments within <tool_call></tool_call> XML tags:\n<tool_call>\n{\"name\": <function-name>, \"arguments\": <args-json-object>}\n</tool_call>";

pub const TOOL_CALL_OPEN: &str = "<tool_call>";
pub const TOOL_CALL_CLOSE: &str = "</tool_call>";

/// The system message as rendered: Neuro's system prompt, then the tools.
pub fn write_system(lang: Lang, out: &mut (impl Sink + ?Sized)) -> Result<(), ContractError> {
    out.put(system_prompt(lang).as_bytes())?;
    out.put(TOOLS_HEAD.as_bytes())?;
    for t in &TOOLS {
        out.put(b"\n")?;
        out.put(t.json.as_bytes())?;
    }
    out.put(TOOLS_TAIL.as_bytes())
}

/// The whole prompt, as llama-server renders the request with reasoning off, ending where the answer begins.
/// `shown_context` is the context after guard A.
pub fn write_prompt(lang: Lang, shown_context: &[u8], question: &[u8], out: &mut (impl Sink + ?Sized)) -> Result<(), ContractError> {
    out.put(CHAT_SYSTEM.as_bytes())?;
    write_system(lang, out)?;
    out.put(CHAT_USER.as_bytes())?;
    out.put(USER_HEAD.as_bytes())?;
    out.put(shown_context)?;
    out.put(USER_MID.as_bytes())?;
    out.put(question)?;
    out.put(CHAT_ASSISTANT.as_bytes())
}

// ------------------------------------------------------------------------------------------- the answer

/// One tool call, typed. `tool` indexes [`TOOLS`], `entity` the context's entity list, `policy` [`POLICIES`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Call {
    pub tool: u8,
    pub entity: u8,
    pub minutes: Option<u32>,
    pub policy: Option<u8>,
}

impl Call {
    pub fn name(&self) -> &'static str {
        TOOLS.get(usize::from(self.tool)).map_or("", |t| t.name)
    }
    /// The only tool that asks for a change; it is a proposal for the owner, never an action.
    pub fn is_proposal(&self) -> bool {
        TOOLS.get(usize::from(self.tool)).is_some_and(|t| t.policy)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Free text: the model asks for no check.
    NoTool,
    Call(Call),
}

/// The largest `minutes` accepted. A day; the schema says only "integer".
pub const MINUTES_MAX: u32 = 1440;

struct P<'a> {
    t: &'a [u8],
    i: usize,
}

impl<'a> P<'a> {
    fn ws(&mut self) {
        while matches!(self.t.get(self.i), Some(b' ' | b'\n' | b'\t' | b'\r')) {
            self.i += 1;
        }
    }
    fn lit(&mut self, s: &[u8]) -> Result<(), ContractError> {
        if self.t.get(self.i..self.i + s.len()) == Some(s) {
            self.i += s.len();
            Ok(())
        } else {
            Err(ContractError::Invalid)
        }
    }
    /// Whitespace, then one byte of punctuation.
    fn punct(&mut self, c: u8) -> Result<(), ContractError> {
        self.ws();
        self.lit(&[c])
    }
    fn peek(&mut self) -> Option<u8> {
        self.ws();
        self.t.get(self.i).copied()
    }
    /// A JSON string without escapes or control characters: its body.
    fn string(&mut self) -> Result<&'a [u8], ContractError> {
        self.punct(b'"')?;
        let start = self.i;
        loop {
            match self.t.get(self.i).copied().ok_or(ContractError::Invalid)? {
                b'"' => break,
                b'\\' | 0..=0x1f | 0x7f => return Err(ContractError::Invalid),
                _ => self.i += 1,
            }
        }
        let s = self.t.get(start..self.i).ok_or(ContractError::Invalid)?;
        self.i += 1;
        Ok(s)
    }
    /// A JSON integer, no sign, no leading zero, no fraction or exponent.
    fn uint(&mut self) -> Result<u32, ContractError> {
        self.ws();
        let start = self.i;
        let mut v = 0u32;
        while let Some(d) = self.t.get(self.i).copied().filter(u8::is_ascii_digit) {
            v = v.checked_mul(10).and_then(|v| v.checked_add(u32::from(d - b'0'))).ok_or(ContractError::Invalid)?;
            self.i += 1;
        }
        let n = self.i - start;
        let leading_zero = n > 1 && self.t.get(start) == Some(&b'0');
        if n == 0 || leading_zero || matches!(self.t.get(self.i), Some(b'.' | b'e' | b'E')) {
            return Err(ContractError::Invalid);
        }
        Ok(v)
    }
}

fn position(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Read an investigation answer. Text without `<tool_call>` is [`Answer::NoTool`]. With it, exactly one
/// well-formed call of one of the five tools is required, its entity one of `entities` (the aliases of the
/// context the model was shown); the closing tag may be missing if the text ends there.
pub fn parse_answer(text: &[u8], entities: &IdList) -> Result<Answer, ContractError> {
    let Some(open) = position(text, TOOL_CALL_OPEN.as_bytes()) else {
        return Ok(Answer::NoTool);
    };
    let mut p = P { t: text, i: open + TOOL_CALL_OPEN.len() };
    p.punct(b'{')?;
    if p.string()? != b"name" {
        return Err(ContractError::Invalid);
    }
    p.punct(b':')?;
    let name = p.string()?;
    let (ti, tool) = TOOLS.iter().enumerate().find(|(_, t)| t.name.as_bytes() == name).ok_or(ContractError::Invalid)?;
    p.punct(b',')?;
    if p.string()? != b"arguments" {
        return Err(ContractError::Invalid);
    }
    p.punct(b':')?;
    p.punct(b'{')?;
    let (mut entity, mut minutes, mut policy) = (None, None, None);
    if p.peek() != Some(b'}') {
        loop {
            let key = p.string()?;
            p.punct(b':')?;
            match key {
                b"entity" if entity.is_none() => {
                    let e = p.string()?;
                    entity = Some(entities.iter().position(|x| x == e).ok_or(ContractError::Invalid)?);
                }
                b"minutes" if tool.minutes && minutes.is_none() => {
                    let m = p.uint()?;
                    if m == 0 || m > MINUTES_MAX {
                        return Err(ContractError::Invalid);
                    }
                    minutes = Some(m);
                }
                b"policy" if tool.policy && policy.is_none() => {
                    let v = p.string()?;
                    policy = Some(POLICIES.iter().position(|x| x.as_bytes() == v).ok_or(ContractError::Invalid)?);
                }
                _ => return Err(ContractError::Invalid),
            }
            if p.peek() == Some(b',') {
                p.i += 1;
            } else {
                break;
            }
        }
    }
    p.punct(b'}')?;
    p.punct(b'}')?;
    p.ws();
    if p.i < text.len() {
        p.lit(TOOL_CALL_CLOSE.as_bytes())?;
        p.ws();
    }
    if p.i != text.len() || (tool.policy && policy.is_none()) {
        return Err(ContractError::Invalid);
    }
    let small = |v: usize| u8::try_from(v).map_err(|_| ContractError::Invalid);
    Ok(Answer::Call(Call { tool: small(ti)?, entity: small(entity.ok_or(ContractError::Invalid)?)?, minutes, policy: policy.map(small).transpose()? }))
}
