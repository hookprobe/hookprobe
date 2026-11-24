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

// ------------------------------------------------------------------------------------------- the grammar

/// What starts the grammar: llama-server's lazy trigger for these tools (a word trigger on the generated text).
pub const TRIGGER: &str = "<tool_call>\n";

/// The added tokens llama-server renders as text for this request (`preserved_tokens`). Under the grammar, no
/// other added token has text, so none can be generated; of these four only the first two fit the grammar.
pub const PRESERVED_TOKENS: [&str; 4] = ["<tool_call>", "</tool_call>", "<think>", "</think>"];

/// One step of the grammar after the trigger. `Sp` is the grammar's `space` (one optional unit).
#[derive(Clone, Copy)]
enum Op {
    Sp,
    Lit(&'static str),
    /// `"\"" <one of the tool names> "\""` without the opening quote.
    Name,
    /// `string` without the opening quote: `char* "\""`.
    Str,
    /// After the entity: what follows depends on the tool.
    AfterEntity,
    /// `integer`.
    Int,
    /// One of [`POLICIES`] and the closing quote.
    Policy,
    /// After a tool object and `space`: `,` and another tool, or `</tool_call>`.
    Sep,
    /// `(tool-call? space)+` after a complete call: whitespace, another call, or the end.
    Loop,
    Jump(u8),
}

const OBJECT: u8 = 0;
const BRANCH_PLAIN: u8 = 25;
const BRANCH_MINUTES: u8 = 28;
const BRANCH_POLICY: u8 = 38;
const CLOSE: u8 = 49;
const CALL_END: u8 = 53;
const LOOP: u8 = 54;
const NEXT_CALL: u8 = 55;

/// llama.cpp's grammar for the five tools (`inv_contract_gen.json`, `server_grammar.grammar`), from the trigger
/// on: `tool-call ::= "<tool_call>\n" space tool (space "," space tool)* space "</tool_call>"`.
const PROGRAM: [Op; 57] = [
    // OBJECT (0): tool-N up to its schema's entity string
    Op::Sp,
    Op::Lit("{"),
    Op::Sp,
    Op::Lit("\"name\""),
    Op::Sp,
    Op::Lit(":"),
    Op::Sp,
    Op::Lit("\""),
    Op::Name,
    Op::Sp,
    Op::Lit(","),
    Op::Sp,
    Op::Lit("\"arguments\""),
    Op::Sp,
    Op::Lit(":"),
    Op::Sp,
    Op::Lit("{"),
    Op::Sp,
    Op::Lit("\"entity\""),
    Op::Sp,
    Op::Lit(":"),
    Op::Sp,
    Op::Lit("\""),
    Op::Str,
    Op::AfterEntity,
    // BRANCH_PLAIN (25): `space "}"`
    Op::Sp,
    Op::Lit("}"),
    Op::Jump(CLOSE),
    // BRANCH_MINUTES (28): `"," space "\"minutes\"" space ":" space integer space "}"`
    Op::Lit(","),
    Op::Sp,
    Op::Lit("\"minutes\""),
    Op::Sp,
    Op::Lit(":"),
    Op::Sp,
    Op::Int,
    Op::Sp,
    Op::Lit("}"),
    Op::Jump(CLOSE),
    // BRANCH_POLICY (38): `"," space "\"policy\"" space ":" space <policy> space "}"`
    Op::Lit(","),
    Op::Sp,
    Op::Lit("\"policy\""),
    Op::Sp,
    Op::Lit(":"),
    Op::Sp,
    Op::Lit("\""),
    Op::Policy,
    Op::Sp,
    Op::Lit("}"),
    Op::Jump(CLOSE),
    // CLOSE (49): the tool object's `space "}"`, then `space` and the separator
    Op::Sp,
    Op::Lit("}"),
    Op::Sp,
    Op::Sep,
    // CALL_END (53)
    Op::Lit("</tool_call>"),
    // LOOP (54)
    Op::Loop,
    // NEXT_CALL (55)
    Op::Lit(TRIGGER),
    Op::Jump(OBJECT),
];

/// Where a `space` unit stands: `"" | " " | "\n"{1,2} [ \t]{0,20}`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ws {
    Start,
    Done,
    /// Newlines seen (1 or 2) and padding characters after them.
    Nl(u8, u8),
}

impl Ws {
    fn step(self, b: u8) -> Option<Ws> {
        match (self, b) {
            (Ws::Start, b' ') => Some(Ws::Done),
            (Ws::Start, b'\n') => Some(Ws::Nl(1, 0)),
            (Ws::Nl(1, 0), b'\n') => Some(Ws::Nl(2, 0)),
            (Ws::Nl(n, pad), b' ' | b'\t') if pad < 20 => Some(Ws::Nl(n, pad + 1)),
            _ => None,
        }
    }
}

const DEAD: u8 = u8::MAX;
const NO_PAD: u8 = u8::MAX;

/// The investigation answer as llama-server constrains it, one byte at a time: free text until the generated
/// text contains [`TRIGGER`], then the grammar the server derives from the five tools. This mirrors the server,
/// so it is wider than [`parse_answer`]: the entity is any JSON string, `minutes` any integer of up to 16
/// digits, and several tools or several calls may follow each other. The engine decodes under this automaton;
/// the device then reads the result with [`parse_answer`], which refuses what the device does not act on.
///
/// Copy and 6 bytes of state. Bytes of 0x80 and above pass inside the entity string, as in the contract's
/// automaton.
#[derive(Clone, Copy)]
pub struct ToolMachine {
    /// Index into the program, or [`DEAD`]. Meaningful once `triggered`.
    pc: u8,
    triggered: bool,
    /// Progress in the current step: bytes of a literal or of the trigger matched, a name or policy position,
    /// the escape state of a string, the digits of an integer.
    pos: u8,
    /// Candidates still possible for a name or a policy, one bit each; the tool once the name is complete.
    mask: u8,
    tool: u8,
    ws: Ws,
}

impl Default for ToolMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolMachine {
    pub fn new() -> Self {
        Self { pc: 0, triggered: false, pos: 0, mask: 0, tool: 0, ws: Ws::Start }
    }

    /// Has the grammar started? Before that, every token is allowed.
    pub fn triggered(&self) -> bool {
        self.triggered
    }

    pub fn dead(&self) -> bool {
        self.pc == DEAD
    }

    /// May the answer end here?
    pub fn accepting(&self) -> bool {
        !self.triggered || self.pc == LOOP
    }

    fn enter(&mut self, pc: u8) {
        self.pc = pc;
        self.pos = 0;
        self.ws = Ws::Start;
        self.mask = match PROGRAM.get(usize::from(pc)) {
            Some(Op::Name) => (1 << TOOLS.len()) - 1,
            Some(Op::Policy) => (1 << POLICIES.len()) - 1,
            _ => 0,
        };
        if matches!(PROGRAM.get(usize::from(pc)), Some(Op::Loop)) {
            self.pos = NO_PAD;
        }
    }

    /// One of `names` spelled byte by byte, then a closing quote. `Some(index)` when the quote completes one.
    fn choice(&mut self, b: u8, names: impl Iterator<Item = &'static str> + Clone) -> Result<Option<u8>, ()> {
        let at = usize::from(self.pos);
        if b == b'"' {
            return names.enumerate().find(|(i, n)| self.mask & (1 << i) != 0 && n.len() == at).map(|(i, _)| Some(i as u8)).ok_or(());
        }
        let mut keep = 0u8;
        for (i, n) in names.enumerate() {
            if self.mask & (1 << i) != 0 && n.as_bytes().get(at) == Some(&b) {
                keep |= 1 << i;
            }
        }
        if keep == 0 {
            return Err(());
        }
        self.mask = keep;
        self.pos += 1;
        Ok(None)
    }

    /// Consume one byte. `false` (and the machine is dead) if the server's grammar does not allow it here.
    pub fn step(&mut self, b: u8) -> bool {
        if !self.triggered {
            // Free text; watch for the trigger. No proper prefix of it is also a suffix, so a mismatch restarts.
            let t = TRIGGER.as_bytes();
            self.pos = if t.get(usize::from(self.pos)) == Some(&b) {
                self.pos + 1
            } else {
                u8::from(t.first() == Some(&b))
            };
            if usize::from(self.pos) == t.len() {
                self.triggered = true;
                self.enter(OBJECT);
            }
            return true;
        }
        // At most a few steps consume nothing (a `space` that ends, an integer that ends, a jump).
        for _ in 0..8 {
            let Some(op) = PROGRAM.get(usize::from(self.pc)).copied() else { break };
            let next = self.pc + 1;
            match op {
                Op::Jump(to) => self.enter(to),
                Op::Sp => match self.ws.step(b) {
                    Some(ws) => {
                        self.ws = ws;
                        return true;
                    }
                    None => self.enter(next),
                },
                Op::Lit(lit) => {
                    if lit.as_bytes().get(usize::from(self.pos)) != Some(&b) {
                        break;
                    }
                    self.pos += 1;
                    if usize::from(self.pos) == lit.len() {
                        self.enter(next);
                    }
                    return true;
                }
                Op::Name => match self.choice(b, TOOLS.iter().map(|t| t.name)) {
                    Ok(Some(tool)) => {
                        self.tool = tool;
                        self.enter(next);
                        return true;
                    }
                    Ok(None) => return true,
                    Err(()) => break,
                },
                Op::Policy => match self.choice(b, POLICIES.iter().copied()) {
                    Ok(Some(_)) => {
                        self.enter(next);
                        return true;
                    }
                    Ok(None) => return true,
                    Err(()) => break,
                },
                // `char ::= [^"\\\x7F\x00-\x1F] | [\\] (["\\bfnrt] | "u" [0-9a-fA-F]{4})`; pos: 0 plain,
                // 1 after a backslash, 2..=5 hex digits still to come (as 6 − pos).
                Op::Str => {
                    match (self.pos, b) {
                        (0, b'"') => self.enter(next),
                        (0, b'\\') => self.pos = 1,
                        (0, 0..=0x1f | 0x7f) => break,
                        (0, _) => {}
                        (1, b'"' | b'\\' | b'b' | b'f' | b'n' | b'r' | b't') => self.pos = 0,
                        (1, b'u') => self.pos = 2,
                        (2..=5, _) if b.is_ascii_hexdigit() => self.pos = if self.pos == 5 { 0 } else { self.pos + 1 },
                        _ => break,
                    }
                    return true;
                }
                Op::AfterEntity => {
                    let t = TOOLS.get(usize::from(self.tool));
                    let (minutes, policy) = t.map_or((false, false), |t| (t.minutes, t.policy));
                    // `entity-kv ("," space minutes-kv)? space "}"`, `entity-kv "," space policy-kv space "}"`,
                    // or `entity-kv space "}"`: the comma, where there is one, follows the string directly.
                    self.enter(if policy {
                        BRANCH_POLICY
                    } else if minutes && b == b',' {
                        BRANCH_MINUTES
                    } else {
                        BRANCH_PLAIN
                    });
                }
                // `"-"? ([0] | [1-9] [0-9]{0,15})`; pos counts digits, mask: 1 = a sign was read, 2 = it is zero.
                Op::Int => {
                    let digits = self.pos;
                    if b == b'-' && digits == 0 && self.mask & 1 == 0 {
                        self.mask |= 1;
                        return true;
                    }
                    if b.is_ascii_digit() && self.mask & 2 == 0 && digits < 16 {
                        if digits == 0 && b == b'0' {
                            self.mask |= 2;
                        }
                        self.pos += 1;
                        return true;
                    }
                    if digits == 0 {
                        break;
                    }
                    self.enter(next);
                }
                Op::Sep => {
                    match b {
                        // `space "," space tool`: the next object begins with its own `space`.
                        b',' => self.enter(OBJECT),
                        b'<' => {
                            self.enter(CALL_END);
                            self.pos = 1;
                        }
                        _ => break,
                    }
                    return true;
                }
                // `(tool-call? space)+`: any run of `space` units, or the next call. pos: padding used after the
                // last newline (a tab is only possible there), or NO_PAD.
                Op::Loop => {
                    match (b, self.pos) {
                        (b'\n', _) => self.pos = 0,
                        (b' ' | b'\t', 0..=19) => self.pos += 1,
                        (b' ', _) => self.pos = NO_PAD,
                        (b'<', _) => {
                            self.enter(NEXT_CALL);
                            self.pos = 1;
                        }
                        _ => break,
                    }
                    return true;
                }
            }
        }
        self.pc = DEAD;
        false
    }

    pub fn feed(&mut self, bytes: &[u8]) -> bool {
        bytes.iter().all(|&b| self.step(b))
    }

    /// Would these bytes be allowed next? The machine is not changed.
    pub fn accepts(&self, bytes: &[u8]) -> bool {
        let mut m = *self;
        m.feed(bytes)
    }
}
