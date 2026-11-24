// SPDX-License-Identifier: AGPL-3.0-only
//! Inference engines behind the worker. Placement (VRAM / RAM / NVMe, speculative decoding, KV tiers) is
//! the engine's business and only ever changes speed; the worker passes the device's hints and cache
//! namespace through and enforces the capability's limits on what comes back.

use crate::http::{self, HttpError, SseLines};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub struct GenRequest<'a> {
    pub prompt: &'a str,
    /// Hard caps from the capability. The worker stops (and reports an error) rather than truncate output.
    pub max_out_bytes: usize,
    pub max_out_units: u32,
    pub deadline: Instant,
    /// 0 none, 1 job, 2 session (HP-EXEC `cache_scope`).
    pub cache_scope: u8,
    /// Device-derived cache namespace (HP-EXEC `cache_salt`): the ONLY namespace the engine may reuse.
    pub cache_salt: [u8; 32],
    pub offload_hints: u8,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GenStats {
    pub ttft_ms: u32,
    /// Output pieces (≈ tokens for streaming engines) and total time, for calibration.
    pub pieces: u32,
    pub total_ms: u32,
}

#[derive(Debug)]
pub enum EngineError {
    /// The output would exceed the capability's limits.
    TooLong,
    Deadline,
    Http(HttpError),
    Protocol(&'static str),
    /// The sink asked to stop (the channel failed).
    Aborted,
}

/// Error codes sent to the device in an ERROR response frame.
pub mod code {
    pub const TOO_LONG: u16 = 1;
    pub const DEADLINE: u16 = 2;
    pub const ENGINE: u16 = 3;
    pub const BUSY: u16 = 4;
}

impl EngineError {
    pub fn code(&self) -> u16 {
        match self {
            Self::TooLong => code::TOO_LONG,
            Self::Deadline => code::DEADLINE,
            _ => code::ENGINE,
        }
    }
}

pub trait Engine: Send {
    fn name(&self) -> String;
    /// Stream output bytes to `sink` (false = stop). Must respect `max_out_bytes` and the deadline.
    fn generate(&mut self, r: &GenRequest, sink: &mut dyn FnMut(&[u8]) -> bool) -> Result<GenStats, EngineError>;
}

/// Deterministic engine for tests and smoke runs: replays scripted outputs in pieces.
pub struct Scripted {
    pub outputs: Vec<String>,
    pub next: usize,
    pub piece: usize,
    pub delay: Duration,
    /// Every request the engine received (tests check what reached it; real engines log nothing).
    pub seen: std::sync::Arc<std::sync::Mutex<Vec<(String, u8, [u8; 32])>>>,
}

impl Scripted {
    pub fn new(outputs: Vec<String>) -> Self {
        Self { outputs, next: 0, piece: 7, delay: Duration::ZERO, seen: Default::default() }
    }
}

impl Engine for Scripted {
    fn name(&self) -> String {
        "scripted".into()
    }
    fn generate(&mut self, r: &GenRequest, sink: &mut dyn FnMut(&[u8]) -> bool) -> Result<GenStats, EngineError> {
        if let Ok(mut s) = self.seen.lock() {
            s.push((r.prompt.to_string(), r.cache_scope, r.cache_salt));
        }
        let start = Instant::now();
        let text = self.outputs.get(self.next).or(self.outputs.last()).cloned().unwrap_or_default();
        self.next += 1;
        if text.len() > r.max_out_bytes || conductor_core::limits::units(text.len()) > r.max_out_units {
            return Err(EngineError::TooLong);
        }
        let mut ttft = None;
        let mut pieces = 0u32;
        for p in text.as_bytes().chunks(self.piece.max(1)) {
            pieces += 1;
            std::thread::sleep(self.delay);
            if Instant::now() > r.deadline {
                return Err(EngineError::Deadline);
            }
            ttft.get_or_insert(start.elapsed());
            if !sink(p) {
                return Err(EngineError::Aborted);
            }
        }
        Ok(GenStats { ttft_ms: ttft.map_or(0, |d| d.as_millis() as u32), pieces, total_ms: start.elapsed().as_millis() as u32 })
    }
}

/// Any OpenAI-compatible server on loopback: llama.cpp `llama-server`, vLLM, Ollama, SGLang.
pub struct OpenAiCompat {
    pub addr: SocketAddr,
    pub prefix: String,
    pub model: String,
    pub timeout: Duration,
}

impl OpenAiCompat {
    pub fn new(url: &str, model: &str) -> Result<Self, HttpError> {
        let (addr, prefix) = http::parse_loopback_url(url)?;
        Ok(Self { addr, prefix, model: model.to_string(), timeout: Duration::from_secs(120) })
    }

    /// The JSON schema of the device's strict reply format. Engines that support structured output
    /// (llama.cpp json_schema → GBNF, vLLM guided decoding) then cannot produce anything the device's
    /// parser would reject; key order follows the schema's property order.
    pub fn reply_schema() -> serde_json::Value {
        let ev = serde_json::json!({"type": "string", "pattern": "^ev:(0|[1-9][0-9]{0,4})$"});
        serde_json::json!({
            "oneOf": [
                {"type": "object", "additionalProperties": false, "required": ["tool", "args"],
                 "properties": {"tool": {"const": "evidence.get"},
                                "args": {"type": "object", "additionalProperties": false, "required": ["id"], "properties": {"id": ev}}}},
                {"type": "object", "additionalProperties": false, "required": ["tool", "args"],
                 "properties": {"tool": {"const": "flows.count"},
                                "args": {"type": "object", "additionalProperties": false, "required": ["ev", "hours"],
                                         "properties": {"ev": ev, "hours": {"type": "integer", "minimum": 1, "maximum": 24}}}}},
                {"type": "object", "additionalProperties": false, "required": ["answer"],
                 "properties": {"answer": {"type": "object", "additionalProperties": false, "required": ["cites", "summary"],
                     "properties": {"verdict": {"enum": ["benign", "suspicious", "malicious", "insufficient_evidence"]},
                                    "cites": {"type": "array", "items": ev, "maxItems": 16},
                                    "summary": {"type": "string", "minLength": 1, "maxLength": 1000}}}}}
            ]
        })
    }

    pub fn request_body(&self, r: &GenRequest) -> Vec<u8> {
        let salt: String = r.cache_salt.iter().map(|b| format!("{b:02x}")).collect();
        let reuse = r.cache_scope != conductor_core::cap::cache_scope::NONE;
        let mut body = serde_json::json!({
            "model": self.model,
            "messages": [{"role": "user", "content": r.prompt}],
            "max_tokens": r.max_out_units,
            "temperature": 0,
            "stream": true,
            "response_format": {"type": "json_schema", "json_schema": {"name": "conductor_reply", "strict": true, "schema": Self::reply_schema()}},
            // llama.cpp: reuse the prompt cache only when the capability allows it.
            "cache_prompt": reuse,
        });
        // vLLM: prefix-cache blocks are shared only between requests with the same salt. With no reuse
        // allowed, the salt is made unique so nothing can ever hit (or be hit by) this request.
        body["cache_salt"] = serde_json::Value::String(if reuse { salt } else { format!("{salt}-{}", unique()) });
        serde_json::to_vec(&body).unwrap_or_default()
    }
}

/// A value never repeated within this process (wall-clock nanoseconds plus a counter).
fn unique() -> String {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
    format!("{t:x}{:x}", N.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
}

impl Engine for OpenAiCompat {
    fn name(&self) -> String {
        format!("openai-compatible {} model {}", self.addr, self.model)
    }
    fn generate(&mut self, r: &GenRequest, sink: &mut dyn FnMut(&[u8]) -> bool) -> Result<GenStats, EngineError> {
        let start = Instant::now();
        let body = self.request_body(r);
        let path = format!("{}/v1/chat/completions", self.prefix);
        let stream = http::post_json(self.addr, &path, &body, self.timeout).map_err(EngineError::Http)?;
        let mut sse = SseLines::new(stream);
        let (mut total, mut ttft, mut pieces) = (0usize, None, 0u32);
        loop {
            if Instant::now() > r.deadline {
                return Err(EngineError::Deadline);
            }
            let Some(d) = sse.next_data().map_err(|e| EngineError::Http(HttpError::Io(e)))? else { break };
            if d == "[DONE]" {
                break;
            }
            let v: serde_json::Value = serde_json::from_str(&d).map_err(|_| EngineError::Protocol("event is not JSON"))?;
            let piece = v["choices"][0]["delta"]["content"].as_str().unwrap_or("");
            if piece.is_empty() {
                continue;
            }
            total += piece.len();
            if total > r.max_out_bytes || conductor_core::limits::units(total) > r.max_out_units {
                return Err(EngineError::TooLong);
            }
            ttft.get_or_insert(start.elapsed());
            pieces += 1;
            if !sink(piece.as_bytes()) {
                return Err(EngineError::Aborted);
            }
        }
        Ok(GenStats { ttft_ms: ttft.map_or(0, |d| d.as_millis() as u32), pieces, total_ms: start.elapsed().as_millis() as u32 })
    }
}
