//! BYO-LLM adapter configuration — env-var driven, air-gap-honest.
//!
//! The OS invariant this module exists to protect: **the model is the operator's choice.** No
//! vendor is hardcoded anywhere in this crate. The operator points at ANY OpenAI-compatible
//! `chat/completions` endpoint — a hosted API (OpenAI, Anthropic-compatible gateways, OpenRouter,
//! …) or a local **Ollama / llama.cpp / vLLM** server for air-gapped sites. Absence of
//! `HOOKPROBE_AI_ENDPOINT` (or `HOOKPROBE_AI_MODEL`) is the air-gap-default, HONEST "not
//! configured" state — [`LlmConfig::from_env`] returns `None`, never a fabricated default
//! endpoint. Every caller in this crate must treat `None` as "no AI planner configured" and stay
//! purely additive (see `plan::propose`'s first line).

use std::time::Duration;

/// Base URL env var, e.g. `https://api.openai.com/v1`, `http://127.0.0.1:11434/v1` (Ollama),
/// or a self-hosted vLLM/llama.cpp server's OpenAI-compatible base. `/chat/completions` is
/// appended by [`crate::adapter::Adapter::chat`] — do not include it here.
pub const ENV_ENDPOINT: &str = "HOOKPROBE_AI_ENDPOINT";
/// Model id passed in the request body's `"model"` field, e.g. `gpt-4o-mini`, `llama3.1:8b`.
pub const ENV_MODEL: &str = "HOOKPROBE_AI_MODEL";
/// Bearer token, when the endpoint requires one. Local Ollama/llama.cpp typically need none —
/// leave unset.
pub const ENV_API_KEY: &str = "HOOKPROBE_AI_API_KEY";
/// Request timeout in milliseconds. Defaults to [`DEFAULT_TIMEOUT_MS`] when unset or unparseable.
pub const ENV_TIMEOUT_MS: &str = "HOOKPROBE_AI_TIMEOUT_MS";

const DEFAULT_TIMEOUT_MS: u64 = 20_000;

/// A configured BYO-LLM endpoint. Constructing one always means the operator explicitly opted in
/// (see [`LlmConfig::from_env`]) — there is no `Default` impl and no constructor that fabricates a
/// base URL, by design.
#[derive(Debug, Clone, PartialEq)]
pub struct LlmConfig {
    /// Base URL of an OpenAI-compatible endpoint (trailing slash stripped).
    pub base_url: String,
    pub model: String,
    pub api_key: Option<String>,
    pub timeout: Duration,
}

impl LlmConfig {
    /// Read from the real process environment. `None` = the honest, air-gap-default "no AI
    /// planner configured" state — callers must not treat this as an error, only as "the planner
    /// is additive and currently off".
    pub fn from_env() -> Option<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Testable variant: any `Fn(&str) -> Option<String>` lookup instead of the real environment.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let base_url = get(ENV_ENDPOINT).filter(|s| !s.trim().is_empty())?;
        let model = get(ENV_MODEL).filter(|s| !s.trim().is_empty())?;
        let api_key = get(ENV_API_KEY).filter(|s| !s.trim().is_empty());
        let timeout_ms = get(ENV_TIMEOUT_MS)
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|&ms| ms > 0)
            .unwrap_or(DEFAULT_TIMEOUT_MS);
        Some(Self {
            base_url: base_url.trim().trim_end_matches('/').to_string(),
            model: model.trim().to_string(),
            api_key,
            timeout: Duration::from_millis(timeout_ms),
        })
    }

    /// A non-secret, human-readable identity for the explanation envelope's `model` field and
    /// logs — endpoint + model id, NEVER the API key.
    pub fn describe(&self) -> String {
        format!("{}::{}", self.base_url, self.model)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn lookup<'a>(map: &'a HashMap<&'a str, &'a str>) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| map.get(k).map(|v| v.to_string())
    }

    #[test]
    fn absent_endpoint_is_the_honest_no_config_path() {
        let map: HashMap<&str, &str> = HashMap::new();
        assert!(LlmConfig::from_lookup(lookup(&map)).is_none(), "no env vars at all -> None, never a fabricated default");
    }

    #[test]
    fn endpoint_without_model_is_still_not_configured() {
        let mut map = HashMap::new();
        map.insert(ENV_ENDPOINT, "http://127.0.0.1:11434/v1");
        assert!(LlmConfig::from_lookup(lookup(&map)).is_none(), "endpoint alone is not a complete config");
    }

    #[test]
    fn blank_endpoint_is_treated_as_absent() {
        let mut map = HashMap::new();
        map.insert(ENV_ENDPOINT, "   ");
        map.insert(ENV_MODEL, "llama3.1:8b");
        assert!(LlmConfig::from_lookup(lookup(&map)).is_none(), "whitespace-only endpoint must not count as configured");
    }

    #[test]
    fn full_config_parses_and_strips_trailing_slash() {
        let mut map = HashMap::new();
        map.insert(ENV_ENDPOINT, "http://127.0.0.1:11434/v1/");
        map.insert(ENV_MODEL, "llama3.1:8b");
        let cfg = LlmConfig::from_lookup(lookup(&map)).expect("fully configured");
        assert_eq!(cfg.base_url, "http://127.0.0.1:11434/v1");
        assert_eq!(cfg.model, "llama3.1:8b");
        assert!(cfg.api_key.is_none(), "no HOOKPROBE_AI_API_KEY set -> local Ollama needs none");
        assert_eq!(cfg.timeout, Duration::from_millis(DEFAULT_TIMEOUT_MS));
        assert_eq!(cfg.describe(), "http://127.0.0.1:11434/v1::llama3.1:8b");
    }

    #[test]
    fn api_key_and_custom_timeout_are_honored() {
        let mut map = HashMap::new();
        map.insert(ENV_ENDPOINT, "https://api.openai.com/v1");
        map.insert(ENV_MODEL, "gpt-4o-mini");
        map.insert(ENV_API_KEY, "sk-test-not-a-real-key");
        map.insert(ENV_TIMEOUT_MS, "5000");
        let cfg = LlmConfig::from_lookup(lookup(&map)).expect("fully configured");
        assert_eq!(cfg.api_key.as_deref(), Some("sk-test-not-a-real-key"));
        assert_eq!(cfg.timeout, Duration::from_millis(5000));
    }

    #[test]
    fn unparseable_or_zero_timeout_falls_back_to_default() {
        for bad in ["not-a-number", "0", "-5"] {
            let mut map = HashMap::new();
            map.insert(ENV_ENDPOINT, "http://127.0.0.1:11434/v1");
            map.insert(ENV_MODEL, "llama3.1:8b");
            map.insert(ENV_TIMEOUT_MS, bad);
            let cfg = LlmConfig::from_lookup(lookup(&map)).expect("fully configured");
            assert_eq!(cfg.timeout, Duration::from_millis(DEFAULT_TIMEOUT_MS), "bad timeout value {bad:?} must fall back safely");
        }
    }
}
