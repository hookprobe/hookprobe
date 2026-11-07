//! The BYO-LLM adapter — a minimal OpenAI-compatible `POST {base_url}/chat/completions` client.
//!
//! This is the ONLY place this crate talks to a network endpoint. It is intentionally dumb: build
//! a request, send it, return the assistant's raw text content (or a typed, non-fabricating
//! error). All "what does the text mean" logic lives in `schema`/`plan`, one layer up — this
//! module has no opinion about JSON envelopes, network intents, or diffs.
//!
//! Timeouts and failures are graceful: every error path returns an [`AdapterError`] variant, never
//! a panic, and never synthesizes a fake successful response.

use crate::config::LlmConfig;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Every way a BYO-LLM call can honestly fail. Deliberately narrow — this enum has no variant
/// that carries an "action to perform"; it only ever carries diagnostic information about a
/// failed HTTP round-trip.
#[derive(Debug)]
pub enum AdapterError {
    /// No model configured (see [`LlmConfig::from_env`]) — the caller should never have
    /// constructed an [`Adapter`] in this state; kept as a variant so a defensive check can still
    /// surface it uniformly alongside the other cases.
    NotConfigured,
    /// The request timed out against the configured [`LlmConfig::timeout`].
    Timeout,
    /// Could not even reach the endpoint (DNS/connect/TLS/transport failure).
    Network(String),
    /// The endpoint answered with a non-2xx status. `body` is truncated to a bounded preview so a
    /// noisy error page can never blow up a log line or the UI's error panel.
    Http { status: u16, body: String },
    /// The response body was not the JSON shape an OpenAI-compatible `chat/completions` response
    /// must have (or contained zero choices).
    BadResponse(String),
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdapterError::NotConfigured => write!(f, "no AI model configured"),
            AdapterError::Timeout => write!(f, "request to the AI endpoint timed out"),
            AdapterError::Network(e) => write!(f, "could not reach the AI endpoint: {e}"),
            AdapterError::Http { status, body } => write!(f, "AI endpoint returned HTTP {status}: {body}"),
            AdapterError::BadResponse(e) => write!(f, "AI endpoint returned an unexpected response: {e}"),
        }
    }
}
impl std::error::Error for AdapterError {}

const BODY_PREVIEW_MAX: usize = 2048;

#[derive(Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<ChatMessage<'a>>,
    temperature: f64,
}

#[derive(Deserialize)]
struct ChatChoiceMessage {
    #[serde(default)]
    content: String,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatChoiceMessage,
}

#[derive(Deserialize, Default)]
struct ChatResponse {
    #[serde(default)]
    choices: Vec<ChatChoice>,
}

/// A configured BYO-LLM client. Cheap to construct — holds only the config, no connection state.
pub struct Adapter {
    cfg: LlmConfig,
}

impl Adapter {
    pub fn new(cfg: LlmConfig) -> Self {
        Self { cfg }
    }

    /// Non-secret identity for the explanation envelope's `model` field — endpoint + model id,
    /// never the API key.
    pub fn describe(&self) -> String {
        self.cfg.describe()
    }

    /// One system+user turn → the assistant's raw text content. Zero temperature (deterministic
    /// as far as the endpoint allows) — this is a planning tool, not a creative one.
    pub fn chat(&self, system: &str, user: &str) -> Result<String, AdapterError> {
        let url = format!("{}/chat/completions", self.cfg.base_url);
        let body = ChatRequest {
            model: &self.cfg.model,
            messages: vec![
                ChatMessage { role: "system", content: system },
                ChatMessage { role: "user", content: user },
            ],
            temperature: 0.0,
        };

        let agent_config = ureq::Agent::config_builder()
            .timeout_global(Some(self.cfg.timeout))
            // We want the response body even on 4xx/5xx (a real operator-facing error message,
            // e.g. an invalid API key), so status is checked manually below rather than turned
            // into an early transport error.
            .http_status_as_error(false)
            .build();
        let agent: ureq::Agent = agent_config.into();

        let mut req = agent.post(&url).header("content-type", "application/json");
        if let Some(key) = &self.cfg.api_key {
            req = req.header("authorization", &format!("Bearer {key}"));
        }

        let mut resp = req.send_json(&body).map_err(map_transport_err)?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            let text = resp.body_mut().read_to_string().unwrap_or_default();
            return Err(AdapterError::Http { status, body: truncate(&text, BODY_PREVIEW_MAX) });
        }

        let parsed: ChatResponse = resp
            .body_mut()
            .read_json()
            .map_err(|e| AdapterError::BadResponse(format!("invalid chat-completions JSON: {e}")))?;

        parsed
            .choices
            .into_iter()
            .next()
            .map(|c| c.message.content)
            .ok_or_else(|| AdapterError::BadResponse("response had zero choices".to_string()))
    }
}

fn map_transport_err(e: ureq::Error) -> AdapterError {
    match e {
        ureq::Error::Timeout(_) => AdapterError::Timeout,
        other => AdapterError::Network(other.to_string()),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}… (truncated)", &s[..max])
    }
}

// `feature = "test-util"` (not just `cfg(test)`): `main.rs`'s own test module lives in a
// DIFFERENT compilation of this package (the `[[bin]]` target) than `src/lib.rs`'s `cfg(test)`
// unit tests do — a `--bin` test build depends on the freshly-built LIB **without** `--cfg test`,
// so a plain `#[cfg(test)]` item here would be invisible to `main.rs`'s tests. The crate lists
// itself as a `dev-dependency` with `features = ["test-util"]` (see `Cargo.toml`) to make this
// module `pub` in that build instead — the standard workaround for sharing test fixtures across a
// package's own lib+bin targets.
#[cfg(any(test, feature = "test-util"))]
pub mod test_server {
    //! A tiny, dependency-free HTTP/1.1 fixture server for adapter tests — no mock-http crate
    //! pulled in for ~40 lines of "listen, read one request, write one canned response".
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    /// Starts a background thread that accepts exactly ONE connection, reads the request (up to
    /// the blank line + a bounded body read), and replies with `status_line` + `body`. Returns the
    /// `http://127.0.0.1:<port>` base URL. The thread is detached — fine for short-lived tests.
    pub fn serve_once(status_line: &'static str, content_type: &'static str, body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 8192];
                let _ = stream.read(&mut buf); // don't care about parsing the request for this fixture
                let response = format!(
                    "{status_line}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    /// Starts a background thread that accepts a connection and then simply sleeps past any
    /// reasonable test timeout without ever writing a response — used to exercise the
    /// [`super::AdapterError::Timeout`] path deterministically.
    pub fn serve_hang(hang: Duration) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                thread::sleep(hang);
                drop(stream);
            }
        });
        format!("http://127.0.0.1:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::test_server::*;
    use super::*;
    use std::time::Duration;

    fn cfg_for(base_url: String) -> LlmConfig {
        LlmConfig { base_url, model: "test-model".to_string(), api_key: None, timeout: Duration::from_secs(2) }
    }

    #[test]
    fn happy_path_returns_the_assistant_content() {
        let body = r#"{"choices":[{"message":{"role":"assistant","content":"hello from the fixture"}}]}"#;
        let base = serve_once("HTTP/1.1 200 OK", "application/json", body);
        let adapter = Adapter::new(cfg_for(base));
        let out = adapter.chat("sys", "user").expect("chat should succeed");
        assert_eq!(out, "hello from the fixture");
    }

    #[test]
    fn non_2xx_status_is_reported_with_the_body() {
        let base = serve_once("HTTP/1.1 401 Unauthorized", "application/json", r#"{"error":"invalid api key"}"#);
        let adapter = Adapter::new(cfg_for(base));
        let err = adapter.chat("sys", "user").expect_err("401 must be an error, not a fabricated success");
        match err {
            AdapterError::Http { status, body } => {
                assert_eq!(status, 401);
                assert!(body.contains("invalid api key"), "real endpoint error body must surface: {body}");
            }
            other => panic!("expected Http, got {other:?}"),
        }
    }

    #[test]
    fn malformed_json_body_is_a_bad_response_not_a_panic() {
        let base = serve_once("HTTP/1.1 200 OK", "application/json", "not json at all");
        let adapter = Adapter::new(cfg_for(base));
        let err = adapter.chat("sys", "user").expect_err("malformed JSON must error, not panic");
        assert!(matches!(err, AdapterError::BadResponse(_)));
    }

    #[test]
    fn zero_choices_is_a_bad_response() {
        let base = serve_once("HTTP/1.1 200 OK", "application/json", r#"{"choices":[]}"#);
        let adapter = Adapter::new(cfg_for(base));
        let err = adapter.chat("sys", "user").expect_err("zero choices must error");
        assert!(matches!(err, AdapterError::BadResponse(_)));
    }

    #[test]
    fn unreachable_endpoint_is_a_network_error_never_a_panic() {
        // Nothing is listening on this port — a real, honest connection failure.
        let adapter = Adapter::new(cfg_for("http://127.0.0.1:1".to_string()));
        let err = adapter.chat("sys", "user").expect_err("an unreachable endpoint must error gracefully");
        assert!(matches!(err, AdapterError::Network(_)), "expected Network, got {err:?}");
    }

    #[test]
    fn slow_endpoint_times_out_gracefully() {
        let base = serve_hang(Duration::from_secs(30));
        let mut cfg = cfg_for(base);
        cfg.timeout = Duration::from_millis(200);
        let adapter = Adapter::new(cfg);
        let err = adapter.chat("sys", "user").expect_err("a hung endpoint must time out, not hang the caller forever");
        assert!(matches!(err, AdapterError::Timeout), "expected Timeout, got {err:?}");
    }
}
