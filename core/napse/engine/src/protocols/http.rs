//! # HTTP/1.1 Protocol Parser
//!
//! Parses HTTP/1.1 requests and responses from TCP payload data. Extracts
//! method, host, URI, headers (User-Agent, Referer, Content-Type), status
//! code, and body lengths.
//!
//! Output is compatible with Zeek `http.log` fields.
//!
//! ## Limitations
//!
//! - Only HTTP/1.1 is supported (not HTTP/2 or HTTP/3).
//! - Chunked transfer encoding is detected but body is not reassembled.
//! - Pipelined requests are not yet handled.
//! - Does not perform TCP reassembly (relies on single-packet messages or
//!   upstream reassembly).

use std::collections::HashMap;

use crate::conntrack::FlowKey;
use crate::protocols::{Direction, ProtocolEvent, ProtocolParser};

// ---------------------------------------------------------------------------
// HTTP event
// ---------------------------------------------------------------------------

/// Parsed HTTP request/response event.
#[derive(Debug, Clone)]
pub struct HttpEvent {
    /// HTTP method (GET, POST, etc.) -- empty for responses.
    pub method: String,
    /// Host header value.
    pub host: String,
    /// Request URI (path + query).
    pub uri: String,
    /// User-Agent header.
    pub user_agent: String,
    /// Referer header.
    pub referer: String,
    /// HTTP version string (e.g., "1.1").
    pub version: String,
    /// Response status code (0 for requests).
    pub status_code: u16,
    /// Response status message.
    pub status_msg: String,
    /// Content-Type header.
    pub content_type: String,
    /// Content-Length header value.
    pub content_length: u64,
    /// Request body length (bytes seen).
    pub request_body_len: u64,
    /// Response body length (bytes seen).
    pub response_body_len: u64,
    /// Whether this is a request or response.
    pub is_request: bool,
    /// All extracted headers.
    pub headers: HashMap<String, String>,
    /// Packet timestamp.
    pub ts: f64,
}

// ---------------------------------------------------------------------------
// HttpParser
// ---------------------------------------------------------------------------

/// HTTP/1.1 protocol parser.
///
/// Stateless per-packet parser that identifies HTTP requests and responses
/// from their first line and extracts relevant headers.
pub struct HttpParser;

impl HttpParser {
    /// Create a new HTTP parser.
    pub fn new() -> Self {
        Self
    }

    /// Attempt to parse an HTTP request from raw bytes.
    fn parse_request(&self, payload: &[u8], ts: f64) -> Option<HttpEvent> {
        let text = std::str::from_utf8(payload).ok()?;

        // Find the end of the first line
        let first_line_end = text.find("\r\n")?;
        let first_line = &text[..first_line_end];

        // Parse: METHOD URI HTTP/VERSION
        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() != 3 {
            return None;
        }

        let method = parts[0];
        let uri = parts[1];
        let version_part = parts[2];

        // Validate it looks like an HTTP request
        if !version_part.starts_with("HTTP/") {
            return None;
        }

        // Validate method
        let valid_methods = [
            "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT",
        ];
        if !valid_methods.contains(&method) {
            return None;
        }

        let version = version_part.trim_start_matches("HTTP/").to_string();

        // Parse headers
        let headers = self.parse_headers(&text[first_line_end + 2..]);

        let host = headers
            .get("host")
            .cloned()
            .unwrap_or_default();
        let user_agent = headers
            .get("user-agent")
            .cloned()
            .unwrap_or_default();
        let referer = headers
            .get("referer")
            .cloned()
            .unwrap_or_default();
        let content_type = headers
            .get("content-type")
            .cloned()
            .unwrap_or_default();
        let content_length: u64 = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        Some(HttpEvent {
            method: method.to_string(),
            host,
            uri: uri.to_string(),
            user_agent,
            referer,
            version,
            status_code: 0,
            status_msg: String::new(),
            content_type,
            content_length,
            request_body_len: content_length,
            response_body_len: 0,
            is_request: true,
            headers,
            ts,
        })
    }

    /// Attempt to parse an HTTP response from raw bytes.
    fn parse_response(&self, payload: &[u8], ts: f64) -> Option<HttpEvent> {
        let text = std::str::from_utf8(payload).ok()?;

        // Find the end of the first line
        let first_line_end = text.find("\r\n")?;
        let first_line = &text[..first_line_end];

        // Parse: HTTP/VERSION STATUS_CODE STATUS_MSG
        if !first_line.starts_with("HTTP/") {
            return None;
        }

        let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return None;
        }

        let version = parts[0].trim_start_matches("HTTP/").to_string();
        let status_code: u16 = parts[1].parse().ok()?;
        let status_msg = if parts.len() > 2 {
            parts[2].to_string()
        } else {
            String::new()
        };

        // Parse headers
        let headers = self.parse_headers(&text[first_line_end + 2..]);

        let content_type = headers
            .get("content-type")
            .cloned()
            .unwrap_or_default();
        let content_length: u64 = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        Some(HttpEvent {
            method: String::new(),
            host: String::new(),
            uri: String::new(),
            user_agent: String::new(),
            referer: String::new(),
            version,
            status_code,
            status_msg,
            content_type,
            content_length,
            request_body_len: 0,
            response_body_len: content_length,
            is_request: false,
            headers,
            ts,
        })
    }

    /// Parse HTTP headers from text after the first line.
    ///
    /// Returns a map of lowercase header names to values.
    fn parse_headers(&self, text: &str) -> HashMap<String, String> {
        let mut headers = HashMap::new();

        for line in text.split("\r\n") {
            if line.is_empty() {
                break; // End of headers
            }

            if let Some(colon_pos) = line.find(':') {
                let name = line[..colon_pos].trim().to_lowercase();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.insert(name, value);
            }
        }

        headers
    }
}

impl ProtocolParser for HttpParser {
    fn parse(
        &self,
        _flow: &FlowKey,
        direction: Direction,
        payload: &[u8],
        ts: f64,
    ) -> Vec<ProtocolEvent> {
        let mut events = Vec::new();

        match direction {
            Direction::Originator => {
                if let Some(event) = self.parse_request(payload, ts) {
                    events.push(ProtocolEvent::Http(event));
                }
            }
            Direction::Responder => {
                if let Some(event) = self.parse_response(payload, ts) {
                    events.push(ProtocolEvent::Http(event));
                }
            }
        }

        events
    }

    fn timeout(&self) -> f64 {
        120.0 // HTTP keep-alive timeout
    }

    fn protocol_id(&self) -> &'static str {
        "http"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_get_request() {
        let parser = HttpParser::new();
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
        let flow = FlowKey::new("10.0.0.1".into(), "10.0.0.2".into(), 12345, 80, 6);

        let events = parser.parse(&flow, Direction::Originator, payload, 1000.0);
        assert_eq!(events.len(), 1);

        match &events[0] {
            ProtocolEvent::Http(event) => {
                assert_eq!(event.method, "GET");
                assert_eq!(event.uri, "/index.html");
                assert_eq!(event.host, "example.com");
                assert_eq!(event.user_agent, "Mozilla/5.0");
                assert!(event.is_request);
            }
            _ => panic!("Expected HttpEvent"),
        }
    }

    #[test]
    fn test_parse_post_request() {
        let parser = HttpParser::new();
        let payload = b"POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 42\r\n\r\n";
        let flow = FlowKey::new("10.0.0.1".into(), "10.0.0.2".into(), 12345, 80, 6);

        let events = parser.parse(&flow, Direction::Originator, payload, 1000.0);
        assert_eq!(events.len(), 1);

        match &events[0] {
            ProtocolEvent::Http(event) => {
                assert_eq!(event.method, "POST");
                assert_eq!(event.content_type, "application/json");
                assert_eq!(event.content_length, 42);
            }
            _ => panic!("Expected HttpEvent"),
        }
    }

    #[test]
    fn test_parse_response() {
        let parser = HttpParser::new();
        let payload = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 1234\r\n\r\n";
        let flow = FlowKey::new("10.0.0.2".into(), "10.0.0.1".into(), 80, 12345, 6);

        let events = parser.parse(&flow, Direction::Responder, payload, 1000.0);
        assert_eq!(events.len(), 1);

        match &events[0] {
            ProtocolEvent::Http(event) => {
                assert_eq!(event.status_code, 200);
                assert_eq!(event.status_msg, "OK");
                assert_eq!(event.content_type, "text/html");
                assert!(!event.is_request);
            }
            _ => panic!("Expected HttpEvent"),
        }
    }

    #[test]
    fn test_parse_404_response() {
        let parser = HttpParser::new();
        let payload = b"HTTP/1.1 404 Not Found\r\n\r\n";
        let flow = FlowKey::new("10.0.0.2".into(), "10.0.0.1".into(), 80, 12345, 6);

        let events = parser.parse(&flow, Direction::Responder, payload, 1000.0);
        assert_eq!(events.len(), 1);

        match &events[0] {
            ProtocolEvent::Http(event) => {
                assert_eq!(event.status_code, 404);
            }
            _ => panic!("Expected HttpEvent"),
        }
    }

    #[test]
    fn test_non_http_payload() {
        let parser = HttpParser::new();
        let payload = b"\x16\x03\x01\x00\xf1"; // TLS record header
        let flow = FlowKey::new("10.0.0.1".into(), "10.0.0.2".into(), 12345, 80, 6);

        let events = parser.parse(&flow, Direction::Originator, payload, 1000.0);
        assert!(events.is_empty());
    }

    #[test]
    fn test_parse_headers() {
        let parser = HttpParser::new();
        let text = "Host: example.com\r\nContent-Type: text/html\r\nX-Custom: value\r\n\r\n";
        let headers = parser.parse_headers(text);

        assert_eq!(headers.get("host").unwrap(), "example.com");
        assert_eq!(headers.get("content-type").unwrap(), "text/html");
        assert_eq!(headers.get("x-custom").unwrap(), "value");
    }
}
