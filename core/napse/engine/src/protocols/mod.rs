//! # Protocol Parsers
//!
//! Application-layer protocol parsers for NAPSE. Each parser implements the
//! [`ProtocolParser`] trait and produces typed [`ProtocolEvent`] values that
//! are forwarded to the engine's event pipeline.
//!
//! ## Supported Protocols
//!
//! | Module   | Protocol            | Well-Known Ports  |
//! |----------|---------------------|-------------------|
//! | `dns`    | DNS                 | 53/udp, 53/tcp    |
//! | `mdns`   | mDNS                | 5353/udp          |
//! | `tcp`    | TCP state tracking  | (any)             |
//! | `tls`    | TLS/SSL             | 443, 8443         |
//! | `http`   | HTTP/1.1            | 80, 8080          |
//! | `dhcp`   | DHCP                | 67/68             |
//! | `ssh`    | SSH                 | 22                |
//!
//! ## Adding a New Protocol
//!
//! 1. Create a new module file `src/protocols/<name>.rs`
//! 2. Declare the module in this file
//! 3. Implement [`ProtocolParser`] for your parser struct
//! 4. Add the corresponding [`ProtocolEvent`] variant
//! 5. Register the parser in the engine's protocol dispatch table

pub mod dhcp;
pub mod dns;
pub mod http;
pub mod mdns;
pub mod ssh;
pub mod tcp;
pub mod tls;

use crate::conntrack::FlowKey;

// ---------------------------------------------------------------------------
// Direction
// ---------------------------------------------------------------------------

/// Packet direction relative to the connection originator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Packet from the connection originator (client).
    Originator,
    /// Packet from the connection responder (server).
    Responder,
}

// ---------------------------------------------------------------------------
// Protocol Events
// ---------------------------------------------------------------------------

/// Typed event produced by a protocol parser.
///
/// Each variant carries the parser-specific output struct. The engine
/// collects these events and dispatches them to the appropriate output
/// channels (Python record drains, alert pipeline, etc.).
#[derive(Debug, Clone)]
pub enum ProtocolEvent {
    /// A DNS query or response was parsed.
    Dns(dns::DnsEvent),
    /// An mDNS service discovery event was observed.
    Mdns(mdns::MdnsEvent),
    /// A TCP state transition occurred.
    Tcp(tcp::TcpEvent),
    /// A TLS handshake message was parsed.
    Tls(tls::TlsEvent),
    /// An HTTP request or response was parsed.
    Http(http::HttpEvent),
    /// A DHCP message was parsed.
    Dhcp(dhcp::DhcpEvent),
    /// An SSH protocol event was observed.
    Ssh(ssh::SshEvent),
}

// ---------------------------------------------------------------------------
// ProtocolParser trait
// ---------------------------------------------------------------------------

/// Trait for application-layer protocol parsers.
///
/// Each parser maintains per-connection state and is driven by the engine
/// as packets arrive. Parsers produce [`ProtocolEvent`] values that the
/// engine forwards to the output pipeline.
///
/// # Lifetime
///
/// Parser instances may be pooled or created per-connection depending on
/// the protocol's statefulness requirements.
pub trait ProtocolParser: Send + Sync {
    /// Parse a payload chunk and return any events produced.
    ///
    /// # Arguments
    ///
    /// * `flow` - The 5-tuple identifying this connection
    /// * `direction` - Whether the payload is from the originator or responder
    /// * `payload` - Raw application-layer bytes
    /// * `ts` - Packet timestamp (Unix epoch seconds)
    ///
    /// # Returns
    ///
    /// A vector of events. May be empty if the parser is accumulating
    /// data across multiple packets (e.g., TCP reassembly for HTTP).
    fn parse(
        &self,
        flow: &FlowKey,
        direction: Direction,
        payload: &[u8],
        ts: f64,
    ) -> Vec<ProtocolEvent>;

    /// Return the idle timeout for this protocol's connection state.
    ///
    /// After this many seconds without data, the parser's per-connection
    /// state may be evicted.
    fn timeout(&self) -> f64;

    /// Return a human-readable protocol identifier.
    fn protocol_id(&self) -> &'static str;
}
