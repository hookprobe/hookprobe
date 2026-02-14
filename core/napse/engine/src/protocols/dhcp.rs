//! # DHCP Protocol Parser
//!
//! Parses DHCP Discover, Offer, Request, and ACK messages. Extracts device
//! fingerprinting data including Option 55 (Parameter Request List),
//! hostname, vendor class identifier, and client MAC address.
//!
//! ## Device Fingerprinting
//!
//! DHCP Option 55 is the primary fingerprinting signal. Different operating
//! systems and device types request different DHCP parameters in a
//! characteristic order. Combined with vendor class and hostname, this
//! enables high-confidence device identification without deep packet
//! inspection.
//!
//! ## Wire Format Reference
//!
//! ```text
//! DHCP Message (over BOOTP):
//!   op       (1 byte) - 1=BOOTREQUEST, 2=BOOTREPLY
//!   htype    (1 byte) - Hardware type (1=Ethernet)
//!   hlen     (1 byte) - Hardware address length (6 for MAC)
//!   hops     (1 byte)
//!   xid      (4 bytes) - Transaction ID
//!   secs     (2 bytes)
//!   flags    (2 bytes)
//!   ciaddr   (4 bytes) - Client IP
//!   yiaddr   (4 bytes) - Your (assigned) IP
//!   siaddr   (4 bytes) - Server IP
//!   giaddr   (4 bytes) - Gateway IP
//!   chaddr   (16 bytes) - Client hardware address
//!   sname    (64 bytes) - Server hostname
//!   file     (128 bytes) - Boot filename
//!   magic    (4 bytes) - 0x63825363
//!   options  (variable)
//! ```

use crate::conntrack::FlowKey;
use crate::protocols::{Direction, ProtocolEvent, ProtocolParser};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// DHCP magic cookie: 0x63825363
const DHCP_MAGIC: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// Minimum DHCP message size (BOOTP header + magic cookie).
const MIN_DHCP_LEN: usize = 240;

/// DHCP option codes.
const OPT_PAD: u8 = 0;
const OPT_SUBNET_MASK: u8 = 1;
const OPT_HOSTNAME: u8 = 12;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MESSAGE_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAM_REQUEST: u8 = 55;
const OPT_VENDOR_CLASS: u8 = 60;
const OPT_CLIENT_ID: u8 = 61;
const OPT_END: u8 = 255;

/// DHCP message types.
const DHCP_DISCOVER: u8 = 1;
const DHCP_OFFER: u8 = 2;
const DHCP_REQUEST: u8 = 3;
const DHCP_DECLINE: u8 = 4;
const DHCP_ACK: u8 = 5;
const DHCP_NAK: u8 = 6;
const DHCP_RELEASE: u8 = 7;
const DHCP_INFORM: u8 = 8;

// ---------------------------------------------------------------------------
// DHCP event
// ---------------------------------------------------------------------------

/// Parsed DHCP event for device fingerprinting and network tracking.
#[derive(Debug, Clone)]
pub struct DhcpEvent {
    /// DHCP message type (Discover, Offer, Request, ACK, etc.).
    pub message_type: DhcpMessageType,
    /// Client MAC address.
    pub client_mac: String,
    /// Assigned IP address (from YIADDR or Requested IP option).
    pub assigned_ip: String,
    /// Client hostname (Option 12).
    pub hostname: String,
    /// Vendor class identifier (Option 60).
    pub vendor_class: String,
    /// Parameter Request List (Option 55) -- device fingerprint.
    pub param_request_list: Vec<u8>,
    /// Fingerprint string: comma-separated Option 55 values.
    pub fingerprint: String,
    /// Lease time in seconds (Option 51).
    pub lease_time: u32,
    /// DHCP server IP (Option 54 or SIADDR).
    pub server_ip: String,
    /// Transaction ID.
    pub xid: u32,
    /// Packet timestamp.
    pub ts: f64,
}

/// DHCP message type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpMessageType {
    Discover,
    Offer,
    Request,
    Decline,
    Ack,
    Nak,
    Release,
    Inform,
    Unknown(u8),
}

impl DhcpMessageType {
    fn from_byte(b: u8) -> Self {
        match b {
            DHCP_DISCOVER => Self::Discover,
            DHCP_OFFER => Self::Offer,
            DHCP_REQUEST => Self::Request,
            DHCP_DECLINE => Self::Decline,
            DHCP_ACK => Self::Ack,
            DHCP_NAK => Self::Nak,
            DHCP_RELEASE => Self::Release,
            DHCP_INFORM => Self::Inform,
            other => Self::Unknown(other),
        }
    }

    /// Return the message type name as a string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Discover => "DISCOVER",
            Self::Offer => "OFFER",
            Self::Request => "REQUEST",
            Self::Decline => "DECLINE",
            Self::Ack => "ACK",
            Self::Nak => "NAK",
            Self::Release => "RELEASE",
            Self::Inform => "INFORM",
            Self::Unknown(_) => "UNKNOWN",
        }
    }
}

// ---------------------------------------------------------------------------
// DhcpParser
// ---------------------------------------------------------------------------

/// DHCP protocol parser for device fingerprinting and lease tracking.
///
/// Extracts all relevant DHCP options from messages on ports 67/68.
pub struct DhcpParser;

impl DhcpParser {
    /// Create a new DHCP parser.
    pub fn new() -> Self {
        Self
    }

    /// Parse a DHCP message from raw UDP payload.
    fn parse_message(&self, payload: &[u8], ts: f64) -> Option<DhcpEvent> {
        if payload.len() < MIN_DHCP_LEN {
            return None;
        }

        // Verify DHCP magic cookie at offset 236
        if payload[236..240] != DHCP_MAGIC {
            return None;
        }

        // Extract BOOTP header fields
        let _op = payload[0]; // 1=request, 2=reply
        let _htype = payload[1];
        let hlen = payload[2] as usize;
        let xid = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);

        // Client IP (ciaddr) at offset 12
        let _ciaddr = format!(
            "{}.{}.{}.{}",
            payload[12], payload[13], payload[14], payload[15]
        );

        // Your IP (yiaddr) at offset 16
        let yiaddr = format!(
            "{}.{}.{}.{}",
            payload[16], payload[17], payload[18], payload[19]
        );

        // Server IP (siaddr) at offset 20
        let siaddr = format!(
            "{}.{}.{}.{}",
            payload[20], payload[21], payload[22], payload[23]
        );

        // Client MAC (chaddr) at offset 28, length = hlen (max 16 bytes)
        let mac_len = hlen.min(6);
        let client_mac = if mac_len == 6 {
            format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                payload[28], payload[29], payload[30], payload[31], payload[32], payload[33]
            )
        } else {
            String::new()
        };

        // Parse DHCP options starting at offset 240
        let mut offset = 240;
        let mut message_type = DhcpMessageType::Unknown(0);
        let mut hostname = String::new();
        let mut vendor_class = String::new();
        let mut param_request_list = Vec::new();
        let mut lease_time: u32 = 0;
        let mut server_ip = siaddr.clone();
        let mut requested_ip = String::new();

        while offset < payload.len() {
            let opt_code = payload[offset];

            match opt_code {
                OPT_PAD => {
                    offset += 1;
                    continue;
                }
                OPT_END => break,
                _ => {}
            }

            // All other options have length byte
            offset += 1;
            if offset >= payload.len() {
                break;
            }
            let opt_len = payload[offset] as usize;
            offset += 1;

            if offset + opt_len > payload.len() {
                break;
            }

            let opt_data = &payload[offset..offset + opt_len];

            match opt_code {
                OPT_MESSAGE_TYPE if opt_len >= 1 => {
                    message_type = DhcpMessageType::from_byte(opt_data[0]);
                }
                OPT_HOSTNAME => {
                    hostname = String::from_utf8_lossy(opt_data).to_string();
                }
                OPT_VENDOR_CLASS => {
                    vendor_class = String::from_utf8_lossy(opt_data).to_string();
                }
                OPT_PARAM_REQUEST => {
                    param_request_list = opt_data.to_vec();
                }
                OPT_LEASE_TIME if opt_len >= 4 => {
                    lease_time =
                        u32::from_be_bytes([opt_data[0], opt_data[1], opt_data[2], opt_data[3]]);
                }
                OPT_SERVER_ID if opt_len >= 4 => {
                    server_ip = format!(
                        "{}.{}.{}.{}",
                        opt_data[0], opt_data[1], opt_data[2], opt_data[3]
                    );
                }
                OPT_REQUESTED_IP if opt_len >= 4 => {
                    requested_ip = format!(
                        "{}.{}.{}.{}",
                        opt_data[0], opt_data[1], opt_data[2], opt_data[3]
                    );
                }
                _ => {} // Ignore unknown options
            }

            offset += opt_len;
        }

        // Build fingerprint string from Option 55
        let fingerprint = param_request_list
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(",");

        // Determine assigned IP: prefer yiaddr, fall back to requested_ip
        let assigned_ip = if yiaddr != "0.0.0.0" {
            yiaddr
        } else {
            requested_ip
        };

        Some(DhcpEvent {
            message_type,
            client_mac,
            assigned_ip,
            hostname,
            vendor_class,
            param_request_list,
            fingerprint,
            lease_time,
            server_ip,
            xid,
            ts,
        })
    }
}

impl ProtocolParser for DhcpParser {
    fn parse(
        &self,
        _flow: &FlowKey,
        _direction: Direction,
        payload: &[u8],
        ts: f64,
    ) -> Vec<ProtocolEvent> {
        match self.parse_message(payload, ts) {
            Some(event) => vec![ProtocolEvent::Dhcp(event)],
            None => vec![],
        }
    }

    fn timeout(&self) -> f64 {
        60.0 // DHCP transactions are short
    }

    fn protocol_id(&self) -> &'static str {
        "dhcp"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dhcp_message_type_from_byte() {
        assert_eq!(DhcpMessageType::from_byte(1), DhcpMessageType::Discover);
        assert_eq!(DhcpMessageType::from_byte(5), DhcpMessageType::Ack);
        assert!(matches!(
            DhcpMessageType::from_byte(99),
            DhcpMessageType::Unknown(99)
        ));
    }

    #[test]
    fn test_dhcp_message_type_as_str() {
        assert_eq!(DhcpMessageType::Discover.as_str(), "DISCOVER");
        assert_eq!(DhcpMessageType::Ack.as_str(), "ACK");
        assert_eq!(DhcpMessageType::Unknown(99).as_str(), "UNKNOWN");
    }

    #[test]
    fn test_parse_too_short() {
        let parser = DhcpParser::new();
        let flow = FlowKey::new("0.0.0.0".into(), "255.255.255.255".into(), 68, 67, 17);
        let events = parser.parse(&flow, Direction::Originator, b"short", 1000.0);
        assert!(events.is_empty());
    }

    #[test]
    fn test_parse_invalid_magic() {
        let parser = DhcpParser::new();
        let mut payload = vec![0u8; 300];
        // Wrong magic cookie
        payload[236] = 0x00;
        payload[237] = 0x00;
        payload[238] = 0x00;
        payload[239] = 0x00;

        let flow = FlowKey::new("0.0.0.0".into(), "255.255.255.255".into(), 68, 67, 17);
        let events = parser.parse(&flow, Direction::Originator, &payload, 1000.0);
        assert!(events.is_empty());
    }

    #[test]
    fn test_parse_discover() {
        let parser = DhcpParser::new();

        // Build a minimal DHCP Discover message
        let mut payload = vec![0u8; 300];

        // BOOTP header
        payload[0] = 1; // BOOTREQUEST
        payload[1] = 1; // Ethernet
        payload[2] = 6; // MAC length

        // XID
        payload[4] = 0x12;
        payload[5] = 0x34;
        payload[6] = 0x56;
        payload[7] = 0x78;

        // Client MAC at offset 28
        payload[28] = 0xAA;
        payload[29] = 0xBB;
        payload[30] = 0xCC;
        payload[31] = 0xDD;
        payload[32] = 0xEE;
        payload[33] = 0xFF;

        // DHCP magic cookie at offset 236
        payload[236..240].copy_from_slice(&DHCP_MAGIC);

        // Option 53 (Message Type) = 1 (Discover)
        payload[240] = OPT_MESSAGE_TYPE;
        payload[241] = 1; // length
        payload[242] = 1; // DISCOVER

        // Option 55 (Parameter Request List)
        payload[243] = OPT_PARAM_REQUEST;
        payload[244] = 4; // length
        payload[245] = 1; // Subnet Mask
        payload[246] = 3; // Router
        payload[247] = 6; // DNS
        payload[248] = 15; // Domain Name

        // Option 12 (Hostname)
        payload[249] = OPT_HOSTNAME;
        payload[250] = 6; // length
        payload[251..257].copy_from_slice(b"myhost");

        // End
        payload[257] = OPT_END;

        let flow = FlowKey::new("0.0.0.0".into(), "255.255.255.255".into(), 68, 67, 17);
        let events = parser.parse(&flow, Direction::Originator, &payload, 1000.0);
        assert_eq!(events.len(), 1);

        match &events[0] {
            ProtocolEvent::Dhcp(event) => {
                assert_eq!(event.message_type, DhcpMessageType::Discover);
                assert_eq!(event.client_mac, "aa:bb:cc:dd:ee:ff");
                assert_eq!(event.hostname, "myhost");
                assert_eq!(event.param_request_list, vec![1, 3, 6, 15]);
                assert_eq!(event.fingerprint, "1,3,6,15");
                assert_eq!(event.xid, 0x12345678);
            }
            _ => panic!("Expected DhcpEvent"),
        }
    }
}
