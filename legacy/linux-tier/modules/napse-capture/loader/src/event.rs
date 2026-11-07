//! The bridge from the kernel detection ringbuf to the SOC flow stream: parse a raw `napse_event`
//! (32-byte record emitted by napse_detect.bpf.c) and render it as one JSON line in NAPSE's exact
//! `parse_record` contract (`/var/lib/hookprobe/flows`). Pure + fully unit-tested — no BPF needed.
//!
//! Layout MUST match `modules/napse-capture/bpf/napse_detect.h` `struct napse_event` (repr C):
//! ```text
//!   u64 ts_ns; u32 saddr; u32 daddr; u16 sport; u16 dport;
//!   u8 proto; u8 role; u8 verdict; u8 reason; u32 ifindex; u32 pkt_len;   // = 32 bytes
//! ```
//! `saddr`/`daddr` hold NETWORK-order bytes (kernel `__be32`); `sport`/`dport` are host order.

use std::net::Ipv4Addr;

pub const EVENT_SIZE: usize = 32;

/// enum napse_verdict
const V_DROP: u8 = 1;
/// enum napse_reason (must match napse_detect.h)
const R_ESTABLISHED: u8 = 1;
const R_NEW_FLOW: u8 = 2;
const R_BLOCKLIST: u8 = 3;
const R_RPF_FAIL: u8 = 5;
const R_SYN_RATE: u8 = 6;
const R_LAN_LATERAL: u8 = 7;

/// A parsed detection event, ready to render.
#[derive(Debug, Clone, PartialEq)]
pub struct NapseEvent {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub role: u8,
    pub verdict: u8,
    pub reason: u8,
    pub ifindex: u32,
    pub pkt_len: u32,
}

fn u16le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn u32le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

impl NapseEvent {
    /// Parse one ringbuf record. Returns None if the buffer is too small. Multi-byte scalars are
    /// native-endian (little on our targets); `saddr`/`daddr` are taken as network-order byte arrays.
    pub fn from_bytes(b: &[u8]) -> Option<NapseEvent> {
        if b.len() < EVENT_SIZE {
            return None;
        }
        Some(NapseEvent {
            // b[0..8] = ts_ns (kernel-monotonic; userspace stamps wall-clock at render time)
            src: Ipv4Addr::new(b[8], b[9], b[10], b[11]), // network order = wire order
            dst: Ipv4Addr::new(b[12], b[13], b[14], b[15]),
            sport: u16le(&b[16..18]),
            dport: u16le(&b[18..20]),
            proto: b[20],
            role: b[21],
            verdict: b[22],
            reason: b[23],
            ifindex: u32le(&b[24..28]),
            pkt_len: u32le(&b[28..32]),
        })
    }

    fn proto_str(&self) -> &'static str {
        match self.proto {
            6 => "tcp",
            17 => "udp",
            1 => "icmp",
            _ => "other",
        }
    }

    /// Zeek-style conn_state inferred from the detection reason.
    fn conn_state(&self) -> &'static str {
        match self.reason {
            R_ESTABLISHED => "SF",
            R_NEW_FLOW => "S0",
            R_BLOCKLIST | R_RPF_FAIL | R_SYN_RATE => "REJ",
            _ => "OTH",
        }
    }

    fn reason_str(&self) -> &'static str {
        match self.reason {
            R_ESTABLISHED => "established",
            R_NEW_FLOW => "new-flow",
            R_BLOCKLIST => "threat-feed-blocklist",
            R_RPF_FAIL => "rpf-spoof",
            R_SYN_RATE => "syn-flood",
            R_LAN_LATERAL => "lan-lateral",
            _ => "none",
        }
    }

    /// Render as one NAPSE flow record. `wall_ts` is the userspace wall-clock time (seconds) — the
    /// kernel ts is monotonic, so the drainer supplies the real time. A DROP becomes an `alert`
    /// record (severity from the reason); everything else is a `conn` record.
    pub fn to_flow_json(&self, wall_ts: f64) -> String {
        let is_drop = self.verdict == V_DROP;
        let rtype = if is_drop { "alert" } else { "conn" };
        let mut s = format!(
            "{{\"type\":\"{rtype}\",\"ts\":{wall_ts:.3},\"src_ip\":\"{src}\",\"src_port\":{sp},\
             \"dst_ip\":\"{dst}\",\"dst_port\":{dp},\"proto\":\"{proto}\",\"conn_state\":\"{cs}\",\
             \"orig_bytes\":{plen},\"resp_bytes\":0,\"napse_role\":\"{role}\",\"napse_reason\":\"{rsn}\"",
            src = self.src, sp = self.sport, dst = self.dst, dp = self.dport,
            proto = self.proto_str(), cs = self.conn_state(), plen = self.pkt_len,
            role = if self.role == 1 { "wan" } else { "lan" }, rsn = self.reason_str(),
        );
        if is_drop {
            let sev = match self.reason {
                R_BLOCKLIST => 1, // critical
                R_RPF_FAIL | R_SYN_RATE => 2,
                _ => 3,
            };
            s.push_str(&format!(
                ",\"alert_severity\":{sev},\"alert_signature\":\"napse.{}\"",
                self.reason_str()
            ));
        }
        s.push('}');
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a raw 32-byte record the way the BPF program would.
    fn raw(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, proto: u8, role: u8, verdict: u8, reason: u8) -> Vec<u8> {
        let mut b = vec![0u8; EVENT_SIZE];
        b[0..8].copy_from_slice(&1234u64.to_le_bytes()); // ts_ns (ignored)
        b[8..12].copy_from_slice(&src);
        b[12..16].copy_from_slice(&dst);
        b[16..18].copy_from_slice(&sport.to_le_bytes());
        b[18..20].copy_from_slice(&dport.to_le_bytes());
        b[20] = proto; b[21] = role; b[22] = verdict; b[23] = reason;
        b[24..28].copy_from_slice(&3u32.to_le_bytes()); // ifindex
        b[28..32].copy_from_slice(&1500u32.to_le_bytes()); // pkt_len
        b
    }

    #[test]
    fn parses_addresses_in_wire_order() {
        let e = NapseEvent::from_bytes(&raw([10, 66, 0, 170], [1, 1, 1, 1], 51000, 443, 6, 0, 0, R_NEW_FLOW)).unwrap();
        assert_eq!(e.src, Ipv4Addr::new(10, 66, 0, 170));
        assert_eq!(e.dst, Ipv4Addr::new(1, 1, 1, 1));
        assert_eq!(e.sport, 51000);
        assert_eq!(e.dport, 443);
    }

    #[test]
    fn new_flow_renders_conn_record() {
        let e = NapseEvent::from_bytes(&raw([10, 66, 0, 5], [8, 8, 8, 8], 5353, 53, 17, 0, 0, R_NEW_FLOW)).unwrap();
        let j = e.to_flow_json(1782886342.5);
        assert!(j.contains("\"type\":\"conn\""));
        assert!(j.contains("\"src_ip\":\"10.66.0.5\""));
        assert!(j.contains("\"dst_port\":53"));
        assert!(j.contains("\"proto\":\"udp\""));
        assert!(j.contains("\"conn_state\":\"S0\""));
        assert!(j.contains("\"napse_role\":\"lan\""));
        assert!(!j.contains("alert_severity"));
    }

    #[test]
    fn blocklist_drop_renders_alert() {
        // WAN-side drop of a threat-feed IP
        let e = NapseEvent::from_bytes(&raw([185, 220, 101, 1], [10, 66, 0, 5], 1234, 22, 6, 1, V_DROP, R_BLOCKLIST)).unwrap();
        let j = e.to_flow_json(1782886350.0);
        assert!(j.contains("\"type\":\"alert\""));
        assert!(j.contains("\"napse_role\":\"wan\""));
        assert!(j.contains("\"alert_severity\":1"));
        assert!(j.contains("\"alert_signature\":\"napse.threat-feed-blocklist\""));
    }

    #[test]
    fn short_buffer_rejected() {
        assert!(NapseEvent::from_bytes(&[0u8; 10]).is_none());
    }
}
