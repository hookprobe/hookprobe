//! G19 SASE tunnel wire format, v1 (pure, no I/O). The device side mirrors these constants.
//!
//! Data datagram (UDP 7655):  "HQT1"(4) ‖ sid(8) ‖ record
//!   record    = LE64 seq ‖ ciphertext ‖ tag16   (securechannel `seal_record` / `open_record`)
//!   AD        = "HQT1" ‖ sid
//!   sid       = SHA-256("HQ-G19-sid-v1" ‖ Session.handshake_hash)[0..8]
//! Record plaintext = type(1) ‖ body:
//!   0x01 DATA      one IPv4 packet (IPv6 reserved in v1: dropped)
//!   0x02 KEEPALIVE empty (device sends when idle; keeps NAT bindings)
//!   0x03 ASSIGN    PoP→dev: inner_v4(4) ‖ plen(1) ‖ dns_v4(4) ‖ mtu LE16
//!   0x04 ADDR_REQ  dev→PoP: empty
//!   0x05 CLOSE     reason(1): 1 shutdown, 2 not authorised, 3 rekey

use boot_abi::sha256;

pub const DATA_PORT: u16 = 7655;
pub const HS_PORT: u16 = 7654;
pub const MAGIC: [u8; 4] = *b"HQT1";
pub const SID_LEN: usize = 8;
pub const HDR_LEN: usize = MAGIC.len() + SID_LEN; // 12
pub const SEQ_LEN: usize = 8;
pub const TAG_LEN: usize = 16;
/// Inner MTU the PoP advertises: fits a 1500 B path with PPPoE (8) + VLAN (4) and our overhead.
pub const DEFAULT_MTU: u16 = 1380;
/// Largest record plaintext we accept/produce: type byte + one inner packet.
pub const MAX_PT: usize = 1 + 1500;
/// Largest datagram we produce/accept.
pub const MAX_DGRAM: usize = HDR_LEN + SEQ_LEN + MAX_PT + TAG_LEN;

pub const T_DATA: u8 = 0x01;
pub const T_KEEPALIVE: u8 = 0x02;
pub const T_ASSIGN: u8 = 0x03;
pub const T_ADDR_REQ: u8 = 0x04;
pub const T_CLOSE: u8 = 0x05;

pub const CLOSE_SHUTDOWN: u8 = 1;
pub const CLOSE_NOT_AUTHORISED: u8 = 2;
pub const CLOSE_REKEY: u8 = 3;

pub type Sid = [u8; SID_LEN];

/// The per-session id: unlinkable across sessions (fresh ephemerals ⇒ fresh handshake hash).
pub fn sid_from_handshake_hash(h: &[u8; 32]) -> Sid {
    let mut m = [0u8; 13 + 32];
    m[..13].copy_from_slice(b"HQ-G19-sid-v1");
    m[13..].copy_from_slice(h);
    let d = sha256::digest(&m);
    let mut sid = [0u8; SID_LEN];
    sid.copy_from_slice(&d[..SID_LEN]);
    sid
}

/// The AEAD associated data for a record on `sid`.
pub fn ad(sid: &Sid) -> [u8; HDR_LEN] {
    let mut a = [0u8; HDR_LEN];
    a[..4].copy_from_slice(&MAGIC);
    a[4..].copy_from_slice(sid);
    a
}

/// Split a data datagram into (sid, record). None = not ours / too short.
pub fn parse_dgram(d: &[u8]) -> Option<(Sid, &[u8])> {
    if d.len() < HDR_LEN + SEQ_LEN + TAG_LEN + 1 || d[..4] != MAGIC {
        return None;
    }
    let mut sid = [0u8; SID_LEN];
    sid.copy_from_slice(&d[4..HDR_LEN]);
    Some((sid, &d[HDR_LEN..]))
}

/// A decoded record plaintext.
#[derive(Debug, PartialEq, Eq)]
pub enum Msg<'a> {
    Data(&'a [u8]),
    Keepalive,
    Assign(Assign),
    AddrReq,
    Close(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Assign {
    pub inner: [u8; 4],
    pub plen: u8,
    pub dns: [u8; 4],
    pub mtu: u16,
}

pub fn decode(pt: &[u8]) -> Option<Msg<'_>> {
    let (&t, body) = pt.split_first()?;
    match t {
        T_DATA if !body.is_empty() => Some(Msg::Data(body)),
        T_KEEPALIVE if body.is_empty() => Some(Msg::Keepalive),
        T_ADDR_REQ if body.is_empty() => Some(Msg::AddrReq),
        T_CLOSE if body.len() == 1 => Some(Msg::Close(body[0])),
        T_ASSIGN if body.len() == 11 => Some(Msg::Assign(Assign {
            inner: [body[0], body[1], body[2], body[3]],
            plen: body[4],
            dns: [body[5], body[6], body[7], body[8]],
            mtu: u16::from_le_bytes([body[9], body[10]]),
        })),
        _ => None,
    }
}

/// Encode a record plaintext into `out`; returns its length.
pub fn encode(m: &Msg<'_>, out: &mut [u8]) -> Option<usize> {
    let body_len = match m {
        Msg::Data(p) => p.len(),
        Msg::Keepalive | Msg::AddrReq => 0,
        Msg::Close(_) => 1,
        Msg::Assign(_) => 11,
    };
    if out.len() < 1 + body_len || 1 + body_len > MAX_PT {
        return None;
    }
    match m {
        Msg::Data(p) => {
            out[0] = T_DATA;
            out[1..1 + p.len()].copy_from_slice(p);
        }
        Msg::Keepalive => out[0] = T_KEEPALIVE,
        Msg::AddrReq => out[0] = T_ADDR_REQ,
        Msg::Close(r) => {
            out[0] = T_CLOSE;
            out[1] = *r;
        }
        Msg::Assign(a) => {
            out[0] = T_ASSIGN;
            out[1..5].copy_from_slice(&a.inner);
            out[5] = a.plen;
            out[6..10].copy_from_slice(&a.dns);
            out[10..12].copy_from_slice(&a.mtu.to_le_bytes());
        }
    }
    Some(1 + body_len)
}

/// IPv4 header facts we police: (version, src, dst). None = not a plausible IPv4 packet.
pub fn ipv4_src_dst(p: &[u8]) -> Option<([u8; 4], [u8; 4])> {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((p[0] & 0x0f) as usize) * 4;
    let total = u16::from_be_bytes([p[2], p[3]]) as usize;
    if ihl < 20 || total < ihl || total > p.len() {
        return None;
    }
    Some(([p[12], p[13], p[14], p[15]], [p[16], p[17], p[18], p[19]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_every_type() {
        let pkt = [0x45u8, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 100, 64, 0, 2, 1, 1, 1, 1];
        let a = Assign { inner: [100, 64, 0, 2], plen: 32, dns: [1, 1, 1, 1], mtu: DEFAULT_MTU };
        for m in [Msg::Data(&pkt), Msg::Keepalive, Msg::AddrReq, Msg::Close(CLOSE_REKEY), Msg::Assign(a)] {
            let mut b = [0u8; 64];
            let n = encode(&m, &mut b).unwrap();
            assert_eq!(decode(&b[..n]).unwrap(), m);
        }
    }

    #[test]
    fn rejects_malformed() {
        assert!(decode(&[]).is_none());
        assert!(decode(&[T_DATA]).is_none()); // empty data
        assert!(decode(&[T_KEEPALIVE, 0]).is_none()); // trailing bytes
        assert!(decode(&[T_ASSIGN, 1, 2, 3]).is_none()); // short assign
        assert!(decode(&[0x7f]).is_none()); // unknown type
        assert!(parse_dgram(b"HQT1short").is_none());
        assert!(parse_dgram(&[0u8; 64]).is_none()); // wrong magic
    }

    #[test]
    fn sid_is_deterministic_and_hash_bound() {
        let h1 = [7u8; 32];
        let mut h2 = h1;
        h2[31] ^= 1;
        assert_eq!(sid_from_handshake_hash(&h1), sid_from_handshake_hash(&h1));
        assert_ne!(sid_from_handshake_hash(&h1), sid_from_handshake_hash(&h2));
    }

    #[test]
    fn ipv4_parse_bounds() {
        let mut p = [0u8; 20];
        p[0] = 0x45;
        p[3] = 20;
        p[12..16].copy_from_slice(&[100, 64, 0, 2]);
        p[16..20].copy_from_slice(&[9, 9, 9, 9]);
        assert_eq!(ipv4_src_dst(&p), Some(([100, 64, 0, 2], [9, 9, 9, 9])));
        p[3] = 40; // total length beyond the buffer
        assert!(ipv4_src_dst(&p).is_none());
        p[0] = 0x60; // IPv6
        assert!(ipv4_src_dst(&p).is_none());
    }
}
