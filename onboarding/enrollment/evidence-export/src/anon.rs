//! What may leave the device: the privacy boundary of the export.
//!
//! HookProbe's privacy guarantee is that export never carries raw packet payloads, local or
//! internal IP addresses, MAC addresses, or other identifying host details. The log images never
//! held payloads (`events.rs` pushes a fixed header, never packet bytes), and [`ExportRec`] has no
//! field that could carry one. The two fields that can identify a host are handled here:
//!
//! * `src` for the IPv4 rules is the source address. An internal address (RFC 1918, CGNAT,
//!   loopback, link-local, multicast, reserved…) is replaced by 0 and marked `Redacted`. A public
//!   source is the attacker, which is the threat signature, so it is kept unless the policy says
//!   otherwise.
//! * `src` for the IPv6 RA rules 121/122/123 is the first four MAC octets. It is replaced by the
//!   same device-keyed pseudonym the live exporter uses (`export.rs::export_src`), so the two
//!   streams correlate. With no key it is redacted, never sent raw.
//!
//! The timestamp is kept (wall-clock ms, needed to place the event); `rule_id`, severity, verdict
//! and class are the BPF/Wasm verdict metadata that are the point of the export.

use crate::record::Event;

/// The IPv6 RA rules whose `src` is MAC-derived (`events::Event::src`).
pub const MAC_KEYED_RULES: [u16; 3] = [121, 122, 123];

/// How a record's `src` should be read. On the wire as one byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SrcKind {
    /// The event had no source.
    None = 0,
    /// A public IPv4 source (host order).
    PublicV4 = 1,
    /// A device-keyed pseudonym of a MAC-derived value.
    Pseudonym = 2,
    /// The source was internal (or MAC-derived with no key) and has been removed.
    Redacted = 3,
}

impl SrcKind {
    pub fn from_u8(b: u8) -> Option<SrcKind> {
        match b {
            0 => Some(SrcKind::None),
            1 => Some(SrcKind::PublicV4),
            2 => Some(SrcKind::Pseudonym),
            3 => Some(SrcKind::Redacted),
            _ => None,
        }
    }
}

/// One record as it leaves the device. There is no payload, destination, port or MAC field.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExportRec {
    pub ts_ms: u64,
    pub src: u32,
    pub src_kind: u8,
    pub rule_id: u16,
    pub severity: u8,
    pub verdict: u8,
    /// Tri-state class (`verdict::CLASS_*`). The 16-byte log image does not store it, so records
    /// read from the log carry 0 (unknown). ADR 0066 notes the image change that would add it.
    pub class: u8,
}

/// Export privacy policy.
#[derive(Clone, Copy)]
pub struct Policy {
    /// `HKDF(SRK, "HQ-MAC-PSEUDONYM")` expanded with `"v1"`: see [`pseudonym_key`].
    pub pseudonym_key: Option<[u8; 32]>,
    /// Keep public IPv4 sources (the attacker address). Set false for a stricter export.
    pub keep_public_src: bool,
}

impl Policy {
    /// The strictest policy: every source removed.
    pub const STRICT: Policy = Policy { pseudonym_key: None, keep_public_src: false };
}

/// The pseudonym key, derived exactly as `export.rs::set_mac_pseudonym_key` does.
pub fn pseudonym_key(srk: &[u8; 32]) -> [u8; 32] {
    let prk = boot_abi::kdf::hkdf_extract(b"HQ-MAC-PSEUDONYM", srk);
    boot_abi::kdf::hkdf_expand32(&prk, b"v1")
}

/// True for every IPv4 address that is not a globally routable unicast host (host-order input).
/// Fail-closed: anything in a special-purpose block counts as internal.
pub fn is_internal_v4(ip: u32) -> bool {
    const BLOCKS: [(u32, u32); 15] = [
        (0x0000_0000, 8),  // 0.0.0.0/8      "this network"
        (0x0A00_0000, 8),  // 10.0.0.0/8     RFC 1918
        (0x6440_0000, 10), // 100.64.0.0/10  CGNAT (RFC 6598)
        (0x7F00_0000, 8),  // 127.0.0.0/8    loopback
        (0xA9FE_0000, 16), // 169.254.0.0/16 link-local
        (0xAC10_0000, 12), // 172.16.0.0/12  RFC 1918
        (0xC000_0000, 24), // 192.0.0.0/24   IETF protocol assignments
        (0xC000_0200, 24), // 192.0.2.0/24   TEST-NET-1
        (0xC058_6300, 24), // 192.88.99.0/24 6to4 relay (deprecated)
        (0xC0A8_0000, 16), // 192.168.0.0/16 RFC 1918
        (0xC612_0000, 15), // 198.18.0.0/15  benchmarking
        (0xC633_6400, 24), // 198.51.100.0/24 TEST-NET-2
        (0xCB00_7100, 24), // 203.0.113.0/24 TEST-NET-3
        (0xE000_0000, 4),  // 224.0.0.0/4    multicast
        (0xF000_0000, 4),  // 240.0.0.0/4    reserved + broadcast
    ];
    BLOCKS.iter().any(|&(net, len)| (ip ^ net) >> (32 - len) == 0)
}

fn pseudonym(k: &[u8; 32], src: u32) -> u32 {
    let h = boot_abi::kdf::hmac_sha256(k, &src.to_le_bytes());
    u32::from_le_bytes([h[0], h[1], h[2], h[3]])
}

/// Map one log event to what may leave the device.
pub fn anonymize(ev: &Event, p: &Policy) -> ExportRec {
    let (src, kind) = if ev.src == 0 {
        (0, SrcKind::None)
    } else if MAC_KEYED_RULES.contains(&ev.rule_id) {
        match &p.pseudonym_key {
            Some(k) => (pseudonym(k, ev.src), SrcKind::Pseudonym),
            None => (0, SrcKind::Redacted),
        }
    } else if is_internal_v4(ev.src) || !p.keep_public_src {
        (0, SrcKind::Redacted)
    } else {
        (ev.src, SrcKind::PublicV4)
    };
    ExportRec {
        ts_ms: ev.ts_ms,
        src,
        src_kind: kind as u8,
        rule_id: ev.rule_id,
        severity: ev.severity,
        verdict: ev.verdict,
        class: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from_be_bytes([a, b, c, d]) // host order, as the kernel stores it
    }

    fn ev(src: u32, rule_id: u16) -> Event {
        Event { ts_ms: 1, src, rule_id, severity: 9, verdict: 2 }
    }

    const KEEP: Policy = Policy { pseudonym_key: None, keep_public_src: true };

    /// Deliverable (a): internal addresses never leave the device.
    #[test]
    fn internal_addresses_are_redacted() {
        for a in [
            ip(10, 1, 2, 3),
            ip(172, 16, 0, 1),
            ip(172, 31, 255, 254),
            ip(192, 168, 1, 10),
            ip(100, 64, 0, 1),
            ip(127, 0, 0, 1),
            ip(169, 254, 3, 4),
            ip(224, 0, 0, 251),
            ip(255, 255, 255, 255),
            ip(0, 1, 2, 3),
            ip(198, 18, 0, 9),
        ] {
            let r = anonymize(&ev(a, 7), &KEEP);
            assert_eq!((r.src, r.src_kind), (0, SrcKind::Redacted as u8), "{a:#x} leaked");
        }
    }

    #[test]
    fn public_attacker_kept_unless_strict() {
        let a = ip(203, 0, 114, 7); // just outside TEST-NET-3
        assert!(!is_internal_v4(a));
        assert!(!is_internal_v4(ip(172, 32, 0, 1)));
        assert!(!is_internal_v4(ip(100, 128, 0, 1)));
        let r = anonymize(&ev(a, 7), &KEEP);
        assert_eq!((r.src, r.src_kind), (a, SrcKind::PublicV4 as u8));
        let r = anonymize(&ev(a, 7), &Policy::STRICT);
        assert_eq!((r.src, r.src_kind), (0, SrcKind::Redacted as u8));
    }

    #[test]
    fn mac_derived_sources_are_pseudonymised_or_removed() {
        let raw = 0xDEAD_BEEF; // first four MAC octets
        for rule in MAC_KEYED_RULES {
            let r = anonymize(&ev(raw, rule), &KEEP);
            assert_eq!((r.src, r.src_kind), (0, SrcKind::Redacted as u8));
            let k = pseudonym_key(&[7; 32]);
            let p = Policy { pseudonym_key: Some(k), keep_public_src: true };
            let r = anonymize(&ev(raw, rule), &p);
            assert_eq!(r.src_kind, SrcKind::Pseudonym as u8);
            assert_ne!(r.src, raw);
            assert_eq!(r.src, anonymize(&ev(raw, rule), &p).src, "stable per device");
            let other = Policy { pseudonym_key: Some(pseudonym_key(&[8; 32])), keep_public_src: true };
            assert_ne!(r.src, anonymize(&ev(raw, rule), &other).src, "unlinkable across devices");
        }
    }

    #[test]
    fn metadata_kept() {
        let r = anonymize(&Event { ts_ms: 42, src: 0, rule_id: 300, severity: 5, verdict: 1 }, &KEEP);
        assert_eq!(r, ExportRec { ts_ms: 42, src: 0, src_kind: 0, rule_id: 300, severity: 5, verdict: 1, class: 0 });
    }
}
