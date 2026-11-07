//! Pure logic: read the scan-responder's persisted quarantine state
//! (`/var/lib/hookprobe/scan-quarantine.json`, `Vec<hookprobe_manifest::scan_responder::QuarantineEntry>`
//! — the SAME struct the responder writes, reused directly so this loader can never drift from
//! that schema) and turn it into the exact BPF-map key sets `quarantine.bpf.c` expects. No BPF
//! syscalls here — everything below builds and tests without libbpf, matching the
//! `hookprobe-manifest`/`napse-loader` convention of keeping the reasoning pure and the kernel
//! glue in a separate `feature = "bpf"` module (`bpf.rs`).
//!
//! C9 (deterministic enforcement): this module does NOT decide who is quarantined — it only
//! mirrors a decision already made by `scan_responder::reconcile_quarantine`/`sweep_quarantine`
//! (the responder) into the shape the kernel map needs. No policy, no AI, no judgment calls.
//!
//! 2026-07-05 threat-model fix (HIGH #3): every desired key now carries the ONE ingress ifindex
//! it is allowed to fire on (LAN entries → the LAN iface's ifindex, WAN entries → the WAN iface's
//! ifindex — the SAME `classify_source` routing `scan_responder::render_element_ops` already uses
//! for the nft rendering, reused here so the two enforcement layers can never disagree on which
//! plane an entry belongs to). This is what makes a LAN-plane quarantine entry structurally unable
//! to fire on the WAN ifindex (and vice versa) at the Ring-0 BPF layer, matching the nft layer's
//! existing `iifname`-scoped rules.

use anyhow::{Context, Result};
use hookprobe_manifest::scan_responder::{classify_source, QuarantineEntry, SourceKind};
use std::collections::BTreeMap;

/// Read and parse the quarantine state file. A missing file is NOT an error — the responder
/// hasn't run yet, or nothing has ever been quarantined — it's simply "empty state" (matches the
/// live file's actual `[]` content pre-any-scan). A malformed file IS an error: silently treating
/// garbage as "nothing quarantined" would erase real quarantine intent.
pub fn load_state(path: &str) -> Result<Vec<QuarantineEntry>> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return Ok(Vec::new());
            }
            serde_json::from_str(trimmed).with_context(|| format!("parse quarantine state {path}"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e).with_context(|| format!("read quarantine state {path}")),
    }
}

/// Parse a dotted-quad IPv4 address into its NETWORK-byte-order u32 representation — i.e. the
/// SAME bytes `iphdr->saddr` carries on the wire, so the BPF program's `ip->saddr` key and this
/// key are byte-identical with no endian conversion needed on either side. `None` for anything
/// that isn't a clean 4-octet IPv4 address (IPv6, hostnames, garbage — the responder's state file
/// only ever contains IPv4 today per `scan_responder::ipv4_octets`).
pub fn parse_ipv4_be(ip: &str) -> Option<u32> {
    let parts: Vec<u8> = ip.split('.').map(|p| p.parse().ok()).collect::<Option<Vec<u8>>>()?;
    if parts.len() != 4 {
        return None;
    }
    Some(u32::from_be_bytes([parts[0], parts[1], parts[2], parts[3]]))
}

/// Parse a colon-hex MAC (`aa:bb:cc:dd:ee:ff`, any case) into the packed-u64 key
/// `quarantine.bpf.c`'s `pack_mac()` computes from the wire (MSB-first, low 48 bits). `None` for
/// anything that isn't exactly 6 colon-separated hex octets.
pub fn parse_mac_packed(mac: &str) -> Option<u64> {
    let parts: Vec<&str> = mac.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut key: u64 = 0;
    for p in parts {
        let byte = u8::from_str_radix(p, 16).ok()?;
        key = (key << 8) | byte as u64;
    }
    Some(key)
}

/// The two ingress ifindexes a quarantine entry can be scoped to. Resolved once at startup
/// (`bpf.rs::sysfs_ifindex` on the LAN/WAN interface names) and passed into [`desired_keys`] every
/// cycle — cheap (two integers), and re-resolving per cycle would cost a `/sys` read for no
/// benefit (an interface's ifindex does not change while it exists).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaneIfindexes {
    pub lan: u32,
    pub wan: u32,
}

/// The desired key sets for one reconcile cycle, derived from the persisted state — everything
/// the loader needs to diff against the live BPF maps. Each key maps to the ONE ifindex it is
/// allowed to match on (2026-07-05 threat-model fix HIGH #3) — never a hit counter or other
/// enforcement-irrelevant value.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DesiredKeys {
    pub ips: BTreeMap<u32, u32>,
    pub macs: BTreeMap<u64, u32>,
}

/// Build the desired key sets from the quarantine state, routing each entry to its LAN or WAN
/// ifindex via [`classify_source`] — the SAME classification `scan_responder::render_element_ops`
/// already uses for the nft rendering, so the two enforcement layers can never disagree on which
/// plane an entry belongs to.
///
/// 2026-07-05 VERIFY-pass re-audit (Q2 half 2, CRITICAL): a LAN-classified entry's `ip` is EXACTLY
/// as spoofable as the alert that produced it — a LAN entry therefore NEVER contributes an IP key
/// at all; enforcement is MAC-ONLY on this plane (`e.mac`, the OBSERVED L2 address at detection
/// time — never resolved from the claimed IP). An entry with no resolved mac is simply not
/// enforced on the LAN plane (skipped entirely — it must never fall back to the spoofable IP,
/// which is exactly the bug this fix closes: the previous version unconditionally inserted
/// `e.ip` into `d.ips` for BOTH planes, so the Ring-0 BPF fast path dropped LAN traffic by the
/// (spoofable) claimed IP in addition to nft's already-correct MAC-only enforcement). A
/// WAN-classified entry contributes an IP key only (a routed WAN source has no L2 address to bind,
/// and even if `mac` were somehow set on such an entry, binding it would be meaningless — a WAN
/// packet's observed src mac is always the upstream router's) — unparseable IPs are skipped
/// (never crash the reconcile loop over one bad record).
pub fn desired_keys(state: &[QuarantineEntry], ifindexes: PlaneIfindexes) -> DesiredKeys {
    let mut d = DesiredKeys::default();
    for e in state {
        match classify_source(&e.ip) {
            SourceKind::Lan => {
                if let Some(mac) = &e.mac {
                    if let Some(k) = parse_mac_packed(mac) {
                        d.macs.insert(k, ifindexes.lan);
                    }
                }
                // Deliberately no `d.ips` insert here — see the doc comment above.
            }
            SourceKind::Wan => {
                if let Some(k) = parse_ipv4_be(&e.ip) {
                    d.ips.insert(k, ifindexes.wan);
                }
            }
        }
    }
    d
}

/// Generic diff over ifindex-valued key maps: a key in `desired` but not `current`, OR present in
/// both with a DIFFERENT ifindex (e.g. the configured LAN/WAN iface names changed across a
/// restart), is `to_add` (an `update()` with the same key overwrites the value); a key in
/// `current` but not `desired` is `to_remove`. Shared by the IP and MAC map reconciles (bpf.rs) so
/// "what changed this cycle" is defined exactly once. Only called from `bpf.rs` (feature = "bpf");
/// still compiled and unit-tested without that feature so its logic is covered on every build.
#[cfg_attr(not(feature = "bpf"), allow(dead_code))]
pub fn diff<T: Ord + Copy>(desired: &BTreeMap<T, u32>, current: &BTreeMap<T, u32>) -> (Vec<(T, u32)>, Vec<T>) {
    let to_add: Vec<(T, u32)> = desired
        .iter()
        .filter(|(k, v)| current.get(k) != Some(*v))
        .map(|(k, v)| (*k, *v))
        .collect();
    let to_remove: Vec<T> = current.keys().filter(|k| !desired.contains_key(k)).copied().collect();
    (to_add, to_remove)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_to_network_order_u32() {
        // 203.0.113.7 → be bytes [203,0,113,7]
        assert_eq!(parse_ipv4_be("203.0.113.7"), Some(u32::from_be_bytes([203, 0, 113, 7])));
        assert_eq!(parse_ipv4_be("not-an-ip"), None);
        assert_eq!(parse_ipv4_be("1.2.3"), None);
        assert_eq!(parse_ipv4_be("2001:db8::1"), None, "IPv6 not handled here");
    }

    #[test]
    fn parses_mac_into_packed_u64_matching_bpf_side_packing() {
        // pack_mac in the BPF program does key = (key<<8)|byte for each of the 6 bytes MSB-first.
        let k = parse_mac_packed("aa:bb:cc:dd:ee:ff").unwrap();
        let expect = 0xaabbccddeeffu64;
        assert_eq!(k, expect);
        assert_eq!(parse_mac_packed("AA:BB:CC:DD:EE:FF"), Some(expect), "case-insensitive");
        assert_eq!(parse_mac_packed("aa:bb:cc:dd:ee"), None, "too few octets");
        assert_eq!(parse_mac_packed("zz:bb:cc:dd:ee:ff"), None, "non-hex octet");
    }

    #[test]
    fn load_state_missing_file_is_empty_not_an_error() {
        let s = load_state("/nonexistent/path/scan-quarantine.json").unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn load_state_parses_the_real_schema() {
        let dir = std::env::temp_dir().join(format!("napse-quarantine-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        std::fs::write(
            &path,
            r#"[{"ip":"203.0.113.7","mac":"aa:bb:cc:dd:ee:ff","first_seen":1000.0,"last_seen":1000.0}]"#,
        )
        .unwrap();
        let s = load_state(path.to_str().unwrap()).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].ip, "203.0.113.7");
        assert_eq!(s[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_state_rejects_malformed_json_rather_than_silently_emptying() {
        let dir = std::env::temp_dir().join(format!("napse-quarantine-test-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        std::fs::write(&path, "{not json").unwrap();
        assert!(load_state(path.to_str().unwrap()).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    const IFX: PlaneIfindexes = PlaneIfindexes { lan: 3, wan: 7 };

    // (c) — the CORE Q2-half-2 re-audit proof: a LAN entry NEVER contributes an IP key (the
    // spoofable claimed IP must never be enforced at the BPF layer either) — only its observed
    // MAC does. A WAN entry (no mac to bind) contributes an IP key as before.
    #[test]
    fn desired_keys_never_emits_an_ip_key_for_a_lan_entry_mac_only() {
        let state = vec![
            QuarantineEntry { ip: "10.66.0.20".into(), mac: Some("aa:bb:cc:dd:ee:ff".into()), first_seen: 0.0, last_seen: 0.0, offenses: 1 },
            QuarantineEntry { ip: "198.51.100.9".into(), mac: None, first_seen: 0.0, last_seen: 0.0, offenses: 1 },
        ];
        let d = desired_keys(&state, IFX);
        assert_eq!(d.ips.len(), 1, "only the WAN entry contributes an ip key — the LAN entry's ip must never be enforced");
        let lan_ip_key = parse_ipv4_be("10.66.0.20").unwrap();
        assert!(!d.ips.contains_key(&lan_ip_key), "the LAN entry's (spoofable) claimed ip must never appear in the ip map");
        assert_eq!(d.macs.len(), 1, "the LAN entry's observed mac IS enforced");
    }

    // A LAN entry with NO resolved mac must not be enforced on either map — it must never fall
    // back to the spoofable ip.
    #[test]
    fn desired_keys_skips_a_lan_entry_with_no_resolved_mac_entirely() {
        let state = vec![QuarantineEntry { ip: "10.66.0.30".into(), mac: None, first_seen: 0.0, last_seen: 0.0, offenses: 1 }];
        let d = desired_keys(&state, IFX);
        assert!(d.ips.is_empty(), "no ip fallback");
        assert!(d.macs.is_empty(), "no mac to enforce with");
    }

    // 2026-07-05 threat-model fix (HIGH #3): every key carries the RIGHT plane's ifindex.
    #[test]
    fn desired_keys_routes_lan_and_wan_entries_to_their_own_ifindex() {
        let state = vec![
            QuarantineEntry { ip: "10.66.0.20".into(), mac: Some("aa:bb:cc:dd:ee:ff".into()), first_seen: 0.0, last_seen: 0.0, offenses: 1 },
            QuarantineEntry { ip: "203.0.113.7".into(), mac: None, first_seen: 0.0, last_seen: 0.0, offenses: 1 },
        ];
        let d = desired_keys(&state, IFX);
        let lan_mac_key = parse_mac_packed("aa:bb:cc:dd:ee:ff").unwrap();
        let wan_ip_key = parse_ipv4_be("203.0.113.7").unwrap();
        assert_eq!(d.macs.get(&lan_mac_key), Some(&3), "LAN entry's mac bound to the LAN ifindex");
        assert_eq!(d.ips.get(&wan_ip_key), Some(&7), "WAN entry bound to the WAN ifindex");
    }

    // A WAN-classified entry must NEVER contribute a mac key, even if `mac` happens to be set —
    // mirrors the nft rendering's WAN-is-ip-only rule (a WAN packet's observed src mac is always
    // the upstream router's, never meaningful to bind).
    #[test]
    fn desired_keys_never_emits_a_mac_key_for_a_wan_entry() {
        let state = vec![QuarantineEntry {
            ip: "203.0.113.7".into(),
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            first_seen: 0.0,
            last_seen: 0.0,
            offenses: 1,
        }];
        let d = desired_keys(&state, IFX);
        assert!(d.macs.is_empty(), "a WAN entry's mac (even if present) must never be enforced");
    }

    #[test]
    fn diff_computes_add_and_remove_sets() {
        let desired: BTreeMap<u32, u32> = [(1, 3), (2, 3), (3, 3)].into_iter().collect();
        let current: BTreeMap<u32, u32> = [(2, 3), (3, 3), (4, 3)].into_iter().collect();
        let (add, remove) = diff(&desired, &current);
        assert_eq!(add, vec![(1, 3)]);
        assert_eq!(remove, vec![4]);
    }

    // A key present in BOTH but bound to a DIFFERENT ifindex (e.g. the LAN/WAN iface names were
    // reconfigured) must be treated as an update (re-`add`, which overwrites the value).
    #[test]
    fn diff_re_adds_a_key_whose_ifindex_changed() {
        let desired: BTreeMap<u32, u32> = [(1, 9)].into_iter().collect();
        let current: BTreeMap<u32, u32> = [(1, 3)].into_iter().collect();
        let (add, remove) = diff(&desired, &current);
        assert_eq!(add, vec![(1, 9)], "must re-add with the NEW ifindex");
        assert!(remove.is_empty());
    }

    #[test]
    fn diff_is_a_noop_when_desired_equals_current_including_ifindexes() {
        let m: BTreeMap<u32, u32> = [(1, 3), (2, 3)].into_iter().collect();
        let (add, remove) = diff(&m, &m);
        assert!(add.is_empty() && remove.is_empty(), "re-applying identical state must add/remove nothing (idempotent)");
    }
}
