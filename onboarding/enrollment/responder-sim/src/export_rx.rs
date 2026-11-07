//! Off-device RECEIVER for heqk M6 evidence exports (the MSSP / Mission Control ingest edge).
//!
//! Opens `exportwire::DGRAM_TAG`-tagged datagram records with the session's anti-replay
//! receiver, authenticates + loss-accounts them with the SHARED `exportwire::Tracker`, anchors
//! each event to wall-clock time, and renders JSON Lines for `hookprobe-evidence`'s
//! `ingest_heqk_export`. The codec is the kernel's own `exportwire.rs` (linked via `#[path]` in
//! main.rs), so the receiver cannot drift from the device's wire format.

use crate::exportwire::{self, Frame, Tracker};
use crate::securechannel::AntiReplayRx;

#[derive(Debug, PartialEq, Eq)]
pub enum RxErr {
    /// Not an export datagram (no tag) — the caller routes it elsewhere.
    NotExport,
    /// AEAD / replay-window refusal (wrong key, tampered, replayed, below the window).
    Channel,
    Malformed,
    IdentityMismatch,
}

/// One enrolled device's export stream.
pub struct ExportRx {
    rx: AntiReplayRx,
    pub tracker: Tracker,
    pub frames: u64,
}

impl ExportRx {
    pub fn new(rx: AntiReplayRx, tenant_id: u64, device_fp: [u8; 32]) -> Self {
        ExportRx { rx, tracker: Tracker::new(tenant_id, device_fp), frames: 0 }
    }

    /// Accept one UDP payload. `Err(NotExport)` = not ours (no tag).
    pub fn accept(&mut self, udp_payload: &[u8]) -> Result<Frame, RxErr> {
        let rec = udp_payload.strip_prefix(&exportwire::DGRAM_TAG[..]).ok_or(RxErr::NotExport)?;
        let mut pt = [0u8; exportwire::MAX_FRAME];
        let n = self.rx.open_record(exportwire::AD, rec, &mut pt).map_err(|_| RxErr::Channel)?;
        let f = self.tracker.accept(&pt[..n]).map_err(|e| match e {
            exportwire::TrackErr::Malformed => RxErr::Malformed,
            exportwire::TrackErr::IdentityMismatch => RxErr::IdentityMismatch,
        })?;
        self.frames += 1;
        Ok(f)
    }
}

/// heqk rule ids whose `src` is a src-MAC hash, not an IPv4 address (IPv6 RA rules — see
/// kernel `events::Event::src`).
const MAC_KEYED_RULES: [u16; 3] = [121, 122, 123];

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn class_name(c: u8) -> &'static str {
    match c {
        1 => "allowlisted",
        2 => "observe",
        3 => "ratelimit",
        4 => "ratelimit_enforced",
        5 => "framedrop",
        6 => "quarantine",
        _ => "unknown",
    }
}

/// Render one accepted frame as JSON Lines: one `heqk_detection` line per event plus one
/// `heqk_frame` line carrying the loss accounting (so the operator sees evidence that did NOT
/// arrive, not just what did). `rx_epoch` = wall-clock seconds when the datagram arrived.
pub fn frame_to_jsonl(f: &Frame, tracker: &Tracker, rx_epoch: f64) -> Vec<String> {
    let h = &f.hdr;
    let fp = hex(&h.device_fp);
    let mut out = Vec::with_capacity(f.n + 1);
    for (i, r) in f.records().iter().enumerate() {
        let src_ip = if MAC_KEYED_RULES.contains(&r.rule_id) || r.src == 0 {
            String::new()
        } else {
            std::net::Ipv4Addr::from(r.src).to_string()
        };
        let src_mac_hash = if MAC_KEYED_RULES.contains(&r.rule_id) { format!("{:08x}", r.src) } else { String::new() };
        out.push(
            serde_json::json!({
                "type": "heqk_detection",
                "ts": exportwire::event_epoch(rx_epoch, h, r.ts),
                "device_fp": fp,
                "tenant": h.tenant_id,
                "boots": h.boots,
                "ev_seq": h.first_ev_seq + i as u64,
                "rule_id": r.rule_id,
                "sev_points": r.severity,
                "verdict": if r.verdict == 2 { "DROP" } else { "PASS" },
                "class": class_name(r.class),
                "src_ip": src_ip,
                "src_mac_hash": src_mac_hash,
            })
            .to_string(),
        );
    }
    out.push(
        serde_json::json!({
            "type": "heqk_frame",
            "ts": rx_epoch,
            "device_fp": fp,
            "tenant": h.tenant_id,
            "boots": h.boots,
            "frame_seq": h.frame_seq,
            "events": f.n,
            "qsecbit": h.qsecbit_score,
            "device_overruns": h.overruns,
            "device_lost": h.lost,
            "gap_events": tracker.gap_events,
            "late_events": tracker.late_events,
        })
        .to_string(),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exportwire::{Header, Rec};
    use crate::securechannel::{
        initiator_read_msg2, initiator_write_msg1, responder_read_msg1, responder_write_msg2, CipherState,
        InitiatorRandomness, ResponderRandomness,
    };

    /// A real in-process PQ-hybrid handshake → (device send cipher, MSSP anti-replay receiver).
    fn session() -> (CipherState, AntiReplayRx, [u8; 32]) {
        use ed25519_compact::{KeyPair, Seed};
        let resp = crate::responder_static();
        let dev = KeyPair::from_seed(Seed::new(boot_abi::sha256::digest(b"export-rx-test-device")));
        let fp = boot_abi::sha256::digest(&dev.pk[..]);
        let mut ent = crate::entropy::OsEntropy;
        let ir = InitiatorRandomness::from_entropy(&mut ent).unwrap();
        let rr = ResponderRandomness::from_entropy(&mut ent).unwrap();
        let (m1, ip) = initiator_write_msg1(&dev, &resp.public(), &ir, &fp).unwrap();
        let rp = responder_read_msg1(&resp, &dev.pk, m1.as_slice()).unwrap();
        let (m2, rs) = responder_write_msg2(rp, &rr, &7u64.to_le_bytes()).unwrap();
        let (is, _) = initiator_read_msg2(ip, m2.as_slice()).unwrap();
        (is.send, rs.recv.into_anti_replay(), fp)
    }

    /// Device side, exactly as the kernel `Exporter` does it: serialize v2, seal_record, tag.
    fn device_dgram(send: &mut CipherState, hdr: &Header, recs: &[Rec]) -> Vec<u8> {
        let mut frame = [0u8; exportwire::MAX_FRAME];
        let n = exportwire::serialize(hdr, recs, &mut frame).unwrap();
        let mut rec = [0u8; 8 + exportwire::MAX_FRAME + 16];
        let rl = send.seal_record(exportwire::AD, &frame[..n], &mut rec).unwrap();
        let mut d = exportwire::DGRAM_TAG.to_vec();
        d.extend_from_slice(&rec[..rl]);
        d
    }

    fn hdr(fp: [u8; 32], frame_seq: u64, first: u64) -> Header {
        Header { tenant_id: 7, device_fp: fp, boots: 2, cntfrq: 1000, frame_seq, first_ev_seq: first, now_ticks: 10_000, ..Default::default() }
    }

    #[test]
    fn device_export_round_trips_to_evidence_jsonl() {
        let (mut send, rx, fp) = session();
        let mut erx = ExportRx::new(rx, 7, fp);
        let recs = [
            Rec { ts: 9_000, src: 0xC0A8_0132, rule_id: 1, severity: 5, verdict: 2, class: 5 },
            Rec { ts: 9_500, src: 0x1122_3344, rule_id: 122, severity: 3, verdict: 2, class: 4 },
        ];
        let f = erx.accept(&device_dgram(&mut send, &hdr(fp, 0, 0), &recs)).unwrap();
        let lines = frame_to_jsonl(&f, &erx.tracker, 1_000_000.0);
        assert_eq!(lines.len(), 3);
        let d0: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(d0["src_ip"], "192.168.1.50");
        assert_eq!(d0["class"], "framedrop");
        assert_eq!(d0["verdict"], "DROP");
        // anchored: event 1000 ticks (1 s at 1 kHz) before the frame's now_ticks
        assert!((d0["ts"].as_f64().unwrap() - 999_999.0).abs() < 1e-6);
        let d1: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!(d1["src_ip"], "", "RA rules carry a MAC hash, never rendered as an IP");
        assert_eq!(d1["src_mac_hash"], "11223344");
        assert_eq!(d1["class"], "ratelimit_enforced");
        let fr: serde_json::Value = serde_json::from_str(&lines[2]).unwrap();
        assert_eq!(fr["type"], "heqk_frame");
        assert_eq!(fr["device_fp"], hex(&fp));
        // Cross-crate e2e hook: hand this exact output to `hookprobe-evidence --heqk-export`.
        if let Ok(path) = std::env::var("HEQK_E2E_JSONL") {
            std::fs::write(path, lines.join("\n") + "\n").unwrap();
        }
    }

    #[test]
    fn lost_datagram_does_not_desync_and_is_reported() {
        let (mut send, rx, fp) = session();
        let mut erx = ExportRx::new(rx, 7, fp);
        let r = [Rec { rule_id: 1, verdict: 2, class: 5, ..Default::default() }; 2];
        let a = device_dgram(&mut send, &hdr(fp, 0, 0), &r);
        let _lost = device_dgram(&mut send, &hdr(fp, 1, 2), &r);
        let c = device_dgram(&mut send, &hdr(fp, 2, 4), &r);
        erx.accept(&a).unwrap();
        erx.accept(&c).expect("a lost datagram must not break the next one");
        assert_eq!(erx.tracker.gap_events, 2);
        assert_eq!(erx.accept(&c).unwrap_err(), RxErr::Channel, "exact replay refused");
    }

    #[test]
    fn foreign_identity_and_untagged_payloads_are_refused() {
        let (mut send, rx, fp) = session();
        let mut erx = ExportRx::new(rx, 7, fp);
        let r = [Rec::default(); 1];
        let mut other = fp;
        other[0] ^= 1;
        assert_eq!(erx.accept(&device_dgram(&mut send, &hdr(other, 0, 0), &r)).unwrap_err(), RxErr::IdentityMismatch);
        assert_eq!(erx.accept(b"HEQK-ENROLL-HELO").unwrap_err(), RxErr::NotExport);
        let mut d = device_dgram(&mut send, &hdr(fp, 1, 1), &r);
        let last = d.len() - 1;
        d[last] ^= 1;
        assert_eq!(erx.accept(&d).unwrap_err(), RxErr::Channel, "tampered tag refused");
    }
}
