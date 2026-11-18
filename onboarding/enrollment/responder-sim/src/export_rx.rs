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

    /// Accept one tagged datagram from either stream on this session: the live HQX1 v2 frames
    /// (`exportwire::AD`) or the sealed-evidence HQX3 frames (`wire::AD_FRAME`, ADR 0066). Both
    /// share the device's send counter, so they share this one anti-replay window; the AD picks the
    /// stream. A failed open leaves the window untouched (`AntiReplayRx::open`), so trying the
    /// second AD after the first is safe and a forgery under either never burns a slot.
    pub fn accept_any(&mut self, udp_payload: &[u8]) -> Result<Stream, RxErr> {
        match self.accept(udp_payload) {
            Err(RxErr::Channel) => {}
            other => return other.map(|f| Stream::Live(Box::new(f))),
        }
        let rec = udp_payload.strip_prefix(&exportwire::DGRAM_TAG[..]).ok_or(RxErr::NotExport)?;
        let mut pt = [0u8; evidence_export::wire::MAX_FRAME];
        let n = self.rx.open_record(evidence_export::wire::AD_FRAME, rec, &mut pt).map_err(|_| RxErr::Channel)?;
        Ok(Stream::Evidence(pt[..n].to_vec()))
    }
}

/// What a tagged export datagram carried.
#[derive(Debug)]
pub enum Stream {
    /// A live HQX1 v2 frame, already authenticated and loss-accounted.
    Live(Box<Frame>),
    /// An opened HQX3 plaintext for `evidence_rx::EvidenceRx::accept`.
    Evidence(Vec<u8>),
}

/// Seal an HQX3 ack onto the session (`wire::AD_ACK`) as a tagged datagram for the device.
pub fn ack_datagram(send: &mut crate::securechannel::CipherState, ack: &evidence_export::wire::Ack) -> Option<Vec<u8>> {
    let mut pt = [0u8; evidence_export::wire::ACK_LEN];
    let n = evidence_export::wire::serialize_ack(ack, &mut pt).ok()?;
    let mut rec = [0u8; 8 + evidence_export::wire::ACK_LEN + 16];
    let rl = send.seal_record(evidence_export::wire::AD_ACK, &pt[..n], &mut rec)?;
    let mut d = exportwire::DGRAM_TAG.to_vec();
    d.extend_from_slice(&rec[..rl]);
    Some(d)
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

    /// ADR 0066 end to end on a real PQ-hybrid session: the device library's `Exporter` reads a
    /// sealed log and sends HQX3 frames; this receiver opens them on the SAME anti-replay window as
    /// the live HQX1 stream, de-duplicates, and seals cumulative acks back; the device opens the
    /// acks under `AD_ACK` and its synced position reaches the log head. One ack is lost on the way,
    /// so the device resends and the receiver must store every event exactly once.
    #[test]
    fn sealed_evidence_round_trip_with_a_lost_ack() {
        use crate::evidence_rx::{outcome_to_jsonl, EvidenceRx};
        use evidence_export::anon::Policy;
        use evidence_export::exporter::{Exporter, Geometry, Identity, SlotSource, Transport};
        use evidence_export::queue::{Config, Link, SyncState};
        use evidence_export::record::{SealOpener, BUILD_TAG_LEN, SEAL_HDR_LEN, SEAL_MAGIC};
        use evidence_export::slot::{frame_slot, RT_EVIDENCE_B, SEC};
        use evidence_export::wire::AD_ACK;
        use ed25519_compact::{KeyPair, Seed};

        // The library treats sealing as opaque (ADR 0066 D5); a pass-through stand-in keeps this test about the
        // stream, not the cipher. HQKSEAL1 itself is proven only once the kernel wiring lands ([P-evexport]).
        struct Plain;
        impl SealOpener for Plain {
            fn open(&self, blob: &[u8], out: &mut [u8]) -> Result<usize, ()> {
                let n = blob.len() - SEAL_HDR_LEN;
                out[..n].copy_from_slice(&blob[SEAL_HDR_LEN..]);
                Ok(n)
            }
        }
        struct Log(Vec<[u8; SEC]>);
        impl SlotSource for Log {
            fn geometry(&self) -> Geometry {
                Geometry { nslots: 64, next_seq: self.0.len() as u64 }
            }
            fn read(&mut self, seq: u64, out: &mut [u8; SEC]) -> Result<(), ()> {
                *out = self.0[seq as usize];
                Ok(())
            }
        }
        struct Tx<'a>(&'a mut CipherState, Vec<Vec<u8>>);
        impl Transport for Tx<'_> {
            fn send(&mut self, ad: &[u8], frame: &[u8]) -> Result<(), ()> {
                let mut rec = [0u8; 8 + evidence_export::wire::MAX_FRAME + 16];
                let rl = self.0.seal_record(ad, frame, &mut rec).ok_or(())?;
                let mut d = exportwire::DGRAM_TAG.to_vec();
                d.extend_from_slice(&rec[..rl]);
                self.1.push(d);
                Ok(())
            }
        }

        // 12 log records × 2 events: an internal LAN source (must never leave) and a public one (kept).
        let mut log = Log(Vec::new());
        for seq in 0..12u64 {
            let mut pt = vec![0u8; BUILD_TAG_LEN];
            pt[..BUILD_TAG_LEN].copy_from_slice(b"e2e-build-tag-01");
            for (src, rule) in [(0xC0A8_0132u32, 100u16), (0x0808_0808, 101)] {
                pt.extend_from_slice(&(1_700_000_000_000 + seq).to_le_bytes());
                pt.extend_from_slice(&src.to_le_bytes());
                pt.extend_from_slice(&rule.to_le_bytes());
                pt.extend_from_slice(&[3, 2]);
            }
            let mut blob = vec![0u8; SEAL_HDR_LEN];
            blob[..8].copy_from_slice(SEAL_MAGIC);
            blob.extend_from_slice(&pt);
            let mut slot = [0u8; SEC];
            assert!(frame_slot(seq, RT_EVIDENCE_B, &blob, &mut slot));
            log.0.push(slot);
        }

        // A real handshake, both directions kept: device send/recv, responder send/recv.
        let resp = crate::responder_static();
        let dev = KeyPair::from_seed(Seed::new(boot_abi::sha256::digest(b"evidence-e2e-device")));
        let fp = boot_abi::sha256::digest(&dev.pk[..]);
        let mut ent = crate::entropy::OsEntropy;
        let ir = InitiatorRandomness::from_entropy(&mut ent).unwrap();
        let rr = ResponderRandomness::from_entropy(&mut ent).unwrap();
        let (m1, ip) = initiator_write_msg1(&dev, &resp.public(), &ir, &fp).unwrap();
        let rp = responder_read_msg1(&resp, &dev.pk, m1.as_slice()).unwrap();
        let (m2, mut rs) = responder_write_msg2(rp, &rr, &7u64.to_le_bytes()).unwrap();
        let (mut is, _) = initiator_read_msg2(ip, m2.as_slice()).unwrap();
        let mut dev_ack_rx = is.recv.into_anti_replay();
        let mut erx = ExportRx::new(rs.recv.into_anti_replay(), 7, fp);
        let mut evrx = EvidenceRx::new(7, fp);

        let cfg = Config { window: 2, ack_timeout_ms: 100, backoff_min_ms: 10, backoff_max_ms: 40 };
        let keep_public = Policy { pseudonym_key: None, keep_public_src: true };
        let mut x = Exporter::new(Identity { tenant_id: 7, device_fp: fp }, keep_public, SyncState::default(), cfg, 60_000);

        // A live HQX1 frame on the same send counter first: the two streams must demux on one window.
        let live = device_dgram(&mut is.send, &hdr(fp, 0, 0), &[Rec { rule_id: 1, verdict: 2, class: 5, ..Default::default() }]);
        assert!(matches!(erx.accept_any(&live).unwrap(), Stream::Live(_)));

        let mut jsonl = Vec::new();
        let mut lost_one = false;
        let mut now = 0u64;
        for _ in 0..200 {
            let mut tx = Tx(&mut is.send, Vec::new());
            x.poll(now, Link::Up, &mut log, &Plain, &mut tx);
            for d in tx.1 {
                let Stream::Evidence(pt) = erx.accept_any(&d).unwrap() else { panic!("HQX3 read as live") };
                let o = evrx.accept(&pt).unwrap();
                jsonl.extend(outcome_to_jsonl(&o, &evrx, 1.0));
                let Some(a) = o.ack(7) else { continue };
                let ad = ack_datagram(&mut rs.send, &a).unwrap();
                if !lost_one {
                    lost_one = true; // the first ack never arrives
                    continue;
                }
                let mut pt = [0u8; 64];
                let n = dev_ack_rx.open_record(AD_ACK, &ad[exportwire::DGRAM_TAG.len()..], &mut pt).unwrap();
                x.on_ack(&pt[..n]);
            }
            if x.state().synced.log_seq == 12 {
                break;
            }
            now += 50;
        }

        assert_eq!(x.state().synced.log_seq, 12, "the device's synced position reaches the log head");
        assert_eq!(evrx.stats.stored_events, 24, "every event stored exactly once");
        assert!(evrx.stats.duplicate_events > 0, "the lost ack forced a resend that was de-duplicated");
        let events: Vec<serde_json::Value> = jsonl.iter().map(|l| serde_json::from_str(l).unwrap()).filter(|v: &serde_json::Value| v["type"] == "heqk_evidence").collect();
        assert_eq!(events.len(), 24);
        assert!(jsonl.iter().all(|l| !l.contains("192.168.")), "no internal address reaches the control plane");
        assert_eq!(events.iter().filter(|v| v["src_ip"] == "8.8.8.8").count(), 12);
        assert_eq!(events.iter().filter(|v| v["src_kind"] == "redacted").count(), 12);
    }
}
