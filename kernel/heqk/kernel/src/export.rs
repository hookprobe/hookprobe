//! M6 (Track C, ADR 0044 D3 **B2**) — the ON-DEVICE evidence/telemetry EXPORT path.
//!
//! Per ADR 0044 D3 (B2, the recommended default): the CM5 is a PURE heqk
//! sensor/enforcer. Mission Control + HYDRA + the heavy tokio services live
//! OFF-DEVICE (the existing hookprobe-os cloud stack, ADR 0009) — NOT on heqk,
//! NOT built here. This module is the **on-device SENSOR half of B2**: heqk
//! collects what it already HAS —
//!   * detection verdicts/alerts from the **M2** SOAR event ring (`events.rs`),
//!   * persisted evidence records from the **M3** crash-safe store (`fslog.rs`),
//!   * the **QSecBit** score (`telemetry.rs`) —
//! bundles them into a fixed-size **export frame**, and streams it over the
//! **M4** enrolled Noise channel (`enroll.rs` / `securechannel.rs`) to the
//! off-device MC, which is the CONSUMER only. The device is the source of truth;
//! the export is authenticated + encrypted by the M4 channel (mutual auth) and
//! self-describes its origin with the device fingerprint + tenant id.
//!
//! ## The sacred air-gap invariant (preserved, testable)
//! Export is **ADDITIVE, never a precondition**. `should_export` returns `false`
//! for an UNENROLLED device — so no export is attempted and nothing blocks the
//! sensor. Evidence still PERSISTS locally (M3) and the local SOC
//! (detection/enforcement) is fully functional with no MC. Enrollment is a state
//! transition on an already-fully-functional device (mirrors `enroll.rs`), and
//! the `[P-m6-export]` gate re-proves the air-gap case every boot.
//!
//! ## What rides the M4 channel (the "enrolled-only" gate)
//! The frame is sealed with the enrolled session's AEAD `CipherState`
//! (`Session::send`), so ONLY the party that completed the mutual-auth handshake
//! as the pinned MSSP (i.e. holds the crossed transport key `mssp.recv ==
//! dev.send`) can decrypt it. A rogue / unenrolled consumer — one that never ran
//! THE enrolled handshake — holds no such key and its `decrypt_into` fails the
//! AEAD (`ExportErr::ChannelReject`); the evidence is never revealed to it.
//!
//! HONESTY (ADR 0044 D5): the OFF-DEVICE Mission Control + HYDRA + heavy services
//! are the existing cloud stack, NOT heqk, NOT built here. This module builds the
//! on-device EXPORT + a minimal in-process/QEMU FAKE consumer to prove the path.
//! NOT the MC UI, NOT the full evidence graph, NOT metal (Gate R).

#![cfg(feature = "securechannel")]

use crate::enroll::EnrollStatus;
use crate::events;
use crate::exportwire;
use crate::securechannel::{AntiReplayRx, CipherState, NoiseErr};

/// Serialized image of one PERSISTED evidence record — identical to the M3 `RT_EVIDENCE`
/// on-disk image (`fslog`/`prodfull` snapshot): ts(8) src(4) rule_id(2) sev(1) verdict(1).
/// The export WIRE record is `exportwire::Rec` (20 B, adds the tri-state class); this 16-byte
/// image stays the on-disk format so persisted evidence needs no migration.
pub const EV_IMAGE_LEN: usize = 16;

pub use crate::exportwire::{MAX_EVENTS, MAX_FRAME};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportErr {
    /// The output buffer is too small for the sealed record.
    ShortBuffer,
    /// The channel refused the record (AEAD auth / truncation / replay window) — a rogue or
    /// unenrolled consumer that lacks the enrolled transport key lands here.
    ChannelReject,
    /// The decrypted bytes are not a valid export frame (magic/version/length).
    Malformed,
    /// The frame's device fingerprint or tenant id did not match what the MC enrolled.
    IdentityMismatch,
}

impl From<NoiseErr> for ExportErr {
    fn from(_: NoiseErr) -> Self {
        ExportErr::ChannelReject
    }
}

/// The air-gap gate: is export ATTEMPTED in this posture? Only an ENROLLED device
/// exports; UNENROLLED (the air-gap steady state) never does — evidence persists
/// locally and the sensor is unaffected. This is the ONE predicate the datapath
/// consults before touching the M4 channel, so "no MC ⇒ no export" is structural,
/// not a runtime accident.
#[inline]
pub fn should_export(status: &EnrollStatus) -> bool {
    matches!(status, EnrollStatus::Enrolled(_))
}

/// Serialize one evidence `Event` into its 16-byte persist image.
#[inline]
pub fn ev_to_image(ev: &events::Event) -> [u8; EV_IMAGE_LEN] {
    let mut b = [0u8; EV_IMAGE_LEN];
    b[0..8].copy_from_slice(&ev.ts.to_le_bytes());
    b[8..12].copy_from_slice(&ev.src.to_le_bytes());
    b[12..14].copy_from_slice(&ev.rule_id.to_le_bytes());
    b[14] = ev.severity;
    b[15] = ev.verdict;
    b
}

/// Parse a 16-byte persist image back into an `Event` (the image carries no class).
#[inline]
pub fn image_to_ev(b: &[u8]) -> Option<events::Event> {
    if b.len() < EV_IMAGE_LEN {
        return None;
    }
    Some(events::Event {
        ts: u64::from_le_bytes(b[0..8].try_into().ok()?),
        src: u32::from_le_bytes(b[8..12].try_into().ok()?),
        rule_id: u16::from_le_bytes(b[12..14].try_into().ok()?),
        severity: b[14],
        verdict: b[15],
        class: crate::verdict::CLASS_UNKNOWN, // the 16-byte persisted image carries no class
    })
}

/// Bounded export queue depth (events drained from the SOAR ring, awaiting a frame).
pub const EXPORT_QUEUE: usize = 64;

/// The DEVICE-side exporter (M6 B2). The prod loop drains the SOAR ring ONCE per heartbeat and
/// `push`es each event here (and into the M3 snapshot); `seal_next` then emits sealed
/// datagram records, one frame (≤ `MAX_EVENTS`) each, over the enrolled session.
///
/// Every pushed event gets a contiguous per-boot sequence number at push time, so loss is
/// never silent: a full queue drops the event but its sequence number is still consumed (the
/// receiver's `Tracker` sees the gap) and `lost` counts it in the next frame header. Frames
/// are sealed with `seal_record` (explicit seq + the RFC 6479 window on the receiver), so a
/// lost or reordered datagram never desyncs the frames after it. Fixed buffers, no heap.
pub struct Exporter {
    hdr: exportwire::Header,
    q: [(u64, exportwire::Rec); EXPORT_QUEUE],
    qhead: usize,
    qlen: usize,
    next_ev_seq: u64,
    /// Events this exporter dropped (queue full, or a frame that could not be sealed/sent).
    pub lost: u32,
    /// Frames sealed so far this boot.
    pub frames: u64,
}

impl Exporter {
    pub fn new(tenant_id: u64, device_fp: [u8; 32], boots: u32, cntfrq: u32) -> Self {
        Exporter {
            hdr: exportwire::Header { tenant_id, device_fp, boots, cntfrq, ..Default::default() },
            q: [(0, exportwire::Rec::default()); EXPORT_QUEUE],
            qhead: 0,
            qlen: 0,
            next_ev_seq: 0,
            lost: 0,
            frames: 0,
        }
    }

    /// Events queued for export.
    pub fn pending(&self) -> usize {
        self.qlen
    }

    /// Queue one drained SOAR event. Non-blocking: a full queue drops the event (counted;
    /// its sequence number is still consumed so the receiver sees the gap).
    pub fn push(&mut self, ev: &events::Event) {
        let seq = self.next_ev_seq;
        self.next_ev_seq = self.next_ev_seq.wrapping_add(1);
        if self.qlen == EXPORT_QUEUE {
            self.lost = self.lost.saturating_add(1);
            return;
        }
        let rec = exportwire::Rec {
            ts: ev.ts,
            src: ev.src,
            rule_id: ev.rule_id,
            severity: ev.severity,
            verdict: ev.verdict,
            class: ev.class,
        };
        self.q[(self.qhead + self.qlen) % EXPORT_QUEUE] = (seq, rec);
        self.qlen += 1;
    }

    /// Seal the next frame into `out` (a datagram record: `LE64(seq) ‖ frame ‖ tag`). Takes up
    /// to `MAX_EVENTS` queued events with CONTIGUOUS sequence numbers (a frame never spans a
    /// gap, so `first_ev_seq + i` is exact). A heartbeat frame with zero events still carries
    /// the counters/QSecBit. Returns `(record_len, events_in_frame)`.
    pub fn seal_next(
        &mut self,
        send: &mut CipherState,
        now_ticks: u64,
        qsecbit: (u32, u64),
        overruns: u32,
        out: &mut [u8],
    ) -> Result<(usize, usize), ExportErr> {
        let mut recs = [exportwire::Rec::default(); MAX_EVENTS];
        let mut n = 0usize;
        let first_seq = if self.qlen > 0 { self.q[self.qhead].0 } else { self.next_ev_seq };
        while n < MAX_EVENTS && n < self.qlen {
            let (seq, r) = self.q[(self.qhead + n) % EXPORT_QUEUE];
            if seq != first_seq.wrapping_add(n as u64) {
                break; // a dropped event sits here — end the frame at the gap
            }
            recs[n] = r;
            n += 1;
        }
        let mut h = self.hdr;
        h.frame_seq = self.frames;
        h.first_ev_seq = first_seq;
        h.now_ticks = now_ticks;
        h.qsecbit_score = qsecbit.0;
        h.qsecbit_ts = qsecbit.1;
        h.overruns = overruns;
        h.lost = self.lost;
        let mut frame = [0u8; MAX_FRAME];
        let flen = exportwire::serialize(&h, &recs[..n], &mut frame).map_err(|_| ExportErr::ShortBuffer)?;
        let rlen = send.seal_record(exportwire::AD, &frame[..flen], out).ok_or(ExportErr::ShortBuffer)?;
        self.qhead = (self.qhead + n) % EXPORT_QUEUE;
        self.qlen -= n;
        self.frames += 1;
        Ok((rlen, n))
    }

    /// The caller could not put a sealed record on the wire: its events are gone. Count them.
    pub fn tx_failed(&mut self, events_in_frame: usize) {
        self.lost = self.lost.saturating_add(events_in_frame as u32);
    }
}

/// Largest sealed export record (seq prefix + frame + AEAD tag).
pub const MAX_RECORD: usize = crate::securechannel::RECORD_SEQ_LEN + MAX_FRAME + 16;

/// OFF-DEVICE consumer step (the in-QEMU fake MC; the host receiver does the same with the same
/// two shared files): open one record through the anti-replay window, then authenticate +
/// account it with the shared `Tracker`.
pub fn mc_open(
    rx: &mut AntiReplayRx,
    tracker: &mut exportwire::Tracker,
    rec: &[u8],
) -> Result<exportwire::Frame, ExportErr> {
    let mut pt = [0u8; MAX_FRAME];
    let n = rx.open_record(exportwire::AD, rec, &mut pt)?;
    tracker.accept(&pt[..n]).map_err(|e| match e {
        exportwire::TrackErr::Malformed => ExportErr::Malformed,
        exportwire::TrackErr::IdentityMismatch => ExportErr::IdentityMismatch,
    })
}

// ===========================================================================
// The [P-m6-export] gate (securechannel-selftest). Deterministic loopback + a
// fake off-device MC consumer; the M2 SOAR ring + M3 store + M4 enrolled Noise
// channel are the REAL kernel primitives. The full (a) gate (M2 verdict -> M3
// DISK persist -> M4 export -> MC verify) additionally needs `p15-write` (the
// store write path) + a virtio-blk backing, so it rides validate.sh's p15-write
// two-boot; the plain build proves the in-RAM (a)/(b)/(c) halves inline.
// ===========================================================================

#[cfg(feature = "securechannel-selftest")]
mod selftest {
    use super::*;
    use crate::enroll::enroll_over_noise;
    use crate::securechannel::{
        test_vectors, InitiatorRandomness, ResponderRandomness,
    };
    use boot_abi::sha256;

    macro_rules! kprint {
        ($($t:tt)*) => { arch_aarch64::_print(format_args!($($t)*)) };
    }
    fn yn(b: bool) -> &'static str {
        if b { "PASS" } else { "FAIL" }
    }

    fn init_rand(label: &[u8]) -> InitiatorRandomness {
        use crate::entropy::{MetalEntropy, StubTrng};
        let mut e = MetalEntropy::new(StubTrng::from_label(label));
        InitiatorRandomness::from_entropy(&mut e).unwrap()
    }
    fn resp_rand(label: &[u8]) -> ResponderRandomness {
        use crate::entropy::{MetalEntropy, StubTrng};
        let mut e = MetalEntropy::new(StubTrng::from_label(label));
        ResponderRandomness::from_entropy(&mut e).unwrap()
    }

    /// Produce a REAL M2 verdict: drain any stale SOAR events, then fire a signed
    /// threat rule (dst port 4444) through `rules::run_l4`, which pushes a DROP
    /// event header into the SOAR ring in the TCB — exactly the P8-soar path.
    /// Drain and return the fresh events (the detection verdicts to export).
    fn produce_m2_verdicts(out: &mut [events::Event]) -> usize {
        // Drain-and-discard so we assert only on our OWN fresh verdicts.
        let mut junk = [events::Event::EMPTY; 16];
        while events::drain(&mut junk) > 0 {}
        // Two fresh threat drops (block-port-4444 + block-port-23), each a real
        // signed-rule verdict that emits a SOAR event.
        for &port in &[4444u16, 23u16] {
            let l4 = [0u8, 0u8, (port >> 8) as u8, (port & 0xff) as u8];
            let _ = crate::rules::run_l4(&l4, 0x0A00_02FF); // src 10.0.2.255 (attribution)
        }
        events::drain(out)
    }

    /// (c) enrolled-only + (a-lite in-RAM) export round-trip + the v2 transport properties.
    /// Runs in EVERY securechannel-selftest build (no disk needed). Returns (a_ram, c).
    fn channel_and_rogue_checks() -> (bool, bool) {
        use crate::exportwire::Tracker;
        let tv = test_vectors();
        let device_fp = sha256::digest(&tv.dev.pk[..]);
        const TEN: u64 = 0x00C0_FFEE_0000_0006; // the enrolled tenant id
        const FRQ: u32 = 62_500_000;

        // --- M2: real verdicts from the SOAR ring ---
        let mut evbuf = [events::Event::EMPTY; 16];
        let nev = produce_m2_verdicts(&mut evbuf);
        let qs = crate::telemetry::score();

        // --- M4: the ENROLLED channel (device <-> fake MC) ---
        let irand = init_rand(b"HEQK-M6-export-init");
        let rrand = resp_rand(b"HEQK-M6-export-resp");
        let (enr, mut dev, mc) = match enroll_over_noise(&tv.dev, &tv.resp, &irand, &rrand, TEN) {
            Ok(x) => x,
            Err(_) => return (false, false),
        };
        let mut ex = Exporter::new(enr.tenant_id, device_fp, 3, FRQ);
        let mut rx = mc.recv.into_anti_replay();
        let mut tr = Tracker::new(enr.tenant_id, device_fp);
        let mut seal = |ex: &mut Exporter, now: u64| -> Option<([u8; MAX_RECORD], usize, usize)> {
            let mut r = [0u8; MAX_RECORD];
            ex.seal_next(&mut dev.send, now, (qs, 0xA6), events::overruns(), &mut r).ok().map(|(l, n)| (r, l, n))
        };

        // (a) real verdicts round-trip field-for-field, INCLUDING the tri-state class.
        for e in &evbuf[..nev] {
            ex.push(e);
        }
        let a_ram = match seal(&mut ex, 1_000) {
            Some((r, l, n)) => match mc_open(&mut rx, &mut tr, &r[..l]) {
                Ok(f) => {
                    n == nev && f.n == nev && f.hdr.boots == 3 && f.hdr.cntfrq == FRQ
                        && f.hdr.qsecbit_score == qs && f.hdr.first_ev_seq == 0
                        && (0..nev).all(|i| {
                            let (w, e) = (f.recs[i], evbuf[i]);
                            w.rule_id == e.rule_id && w.verdict == e.verdict && w.src == e.src
                                && w.ts == e.ts && w.class == e.class
                        })
                        && nev >= 1
                        && f.records().iter().any(|w| w.verdict == crate::packet::DROP as u8 && w.class != 0)
                }
                Err(_) => false,
            },
            None => false,
        };

        // (t) TRANSPORT: frame B is lost in transit, C still opens (no desync) and the gap is
        // counted; B then arrives late and is accepted as late; an exact replay and a tampered
        // record are refused.
        let synth = |rule: u16| events::Event { ts: 2_000, src: 0xC612_0001, rule_id: rule, severity: 3, verdict: 1, class: crate::verdict::CLASS_OBSERVE };
        for r in 0..3u16 {
            ex.push(&synth(200 + r));
        }
        let b = seal(&mut ex, 2_100);
        ex.push(&synth(210));
        ex.push(&synth(211));
        let c = seal(&mut ex, 2_200);
        let t_ok = match (b, c) {
            (Some((br, bl, 3)), Some((cr, cl, 2))) => {
                let c_ok = mc_open(&mut rx, &mut tr, &cr[..cl]).map_or(false, |f| f.recs[0].rule_id == 210);
                let gap = tr.gap_events == 3;
                let b_late = mc_open(&mut rx, &mut tr, &br[..bl]).is_ok() && tr.late_events == 3;
                let replay = matches!(mc_open(&mut rx, &mut tr, &cr[..cl]), Err(ExportErr::ChannelReject));
                let mut bad = cr;
                bad[cl / 2] ^= 0x40;
                let tamper = mc_open(&mut rx, &mut tr, &bad[..cl]).is_err();
                c_ok && gap && b_late && replay && tamper
            }
            _ => false,
        };

        // (o) OVERFLOW honesty: a full queue drops events, counts them in `lost`, and the
        // receiver sees the same number as a sequence gap.
        let mut ex2 = Exporter::new(enr.tenant_id, device_fp, 3, FRQ);
        for i in 0..(EXPORT_QUEUE + 5) {
            ex2.push(&synth(300 + i as u16));
        }
        let lost5 = ex2.lost == 5;
        let mut gap_before = 0;
        let mut o_ok = lost5;
        let mut rx2_tr = Tracker::new(enr.tenant_id, device_fp);
        let mut drained = true;
        while ex2.pending() > 0 {
            match seal(&mut ex2, 3_000) {
                Some((r, l, _)) => {
                    if mc_open(&mut rx, &mut rx2_tr, &r[..l]).is_err() {
                        drained = false;
                    }
                }
                None => drained = false,
            }
            gap_before = rx2_tr.gap_events;
        }
        ex2.push(&synth(400));
        if let Some((r, l, _)) = seal(&mut ex2, 3_100) {
            match mc_open(&mut rx, &mut rx2_tr, &r[..l]) {
                Ok(f) => o_ok &= f.hdr.lost == 5 && rx2_tr.gap_events == gap_before + 5,
                Err(_) => o_ok = false,
            }
        } else {
            o_ok = false;
        }
        o_ok &= drained && gap_before == 0;

        // (c) enrolled-only: a ROGUE consumer (an independent handshake → unrelated key) cannot
        // open the record; a frame claiming another device is refused even on the right key.
        let irand2 = init_rand(b"HEQK-M6-rogue-init");
        let rrand2 = resp_rand(b"HEQK-M6-rogue-resp");
        let c_ok = match enroll_over_noise(&tv.dev, &tv.resp, &irand2, &rrand2, TEN) {
            Ok((_e2, _dev2, rogue_mc)) => match seal(&mut ex, 4_000) {
                Some((r, l, _)) => {
                    let mut rogue_rx = rogue_mc.recv.into_anti_replay();
                    let mut rogue_tr = Tracker::new(enr.tenant_id, device_fp);
                    let rogue_rejected = matches!(mc_open(&mut rogue_rx, &mut rogue_tr, &r[..l]), Err(ExportErr::ChannelReject));
                    let mut wrong = Tracker::new(enr.tenant_id, [0xEE; 32]);
                    let id_refused = matches!(mc_open(&mut rx, &mut wrong, &r[..l]), Err(ExportErr::IdentityMismatch));
                    rogue_rejected && id_refused
                }
                None => false,
            },
            Err(_) => false,
        };

        kprint!(
            "   channel: M2-verdicts+class-exported={} (n={}, qsecbit={}) loss/reorder/replay/tamper={} (gap={} late={}) overflow-honest(lost=gap)={} enrolled-only+identity={}\n",
            yn(a_ram), nev, qs, yn(t_ok), tr.gap_events, tr.late_events, yn(o_ok), yn(c_ok)
        );
        (a_ram && t_ok && o_ok, c_ok)
    }

    /// (b) AIR-GAP: UNENROLLED is a valid steady state — no export attempted, no
    /// block, and the local SOC is unaffected. Pure logic (no disk); the DISK
    /// persist-while-unenrolled leg is proven in the p15-write full gate.
    fn airgap_checks() -> bool {
        let unenrolled = EnrollStatus::default_standalone();
        // The air-gap gate REFUSES export when there is no MC.
        let no_export_unenrolled = !should_export(&unenrolled);
        // ...yet the local SOC is available and never boot-blocking (the invariant).
        let soc_up = unenrolled.local_soc_available() && !unenrolled.is_boot_blocking();
        // An ENROLLED device DOES export (the additive layer), symmetric proof.
        let tv = test_vectors();
        let enr = crate::enroll::Enrollment {
            tenant_id: 7,
            responder_x_pk: tv.resp.public().x_pk(),
            device_fp: sha256::digest(&tv.dev.pk[..]),
            generation: 1,
        };
        let export_when_enrolled = should_export(&EnrollStatus::Enrolled(enr));
        // Even ENROLLED, export is non-blocking / additive (never gates the SOC).
        let enrolled_soc_up = EnrollStatus::Enrolled(enr).local_soc_available()
            && !EnrollStatus::Enrolled(enr).is_boot_blocking();
        let ok = no_export_unenrolled && soc_up && export_when_enrolled && enrolled_soc_up;
        kprint!(
            "   air-gap: unenrolled->no-export={} local-SOC-up={} enrolled->export={} export-additive(non-blocking)={}\n",
            yn(no_export_unenrolled), yn(soc_up), yn(export_when_enrolled), yn(enrolled_soc_up)
        );
        ok
    }

    /// The M6 export self-test entry.
    pub fn m6_export_selftest() {
        kprint!(" [P-m6-export] M6 (ADR 0044 D3 B2) evidence/telemetry export: on-device sensor -> M4 enrolled Noise channel -> OFF-DEVICE (fake) MC consumer:\n");

        let (a_ram, c) = channel_and_rogue_checks();
        let b = airgap_checks();

        // Fixed-buffer discipline: repeated exports must not grow the bump heap.
        let buffers_ok = heap_stability_check();

        kprint!(
            "   in-RAM(a) export-round-trip={} air-gap(b)={} enrolled-only(c)={} fixed-buffers={}\n",
            yn(a_ram), yn(b), yn(c), yn(buffers_ok)
        );

        // The FULL (a) — M2 verdict -> M3 DISK persist -> M4 export -> MC verify —
        // needs the store write path + a disk. Without p15-write this is a partial
        // proof; do NOT emit the PASS marker (the gate is captured from the
        // p15-write two-boot, whose output validate.sh folds into the report).
        #[cfg(not(feature = "p15-write"))]
        {
            kprint!(" [P-m6-export] SKIP — read-only build: M2-verdict->M4-export->fake-MC-verify, air-gap, enrolled-only proven in-RAM above; the FULL gate (M2 verdict -> M3 DISK-persisted evidence -> exported over the enrolled channel -> MC verifies the PERSISTED record) needs --features p15-write (virtio-blk)\n");
        }
        #[cfg(feature = "p15-write")]
        persist_leg_gate(a_ram, b, c, buffers_ok);
    }

    /// N exports must not grow the heap (fixed buffers, no per-frame Vec).
    fn heap_stability_check() -> bool {
        let tv = test_vectors();
        let device_fp = sha256::digest(&tv.dev.pk[..]);
        let irand = init_rand(b"HEQK-M6-heap-init");
        let rrand = resp_rand(b"HEQK-M6-heap-resp");
        let (enr, mut dev, mc) =
            match enroll_over_noise(&tv.dev, &tv.resp, &irand, &rrand, 9) {
                Ok(x) => x,
                Err(_) => return false,
            };
        let ev = events::Event { ts: 1, src: 2, rule_id: 3, severity: 5, verdict: 2, class: crate::verdict::CLASS_FRAMEDROP };
        let mut ex = Exporter::new(enr.tenant_id, device_fp, 1, 1);
        let mut rx = mc.recv.into_anti_replay();
        let mut tr = crate::exportwire::Tracker::new(enr.tenant_id, device_fp);
        let mut one = |ex: &mut Exporter| {
            ex.push(&ev);
            let mut r = [0u8; MAX_RECORD];
            if let Ok((l, _)) = ex.seal_next(&mut dev.send, 1, (42, 0), 0, &mut r) {
                let _ = mc_open(&mut rx, &mut tr, &r[..l]);
            }
        };
        one(&mut ex); // warm-up absorbs any first-touch allocation
        let before = crate::heap::used();
        for _ in 0..4 {
            one(&mut ex);
        }
        crate::heap::used() - before == 0
    }

    // --- (a) FULL: M2 verdict -> M3 DISK persist -> M4 export -> MC verify -----
    #[cfg(feature = "p15-write")]
    fn persist_leg_gate(a_ram: bool, b: bool, c: bool, buffers_ok: bool) {
        use crate::fslog::{self, RT_EVIDENCE, RT_QSECBIT};
        use crate::store::{RegionKind, SealedStore};

        let mut dev_blk = match arch_aarch64::virtio_blk::VirtioBlk::open() {
            Some(d) => d,
            None => {
                kprint!(" [P-m6-export] SKIP — no virtio-blk device (diskless boot); in-RAM (a)/(b)/(c) proven above\n");
                return;
            }
        };
        let mut store = match SealedStore::open(&mut dev_blk) {
            Ok(s) => s,
            Err(e) => {
                kprint!(" [P-m6-export] FAIL — guard refused device MBR: {:?}\n", e);
                return;
            }
        };
        // Regions disjoint from every other selftest (all < 10000): evidence log
        // for the (a) full leg, and a second log for the (b) unenrolled-persist leg.
        const EV_LO: u64 = 10000;
        const EV_HI: u64 = 10040; // enrolled-export evidence log
        const AG_LO: u64 = 10100;
        const AG_HI: u64 = 10140; // air-gap (unenrolled) persist log
        if store.add_region(EV_LO, EV_HI, RegionKind::DataVolume).is_err()
            || store.add_region(AG_LO, AG_HI, RegionKind::DataVolume).is_err()
        {
            kprint!(" [P-m6-export] FAIL — could not register the export data regions\n");
            return;
        }

        // ==== (a) M2 verdict -> M3 DISK persist -> M4 export -> MC verify ====
        let full_a = (|| -> bool {
            // M2: real verdicts from the SOAR ring.
            let mut evbuf =
                [events::Event::EMPTY; 16];
            let nev = produce_m2_verdicts(&mut evbuf);
            if nev == 0 {
                return false;
            }
            let qs = crate::telemetry::score();

            // M3: PERSIST each verdict as an RT_EVIDENCE record + a QSecBit record
            // (fresh format so read-back is deterministic; ring, guarded write).
            let mut log = match fslog::format(&mut store, EV_LO, EV_HI) {
                Ok(l) => l,
                Err(_) => return false,
            };
            for ev in &evbuf[..nev] {
                if log.append(&mut store, RT_EVIDENCE, &ev_to_image(ev)).is_err() {
                    return false;
                }
            }
            let mut qsb = [0u8; 12];
            qsb[0..8].copy_from_slice(&0xA6u64.to_le_bytes());
            qsb[8..12].copy_from_slice(&qs.to_le_bytes());
            if log.append(&mut store, RT_QSECBIT, &qsb).is_err() {
                return false;
            }

            // Re-MOUNT and READ BACK the PERSISTED evidence (crash-safe store) —
            // the export is built from what actually landed on disk, not RAM.
            let mounted = match fslog::LogStore::mount(&store, EV_LO, EV_HI) {
                Ok(l) => l,
                Err(_) => return false,
            };
            let mut persisted = [events::Event::EMPTY; 16];
            let mut np = 0usize;
            let mut qs_persisted = 0u32;
            mounted
                .for_each(&store, |_seq, rt, pl| {
                    if rt == RT_EVIDENCE {
                        if let Some(ev) = image_to_ev(pl) {
                            if np < persisted.len() {
                                persisted[np] = ev;
                                np += 1;
                            }
                        }
                    } else if rt == RT_QSECBIT && pl.len() >= 12 {
                        qs_persisted = u32::from_le_bytes(pl[8..12].try_into().unwrap());
                    }
                })
                .ok();
            if np != nev || qs_persisted != qs {
                return false; // persistence lost a record
            }

            // M4: export the PERSISTED evidence over the enrolled Noise channel to
            // the fake off-device MC, which decrypts + verifies it.
            let tv = test_vectors();
            let device_fp = sha256::digest(&tv.dev.pk[..]);
            const TEN: u64 = 0x00C0_FFEE_0000_0006;
            let irand = init_rand(b"HEQK-M6-full-init");
            let rrand = resp_rand(b"HEQK-M6-full-resp");
            let (enr, mut dsess, msess) =
                match enroll_over_noise(&tv.dev, &tv.resp, &irand, &rrand, TEN) {
                    Ok(x) => x,
                    Err(_) => return false,
                };
            let mut ex = Exporter::new(enr.tenant_id, device_fp, 1, 1);
            for e in &persisted[..np] {
                ex.push(e);
            }
            let mut r = [0u8; MAX_RECORD];
            let rl = match ex.seal_next(&mut dsess.send, 1, (qs_persisted, 0xA6), 0, &mut r) {
                Ok((l, _)) => l,
                Err(_) => return false,
            };
            let mut rx = msess.recv.into_anti_replay();
            let mut tr = crate::exportwire::Tracker::new(enr.tenant_id, device_fp);
            match mc_open(&mut rx, &mut tr, &r[..rl]) {
                Ok(f) => {
                    f.n == np
                        && f.hdr.qsecbit_score == qs_persisted
                        && f.hdr.device_fp == device_fp
                        && (0..np).all(|i| {
                            f.recs[i].rule_id == persisted[i].rule_id
                                && f.recs[i].verdict == persisted[i].verdict
                                && f.recs[i].src == persisted[i].src
                                && f.recs[i].ts == persisted[i].ts
                        })
                        && f.records().iter().any(|w| w.verdict == crate::packet::DROP as u8)
                }
                Err(_) => false,
            }
        })();

        // ==== (b) AIR-GAP on DISK: UNENROLLED -> evidence PERSISTS locally,
        //         SOC unaffected, and NO export is attempted (should_export=false).
        let airgap_disk = (|| -> bool {
            let status = EnrollStatus::default_standalone(); // Unenrolled
            // The datapath consults the gate BEFORE the channel: no MC => no export.
            let attempted = should_export(&status);
            if attempted {
                return false; // must NOT attempt export when unenrolled
            }
            // Meanwhile the local SOC keeps persisting evidence (M3) with no channel.
            let mut evbuf =
                [events::Event::EMPTY; 16];
            let nev = produce_m2_verdicts(&mut evbuf);
            let mut log = match fslog::format(&mut store, AG_LO, AG_HI) {
                Ok(l) => l,
                Err(_) => return false,
            };
            for ev in &evbuf[..nev] {
                if log.append(&mut store, RT_EVIDENCE, &ev_to_image(ev)).is_err() {
                    return false;
                }
            }
            let mounted = match fslog::LogStore::mount(&store, AG_LO, AG_HI) {
                Ok(l) => l,
                Err(_) => return false,
            };
            let mut np = 0usize;
            mounted
                .for_each(&store, |_s, rt, _pl| {
                    if rt == RT_EVIDENCE {
                        np += 1;
                    }
                })
                .ok();
            // Evidence persisted locally, SOC available, never boot-blocking, no export.
            np == nev
                && nev >= 1
                && status.local_soc_available()
                && !status.is_boot_blocking()
        })();

        let pass = full_a && airgap_disk && a_ram && b && c && buffers_ok;
        kprint!(
            "   full: M2-verdict->M3-disk-persist->M4-export->MC-verify(a)={} air-gap-on-disk(unenrolled persists, no export)(b)={}\n",
            yn(full_a), yn(airgap_disk)
        );
        kprint!(" [P-m6-export] {} — M6 (ADR 0044 D3 B2) on-device SENSOR-EXPORT: a real M2 SOAR verdict is PERSISTED to the M3 crash-safe store, read back, and EXPORTED over the M4 enrolled PQ-hybrid Noise channel to a FAKE off-device MC that DECRYPTS + AUTHENTICATES it (tenant + device fingerprint); the AIR-GAP invariant holds — UNENROLLED persists evidence locally with the local SOC unaffected and NO export attempted (should_export=false, additive/never-blocking); and the export is ENROLLED-ONLY — a rogue/unenrolled consumer lacking the enrolled transport key FAILS the AEAD (never sees the evidence) while the legit MC accepts it. The OFF-DEVICE Mission Control + HYDRA + heavy tokio services are the existing cloud stack (ADR 0009), NOT heqk, NOT built here; this is the on-device export + a minimal fake consumer. Real mssp.hookprobe.com PKI + HW-TRNG + network + real MC = metal (Gate R)\n",
            yn(pass));
    }
}

#[cfg(feature = "securechannel-selftest")]
pub use selftest::m6_export_selftest;
