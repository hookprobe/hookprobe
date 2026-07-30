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
use crate::securechannel::{NoiseErr, Session};

/// Frame magic b"HQX1" (LE) — an evidence-export frame. A foreign/garbage record
/// is never misread as an export.
pub const EXPORT_MAGIC: u32 = 0x3158_5148;
/// Export wire-format version.
pub const EXPORT_VERSION: u16 = 1;

/// Serialized image of one evidence record — identical to the M3 `RT_EVIDENCE`
/// on-disk image (`fslog`/`p15_fs_selftest`): ts(8) src(4) rule_id(2) sev(1)
/// verdict(1). Keeping the export image == the persisted image means an exported
/// record is byte-for-byte the persisted evidence node (no re-encoding drift).
pub const EV_IMAGE_LEN: usize = 16;

/// Largest evidence batch one frame carries. Bounded (no heap) — the exporter
/// drains the ring in fixed-size batches; more records ⇒ more frames.
pub const MAX_EVENTS: usize = 16;

/// Frame header length (bytes before the events array).
///   0  magic u32 · 4 version u16 · 6 reserved u16 · 8 tenant_id u64
///   16 device_fp[32] · 48 qsecbit_score u32 · 52 qsecbit_ts u64 · 60 n_events u16
pub const FRAME_HDR: usize = 62;
/// Largest serialized frame (header + full batch).
pub const MAX_FRAME: usize = FRAME_HDR + MAX_EVENTS * EV_IMAGE_LEN; // 318

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportErr {
    /// The batch is larger than one frame can hold.
    TooManyEvents,
    /// The output buffer is too small for the (cipher)text.
    ShortBuffer,
    /// The M4 channel refused the record (AEAD auth / truncation) — a rogue or
    /// unenrolled consumer that lacks the enrolled transport key lands here.
    ChannelReject,
    /// The decrypted bytes are not a valid export frame (magic/version/length).
    Malformed,
    /// The frame's device fingerprint or tenant id did not match what the MC
    /// enrolled — the export is authenticated to the device identity, so a
    /// mismatched-origin frame is rejected fail-closed.
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

/// Serialize one evidence `Event` into its 16-byte export/persist image.
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

/// Parse a 16-byte evidence image back into an `Event` (used by the MC consumer).
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
    })
}

/// A batch the device exports: the enrolled tenant/device identity, the current
/// QSecBit score + its timestamp, and up to `MAX_EVENTS` evidence records. All
/// borrowed / `Copy` — no heap.
pub struct ExportBatch<'a> {
    pub tenant_id: u64,
    pub device_fp: &'a [u8; 32],
    pub qsecbit_score: u32,
    pub qsecbit_ts: u64,
    pub events: &'a [events::Event],
}

/// Serialize `batch` into `out`, returning the frame length. Fails closed if the
/// batch overflows a frame or `out` is too small.
pub fn serialize_frame(batch: &ExportBatch, out: &mut [u8]) -> Result<usize, ExportErr> {
    if batch.events.len() > MAX_EVENTS {
        return Err(ExportErr::TooManyEvents);
    }
    let n = batch.events.len();
    let total = FRAME_HDR + n * EV_IMAGE_LEN;
    if out.len() < total {
        return Err(ExportErr::ShortBuffer);
    }
    out[0..4].copy_from_slice(&EXPORT_MAGIC.to_le_bytes());
    out[4..6].copy_from_slice(&EXPORT_VERSION.to_le_bytes());
    out[6..8].copy_from_slice(&0u16.to_le_bytes()); // reserved
    out[8..16].copy_from_slice(&batch.tenant_id.to_le_bytes());
    out[16..48].copy_from_slice(batch.device_fp);
    out[48..52].copy_from_slice(&batch.qsecbit_score.to_le_bytes());
    out[52..60].copy_from_slice(&batch.qsecbit_ts.to_le_bytes());
    out[60..62].copy_from_slice(&(n as u16).to_le_bytes());
    for (i, ev) in batch.events.iter().enumerate() {
        let off = FRAME_HDR + i * EV_IMAGE_LEN;
        out[off..off + EV_IMAGE_LEN].copy_from_slice(&ev_to_image(ev));
    }
    Ok(total)
}

/// The MC-side parsed view of an export frame (fixed buffers, no heap).
#[derive(Clone, Copy)]
pub struct ReceivedExport {
    pub tenant_id: u64,
    pub device_fp: [u8; 32],
    pub qsecbit_score: u32,
    pub qsecbit_ts: u64,
    pub n_events: usize,
    pub events: [events::Event; MAX_EVENTS],
}

/// Parse a decrypted export frame. Validates magic/version/declared-count/length
/// fail-closed. Does NOT check identity (that is the caller's policy, see
/// `mc_receive_export`).
pub fn parse_frame(buf: &[u8]) -> Result<ReceivedExport, ExportErr> {
    if buf.len() < FRAME_HDR {
        return Err(ExportErr::Malformed);
    }
    let magic = u32::from_le_bytes(buf[0..4].try_into().unwrap());
    let version = u16::from_le_bytes(buf[4..6].try_into().unwrap());
    if magic != EXPORT_MAGIC || version != EXPORT_VERSION {
        return Err(ExportErr::Malformed);
    }
    let n = u16::from_le_bytes(buf[60..62].try_into().unwrap()) as usize;
    if n > MAX_EVENTS {
        return Err(ExportErr::Malformed);
    }
    let total = FRAME_HDR + n * EV_IMAGE_LEN;
    if buf.len() < total {
        return Err(ExportErr::Malformed); // truncated / lied-about count
    }
    let mut device_fp = [0u8; 32];
    device_fp.copy_from_slice(&buf[16..48]);
    let empty = events::Event { ts: 0, src: 0, rule_id: 0, severity: 0, verdict: 0 };
    let mut ev = [empty; MAX_EVENTS];
    for (i, slot) in ev.iter_mut().enumerate().take(n) {
        let off = FRAME_HDR + i * EV_IMAGE_LEN;
        *slot = image_to_ev(&buf[off..off + EV_IMAGE_LEN]).ok_or(ExportErr::Malformed)?;
    }
    Ok(ReceivedExport {
        tenant_id: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        device_fp,
        qsecbit_score: u32::from_le_bytes(buf[48..52].try_into().unwrap()),
        qsecbit_ts: u64::from_le_bytes(buf[52..60].try_into().unwrap()),
        n_events: n,
        events: ev,
    })
}

/// DEVICE side: serialize `batch` and SEAL it into `ct_out` with the enrolled
/// session's `send` AEAD cipher. Returns the ciphertext length. This is what
/// rides the M4 channel — the exact `encrypt_into` discipline `enroll.rs` uses
/// for its fetch request (counter-advanced, tamper/replay-detecting AEAD).
pub fn device_encrypt_export(
    dev: &mut Session,
    batch: &ExportBatch,
    ct_out: &mut [u8],
) -> Result<usize, ExportErr> {
    let mut frame = [0u8; MAX_FRAME];
    let flen = serialize_frame(batch, &mut frame)?;
    // AEAD ciphertext = plaintext + 16-byte tag.
    if ct_out.len() < flen + 16 {
        return Err(ExportErr::ShortBuffer);
    }
    let n = dev
        .send
        .encrypt_into(b"", &frame[..flen], ct_out)
        .ok_or(ExportErr::ShortBuffer)?;
    Ok(n)
}

/// OFF-DEVICE MC (fake) consumer: DECRYPT `ct` with the enrolled session's `recv`
/// cipher, parse the frame, and AUTHENTICATE its origin against the enrolled
/// `(tenant, device_fp)`. Fail-closed at every step:
///   * a party without the enrolled transport key (rogue/unenrolled) fails the
///     AEAD ⇒ `ChannelReject` (never sees plaintext);
///   * a frame whose device fingerprint / tenant does not match what the MC
///     enrolled ⇒ `IdentityMismatch`.
/// On success returns the received evidence — the MC is a CONSUMER only; it does
/// not (and cannot) originate evidence, the device is the source of truth.
pub fn mc_receive_export(
    mc: &mut Session,
    ct: &[u8],
    expect_tenant: u64,
    expect_fp: &[u8; 32],
) -> Result<ReceivedExport, ExportErr> {
    let mut pt = [0u8; MAX_FRAME];
    let n = mc.recv.decrypt_into(b"", ct, &mut pt)?; // ChannelReject on AEAD failure
    let rx = parse_frame(&pt[..n])?;
    if rx.tenant_id != expect_tenant || &rx.device_fp != expect_fp {
        return Err(ExportErr::IdentityMismatch);
    }
    Ok(rx)
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
        let mut junk = [events::Event { ts: 0, src: 0, rule_id: 0, severity: 0, verdict: 0 }; 16];
        while events::drain(&mut junk) > 0 {}
        // Two fresh threat drops (block-port-4444 + block-port-23), each a real
        // signed-rule verdict that emits a SOAR event.
        for &port in &[4444u16, 23u16] {
            let l4 = [0u8, 0u8, (port >> 8) as u8, (port & 0xff) as u8];
            let _ = crate::rules::run_l4(&l4, 0x0A00_02FF); // src 10.0.2.255 (attribution)
        }
        events::drain(out)
    }

    /// (c) enrolled-only + (a-lite in-RAM) export round-trip. Runs in EVERY
    /// securechannel-selftest build (no disk needed). Returns (a_ram, c).
    fn channel_and_rogue_checks() -> (bool, bool) {
        let tv = test_vectors();
        let device_fp = sha256::digest(&tv.dev.pk[..]);
        const TEN: u64 = 0x00C0_FFEE_0000_0006; // the enrolled tenant id

        // --- M2: real verdicts from the SOAR ring ---
        let mut evbuf = [events::Event { ts: 0, src: 0, rule_id: 0, severity: 0, verdict: 0 }; 16];
        let nev = produce_m2_verdicts(&mut evbuf);
        let qs = crate::telemetry::score();

        // --- M4: the ENROLLED channel (device <-> fake MC) ---
        let irand = init_rand(b"HEQK-M6-export-init");
        let rrand = resp_rand(b"HEQK-M6-export-resp");
        let (enr, mut dev, mut mc) = match enroll_over_noise(&tv.dev, &tv.resp, &irand, &rrand, TEN) {
            Ok(x) => x,
            Err(_) => return (false, false),
        };

        let batch = ExportBatch {
            tenant_id: enr.tenant_id,
            device_fp: &device_fp,
            qsecbit_score: qs,
            qsecbit_ts: 0x0000_0000_00A6_0006,
            events: &evbuf[..nev],
        };

        // Device seals + exports over dev.send; the LEGIT MC (mssp.recv) receives.
        let mut ct = [0u8; MAX_FRAME + 16];
        let ctlen = match device_encrypt_export(&mut dev, &batch, &mut ct) {
            Ok(n) => n,
            Err(_) => return (false, false),
        };
        let a_ram = match mc_receive_export(&mut mc, &ct[..ctlen], enr.tenant_id, &device_fp) {
            Ok(rx) => {
                rx.n_events == nev
                    && rx.qsecbit_score == qs
                    && rx.device_fp == device_fp
                    && rx.tenant_id == enr.tenant_id
                    // the exported verdicts survived the channel field-for-field
                    && (0..nev).all(|i| {
                        rx.events[i].rule_id == evbuf[i].rule_id
                            && rx.events[i].verdict == evbuf[i].verdict
                            && rx.events[i].src == evbuf[i].src
                    })
                    // at least one real DROP verdict was exported
                    && nev >= 1
                    && rx.events[..nev].iter().any(|e| e.verdict == crate::packet::DROP as u8)
            }
            Err(_) => false,
        };

        // --- (c) enrolled-only: a ROGUE consumer cannot receive ---
        // The rogue ran a DIFFERENT handshake (independent ephemerals) so it holds
        // a transport key unrelated to dev.send. Re-export a fresh frame (dev's
        // counter advanced) and feed it to the rogue's recv -> AEAD fails.
        let irand2 = init_rand(b"HEQK-M6-rogue-init");
        let rrand2 = resp_rand(b"HEQK-M6-rogue-resp");
        let rogue = enroll_over_noise(&tv.dev, &tv.resp, &irand2, &rrand2, TEN);
        let c = match rogue {
            Ok((_e2, _dev2, mut rogue_mc)) => {
                // Fresh legit export (dev.send counter advances each record).
                let mut ct2 = [0u8; MAX_FRAME + 16];
                match device_encrypt_export(&mut dev, &batch, &mut ct2) {
                    Ok(n2) => {
                        // The rogue MC (wrong transport key) must FAIL to decrypt.
                        let rogue_rejected = matches!(
                            mc_receive_export(&mut rogue_mc, &ct2[..n2], enr.tenant_id, &device_fp),
                            Err(ExportErr::ChannelReject)
                        );
                        // ...and the LEGIT MC still accepts the same fresh frame.
                        let legit_ok =
                            mc_receive_export(&mut mc, &ct2[..n2], enr.tenant_id, &device_fp).is_ok();
                        rogue_rejected && legit_ok
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        };

        kprint!(
            "   channel: M2-verdicts-exported={} (n={}, qsecbit={}) enrolled-only(rogue-rejected+legit-ok)={}\n",
            yn(a_ram), nev, qs, yn(c)
        );
        (a_ram, c)
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
        let (enr, mut dev, mut mc) =
            match enroll_over_noise(&tv.dev, &tv.resp, &irand, &rrand, 9) {
                Ok(x) => x,
                Err(_) => return false,
            };
        let evs = [events::Event { ts: 1, src: 2, rule_id: 3, severity: 5, verdict: 2 }];
        let batch = ExportBatch {
            tenant_id: enr.tenant_id,
            device_fp: &device_fp,
            qsecbit_score: 42,
            qsecbit_ts: 0,
            events: &evs,
        };
        // Warm-up absorbs any first-touch allocation.
        let mut ct = [0u8; MAX_FRAME + 16];
        if let Ok(n) = device_encrypt_export(&mut dev, &batch, &mut ct) {
            let _ = mc_receive_export(&mut mc, &ct[..n], enr.tenant_id, &device_fp);
        }
        const N: u64 = 4;
        let before = crate::heap::used();
        for _ in 0..N {
            if let Ok(n) = device_encrypt_export(&mut dev, &batch, &mut ct) {
                let _ = mc_receive_export(&mut mc, &ct[..n], enr.tenant_id, &device_fp);
            }
        }
        let growth = crate::heap::used() - before;
        growth == 0
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
                [events::Event { ts: 0, src: 0, rule_id: 0, severity: 0, verdict: 0 }; 16];
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
            let mut persisted = [events::Event { ts: 0, src: 0, rule_id: 0, severity: 0, verdict: 0 }; 16];
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
            let (enr, mut dsess, mut msess) =
                match enroll_over_noise(&tv.dev, &tv.resp, &irand, &rrand, TEN) {
                    Ok(x) => x,
                    Err(_) => return false,
                };
            let batch = ExportBatch {
                tenant_id: enr.tenant_id,
                device_fp: &device_fp,
                qsecbit_score: qs_persisted,
                qsecbit_ts: 0xA6,
                events: &persisted[..np],
            };
            let mut ct = [0u8; MAX_FRAME + 16];
            let ctlen = match device_encrypt_export(&mut dsess, &batch, &mut ct) {
                Ok(n) => n,
                Err(_) => return false,
            };
            match mc_receive_export(&mut msess, &ct[..ctlen], enr.tenant_id, &device_fp) {
                Ok(rx) => {
                    rx.n_events == np
                        && rx.qsecbit_score == qs_persisted
                        && rx.device_fp == device_fp
                        && (0..np).all(|i| {
                            rx.events[i].rule_id == persisted[i].rule_id
                                && rx.events[i].verdict == persisted[i].verdict
                                && rx.events[i].src == persisted[i].src
                                && rx.events[i].ts == persisted[i].ts
                        })
                        && rx.events[..np].iter().any(|e| e.verdict == crate::packet::DROP as u8)
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
                [events::Event { ts: 0, src: 0, rule_id: 0, severity: 0, verdict: 0 }; 16];
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
