//! M6 export frame **v2** — the device→off-device evidence wire format, as a PURE codec.
//!
//! No crate dependencies (no `events`, no asm, no allocator), so the off-device receiver
//! (`onboarding/enrollment/responder-sim`) links this exact file via `#[path]`: every byte the MC parses is
//! produced by the code the device runs, with no second implementation to drift.
//!
//! Why v2 (v1 = `export.rs` HQX1/1, self-test only): v1 frames could not be interpreted
//! off-device —
//!   * `ts` was raw `cntpct` ticks with no frequency, boot identity or anchor;
//!   * nothing numbered the frames or events, so a lost frame was silent;
//!   * the tri-state verdict class was collapsed to PASS/DROP;
//!   * ring overruns (evidence the device itself dropped) were never reported.
//!
//! v2 fixes each: `boots` + `cntfrq` + `now_ticks` let the receiver anchor every event to wall
//! time (`event_wall = rx_wall − (now_ticks − ev.ts)/cntfrq`, accurate to the link latency, no
//! SNTP needed); `frame_seq` + a contiguous per-boot `first_ev_seq` make every gap detectable;
//! `overruns`/`lost` carry the device's own loss honestly; each record carries its class.
//!
//! Layout (little-endian). Header, `FRAME_HDR` = 104 bytes:
//! ```text
//!   0 magic u32 "HQX1" | 4 version u16 = 2 | 6 n_events u16 | 8 tenant_id u64
//!  16 device_fp [32]   | 48 boots u32      | 52 cntfrq u32  | 56 frame_seq u64
//!  64 first_ev_seq u64 | 72 now_ticks u64  | 80 qsecbit_ts u64
//!  88 overruns u32     | 92 lost u32       | 96 qsecbit_score u32 | 100 reserved u32
//! ```
//! Then `n_events` × `REC_LEN` = 20-byte records:
//! `ts u64 | src u32 | rule_id u16 | severity u8 | verdict u8 | class u8 | reserved [3]`.
//! (`src` is rule-keyed: IPv4 host-order for flow rules, a src-MAC hash for the IPv6 RA rules
//! 121/122/123 — see `events::Event::src`.)

pub const MAGIC: u32 = 0x3158_5148; // b"HQX1" LE (shared with v1; the version field splits them)
pub const VERSION: u16 = 2;
pub const FRAME_HDR: usize = 104;
pub const REC_LEN: usize = 20;
/// Largest batch one frame carries — sized so a sealed frame (seq 8 + frame + tag 16) fits one
/// un-fragmented UDP datagram with room to spare (8 + 104 + 16·20 + 16 = 448 B payload).
pub const MAX_EVENTS: usize = 16;
pub const MAX_FRAME: usize = FRAME_HDR + MAX_EVENTS * REC_LEN; // 424
/// UDP-payload tag in front of every sealed export record on the control-plane port. Read as a
/// handshake chunk header it gives `total_len = 0x5148` (20808) > `HS_MSG_MAX`, so the
/// reassembler rejects it as malformed — a tagged export can never be mistaken for a handshake
/// chunk (or vice versa), and the MSSP demuxes on it without trial decryption.
pub const DGRAM_TAG: &[u8; 4] = b"HQXR";
/// AEAD associated data for export records — domain-separates them from every other record
/// on the session (a replayed reach-policy record can never open as an export, and vice versa).
pub const AD: &[u8] = b"HQX2-export";

/// One evidence record on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Rec {
    pub ts: u64,
    pub src: u32,
    pub rule_id: u16,
    pub severity: u8,
    pub verdict: u8,
    pub class: u8,
}

/// Frame header fields (everything except the records).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Header {
    pub tenant_id: u64,
    pub device_fp: [u8; 32],
    pub boots: u32,
    pub cntfrq: u32,
    pub frame_seq: u64,
    pub first_ev_seq: u64,
    pub now_ticks: u64,
    pub qsecbit_ts: u64,
    pub overruns: u32,
    pub lost: u32,
    pub qsecbit_score: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireErr {
    TooManyEvents,
    ShortBuffer,
    Malformed,
}

/// A parsed frame (fixed buffers, no heap).
#[derive(Clone, Copy, Debug)]
pub struct Frame {
    pub hdr: Header,
    pub n: usize,
    pub recs: [Rec; MAX_EVENTS],
}

impl Frame {
    pub fn records(&self) -> &[Rec] {
        &self.recs[..self.n]
    }
}

fn put(b: &mut [u8], o: usize, v: &[u8]) {
    b[o..o + v.len()].copy_from_slice(v);
}
fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

/// Serialize `hdr` + `recs` into `out`; returns the frame length. Fail-closed on overflow.
pub fn serialize(hdr: &Header, recs: &[Rec], out: &mut [u8]) -> Result<usize, WireErr> {
    if recs.len() > MAX_EVENTS {
        return Err(WireErr::TooManyEvents);
    }
    let total = FRAME_HDR + recs.len() * REC_LEN;
    if out.len() < total {
        return Err(WireErr::ShortBuffer);
    }
    for x in out[..FRAME_HDR].iter_mut() {
        *x = 0;
    }
    put(out, 0, &MAGIC.to_le_bytes());
    put(out, 4, &VERSION.to_le_bytes());
    put(out, 6, &(recs.len() as u16).to_le_bytes());
    put(out, 8, &hdr.tenant_id.to_le_bytes());
    put(out, 16, &hdr.device_fp);
    put(out, 48, &hdr.boots.to_le_bytes());
    put(out, 52, &hdr.cntfrq.to_le_bytes());
    put(out, 56, &hdr.frame_seq.to_le_bytes());
    put(out, 64, &hdr.first_ev_seq.to_le_bytes());
    put(out, 72, &hdr.now_ticks.to_le_bytes());
    put(out, 80, &hdr.qsecbit_ts.to_le_bytes());
    put(out, 88, &hdr.overruns.to_le_bytes());
    put(out, 92, &hdr.lost.to_le_bytes());
    put(out, 96, &hdr.qsecbit_score.to_le_bytes());
    for (i, r) in recs.iter().enumerate() {
        let o = FRAME_HDR + i * REC_LEN;
        put(out, o, &r.ts.to_le_bytes());
        put(out, o + 8, &r.src.to_le_bytes());
        put(out, o + 12, &r.rule_id.to_le_bytes());
        out[o + 14] = r.severity;
        out[o + 15] = r.verdict;
        out[o + 16] = r.class;
        put(out, o + 17, &[0u8; 3]);
    }
    Ok(total)
}

/// Parse a decrypted frame. Validates magic/version/declared count/length, fail-closed.
/// Identity (tenant/device_fp) is the caller's policy.
pub fn parse(b: &[u8]) -> Result<Frame, WireErr> {
    if b.len() < FRAME_HDR || u32_at(b, 0) != MAGIC || u16_at(b, 4) != VERSION {
        return Err(WireErr::Malformed);
    }
    let n = u16_at(b, 6) as usize;
    if n > MAX_EVENTS || b.len() < FRAME_HDR + n * REC_LEN {
        return Err(WireErr::Malformed);
    }
    let mut device_fp = [0u8; 32];
    device_fp.copy_from_slice(&b[16..48]);
    let hdr = Header {
        tenant_id: u64_at(b, 8),
        device_fp,
        boots: u32_at(b, 48),
        cntfrq: u32_at(b, 52),
        frame_seq: u64_at(b, 56),
        first_ev_seq: u64_at(b, 64),
        now_ticks: u64_at(b, 72),
        qsecbit_ts: u64_at(b, 80),
        overruns: u32_at(b, 88),
        lost: u32_at(b, 92),
        qsecbit_score: u32_at(b, 96),
    };
    let mut recs = [Rec::default(); MAX_EVENTS];
    for (i, r) in recs.iter_mut().enumerate().take(n) {
        let o = FRAME_HDR + i * REC_LEN;
        *r = Rec {
            ts: u64_at(b, o),
            src: u32_at(b, o + 8),
            rule_id: u16_at(b, o + 12),
            severity: b[o + 14],
            verdict: b[o + 15],
            class: b[o + 16],
        };
    }
    Ok(Frame { hdr, n, recs })
}

/// Receiver-side wall-clock anchor: the epoch time (seconds, f64) of an event stamped `ev_ts`
/// ticks, given the frame's `now_ticks`/`cntfrq` and the epoch time the frame was received.
/// An event "from the future" (clock glitch) is clamped to the receive time, never after it.
pub fn event_epoch(rx_epoch: f64, hdr: &Header, ev_ts: u64) -> f64 {
    if hdr.cntfrq == 0 {
        return rx_epoch;
    }
    let age_ticks = hdr.now_ticks.saturating_sub(ev_ts);
    rx_epoch - age_ticks as f64 / hdr.cntfrq as f64
}

/// Receiver-side policy over DECRYPTED frames (the AEAD + RFC 6479 window is the caller's job,
/// via `AntiReplayRx::open_record` with `AD`): authenticate the frame's origin against what was
/// enrolled, and account for evidence that never arrived. Shared by the kernel's in-QEMU fake MC
/// and the host receiver so both count loss identically.
#[derive(Clone, Copy, Debug)]
pub struct Tracker {
    pub tenant_id: u64,
    pub device_fp: [u8; 32],
    boots: u32,
    /// Next expected per-boot event seq (high-water + 1).
    next_ev: u64,
    started: bool,
    /// Events skipped by a forward jump in `first_ev_seq` (lost in transit, or shed on-device —
    /// the device's own `lost`/`overruns` say which).
    pub gap_events: u64,
    /// Events that arrived BEHIND the high-water (a reordered frame filling an earlier gap).
    pub late_events: u64,
    /// Device reboots observed (a new `boots` value restarts the sequence space).
    pub reboots_seen: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrackErr {
    Malformed,
    /// Authenticated on the channel, but the frame claims another tenant/device — refused.
    IdentityMismatch,
}

impl Tracker {
    pub const fn new(tenant_id: u64, device_fp: [u8; 32]) -> Self {
        Tracker { tenant_id, device_fp, boots: 0, next_ev: 0, started: false, gap_events: 0, late_events: 0, reboots_seen: 0 }
    }

    /// Parse + authenticate + account one decrypted frame.
    pub fn accept(&mut self, pt: &[u8]) -> Result<Frame, TrackErr> {
        let f = parse(pt).map_err(|_| TrackErr::Malformed)?;
        if f.hdr.tenant_id != self.tenant_id || f.hdr.device_fp != self.device_fp {
            return Err(TrackErr::IdentityMismatch);
        }
        if !self.started || f.hdr.boots != self.boots {
            if self.started {
                self.reboots_seen += 1;
            }
            self.started = true;
            self.boots = f.hdr.boots;
            self.next_ev = f.hdr.first_ev_seq; // a fresh boot: no gap before its first frame
        }
        let first = f.hdr.first_ev_seq;
        let end = first + f.n as u64;
        if first >= self.next_ev {
            self.gap_events += first - self.next_ev;
            self.next_ev = end;
        } else {
            self.late_events += f.n as u64;
        }
        Ok(f)
    }
}
