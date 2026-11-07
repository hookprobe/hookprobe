//! The bounded, sealed M3 evidence SNAPSHOT the `prod-full` sensor persists across reboots —
//! counters + a ring of the most recent event images. Pure (no MMIO, no storage), so its ring
//! and codec are QEMU-testable (`[P-snapshot]`); `prodfull.rs` owns sealing + the eMMC write.
//!
//! v2 (this layout) fixes two v1 defects:
//!   * v1 restored the ring's write cursor as `nev % SNAP_EVENTS` — once the ring had wrapped
//!     that is 0, not the true oldest slot, so the first event after a reboot overwrote an
//!     arbitrary record and the ring's order was lost. v2 persists the real `head`.
//!   * v1 overwrote the oldest record at capacity without counting it. v2 counts `evicted`
//!     (bounded & honest retention: the operator sees how much fell off the end) and carries
//!     the SOAR ring's `overruns` (events the detector itself could not queue).
//! v1 blobs still parse (legacy cursor rule, zero counters) so an upgrade keeps the history.

use crate::events;
use crate::export;

const SNAP_VERSION: u16 = 2;
const SNAP_VERSION_V1: u16 = 1;

/// How many recent event images ride in a snapshot (16 B each — the M3 persist image).
pub const SNAP_EVENTS: usize = 64;

const SNAP_HDR_V1: usize = 64;
const SNAP_HDR: usize = 80;
const SNAP_LEN_V1: usize = SNAP_HDR_V1 + SNAP_EVENTS * export::EV_IMAGE_LEN; // 1088
/// Fixed v2 snapshot size. Must stay under `seal::SEAL_MAX_PT` (3968).
pub const SNAP_LEN: usize = SNAP_HDR + SNAP_EVENTS * export::EV_IMAGE_LEN; // 1104

/// The running counters the sensor loop owns; snapshotted verbatim.
#[derive(Clone, Copy, Default)]
pub struct Counters {
    pub seen: u64,
    pub forwarded: u64,
    pub dropped: u64,
    pub tx_fail: u64,
    pub faults: u64,
    pub empty: u64,
}

// Header layout (little-endian, offsets stable across versions; v2 appends 64..80):
const O_MAGIC: usize = 0; // u32
const O_VER: usize = 4; // u16
const O_NEV: usize = 6; // u16  (events actually present, <= SNAP_EVENTS)
const O_BOOTS: usize = 8; // u64
const O_UPTIME: usize = 16; // u64 (seconds THIS boot at persist time)
const O_SEEN: usize = 24;
const O_FWD: usize = 32;
const O_DROP: usize = 40;
const O_TXF: usize = 48;
const O_QSEC: usize = 56; // u32
const O_FAULTS: usize = 60; // u32 (truncated — diagnostics, not accounting)
const O_HEAD: usize = 64; // u32 v2: ring write cursor
const O_OVERRUNS: usize = 68; // u32 v2: SOAR-ring overruns (detector-side loss)
const O_EVICTED: usize = 72; // u64 v2: records overwritten at capacity (retention loss)

fn put_u64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
fn put_u32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn get_u64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}
fn get_u32(b: &[u8], o: usize) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[o..o + 4]);
    u32::from_le_bytes(a)
}

/// `HQKS` little-endian.
fn snap_magic() -> u32 {
    u32::from_le_bytes(*b"HQKS")
}

/// The bounded, sealed persistence record.
pub struct Snapshot {
    pub boots: u64,
    pub uptime_s: u64,
    pub counters: Counters,
    pub qsecbit: u32,
    /// SOAR-ring overruns at persist time (cumulative this boot).
    pub overruns: u32,
    /// Records overwritten because the ring was full (cumulative across boots).
    pub evicted: u64,
    /// Ring of the most recent event images (16 B each, the M3 persist encoding).
    pub events: [[u8; export::EV_IMAGE_LEN]; SNAP_EVENTS],
    pub nev: usize,
    /// Write cursor into `events` (ring; wraps). Persisted in v2.
    head: usize,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self::new()
    }
}

/// Verdict-byte flag on a persisted event image: its `ts` is wall-clock Unix ms (an SNTP-synced
/// clock was known), not boot-local ticks. `ts == 0` with the flag = "time unknown" (a prior
/// boot that never synced). Verdicts are 0..=2, so the bit is free; it never leaves the device.
pub const IMG_EPOCH: u8 = 0x80;

impl Snapshot {
    /// Rewrite this boot's tick-stamped events to wall-clock ms via `to_ms` (called once when the
    /// clock first becomes known). Already-converted images are untouched.
    pub fn anchor_events(&mut self, to_ms: impl Fn(u64) -> u64) {
        for i in 0..self.nev {
            let o = (self.head + SNAP_EVENTS - self.nev + i) % SNAP_EVENTS;
            let img = &mut self.events[o];
            if img[15] & IMG_EPOCH == 0 {
                let ts = u64::from_le_bytes(img[0..8].try_into().unwrap());
                img[0..8].copy_from_slice(&to_ms(ts).to_le_bytes());
                img[15] |= IMG_EPOCH;
            }
        }
    }

    /// After a restore: a prior boot's tick-stamped images can never be placed in time (its tick
    /// counter is gone) — mark them "time unknown" so nothing renders them at a fake time.
    pub fn forget_prior_ticks(&mut self) {
        for i in 0..self.nev {
            let o = (self.head + SNAP_EVENTS - self.nev + i) % SNAP_EVENTS;
            let img = &mut self.events[o];
            if img[15] & IMG_EPOCH == 0 {
                img[0..8].copy_from_slice(&0u64.to_le_bytes());
                img[15] |= IMG_EPOCH;
            }
        }
    }

    /// The `i`-th oldest event with a known wall-clock time: (event, Unix ms).
    pub fn timed_event(&self, i: usize) -> Option<(events::Event, u64)> {
        let img = self.event_in_order(i)?;
        if img[15] & IMG_EPOCH == 0 {
            return None;
        }
        let ms = u64::from_le_bytes(img[0..8].try_into().ok()?);
        let mut ev = export::image_to_ev(img)?;
        ev.verdict &= !IMG_EPOCH;
        (ms != 0).then_some((ev, ms))
    }

    pub const fn new() -> Self {
        Snapshot {
            boots: 0,
            uptime_s: 0,
            counters: Counters { seen: 0, forwarded: 0, dropped: 0, tx_fail: 0, faults: 0, empty: 0 },
            qsecbit: 0,
            overruns: 0,
            evicted: 0,
            events: [[0u8; export::EV_IMAGE_LEN]; SNAP_EVENTS],
            nev: 0,
            head: 0,
        }
    }

    /// Record one event image into the ring (oldest overwritten — and COUNTED — at capacity).
    pub fn push_event(&mut self, ev: &events::Event) {
        if self.nev == SNAP_EVENTS {
            self.evicted = self.evicted.saturating_add(1);
        }
        self.events[self.head] = export::ev_to_image(ev);
        self.head = (self.head + 1) % SNAP_EVENTS;
        if self.nev < SNAP_EVENTS {
            self.nev += 1;
        }
    }

    /// The `i`-th OLDEST event image present (0 = oldest), in ring order.
    pub fn event_in_order(&self, i: usize) -> Option<&[u8; export::EV_IMAGE_LEN]> {
        if i >= self.nev {
            return None;
        }
        let oldest = (self.head + SNAP_EVENTS - self.nev) % SNAP_EVENTS;
        Some(&self.events[(oldest + i) % SNAP_EVENTS])
    }

    pub fn serialize(&self, out: &mut [u8; SNAP_LEN]) {
        for x in out[..SNAP_HDR].iter_mut() {
            *x = 0;
        }
        put_u32(out, O_MAGIC, snap_magic());
        out[O_VER..O_VER + 2].copy_from_slice(&SNAP_VERSION.to_le_bytes());
        out[O_NEV..O_NEV + 2].copy_from_slice(&(self.nev as u16).to_le_bytes());
        put_u64(out, O_BOOTS, self.boots);
        put_u64(out, O_UPTIME, self.uptime_s);
        put_u64(out, O_SEEN, self.counters.seen);
        put_u64(out, O_FWD, self.counters.forwarded);
        put_u64(out, O_DROP, self.counters.dropped);
        put_u64(out, O_TXF, self.counters.tx_fail);
        put_u32(out, O_QSEC, self.qsecbit);
        put_u32(out, O_FAULTS, self.counters.faults as u32);
        put_u32(out, O_HEAD, self.head as u32);
        put_u32(out, O_OVERRUNS, self.overruns);
        put_u64(out, O_EVICTED, self.evicted);
        for i in 0..SNAP_EVENTS {
            let o = SNAP_HDR + i * export::EV_IMAGE_LEN;
            out[o..o + export::EV_IMAGE_LEN].copy_from_slice(&self.events[i]);
        }
    }

    /// Parse a v2 (or legacy v1) snapshot. Fail-closed: a wrong magic/version/count/cursor
    /// yields `None` rather than a misparsed record.
    pub fn parse(b: &[u8]) -> Option<Snapshot> {
        if b.len() < SNAP_HDR_V1 || get_u32(b, O_MAGIC) != snap_magic() {
            return None;
        }
        let ver = u16::from_le_bytes([b[O_VER], b[O_VER + 1]]);
        let (hdr, len) = match ver {
            SNAP_VERSION => (SNAP_HDR, SNAP_LEN),
            SNAP_VERSION_V1 => (SNAP_HDR_V1, SNAP_LEN_V1),
            _ => return None,
        };
        if b.len() < len {
            return None;
        }
        let nev = u16::from_le_bytes([b[O_NEV], b[O_NEV + 1]]) as usize;
        if nev > SNAP_EVENTS {
            return None;
        }
        let mut s = Snapshot::new();
        s.boots = get_u64(b, O_BOOTS);
        s.uptime_s = get_u64(b, O_UPTIME);
        s.counters.seen = get_u64(b, O_SEEN);
        s.counters.forwarded = get_u64(b, O_FWD);
        s.counters.dropped = get_u64(b, O_DROP);
        s.counters.tx_fail = get_u64(b, O_TXF);
        s.qsecbit = get_u32(b, O_QSEC);
        s.counters.faults = get_u32(b, O_FAULTS) as u64;
        s.nev = nev;
        if ver == SNAP_VERSION {
            let head = get_u32(b, O_HEAD) as usize;
            if head >= SNAP_EVENTS {
                return None;
            }
            s.head = head;
            s.overruns = get_u32(b, O_OVERRUNS);
            s.evicted = get_u64(b, O_EVICTED);
        } else {
            s.head = nev % SNAP_EVENTS; // the v1 rule (correct until the ring first wrapped)
        }
        for i in 0..SNAP_EVENTS {
            let o = hdr + i * export::EV_IMAGE_LEN;
            s.events[i].copy_from_slice(&b[o..o + export::EV_IMAGE_LEN]);
        }
        Some(s)
    }
}

/// `[P-snapshot]` — the ring survives a persist/restore cycle IN ORDER after wrapping, eviction
/// is counted, and a legacy v1 blob still restores. Pure logic; QEMU-provable.
#[cfg(feature = "securechannel-selftest")]
pub fn snapshot_selftest() -> bool {
    macro_rules! kprint { ($($t:tt)*) => { arch_aarch64::_print(format_args!($($t)*)) }; }
    let ev = |k: u64| events::Event { ts: k, src: k as u32, rule_id: k as u16, severity: 1, verdict: 2, class: 5, dst: 0, dport: 0 };
    let ts_of = |img: &[u8; export::EV_IMAGE_LEN]| u64::from_le_bytes(img[0..8].try_into().unwrap());

    // Wrap the ring (SNAP_EVENTS + 10 events), persist, restore, then push ONE more.
    let mut a = Snapshot::new();
    for k in 0..(SNAP_EVENTS as u64 + 10) {
        a.push_event(&ev(k));
    }
    a.overruns = 7;
    let mut blob = [0u8; SNAP_LEN];
    a.serialize(&mut blob);
    let mut b = match Snapshot::parse(&blob) {
        Some(s) => s,
        None => return false,
    };
    let evicted = b.evicted == 10 && b.overruns == 7;
    let restored_order = (0..SNAP_EVENTS).all(|i| b.event_in_order(i).map(ts_of) == Some(10 + i as u64));
    b.push_event(&ev(1000));
    // After the post-restore push: the oldest (10) is evicted, 1000 is newest, order intact.
    let after = b.event_in_order(0).map(ts_of) == Some(11)
        && b.event_in_order(SNAP_EVENTS - 1).map(ts_of) == Some(1000)
        && b.evicted == 11;

    // Legacy v1 (unwrapped) still restores.
    let mut v1 = [0u8; SNAP_LEN_V1];
    v1[0..4].copy_from_slice(&snap_magic().to_le_bytes());
    v1[4..6].copy_from_slice(&SNAP_VERSION_V1.to_le_bytes());
    v1[6..8].copy_from_slice(&2u16.to_le_bytes());
    v1[8..16].copy_from_slice(&5u64.to_le_bytes());
    v1[SNAP_HDR_V1..SNAP_HDR_V1 + 8].copy_from_slice(&42u64.to_le_bytes());
    let legacy = Snapshot::parse(&v1).map_or(false, |s| s.boots == 5 && s.nev == 2 && s.event_in_order(0).map(ts_of) == Some(42));
    // A corrupt cursor is refused, never trusted.
    let mut bad = blob;
    bad[O_HEAD..O_HEAD + 4].copy_from_slice(&(SNAP_EVENTS as u32).to_le_bytes());
    let bad_refused = Snapshot::parse(&bad).is_none();

    // D1 wall clock: a boot that synced persists Unix ms; one that never synced restores as
    // "time unknown" (never rendered at a fake time); verdicts come back without the flag.
    let timed = {
        let mut a = Snapshot::new();
        a.push_event(&ev(1_000)); // before the sync: ticks
        a.anchor_events(|t| 1_800_000_000_000 + t); // the sync converts it
        let mut e2 = ev(2_000);
        e2.ts = 1_800_000_002_000;
        e2.verdict |= IMG_EPOCH; // after the sync: stamped at record time
        a.push_event(&e2);
        a.push_event(&ev(3_000)); // a tick-stamped event left over (a prior boot, never synced)
        let mut blob = [0u8; SNAP_LEN];
        a.serialize(&mut blob);
        let mut b = Snapshot::parse(&blob).unwrap();
        b.forget_prior_ticks();
        let first = b.timed_event(0).map(|(e, ms)| (e.verdict, ms));
        let second = b.timed_event(1).map(|(e, ms)| (e.rule_id, ms));
        first == Some((2, 1_800_000_001_000)) && second == Some((2_000u16, 1_800_000_002_000)) && b.timed_event(2).is_none()
    };
    let pass = evicted && restored_order && after && legacy && bad_refused && timed;
    kprint!(
        " [P-snapshot] {} — M3 evidence snapshot v2: wrapped ring restores IN ORDER across persist/restore={} post-restore push keeps order={} eviction+overruns counted={} legacy-v1-restores={} corrupt-cursor-refused={} wall-clock rows restore + unsynced never faked={}\n",
        if pass { "PASS" } else { "FAIL" }, restored_order, after, evicted, legacy, bad_refused, timed
    );
    pass
}
