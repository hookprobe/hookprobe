//! `prod-full` — M3 persistence / M4 control-plane posture / M6 export, wired into
//! the PH1 production sensor loop on metal.
//!
//! # Why this module exists
//!
//! M2–M6 are QEMU-green, but on the `cm5` (metal) profile their code had **no
//! caller**: every entry point lives in the QEMU self-test sequence that `prod`
//! replaces with the sensor loop, and `ota` even carries an explicit
//! `#[cfg_attr(feature = "cm5", allow(dead_code))]`. Adding `p15-write` +
//! `securechannel` + `netsvc` to a `prod` build changed the binary by **80 bytes** —
//! the subsystems were dead-stripped. So "needs a metal gate" understated it: the
//! code was not merely unproven on hardware, it was not *reached* on hardware.
//! This module is the missing caller.
//!
//! # What is honestly possible on metal TODAY (read before extending)
//!
//! **The eMMC write path is hard-clamped to LBA 2016..2047 — 32 sectors, 16 KiB**
//! (`emmc::write_block_impl` Gate 1, plus the narrowing-only `arm_write_window`
//! Gate 2). Therefore:
//!
//!   * `fslog`'s multi-region log store **cannot run on metal**: its DataVolume
//!     region lies outside the reserved window, so every append would return
//!     `WriteRefused`. Full multi-region eMMC write is Gate R.
//!   * What DOES fit is exactly one sealed blob (`SEAL_MAX_PT` = 3968 B). So M3 on
//!     metal is a **bounded snapshot**, not an evidence log — a rolling summary
//!     plus the most recent events, sealed under the per-device SRK and reloaded on
//!     the next boot. That is a real cross-reboot persistence proof on silicon, and
//!     it is deliberately not dressed up as the full evidence graph.
//!
//! **UPDATE (2026-09-08): the GEM control-plane transport now EXISTS.** The `netmetal` sensor
//! loop feeds `MetalBridge` (ARP first-light + presence beacon metal-proven) off its SINGLE drain
//! (the Linux-`macb` single-ring-owner rule), and the smoltcp-FREE `ControlPlane` (`controlplane.rs`)
//! drives the full PQ-hybrid Noise handshake over a hand-framed UDP transport that rides that same
//! drain + the one `gem::tx_frame` — QEMU-proven end-to-end ([P19-controlplane]), and
//! `reconcile_reach_policy` arms segmentation off a channel-fetched signed policy ([P20-reconcile]).
//! What remains is the METAL live handshake (a host MSSP-sim on the wire). This `prodfull` posture
//! layer (air-gap-safe config resolution, enrollment status, the M6 `should_export` structural
//! gate) is unchanged and correct; it no longer implies the transport is absent.
//!
//! # Invariants this module must not break
//!
//! * **The sensor never halts** (PH1). Every path here is failure-tolerant: any
//!   error degrades to "not persisted / not exported" and the loop continues.
//! * **Air-gap is sacred.** Unenrolled is a valid steady state; nothing blocks on a
//!   network, and evidence still persists locally with no control plane.
//! * **`prod` stays byte-identical.** Everything is behind `prod-full`.
//! * **eMMC wear.** The reserved window is 32 sectors and every persist rewrites the
//!   same LBAs, so persistence is throttled by BOTH an interval and a dirty flag.

/// `kprint!` is a textually-scoped `macro_rules!` declared in main.rs AFTER the `mod`
/// items, so it is not visible here. Same local re-definition `export.rs` uses.
macro_rules! kprint {
    ($($t:tt)*) => { arch_aarch64::_print(format_args!($($t)*)) };
}

use crate::enroll::EnrollStatus;
use crate::export;
use crate::events;
use crate::seal::{self, Policy, SealBlob};
use crate::store::SealedStore;
use arch_aarch64::emmc::Emmc;

/// Snapshot wire version — bump on any layout change (an older/newer blob is
/// refused rather than misparsed).
const SNAP_VERSION: u16 = 1;

/// How many recent event images ride in a snapshot. 16 B each (the M6 `EV_IMAGE_LEN`
/// image, so the persisted bytes are IDENTICAL to what M6 exports — no re-encoding
/// drift, the same load-bearing property `export.rs` establishes).
pub const SNAP_EVENTS: usize = 64;

/// Fixed snapshot size: header + events. Must stay under `seal::SEAL_MAX_PT` (3968).
const SNAP_HDR: usize = 64;
const SNAP_LEN: usize = SNAP_HDR + SNAP_EVENTS * export::EV_IMAGE_LEN; // 64 + 1024 = 1088

/// Persist at most this often. The reserved window is 32 sectors and every persist
/// rewrites the same LBAs, so a per-heartbeat write would hammer one eMMC erase
/// block. 300 s + a dirty flag keeps steady-state writes near zero on a quiet link.
const PERSIST_INTERVAL_S: u64 = 300;

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

#[inline]
fn put_u64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn put_u32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn get_u64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}
#[inline]
fn get_u32(b: &[u8], o: usize) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[o..o + 4]);
    u32::from_le_bytes(a)
}

// Header layout (little-endian, offsets stable across versions):
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

/// The bounded, sealed persistence record.
pub struct Snapshot {
    pub boots: u64,
    pub uptime_s: u64,
    pub counters: Counters,
    pub qsecbit: u32,
    /// Ring of the most recent event images (16 B each, M6-identical encoding).
    pub events: [[u8; export::EV_IMAGE_LEN]; SNAP_EVENTS],
    pub nev: usize,
    /// Write cursor into `events` (ring; wraps).
    head: usize,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self::new()
    }
}

impl Snapshot {
    pub const fn new() -> Self {
        Snapshot {
            boots: 0,
            uptime_s: 0,
            counters: Counters {
                seen: 0,
                forwarded: 0,
                dropped: 0,
                tx_fail: 0,
                faults: 0,
                empty: 0,
            },
            qsecbit: 0,
            events: [[0u8; export::EV_IMAGE_LEN]; SNAP_EVENTS],
            nev: 0,
            head: 0,
        }
    }

    /// Record one event image into the ring (oldest overwritten at capacity).
    pub fn push_event(&mut self, ev: &events::Event) {
        self.events[self.head] = export::ev_to_image(ev);
        self.head = (self.head + 1) % SNAP_EVENTS;
        if self.nev < SNAP_EVENTS {
            self.nev += 1;
        }
    }

    fn serialize(&self, out: &mut [u8; SNAP_LEN]) {
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
        for i in 0..SNAP_EVENTS {
            let o = SNAP_HDR + i * export::EV_IMAGE_LEN;
            out[o..o + export::EV_IMAGE_LEN].copy_from_slice(&self.events[i]);
        }
    }

    /// Parse a snapshot. Fail-closed: a wrong magic/version/count yields `None`
    /// rather than a misparsed record (a stale-layout blob must not resurrect as
    /// plausible-looking counters).
    fn parse(b: &[u8]) -> Option<Snapshot> {
        if b.len() < SNAP_LEN || get_u32(b, O_MAGIC) != snap_magic() {
            return None;
        }
        let ver = u16::from_le_bytes([b[O_VER], b[O_VER + 1]]);
        if ver != SNAP_VERSION {
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
        s.head = nev % SNAP_EVENTS;
        for i in 0..SNAP_EVENTS {
            let o = SNAP_HDR + i * export::EV_IMAGE_LEN;
            s.events[i].copy_from_slice(&b[o..o + export::EV_IMAGE_LEN]);
        }
        Some(s)
    }
}

/// `HQKS` little-endian.
#[inline]
fn snap_magic() -> u32 {
    u32::from_le_bytes(*b"HQKS")
}

/// The `prod-full` runtime state, owned by the sensor loop.
pub struct ProdFull {
    emmc: Option<Emmc>,
    srk: [u8; 32],
    policy: Policy,
    /// Accumulates across boots (restored + 1 at init).
    pub snap: Snapshot,
    last_persist_s: u64,
    dirty: bool,
    /// M4 posture. `Unenrolled` is a fully valid steady state (air-gap invariant).
    pub enroll: EnrollStatus,
    /// True once storage is usable for writes (probe + guard + armed window all OK).
    pub persist_ready: bool,
}

impl ProdFull {
    /// Bring up M3 storage, restore the prior snapshot, and establish the M4/M6
    /// posture. NEVER fails hard: on any error the sensor still runs, just without
    /// persistence (reported honestly on the console).
    pub fn init() -> ProdFull {
        let srk = crate::seal_srk().unwrap_or([0x5au8; 32]);
        let handoff = crate::read_seal_handoff();
        let (device_id, svn_floor, pcr) = match handoff {
            Some(h) => (h.device_id, h.svn_floor, h.pcr),
            None => (0, 0, [[0u8; 32]; boot_abi::NUM_PCR]),
        };
        let policy = Policy {
            mask: boot_abi::SEAL_POLICY_STRICT,
            device_id,
            svn_floor,
            pcr,
        };
        let mut pf = ProdFull {
            emmc: None,
            srk,
            policy,
            snap: Snapshot::new(),
            last_persist_s: 0,
            dirty: false,
            // Air-gap default. Enrollment is additive and never a boot precondition.
            enroll: EnrollStatus::default_standalone(),
            persist_ready: false,
        };

        match Emmc::probe() {
            Ok(mut dev) => {
                // Arm the narrowing-only Gate-2 window across the reserved region.
                // It can only ever shrink from here, so a later store-layer bug
                // cannot widen it.
                let (wlo, whi) = dev.arm_write_window(
                    arch_aarch64::emmc::RESERVED_LBA_LO,
                    arch_aarch64::emmc::RESERVED_LBA_HI,
                );
                kprint!(
                    "   [PROD-FULL] eMMC up: {} sectors; write window armed LBA {}..{} ({} sectors — the ONLY writable region)\n",
                    dev.sec_count(), wlo, whi, whi - wlo
                );
                // Restore the previous boot's snapshot, if any.
                match SealedStore::open(&mut dev) {
                    Ok(ss) => {
                        let mut blob = [0u8; seal::SEAL_MAX_BLOB];
                        if let Some(n) = ss.load(&mut blob) {
                            let mut pt = [0u8; seal::SEAL_MAX_PT];
                            match seal::unseal(&pf.srk, &pf.policy, &blob[..n], &mut pt) {
                                Ok(len) => match Snapshot::parse(&pt[..len]) {
                                    Some(prev) => {
                                        kprint!(
                                            "   [PROD-FULL] M3 RESTORED across reboot: boots={} prior seen={} drop={} qsecbit={} events={}\n",
                                            prev.boots, prev.counters.seen, prev.counters.dropped,
                                            prev.qsecbit, prev.nev
                                        );
                                        pf.snap = prev;
                                    }
                                    None => kprint!(
                                        "   [PROD-FULL] M3: sealed blob unsealed but is not a v{} snapshot — starting fresh (fail-closed)\n",
                                        SNAP_VERSION
                                    ),
                                },
                                Err(e) => kprint!(
                                    "   [PROD-FULL] M3: sealed blob REFUSED ({:?}) — wrong device/measurement; starting fresh\n",
                                    e
                                ),
                            }
                        } else {
                            kprint!("   [PROD-FULL] M3: no prior snapshot (fresh disk)\n");
                        }
                        pf.persist_ready = true;
                    }
                    Err(e) => kprint!(
                        "   [PROD-FULL] M3: write-guard refuses this disk ({:?}) — running WITHOUT persistence\n",
                        e
                    ),
                }
                pf.emmc = Some(dev);
            }
            Err((step, e)) => kprint!(
                "   [PROD-FULL] M3: eMMC silent at step {} ({:?}) — running WITHOUT persistence (sensor unaffected)\n",
                step, e
            ),
        }

        pf.snap.boots = pf.snap.boots.saturating_add(1);
        pf.dirty = true;

        // M4 posture. No DHCP is attempted: the prod datapath drives the GEM ring
        // directly and does not feed smoltcp, so there is no transport to run a
        // lease over. `resolve_or_fallback` still yields the honest standalone
        // config, and the air-gap invariant is stated explicitly.
        // The compiled static default: a link-local-ish standalone address. Never a
        // "wait for a server" state — resolve_or_fallback ALWAYS yields something
        // usable, which is the air-gap invariant expressed as a function.
        let static_default = crate::netcfg::NetConfig {
            ip: [169, 254, 1, 1],
            prefix: 16,
            gw: [0, 0, 0, 0],
            dns: [0, 0, 0, 0],
            source: crate::netcfg::ConfigSource::Static,
        };
        let cfg = crate::netcfg::resolve_or_fallback(None, None, static_default);
        kprint!(
            "   [PROD-FULL] M4 posture: source={:?}, enrolled={}, local SOC available={} (air-gap: enrollment is additive, never boot-blocking)\n",
            cfg.source,
            matches!(pf.enroll, EnrollStatus::Enrolled(_)),
            pf.enroll.local_soc_available()
        );
        kprint!(
            "   [PROD-FULL] M6 export gate: should_export={} (no on-device transport yet — smoltcp<->GEM bridge is PH5/Gate R)\n",
            export::should_export(&pf.enroll)
        );
        pf
    }

    /// Record a threat verdict as a persisted event. Cheap: RAM only, marks dirty.
    pub fn on_threat(&mut self, ev: &events::Event) {
        self.snap.push_event(ev);
        self.dirty = true;
    }

    /// Heartbeat hook: throttled persist + the structural export gate. Returns true
    /// if a persist actually happened (so the caller can report it).
    pub fn on_heartbeat(&mut self, uptime_s: u64, counters: Counters, qsecbit: u32) -> bool {
        if counters.seen != self.snap.counters.seen || counters.dropped != self.snap.counters.dropped {
            self.dirty = true;
        }
        self.snap.counters = counters;
        self.snap.qsecbit = qsecbit;
        self.snap.uptime_s = uptime_s;

        // M6: consult the gate BEFORE any channel work — unenrolled ⇒ no export is
        // attempted at all (structural air-gap, not a runtime check that could be
        // reordered). Evidence still persists locally below either way.
        if export::should_export(&self.enroll) {
            // Reaching here needs an enrolled device AND a live transport; the
            // transport does not exist in the prod datapath yet (PH5/Gate R), so
            // this is intentionally the only statement in the branch.
            kprint!("   [PROD-FULL] M6: enrolled, but no on-device transport — export skipped (Gate R)\n");
        }

        if !self.persist_ready || !self.dirty {
            return false;
        }
        if uptime_s < self.last_persist_s.saturating_add(PERSIST_INTERVAL_S) {
            return false;
        }
        let ok = self.persist();
        if ok {
            self.last_persist_s = uptime_s;
            self.dirty = false;
        }
        ok
    }

    /// Seal the snapshot and write it into the reserved window. Failure is reported
    /// and swallowed — the sensor loop must never halt on a storage error.
    fn persist(&mut self) -> bool {
        let mut pt = [0u8; SNAP_LEN];
        self.snap.serialize(&mut pt);
        let mut blob = SealBlob::new();
        if let Err(e) = seal::seal(&self.srk, &self.policy, &pt, &mut blob) {
            kprint!("   [PROD-FULL] M3 persist: seal failed ({:?}) — continuing\n", e);
            return false;
        }
        let dev = match self.emmc.as_mut() {
            Some(d) => d,
            None => return false,
        };
        match SealedStore::open(dev) {
            Ok(mut ss) => match ss.store(blob.as_slice()) {
                Ok(()) => true,
                Err(e) => {
                    kprint!("   [PROD-FULL] M3 persist: store refused ({:?}) — continuing\n", e);
                    false
                }
            },
            Err(e) => {
                kprint!("   [PROD-FULL] M3 persist: guard refused ({:?}) — continuing\n", e);
                false
            }
        }
    }
}
