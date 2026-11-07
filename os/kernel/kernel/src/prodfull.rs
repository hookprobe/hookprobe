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

pub use crate::snapshot::{Counters, Snapshot, SNAP_LEN};

/// Persist at most this often. The reserved window is 32 sectors and every persist
/// rewrites the same LBAs, so a per-heartbeat write would hammer one eMMC erase
/// block. 300 s + a dirty flag keeps steady-state writes near zero on a quiet link.
const PERSIST_INTERVAL_S: u64 = 300;

/// The `prod-full` runtime state, owned by the sensor loop.
/// Boot-local `ticks` -> Unix ms given that `epoch_ms` was true at `at` (ticks may precede `at`).
pub fn tick_to_ms(ticks: u64, epoch_ms: u64, at: u64, frq: u64) -> u64 {
    let frq = frq.max(1) as u128;
    if ticks >= at {
        epoch_ms.saturating_add(((ticks - at) as u128 * 1000 / frq) as u64)
    } else {
        epoch_ms.saturating_sub(((at - ticks) as u128 * 1000 / frq) as u64)
    }
}

pub struct ProdFull {
    /// Generation of the last committed A/B snapshot slot (task #27; 0 = none this boot).
    pub last_gen: u64,
    emmc: Option<Emmc>,
    srk: [u8; 32],
    policy: Policy,
    /// Accumulates across boots (restored + 1 at init).
    pub snap: Snapshot,
    /// (Unix ms, ticks, cntfrq) once SNTP set the wall clock this boot.
    clock: Option<(u64, u64, u64)>,
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
        crate::export::set_mac_pseudonym_key(&srk); // exported RA-rule sources become device-keyed pseudonyms
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
            last_gen: 0,
            emmc: None,
            srk,
            policy,
            snap: Snapshot::new(),
            clock: None,
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
                    "   [PROD-FULL] eMMC up: {} sectors; write window armed LBA {}..{} ({} sectors — the ONLY writable region); volatile cache {}\n",
                    dev.sec_count(), wlo, whi, whi - wlo,
                    if dev.cache_on() { "ON — A/B snapshot write ORDER NOT GUARANTEED (no CMD6 flush in this driver)" } else { "off (A/B commit order holds)" }
                );
                {
                    // eMMC wear, from the device itself (review 2026-11-05: no endurance figure in-tree).
                    let (eol, a, b) = dev.wear();
                    let life = |v: u8| -> (u32, u32) { if v == 0 || v > 0x0b { (0, 0) } else { (((v - 1) as u32) * 10, (v as u32) * 10) } };
                    let (al, ah) = life(a);
                    let (bl, bh) = life(b);
                    kprint!(
                        "   [PROD-FULL] eMMC wear: PRE_EOL_INFO={} ({}) | life used TYP_A {}-{}% TYP_B {}-{}% (raw {:#04x}/{:#04x}; 0 = not reported)\n",
                        eol, match eol { 1 => "normal", 2 => "WARNING: >= 80% reserved blocks consumed", 3 => "URGENT", _ => "not reported" },
                        al, ah, bl, bh, a, b
                    );
                }
                // Restore the previous boot's snapshot, if any.
                match SealedStore::open(&mut dev) {
                    Ok(ss) => {
                        let mut blob = [0u8; seal::SEAL_MAX_BLOB];
                        if let Some(n) = ss.load_ab(&mut blob) {
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
                                        pf.snap.forget_prior_ticks();
                                    }
                                    None => kprint!(
                                        "   [PROD-FULL] M3: sealed blob unsealed but is not a v1/v2 snapshot — starting fresh (fail-closed)\n"
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
            "   [PROD-FULL] M6 export gate: should_export={} (enrolls on the control-plane handshake when the image carries netmetal; air-gap otherwise)\n",
            export::should_export(&pf.enroll)
        );
        pf
    }

    /// The owner verifier from the eMMC boot partition's OWNER.TXT (ADR 0037 D3), for the
    /// on-device Mission Control. `None` = unclaimed (or eMMC silent): every protected route refuses.
    /// ADR 0051: bring up the EL0 TLS server with `MCTLS.CRT` from the eMMC boot partition.
    #[cfg(feature = "mctls")]
    pub fn tls_bring_up(&self) {
        crate::tlshost::bring_up(self.emmc.as_ref());
    }

    #[cfg(feature = "mcserve")]
    pub fn read_owner(&self) -> Option<crate::mcauth::Owner> {
        self.emmc.as_ref().and_then(|d| crate::mcauth::load_owner(d))
    }

    /// Record a threat verdict as a persisted event. Cheap: RAM only, marks dirty.
    pub fn on_threat(&mut self, ev: &events::Event) {
        match self.clock {
            Some((ms, ticks, frq)) => {
                let mut e = *ev;
                e.ts = tick_to_ms(ev.ts, ms, ticks, frq);
                e.verdict |= crate::snapshot::IMG_EPOCH;
                self.snap.push_event(&e);
            }
            None => self.snap.push_event(ev),
        }
        self.dirty = true;
    }

    /// The wall clock became known (SNTP): `epoch_ms` is true at `ticks`. This boot's events
    /// recorded before it are converted now; later ones are stamped at record time.
    pub fn set_clock(&mut self, epoch_ms: u64, ticks: u64, frq: u64) {
        let frq = frq.max(1);
        self.clock = Some((epoch_ms, ticks, frq));
        self.snap.anchor_events(|t| tick_to_ms(t, epoch_ms, ticks, frq));
        self.dirty = true;
    }

    /// Heartbeat hook: throttled persist. Returns true if a persist actually happened (so the
    /// caller can report it). Export is driven by the sensor loop (it owns the control-plane
    /// transport) and consults `should_export(&pf.enroll)` before touching the channel —
    /// unenrolled ⇒ nothing is attempted; evidence persists locally either way.
    pub fn on_heartbeat(&mut self, uptime_s: u64, counters: Counters, qsecbit: u32) -> bool {
        if counters.seen != self.snap.counters.seen || counters.dropped != self.snap.counters.dropped {
            self.dirty = true;
        }
        self.snap.counters = counters;
        self.snap.qsecbit = qsecbit;
        self.snap.uptime_s = uptime_s;
        self.snap.overruns = events::overruns();

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
            // A/B slots with a commit header (task #27 F2): a torn write never destroys the
            // previous snapshot.
            Ok(mut ss) => match ss.store_ab(blob.as_slice()) {
                Ok(gen) => {
                    self.last_gen = gen;
                    true
                }
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
