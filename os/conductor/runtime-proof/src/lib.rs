// SPDX-License-Identifier: AGPL-3.0-only
//! HEQK Runtime Proof 001. One `no_std`, allocation-free pipeline:
//!
//! frame ──▶ [1 neuro-dp: parse, DNS, fingerprints] ──▶ [2 DNS / flow classification into events]
//!        ──▶ [3 neuro-l1 S1 integer specialist] + [4 neuro-core temporal engine (Neural DNA)]
//!        ──▶ [5 L0 rule: deterministic verdict; enforcement stays `Observed`]
//!        ──▶ [6 Conductor harness: investigation job with evidence cards]
//!
//! Frames are borrowed (`&[u8]`), never copied; workloads exchange 16-byte event records and, per finding,
//! one job description. All state is fixed-size and lives in one struct (a static on the device).
//!
//! What this is NOT: a detection-quality result. S1 is fed flow-level features only (the data plane's
//! connection tracking is kernel work, Neuro doc 35 M4), so its alerts here prove the plumbing and the cost,
//! nothing about accuracy. Neuro output is evidence, never enforcement (ADR 0023, contract C9).
#![no_std]
#![forbid(unsafe_code)]

use conductor_core::class::DataClass;
use conductor_core::job::Verdict;
use conductor_core::wire::Writer;
use neuro_core::{Dna, Driver, HourAgg, Score, CALM_Q8};
use neuro_dp::{Dp, Out};

/// Devices tracked in the proof (the fixture has four).
pub const DEVICES: usize = 4;
const HOUR_US: u64 = 3_600_000_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub frames: u64,
    pub frame_bytes: u64,
    pub events: u64,
    pub hours_closed: u64,
    pub findings: u64,
}

/// One device-hour's result from workloads 3–5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Finding {
    pub dev: u16,
    pub hour: u64,
    pub dna: Score,
    pub dna_alarm: bool,
    pub s1_score: i32,
    pub s1_alert: bool,
    /// L0's deterministic verdict; `None` = nothing to investigate.
    pub verdict: Option<Verdict>,
}

/// Workload 5. Two independent signals agree → suspicious; exactly one → insufficient evidence (a single
/// weak signal, the shape Neuro doc 40's rule T handles); none → no investigation. Whatever it says, the
/// enforcement action is `Observed`: Neuro never drives a drop.
pub fn l0_rule(dna_alarm: bool, s1_alert: bool) -> Option<Verdict> {
    match (dna_alarm, s1_alert) {
        (true, true) => Some(Verdict::Suspicious),
        (true, false) | (false, true) => Some(Verdict::InsufficientEvidence),
        (false, false) => None,
    }
}

pub struct Proof {
    dp: Dp,
    dna: [Dna; DEVICES],
    agg: [HourAgg; DEVICES],
    l1: [neuro_l1::HourAgg; DEVICES],
    active: [bool; DEVICES],
    hour: u64,
    specialist: Option<neuro_engine::Model<'static>>,
    arena: [u8; 64],
    pub c: Counters,
}

impl Default for Proof {
    fn default() -> Self {
        Self::new()
    }
}

impl Proof {
    pub const fn new() -> Self {
        Self {
            dp: Dp::new(),
            dna: [const { Dna::new() }; DEVICES],
            agg: [const { HourAgg::new() }; DEVICES],
            l1: [const { neuro_l1::HourAgg::new() }; DEVICES],
            active: [false; DEVICES],
            hour: 0,
            specialist: None,
            arena: [0; 64],
            c: Counters { frames: 0, frame_bytes: 0, events: 0, hours_closed: 0, findings: 0 },
        }
    }

    /// Workloads 1–4 for one frame. When the frame starts a new hour, the previous hour is closed first and
    /// each active device's result goes to `on_finding`.
    pub fn frame(&mut self, frame: &[u8], ts_us: u64, dev_src: Option<u16>, dev_dst: Option<u16>, on_finding: &mut impl FnMut(Finding)) {
        let hour = ts_us / HOUR_US;
        if self.hour == 0 {
            self.hour = hour;
        }
        if hour > self.hour {
            self.close_hour(on_finding);
            self.hour = hour;
        }
        self.c.frames += 1;
        self.c.frame_bytes += frame.len() as u64;
        let Self { dp, dna, agg, l1, active, c, .. } = self;
        let mut sink = |o: Out| {
            c.events += 1;
            let (dev, ts) = match o {
                Out::Flow { dev, ts_us, .. } | Out::Dns { dev, ts_us, .. } | Out::Bytes { dev, ts_us, .. } => (usize::from(dev), ts_us),
            };
            let (Some(mem), Some(a), Some(l), Some(act)) = (dna.get(dev), agg.get_mut(dev), l1.get_mut(dev), active.get_mut(dev)) else { return };
            *act = true;
            match o {
                Out::Flow { fp, .. } => {
                    a.add_flow(mem, Some(fp), 0, 1);
                    // Flow-level features only (see the module note).
                    l.add(&neuro_l1::Conn {
                        t_us: (ts % HOUR_US) as u32,
                        out: true,
                        peer: fp,
                        peer_lan: false,
                        port: None,
                        proto: neuro_l1::Proto::Other,
                        failed: false,
                        bytes_out: 0,
                        bytes_in: 0,
                        dur_us: 0,
                        pkts: 1,
                        novel: false,
                    });
                }
                Out::Dns { fp, nx, .. } => a.add_dns(mem, fp, nx),
                Out::Bytes { bytes, .. } => a.add_flow(mem, None, u64::from(bytes), 0),
            }
        };
        dp.frame(frame, ts_us, dev_src, dev_dst, &mut sink);
        dp.expire(ts_us, &mut sink);
    }

    /// Install the specialist model (workload 3) as an admitted DATA package. Without one, the hour closes
    /// with no specialist signal. The model can be replaced without changing this code.
    pub fn set_specialist(&mut self, m: neuro_engine::Model<'static>) -> bool {
        if m.input_len() != 28 || m.output_len() != 5 || m.arena_bytes() > self.arena.len() {
            return false;
        }
        self.specialist = Some(m);
        true
    }

    /// Close the current hour (also call once at the end of a capture).
    pub fn close_hour(&mut self, on_finding: &mut impl FnMut(Finding)) {
        let hr = (self.hour % 24) as usize;
        for dev in 0..DEVICES {
            if !self.active[dev] {
                continue;
            }
            let dna = self.dna[dev].close_hour(hr, &self.agg[dev]);
            let q = self.l1[dev].quantise();
            // Workload 3 runs through the engine: the model is data, not code linked into this crate.
            let mut res = [0u8; 5];
            let (s1_score, s1_alert) = match &self.specialist {
                Some(m) if m.run(&mut self.arena, &q, &mut res).is_ok() => (i32::from_le_bytes([res[0], res[1], res[2], res[3]]), res[4] == 1),
                _ => (0, false),
            };
            let dna_alarm = dna.score >= CALM_Q8;
            let verdict = l0_rule(dna_alarm, s1_alert);
            self.agg[dev].reset();
            self.l1[dev].clear();
            self.active[dev] = false;
            self.c.hours_closed += 1;
            if verdict.is_some() {
                self.c.findings += 1;
            }
            on_finding(Finding { dev: dev as u16, hour: self.hour, dna, dna_alarm, s1_score, s1_alert, verdict });
        }
    }
}

fn driver_name(d: Driver) -> &'static [u8] {
    match d {
        Driver::Volume => b"volume",
        Driver::FanOut => b"fan-out",
        Driver::NovelPeers => b"novel peers",
        Driver::Dns => b"DNS",
        Driver::Activity => b"activity",
    }
}

fn dec(w: &mut Writer, mut v: u64) -> Option<()> {
    let mut d = [0u8; 20];
    let mut i = 20;
    loop {
        i -= 1;
        d[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    w.put(&d[i..])
}

/// Workload 6's input: turn a finding into a Conductor job (evidence cards with data classes, the L0
/// verdict, budgets). Returns the encoded length. Cards carry numbers and a device SLOT, never an address
/// or a name.
pub fn investigation_job(f: &Finding, job_id: [u8; 16], model: [u8; 32], deadline_ms: u64, out: &mut [u8]) -> Option<usize> {
    let verdict = f.verdict?;
    let mut card1 = [0u8; 160];
    let n1 = {
        let mut w = Writer::new(&mut card1);
        w.put(b"Behaviour deviation, device slot ")?;
        dec(&mut w, u64::from(f.dev))?;
        w.put(b": score ")?;
        dec(&mut w, (f.dna.score.max(0) as u64) * 100 / 256)?;
        w.put(b"/100 of the alarm level, main driver ")?;
        w.put(driver_name(f.dna.driver()))?;
        w.len()
    };
    let mut card2 = [0u8; 96];
    let n2 = {
        let mut w = Writer::new(&mut card2);
        w.put(b"S1 specialist (integer model): ")?;
        w.put(if f.s1_alert { b"above its threshold" } else { b"below its threshold" })?;
        w.len()
    };
    let intent: &[u8] = b"Explain this device-hour for the owner in one or two sentences.";
    let mut w = Writer::new(out);
    w.put(&job_id)?;
    w.put(&model)?;
    w.put(&[conductor_core::tools::bit::EVIDENCE_GET, verdict as u8, 2, 0, 0, 0])?; // tools, l0, steps, cache, offload, energy
    w.put(&[0; 16])?; // affinity
    w.u32(0)?; // slo ttft
    w.u32(0)?; // slo tpot
    w.u32(512)?; // out units total
    w.u32(30_000)?; // compute total
    w.u32(15_000)?; // per call
    w.u64(deadline_ms)?;
    w.u16(intent.len() as u16)?;
    w.put(intent)?;
    w.u8(2)?;
    for (id, class, required, text) in [(1u16, DataClass::Aggregate, true, &card1[..n1]), (2, DataClass::Aggregate, false, &card2[..n2])] {
        w.u16(id)?;
        w.u8(class as u8)?;
        w.u8(u8::from(required))?;
        w.u16(text.len() as u16)?;
        w.put(text)?;
    }
    Some(w.len())
}
