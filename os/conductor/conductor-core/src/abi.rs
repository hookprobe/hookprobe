// SPDX-License-Identifier: AGPL-3.0-only
//! PROPOSED kernel <-> el0-harness IO-page ABI, v0 (C0). It lives here, not in `os/kernel/hal`, because
//! C0 must not change the kernel; moving it into `hal` (as `hal::neuroabi` was) is a HomePods decision.
//!
//! Header (little-endian u32 words, like `hal::neuroabi`): MAGIC "HQCN", CMD, IN_LEN, STATUS, OUT_LEN.
//! IN starts at `IN_OFF`, OUT at `OUT_OFF`. One command per excursion; the harness state persists in .bss.

use crate::class::OwnerPolicy;
use crate::place::{Env, WorkerInfo};
use crate::wire::Reader;

pub const MAGIC: u32 = u32::from_le_bytes(*b"HQCN");
pub const H_MAGIC: usize = 0;
pub const H_CMD: usize = 4;
pub const H_IN_LEN: usize = 8;
pub const H_STATUS: usize = 12;
pub const H_OUT_LEN: usize = 16;
pub const IN_OFF: usize = 0x40;
pub const IN_MAX: usize = 0x2800;
pub const OUT_OFF: usize = IN_OFF + IN_MAX;
pub const OUT_MAX: usize = 0x2800;
pub const IO_SIZE: usize = OUT_OFF + OUT_MAX;

/// IN = env ‖ job bytes. Resets the harness.
pub const CMD_LOAD: u32 = 1;
/// IN = encoded event (tag u8 + fields). OUT = encoded actions.
pub const CMD_EVENT: u32 = 2;

pub const ST_OK: u32 = 0;
pub const ST_BAD_INPUT: u32 = 1;
pub const ST_PANIC: u32 = 0xdead;

pub const ENV_LEN: usize = 32 + 8 + 5 * (1 + 32 + 16 + 1 + 1);

/// env = device_pk[32] policy[8 bytes: remote, tiers, fp_p1, fp_p4, addr_p1, addr_p4, agg_p5, p4_proven]
/// then for tiers 1..=5: present u8, pk[32], egress[16], available u8, idle u8.
pub fn decode_env(b: &[u8]) -> Option<Env> {
    let r = &mut Reader::new(b);
    let device_pk = r.arr()?;
    let flag = |r: &mut Reader| -> Option<bool> {
        match r.u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    };
    let remote_enabled = flag(r)?;
    let tiers = r.u8()?;
    let policy = OwnerPolicy {
        remote_enabled,
        tiers,
        fingerprints_p1: flag(r)?,
        fingerprints_p4: flag(r)?,
        addresses_p1: flag(r)?,
        addresses_p4: flag(r)?,
        aggregate_p5: flag(r)?,
        p4_chain_proven: flag(r)?,
    };
    let mut workers = [WorkerInfo::EMPTY; 6];
    for slot in workers.iter_mut().skip(1) {
        *slot = WorkerInfo { present: flag(r)?, public_key: r.arr()?, egress_policy_id: r.arr()?, available: flag(r)?, idle: flag(r)? };
    }
    r.done().then_some(Env { device_pk, policy, workers })
}

// ------------------------------------------------------------------ events in, actions out

use crate::cap::{HpExec, BODY_LEN};
use crate::harness::{Action, Actions, Event, Harness, Outcome};
use crate::ledger::RECORD_LEN;
use crate::tools::ToolCall;
use crate::wire::Writer;

/// IN of CMD_EVENT: tag u8, now_ms u64, then per tag:
/// 1 Start · 2 SessionOpened tier u8 binding[32] · 3 SessionFailed · 4 Signed len u16 blob · 5 SignRefused u16
/// · 6 Frame len u16 bytes · 7 ToolResult class u8 len u16 data · 8 ToolFailed · 9 Tick · 10 Cancel
pub fn decode_event(b: &[u8]) -> Option<(u64, Event<'_>)> {
    let r = &mut Reader::new(b);
    let tag = r.u8()?;
    let now = r.u64()?;
    let ev = match tag {
        1 => Event::Start,
        2 => Event::SessionOpened { tier: r.u8()?, binding: r.arr()? },
        3 => Event::SessionFailed,
        4 => {
            let n = usize::from(r.u16()?);
            Event::Signed(r.take(n)?)
        }
        5 => Event::SignRefused(r.u16()?),
        6 => {
            let n = usize::from(r.u16()?);
            Event::Frame(r.take(n)?)
        }
        7 => {
            let class = r.u8()?;
            let n = usize::from(r.u16()?);
            Event::ToolResult { class, data: r.take(n)? }
        }
        8 => Event::ToolFailed,
        9 => Event::Tick,
        10 => Event::Cancel,
        _ => return None,
    };
    r.done().then_some((now, ev))
}

/// OUT of CMD_EVENT: n u8, then each action (tag u8 + fields), then the payload the actions refer to:
/// after a Sign, the sign request as an HP-EXEC body with zero authority fields and expiry = ttl; after a
/// Send, the bytes to send. `payload_len u16` precedes it (0 = none).
pub fn encode_output(acts: &Actions, h: &Harness, out: &mut [u8]) -> Option<usize> {
    let mut w = Writer::new(out);
    w.u8(u8::try_from(acts.len()).ok()?)?;
    let mut sign = false;
    let mut send = false;
    for a in acts.iter() {
        match *a {
            Action::OpenSession { tier } => {
                w.u8(1)?;
                w.u8(tier as u8)?;
            }
            Action::Sign => {
                w.u8(2)?;
                sign = true;
            }
            Action::StartLease { tier, until_ms, egress_policy_id } => {
                w.u8(3)?;
                w.u8(tier as u8)?;
                w.u64(until_ms)?;
                w.put(&egress_policy_id)?;
            }
            Action::EndLease { tier } => {
                w.u8(4)?;
                w.u8(tier as u8)?;
            }
            Action::Send => {
                w.u8(5)?;
                send = true;
            }
            Action::RunTool(c) => {
                w.u8(6)?;
                match c {
                    ToolCall::EvidenceGet { ev } => {
                        w.u8(1)?;
                        w.u16(ev)?;
                        w.u8(0)?;
                    }
                    ToolCall::FlowCount { ev, hours } => {
                        w.u8(2)?;
                        w.u16(ev)?;
                        w.u8(hours)?;
                    }
                }
            }
            Action::Ledger(rec) => {
                w.u8(7)?;
                let mut b = [0u8; RECORD_LEN];
                rec.encode(&mut b);
                w.put(&b)?;
            }
            Action::Finished(o) => {
                w.u8(8)?;
                let (kind, code, st, shown, l0, model) = match o {
                    Outcome::Verified(v) => (1u8, v.finding as u16, v.status as u8, v.shown_verdict.map_or(0, |x| x as u8), u8::from(v.l0_decided), v.model_verdict.map_or(0, |x| x as u8)),
                    Outcome::Rejected(v) => (2, v as u16, 1, 0, 0, 0),
                    Outcome::Refused(r) => (3, r as u16, 0, 0, 0, 0),
                    Outcome::Aborted(a) => (4, a as u16, 0, 0, 0, 0),
                };
                w.u8(kind)?;
                w.u16(code)?;
                w.put(&[st, shown, l0, model])?;
            }
        }
    }
    if sign {
        let req = *h.sign_request()?;
        let body = HpExec {
            version: crate::cap::VERSION,
            capability_id: [0; 16],
            device_identity: [0; 32],
            req,
            counter: 0,
            not_before_ms: 0,
            expiry_ms: req.ttl_ms,
            revocation_epoch: 0,
            nonce: [0; 16],
            cache_salt: [0; 32],
        };
        let mut b = [0u8; BODY_LEN];
        body.encode(&mut b)?;
        w.u16(u16::try_from(BODY_LEN).ok()?)?;
        w.put(&b)?;
    } else if send {
        let tx = h.tx();
        w.u16(u16::try_from(tx.len()).ok()?)?;
        w.put(tx)?;
    } else {
        w.u16(0)?;
    }
    Some(w.len())
}

// The largest IN (a Signed blob or a CHUNK frame plus header) and OUT (actions plus a full request frame)
// must fit their windows.
const _: () = assert!(crate::cap::SIGNED_LEN + 16 <= IN_MAX && crate::frame::RES_MAX + 16 <= IN_MAX);
const _: () = assert!(512 + crate::cap::SIGNED_LEN + crate::frame::REQ_MAX <= OUT_MAX);
