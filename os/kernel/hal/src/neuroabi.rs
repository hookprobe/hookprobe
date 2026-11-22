// SPDX-License-Identifier: AGPL-3.0-only
//! The kernel <-> EL0 `el0-neuro` ABI, version 1 (the repo-root design doc heqk-neuro-integration.md §4). Shared by the kernel
//! host (`kernel/src/neuro.rs`) and the server (`os/neuro/el0-neuro`) so the two cannot drift (the hal convention,
//! as `hshabi`). It replaces the PROPOSED `os/neuro/el0-neuro/src/abi.rs`; the wire format of v1.0 is unchanged
//! byte for byte, v1.1 only adds (a version word, an extended INFO, HEALTH).
//!
//! Neuro OBSERVES and SCORES. Nothing in this ABI carries an enforcement decision, and the kernel never derives one
//! from it: a result is a "behaviour deviation" EVIDENCE record (docs/research/neuro/20; ADR 0023 / contract C9).
//! Every byte the server returns is untrusted input to EL1 and is validated here before the kernel keeps it.
//!
//! One shared IO region. Every bounded excursion runs ONE command and exits with `SYS_EXIT_USER`.
//!   CMD_EVENTS     IN  = n x 16-byte event records. OUT = nothing. Feeds the per-device hour aggregators.
//!   CMD_CLOSE_HOUR IN  = `[hr u8]` (UTC hour of day, 0..23). OUT = one 20-byte result per device that had events.
//!   CMD_RESET_DEV  IN  = `[dev u16]`. Forget a device (its slot is re-assigned).
//!   CMD_INFO       OUT = v1.0 `[devices u16][bytes_per_device u32][abi_major u16]`;
//!                        v1.1 appends `[abi_minor u16][caps u16][engine_rev u32]` (16 bytes).
//!   CMD_HEALTH     (v1.1) OUT = `[events_ok u32][events_bad u32][batches_bad u32][hours_closed u32]
//!                        [reports_dropped u32][active u16][slots_used u16]` (24 bytes).
//! Engine state lives in the server's own .bss: the kernel keeps the server's data pages across excursions. A fault
//! resets the server from its signed ELF and the behavioural memory relearns from cold (state class Volatile).

pub const BASE_QEMU: usize = 0xBE00_0000;
/// CM5: the free gap 0x1_4025_4000..0x1_4030_0000 of the GB5 window, between el0-lansvc (ends 0x1_4025_4000) and
/// el0-hsh (0x1_4030_0000).
pub const BASE_CM5: usize = 0x1_4026_0000;
pub const IMAGE_MAX: usize = 0x2_0000; // 128 KiB: code + rodata + data + .bss (engine state)
pub const STACK_OFF: usize = 0x2_0000;
pub const STACK_SIZE: usize = 0x4000;
pub const IO_OFF: usize = 0x2_4000;
pub const IO_SIZE: usize = 0x4000;
const _: () = assert!(BASE_CM5 >= 0x1_4025_4000 && BASE_CM5 + IO_OFF + IO_SIZE <= 0x1_4030_0000);
const _: () = assert!(IMAGE_MAX <= STACK_OFF && STACK_OFF + STACK_SIZE <= IO_OFF);

pub const H_MAGIC: usize = 0; // u32 "HQNE"
pub const H_CMD: usize = 4;
pub const H_IN_LEN: usize = 8;
pub const H_STATUS: usize = 12;
pub const H_OUT_LEN: usize = 16;
/// v1.1: the ABI version the kernel speaks, `major << 16 | minor`. 0 = a v1.0 kernel (no version word).
pub const H_ABI: usize = 20;
pub const MAGIC: u32 = u32::from_le_bytes(*b"HQNE");

pub const ABI_MAJOR: u16 = 1;
pub const ABI_MINOR: u16 = 1;
pub const ABI_WORD: u32 = (ABI_MAJOR as u32) << 16 | ABI_MINOR as u32;
/// INFO caps bits (v1.1).
pub const CAP_HEALTH: u16 = 1 << 0;

pub const IN_OFF: usize = 0x40;
pub const IN_MAX: usize = 0x2000; // 512 events per excursion
pub const OUT_OFF: usize = 0x2040;
pub const OUT_MAX: usize = IO_SIZE - OUT_OFF;

pub const CMD_EVENTS: u32 = 1;
pub const CMD_CLOSE_HOUR: u32 = 2;
pub const CMD_RESET_DEV: u32 = 3;
pub const CMD_INFO: u32 = 4;
pub const CMD_HEALTH: u32 = 5;
/// Test only: the server panics, so the kernel can prove fault containment (as hsh's CMD_SELFTEST_FAULT).
pub const CMD_SELFTEST_FAULT: u32 = 99;

pub const ST_OK: u32 = 0;
pub const ST_BAD_CMD: u32 = 2;
pub const ST_BAD_INPUT: u32 = 3;
/// v1.1: the kernel speaks an ABI major this server does not.
pub const ST_BAD_VERSION: u32 = 4;
pub const ST_PANIC: u32 = 6;

pub const INFO_LEN_V10: usize = 8;
pub const INFO_LEN: usize = 16;
pub const HEALTH_LEN: usize = 24;

/// Device slots the server keeps (each ~1.3 KiB of behavioural memory). The kernel maps a MAC to a slot.
pub const DEVICES: usize = 64;

/// Event record, 16 bytes, little-endian: `[kind u8][flags u8][dev u16][fp u32][bytes u48][conns u16]`
/// - EV_FLOW: new connection(s) to peer fingerprint `fp` (doc 20: `peerkey::peer_fp(Mode::V2{plen:24}, ..)`);
///   `bytes` sent by the device, `conns` connections;
/// - EV_VOLUME: bytes and connections with no peer identity;
/// - EV_DNS: one query for registered-domain fingerprint `fp`; flags bit 0 = NXDOMAIN (rcode 3).
///
/// The kernel computes fingerprints. The server never sees addresses or names.
pub const EV_SIZE: usize = 16;
pub const EV_FLOW: u8 = 1;
pub const EV_VOLUME: u8 = 2;
pub const EV_DNS: u8 = 3;
pub const EV_FLAG_NX: u8 = 1;
pub const BYTES_MAX: u64 = (1 << 48) - 1;

/// Result record, 20 bytes, little-endian:
/// `[dev u16][driver u8][deviant u8][score u32][vol u16][fan u16][novel u16][dns u16][act u16][rsv u16]`.
/// Q8 values (256 = 1.0). deviant = score >= 1.0. EVIDENCE ONLY (doc 20): never an alert, a notification or an
/// enforcement input. driver: 0 volume, 1 fan-out, 2 novel peers, 3 dns, 4 activity.
pub const RES_SIZE: usize = 20;
pub const CALM_Q8: u32 = 256;
pub const DRIVERS: [&str; 5] = ["volume", "fan-out", "novel-peers", "dns", "activity"];

/// Encode one event (the kernel side). None = a kind outside the ABI or a device outside the table.
pub fn encode_event(kind: u8, flags: u8, dev: u16, fp: u32, bytes: u64, conns: u16) -> Option<[u8; EV_SIZE]> {
    if !matches!(kind, EV_FLOW | EV_VOLUME | EV_DNS) || dev as usize >= DEVICES {
        return None;
    }
    let mut r = [0u8; EV_SIZE];
    r[0] = kind;
    r[1] = if kind == EV_DNS { flags & EV_FLAG_NX } else { 0 };
    r[2..4].copy_from_slice(&dev.to_le_bytes());
    r[4..8].copy_from_slice(&fp.to_le_bytes());
    r[8..14].copy_from_slice(&bytes.min(BYTES_MAX).to_le_bytes()[..6]);
    r[14..16].copy_from_slice(&conns.to_le_bytes());
    Some(r)
}

/// One validated result record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deviation {
    pub dev: u16,
    pub driver: u8,
    pub deviant: bool,
    pub score_q8: u32,
    /// vol, fan, novel, dns, act (Q8, saturated).
    pub parts: [u16; 5],
}

/// Why a CLOSE_HOUR reply was refused (the kernel journals it as a complaint and resets the server).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyErr {
    /// Not a whole number of records, longer than OUT, or more records than devices.
    Length,
    /// A device outside the table, or one the kernel fed no event this hour.
    Device,
    /// The same device twice.
    Duplicate,
    /// A driver outside 0..=4, a deviant byte other than 0/1, a deviant flag that contradicts the score, or rsv != 0.
    Field,
}

/// Decode one record without the cross-record checks.
pub fn decode_result(r: &[u8]) -> Result<Deviation, ReplyErr> {
    if r.len() != RES_SIZE {
        return Err(ReplyErr::Length);
    }
    let le16 = |i: usize| u16::from_le_bytes([r[i], r[i + 1]]);
    let dev = le16(0);
    if dev as usize >= DEVICES {
        return Err(ReplyErr::Device);
    }
    let (driver, flag) = (r[2], r[3]);
    let score_q8 = u32::from_le_bytes([r[4], r[5], r[6], r[7]]);
    if driver as usize >= DRIVERS.len() || flag > 1 || (flag == 1) != (score_q8 >= CALM_Q8) || le16(18) != 0 {
        return Err(ReplyErr::Field);
    }
    Ok(Deviation { dev, driver, deviant: flag == 1, score_q8, parts: core::array::from_fn(|i| le16(8 + 2 * i)) })
}

/// Validate a whole CLOSE_HOUR reply against what the kernel fed this hour (`fed`: bit d = device d had at least one
/// event), then hand each record to `f`. All-or-nothing: on any error `f` has not been called. Ok = records.
pub fn parse_close_reply(out: &[u8], fed: u64, mut f: impl FnMut(Deviation)) -> Result<usize, ReplyErr> {
    if !out.len().is_multiple_of(RES_SIZE) || out.len() > OUT_MAX || out.len() / RES_SIZE > DEVICES {
        return Err(ReplyErr::Length);
    }
    let mut seen = 0u64;
    for r in out.as_chunks::<RES_SIZE>().0 {
        let d = decode_result(r)?;
        let bit = 1u64 << d.dev;
        if fed & bit == 0 {
            return Err(ReplyErr::Device);
        }
        if seen & bit != 0 {
            return Err(ReplyErr::Duplicate);
        }
        seen |= bit;
    }
    for r in out.as_chunks::<RES_SIZE>().0 {
        if let Ok(d) = decode_result(r) {
            f(d);
        }
    }
    Ok(out.len() / RES_SIZE)
}

/// INFO, decoded. v1.0 servers report only the first three fields (minor 0, caps 0, rev 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub devices: u16,
    pub bytes_per_device: u32,
    pub major: u16,
    pub minor: u16,
    pub caps: u16,
    pub engine_rev: u32,
}

/// Decode and check INFO: the server must speak our major and keep exactly the kernel's device table.
pub fn parse_info(o: &[u8]) -> Option<Info> {
    if o.len() != INFO_LEN_V10 && o.len() != INFO_LEN {
        return None;
    }
    let le16 = |i: usize| u16::from_le_bytes([o[i], o[i + 1]]);
    let le32 = |i: usize| u32::from_le_bytes([o[i], o[i + 1], o[i + 2], o[i + 3]]);
    let v11 = o.len() == INFO_LEN;
    let i = Info {
        devices: le16(0),
        bytes_per_device: le32(2),
        major: le16(6),
        minor: if v11 { le16(8) } else { 0 },
        caps: if v11 { le16(10) } else { 0 },
        engine_rev: if v11 { le32(12) } else { 0 },
    };
    (i.major == ABI_MAJOR && i.devices as usize == DEVICES && i.bytes_per_device > 0 && i.bytes_per_device < 64 * 1024).then_some(i)
}

/// HEALTH, decoded (v1.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Health {
    pub events_ok: u32,
    pub events_bad: u32,
    pub batches_bad: u32,
    pub hours_closed: u32,
    pub reports_dropped: u32,
    pub active: u16,
    pub slots_used: u16,
}

pub fn parse_health(o: &[u8]) -> Option<Health> {
    if o.len() != HEALTH_LEN {
        return None;
    }
    let le16 = |i: usize| u16::from_le_bytes([o[i], o[i + 1]]);
    let le32 = |i: usize| u32::from_le_bytes([o[i], o[i + 1], o[i + 2], o[i + 3]]);
    let h = Health { events_ok: le32(0), events_bad: le32(4), batches_bad: le32(8), hours_closed: le32(12), reports_dropped: le32(16), active: le16(20), slots_used: le16(22) };
    (h.active as usize <= DEVICES && h.slots_used as usize <= DEVICES).then_some(h)
}

pub fn encode_health(h: &Health) -> [u8; HEALTH_LEN] {
    let mut o = [0u8; HEALTH_LEN];
    for (i, v) in [h.events_ok, h.events_bad, h.batches_bad, h.hours_closed, h.reports_dropped].iter().enumerate() {
        o[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
    }
    o[20..22].copy_from_slice(&h.active.to_le_bytes());
    o[22..24].copy_from_slice(&h.slots_used.to_le_bytes());
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(dev: u16, driver: u8, flag: u8, score: u32) -> [u8; RES_SIZE] {
        let mut r = [0u8; RES_SIZE];
        r[0..2].copy_from_slice(&dev.to_le_bytes());
        r[2] = driver;
        r[3] = flag;
        r[4..8].copy_from_slice(&score.to_le_bytes());
        r[8..10].copy_from_slice(&7u16.to_le_bytes());
        r
    }

    #[test]
    fn v10_layout_is_frozen() {
        // the v1.0 wire format of os/neuro/el0-neuro/src/abi.rs, byte for byte
        assert_eq!((H_MAGIC, H_CMD, H_IN_LEN, H_STATUS, H_OUT_LEN), (0, 4, 8, 12, 16));
        assert_eq!((IN_OFF, IN_MAX, OUT_OFF, OUT_MAX), (0x40, 0x2000, 0x2040, 0x4000 - 0x2040));
        assert_eq!((CMD_EVENTS, CMD_CLOSE_HOUR, CMD_RESET_DEV, CMD_INFO, CMD_SELFTEST_FAULT), (1, 2, 3, 4, 99));
        assert_eq!((ST_OK, ST_BAD_CMD, ST_BAD_INPUT, ST_PANIC), (0, 2, 3, 6));
        assert_eq!((EV_SIZE, RES_SIZE, EV_FLOW, EV_VOLUME, EV_DNS), (16, 20, 1, 2, 3));
        assert_eq!(MAGIC, 0x454E_5148);
        assert!(H_ABI + 4 <= IN_OFF);
        assert!(OUT_MAX / RES_SIZE >= DEVICES, "a full hour close always fits");
    }

    #[test]
    fn event_encoding() {
        let r = encode_event(EV_FLOW, 0xFF, 3, 0xDEAD_BEEF, u64::MAX, 2).unwrap();
        assert_eq!(r[0], EV_FLOW);
        assert_eq!(r[1], 0, "flags only on DNS");
        assert_eq!(&r[2..4], &3u16.to_le_bytes());
        assert_eq!(&r[4..8], &0xDEAD_BEEFu32.to_le_bytes());
        assert_eq!(&r[8..14], &[0xFF; 6], "bytes saturate at 2^48-1");
        assert_eq!(encode_event(EV_DNS, 0xFF, 0, 1, 0, 1).unwrap()[1], EV_FLAG_NX);
        assert!(encode_event(9, 0, 0, 0, 0, 0).is_none());
        assert!(encode_event(EV_FLOW, 0, DEVICES as u16, 0, 0, 0).is_none());
    }

    #[test]
    fn close_reply_validation() {
        let mut out = [0u8; 3 * RES_SIZE];
        out[..20].copy_from_slice(&rec(0, 2, 1, 300));
        out[20..40].copy_from_slice(&rec(5, 0, 0, 10));
        out[40..60].copy_from_slice(&rec(63, 4, 0, 255));
        let fed = 1 | 1 << 5 | 1 << 63;
        let mut got = [Deviation { dev: 0, driver: 0, deviant: false, score_q8: 0, parts: [0; 5] }; 3];
        let mut n = 0;
        assert_eq!(parse_close_reply(&out, fed, |d| { got[n] = d; n += 1 }), Ok(3));
        assert!(got[0].deviant && got[0].driver == 2 && got[0].parts[0] == 7);
        assert!(!got[2].deviant);
        // a device the kernel did not feed -> refused, nothing delivered
        let mut calls = 0;
        assert_eq!(parse_close_reply(&out, 1 | 1 << 5, |_| calls += 1), Err(ReplyErr::Device));
        assert_eq!(calls, 0);
        // duplicate
        let mut dup = out;
        dup[20..40].copy_from_slice(&rec(0, 1, 0, 1));
        assert_eq!(parse_close_reply(&dup, fed, |_| ()), Err(ReplyErr::Duplicate));
        // flag contradicts the score, bad driver, bad flag byte, rsv set, out-of-range device, partial record
        assert_eq!(decode_result(&rec(1, 0, 1, 255)), Err(ReplyErr::Field));
        assert_eq!(decode_result(&rec(1, 0, 0, 256)), Err(ReplyErr::Field));
        assert_eq!(decode_result(&rec(1, 5, 0, 0)), Err(ReplyErr::Field));
        assert_eq!(decode_result(&rec(1, 0, 2, 0)), Err(ReplyErr::Field));
        let mut r = rec(1, 0, 0, 0);
        r[18] = 1;
        assert_eq!(decode_result(&r), Err(ReplyErr::Field));
        assert_eq!(decode_result(&rec(64, 0, 0, 0)), Err(ReplyErr::Device));
        assert_eq!(parse_close_reply(&out[..19], fed, |_| ()), Err(ReplyErr::Length));
        assert_eq!(parse_close_reply(&[0u8; (DEVICES + 1) * RES_SIZE], u64::MAX, |_| ()), Err(ReplyErr::Length));
        assert_eq!(parse_close_reply(&[], 0, |_| ()), Ok(0));
    }

    #[test]
    fn info_and_health() {
        let mut o = [0u8; INFO_LEN];
        o[0..2].copy_from_slice(&(DEVICES as u16).to_le_bytes());
        o[2..6].copy_from_slice(&1296u32.to_le_bytes());
        o[6..8].copy_from_slice(&1u16.to_le_bytes());
        o[8..10].copy_from_slice(&1u16.to_le_bytes());
        o[10..12].copy_from_slice(&CAP_HEALTH.to_le_bytes());
        let i = parse_info(&o).unwrap();
        assert_eq!((i.minor, i.caps), (1, CAP_HEALTH));
        let v10 = parse_info(&o[..INFO_LEN_V10]).unwrap();
        assert_eq!((v10.minor, v10.caps), (0, 0));
        o[6] = 2; // major 2
        assert!(parse_info(&o).is_none());
        o[6] = 1;
        o[0] = 32; // a different table size
        assert!(parse_info(&o).is_none());
        assert!(parse_info(&o[..10]).is_none());
        let h = Health { events_ok: 9, events_bad: 1, batches_bad: 1, hours_closed: 3, reports_dropped: 0, active: 2, slots_used: 4 };
        assert_eq!(parse_health(&encode_health(&h)), Some(h));
        let mut bad = encode_health(&h);
        bad[20] = 65;
        assert!(parse_health(&bad).is_none());
    }
}
