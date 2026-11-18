// SPDX-License-Identifier: AGPL-3.0-only
//! PROPOSED kernel <-> EL0 `neuro` ABI, modelled on `os/kernel/hal/src/hshabi.rs`.
//!
//! When HomePods accepts the server, this file moves to `hal/src/neuroabi.rs`, so the kernel and the
//! server share one definition (the hal convention). Until then it lives here, and the kernel side
//! does not exist. Addresses are proposals; HomePods assigns the final ones (docs/research/neuro/12 R1).
//!
//! One shared IO region. Every bounded excursion runs ONE command and exits with `SYS_EXIT_USER`.
//!   CMD_EVENTS     IN  = n x 16-byte event records (below). OUT = nothing. Feeds the per-device hour aggregators.
//!   CMD_CLOSE_HOUR IN  = `[hr u8]` (hour of day, 0..23). OUT = one 20-byte result per device that had events
//!                  this hour. Scores and updates those devices, then clears their aggregators.
//!   CMD_RESET_DEV  IN  = `[dev u16]`. Forget a device (re-assigned slot).
//!   CMD_INFO       OUT = `[devices u16][bytes_per_device u32][version u16]`.
//! Engine state lives in the server's own .bss, so the kernel must keep the server's data pages across
//! excursions (as it does for el0-wpa's state pages). A reset or fault loses the memory; the DNA relearns
//! (cold start, Phase 0b).

pub const BASE_QEMU: usize = 0xBE00_0000; // PROPOSED
pub const BASE_CM5: usize = 0x1_4026_0000; // PROPOSED: in the free gap 0x1_4025_4000..0x1_4030_0000
pub const IMAGE_MAX: usize = 0x2_0000; // 128 KiB: code + rodata + data + .bss (engine state)
pub const STACK_OFF: usize = 0x2_0000;
pub const STACK_SIZE: usize = 0x4000;
pub const IO_OFF: usize = 0x2_4000;
pub const IO_SIZE: usize = 0x4000;
/// The whole server must fit before el0-hsh at 0x1_4030_0000.
const _: () = assert!(BASE_CM5 + IO_OFF + IO_SIZE <= 0x1_4030_0000);

pub const H_MAGIC: usize = 0; // u32 "HQNE"
pub const H_CMD: usize = 4;
pub const H_IN_LEN: usize = 8;
pub const H_STATUS: usize = 12;
pub const H_OUT_LEN: usize = 16;
pub const MAGIC: u32 = u32::from_le_bytes(*b"HQNE");

pub const IN_OFF: usize = 0x40;
pub const IN_MAX: usize = 0x2000; // 512 events per excursion
pub const OUT_OFF: usize = 0x2040;
pub const OUT_MAX: usize = IO_SIZE - OUT_OFF;

pub const CMD_EVENTS: u32 = 1;
pub const CMD_CLOSE_HOUR: u32 = 2;
pub const CMD_RESET_DEV: u32 = 3;
pub const CMD_INFO: u32 = 4;

pub const ST_OK: u32 = 0;
pub const ST_BAD_CMD: u32 = 2;
pub const ST_BAD_INPUT: u32 = 3;
pub const ST_PANIC: u32 = 6;

/// Event record, 16 bytes, little-endian:
/// `[kind u8][flags u8][dev u16][fp u32][bytes u64]`
/// - kind EV_FLOW: one flow to peer `fp` (fingerprint of ip:port, `neuro_core::fingerprint(peer_key(..))`),
///   `bytes` sent by the device, one connection;
/// - kind EV_VOLUME: bytes and one connection with no peer identity;
/// - kind EV_DNS: one query for suffix `fp` (fingerprint of FNV-1a of the registered suffix); flags bit 0 = NXDOMAIN.
///
/// The kernel computes fingerprints. The server never sees addresses or names.
pub const EV_SIZE: usize = 16;
pub const EV_FLOW: u8 = 1;
pub const EV_VOLUME: u8 = 2;
pub const EV_DNS: u8 = 3;

/// Result record, 20 bytes, little-endian:
/// `[dev u16][driver u8][alarm u8][score u32][vol u16][fan u16][novel u16][dns u16][act u16][rsv u16]`.
/// Q8 values (256 = 1.0), saturated to the field width. alarm = score >= 1.0.
/// driver: 0 volume, 1 fan-out, 2 novel peers, 3 dns, 4 activity.
pub const RES_SIZE: usize = 20;
