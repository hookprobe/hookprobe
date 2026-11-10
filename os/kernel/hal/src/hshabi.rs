//! The kernel <-> EL0 `hsh` (native management shell) ABI (ADR 0059 step 4; hsh spec R1). One shared IO region;
//! every bounded excursion runs ONE command and exits. Two-phase per shell command:
//!   1. CMD_LINE  : IN = one input line. OUT = text (ST_TEXT), or one management request (ST_REQUEST:
//!                  `[msg u16][rsv u16]`) the kernel dispatches through `mgmtabi` with the session's role;
//!   2. CMD_REPLY : IN = `[msg u16][result u8][rsv u8]` + the fixed reply record. OUT = the formatted text.
//! The shell keeps no state between excursions. Shared by `el0-hsh` and the kernel so the two cannot drift.

pub const BASE_QEMU: usize = 0xB800_0000;
/// CM5: the GB5 window's second 2 MiB block, 1 MiB in (el0-lansvc uses its first 336 KiB).
pub const BASE_CM5: usize = 0x1_4030_0000;
pub const IMAGE_MAX: usize = 0x2_0000; // 128 KiB
pub const STACK_OFF: usize = 0x2_0000;
pub const STACK_SIZE: usize = 0x8000;
pub const IO_OFF: usize = 0x2_8000;
pub const IO_SIZE: usize = 0x2000;

pub const H_MAGIC: usize = 0; // u32 "HQSH"
pub const H_CMD: usize = 4;
pub const H_IN_LEN: usize = 8;
pub const H_STATUS: usize = 12;
pub const H_OUT_LEN: usize = 16;
/// The session's role (mgmtabi ROLE_*): the shell only HIDES commands with it; the kernel enforces.
pub const H_ROLE: usize = 20;
pub const MAGIC: u32 = u32::from_le_bytes(*b"HQSH");

pub const IN_OFF: usize = 0x40;
pub const IN_MAX: usize = 0x200;
pub const OUT_OFF: usize = 0x400;
pub const OUT_MAX: usize = IO_SIZE - OUT_OFF;

/// Input line limits (hsh spec §9.1).
pub const LINE_MAX: usize = 255;
pub const TOKENS_MAX: usize = 12;
pub const TOKEN_MAX: usize = 64;

pub const CMD_LINE: u32 = 1;
pub const CMD_REPLY: u32 = 2;
pub const CMD_SELFTEST_FAULT: u32 = 99;

pub const ST_TEXT: u32 = 0;
pub const ST_REQUEST: u32 = 1;
pub const ST_BAD_CMD: u32 = 2;
pub const ST_PANIC: u32 = 6;
