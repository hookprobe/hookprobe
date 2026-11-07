//! The kernel <-> EL0 TLS server ABI (ADR 0050 D2 / ADR 0051). One shared IO region; every bounded
//! excursion carries ONE command. Shared by `el0-tlshost` and the kernel so the two cannot drift.
//!
//! Address space (both targets): the server image is linked at `base`; the kernel maps the heap, stack
//! and IO region at the fixed offsets below. QEMU base `0xA000_0000`; CM5 base `USER_VA_BASE + 0x8_0000`
//! (inside the 2 MiB GB5 user window, clear of the GEM stub's first pages).

pub const BASE_QEMU: usize = 0xA000_0000;
pub const BASE_CM5: usize = 0x1_4008_0000;
pub const IMAGE_MAX: usize = 0x8_0000; // 512 KiB for text+rodata+data+bss
pub const HEAP_OFF: usize = 0x8_0000;
pub const HEAP_SIZE: usize = 0xA_0000; // 640 KiB (talc)
pub const STACK_OFF: usize = 0x12_0000;
pub const STACK_SIZE: usize = 0x1_0000;
pub const IO_OFF: usize = 0x13_0000;
pub const IO_SIZE: usize = 0x1_0000;

// Header (little-endian), at the IO base.
pub const H_MAGIC: usize = 0; // u32 "HQTL"
pub const H_CMD: usize = 4; // u32 (in)
pub const H_CONN: usize = 8; // u32 (in) slot
pub const H_IN_LEN: usize = 12; // u32 (in)
pub const H_STATUS: usize = 16; // u32 (out)
pub const H_OUT_TLS: usize = 20; // u32 (out) bytes at OUT_TLS
pub const H_OUT_PLAIN: usize = 24; // u32 (out) bytes at OUT_PLAIN
pub const H_FLAGS: usize = 28; // u32 (out)
pub const H_UNIX_SECS: usize = 32; // u64 (in)
pub const H_ENT_LEN: usize = 40; // u32 (in) fresh entropy bytes at H_ENT
pub const H_ENT: usize = 48; // [u8; ENT_MAX] (in) — refreshed by the kernel every call
pub const ENT_MAX: usize = 256;
pub const MAGIC: u32 = u32::from_le_bytes(*b"HQTL");

pub const IN_OFF: usize = 0x200;
pub const IN_MAX: usize = 0x5E00; // ~23.5 KiB: one full TLS record + slack
pub const OUT_TLS_OFF: usize = 0x6000;
pub const OUT_TLS_MAX: usize = 0x7000;
pub const OUT_PLAIN_OFF: usize = 0xD000;
pub const OUT_PLAIN_MAX: usize = 0x3000;

/// Plaintext per SEND (one TLS record's worth; the kernel chunks larger responses).
pub const SEND_CHUNK: usize = 16 * 1024;
/// Concurrent TLS connections the server holds.
pub const SLOTS: usize = 4;

// Commands.
/// IN = [32-byte P-256 scalar][u16 n_certs]{[u16 len][DER]}* — builds the server config once.
pub const CMD_INIT: u32 = 1;
pub const CMD_OPEN: u32 = 2;
/// IN = ciphertext from the client. OUT_TLS = bytes to send; OUT_PLAIN = decrypted application data.
pub const CMD_RECV: u32 = 3;
/// IN = application plaintext (≤ SEND_CHUNK). OUT_TLS = records to send.
pub const CMD_SEND: u32 = 4;
/// OUT_TLS = close_notify (if the session got that far); the slot is freed.
pub const CMD_CLOSE: u32 = 5;

// Status codes.
pub const ST_OK: u32 = 0;
pub const ST_BAD_CMD: u32 = 1;
pub const ST_NO_SLOT: u32 = 2;
pub const ST_TLS_ERROR: u32 = 3;
pub const ST_TOO_BIG: u32 = 4;
pub const ST_NOT_INIT: u32 = 5;
pub const ST_PANIC: u32 = 6;
pub const ST_BAD_INIT: u32 = 7;
pub const ST_NOT_READY: u32 = 8;

// Flags (out).
pub const F_HANDSHAKE_DONE: u32 = 1;
pub const F_PEER_CLOSED: u32 = 2;
pub const F_CLOSED: u32 = 4;
