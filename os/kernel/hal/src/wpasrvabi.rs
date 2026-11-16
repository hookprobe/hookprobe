//! ADR 0065 step 4g (S1): the ABI of `el0-wpa`, the resident EL0 WPA security server.
//!
//! Window: the image, its stack, one control page (the SAME layout as el0-wifi's, `crate::wifisrvabi::H_*` /
//! `IN_OFF` / `OUT_OFF`), the PERSISTENT state pages (a normal restart after a fault keeps them; only a full wipe
//! zeroes them — operator decision 2026-11-15: a bus fault must never erase the PMKSA cache, a security-server fault
//! wipes secrets only when its state cannot be trusted), then the key-transfer page (RW here, read-only in el0-wifi:
//! the only path a key takes to the chip, design docs/design/wifi-el0-split.md §3).

pub const BASE_QEMU: usize = 0xBD00_0000;
/// After el0-wifi (ends 0x1_4039_C000), inside the CM5 GB5 user window (ends 0x1_4040_0000).
pub const BASE_CM5: usize = 0x1_403A_0000;
pub const IMAGE_MAX: usize = 0x2_0000; // 128 KiB
pub const STACK_OFF: usize = 0x2_0000;
pub const STACK_SIZE: usize = 0x1_0000; // 64 KiB: the SAE curve arithmetic moves here in S2
pub const CTRL_OFF: usize = 0x3_0000;
/// Persistent state: survives a restart after a fault, zeroed by a full wipe.
pub const STATE_OFF: usize = 0x3_1000;
pub const STATE_PAGES: usize = 8;
pub const STATE_SIZE: usize = STATE_PAGES * 0x1000;
/// The key-transfer page (RW in el0-wpa, RO in el0-wifi at `crate::wifisrvabi::KEYX_OFF`).
pub const KEYX_OFF: usize = STATE_OFF + STATE_SIZE;
pub const WINDOW_END: usize = KEYX_OFF + 0x1000;
const _: () = assert!(BASE_CM5 + WINDOW_END <= 0x1_4040_0000);
const _: () = assert!(crate::wifisrvabi::BASE_CM5 + crate::wifisrvabi::WINDOW_END <= BASE_CM5);
const _: () = assert!(crate::wifisrvabi::BASE_QEMU + crate::wifisrvabi::WINDOW_END <= BASE_QEMU);

pub const MAGIC: u32 = u32::from_le_bytes(*b"HQWP");

pub const CMD_INIT: u32 = 1;
/// S1 substrate test: add 1 to a counter in the persistent state. R0 = the new value.
pub const CMD_STATE_BUMP: u32 = 40;
/// S1 substrate test: R0 = the counter.
pub const CMD_STATE_READ: u32 = 41;
/// S1 substrate test: IN bytes copied to the key-transfer page (S3 puts a key record there).
pub const CMD_KEYX_PUT: u32 = 42;
/// Test only: fault on purpose.
pub const CMD_SELFTEST_FAULT: u32 = 99;
