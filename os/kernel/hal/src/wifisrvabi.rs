//! ADR 0065: the ABI of `el0-wifi`, the resident EL0 Wi-Fi driver server.
//!
//! Window (one per platform): the image, its stack, one control page, the device mapping, then the two frame rings
//! ([`crate::el0ring`]). Step 2 (this ABI's first user) drives a FAKE device in QEMU: one RAM page with the register
//! layout below; the real CYW43455 / SDHCI mapping replaces it in step 4.

pub const BASE_QEMU: usize = 0xBC00_0000;
/// After el0-hsh (ends 0x1_4032_A000), inside the CM5 GB5 user window (ends 0x1_4040_0000).
pub const BASE_CM5: usize = 0x1_4034_0000;
pub const IMAGE_MAX: usize = 0x2_0000; // 128 KiB
pub const STACK_OFF: usize = 0x2_0000;
pub const STACK_SIZE: usize = 0x8000;
/// One page: the command block below.
pub const CTRL_OFF: usize = 0x2_8000;
/// One page: the device the kernel granted (step 2: the fake device; step 4: the SDHCI registers).
pub const DEV_OFF: usize = 0x2_9000;
/// Driver -> kernel frames (received from the device).
pub const RX_OFF: usize = 0x3_0000;
/// Kernel -> driver frames (to send to the device).
pub const TX_OFF: usize = RX_OFF + crate::el0ring::RING_BYTES + 0x1000;
/// The window's end, relative to the base (must stay inside the platform's user window).
pub const WINDOW_END: usize = TX_OFF + crate::el0ring::RING_BYTES;

// ---- control page ----
pub const H_MAGIC: usize = 0; // u32 "HQWF"
pub const H_CMD: usize = 4;
pub const H_STATUS: usize = 8;
/// u32 the server returns (CMD_POLL: frames moved; CMD_INIT: 0).
pub const H_R0: usize = 12;
/// u32 the server keeps in its own .bss and reports: how many commands this incarnation has served (proves the
/// server is RESIDENT — its memory persists between calls until a fault resets it).
pub const H_SERVED: usize = 16;
pub const MAGIC: u32 = u32::from_le_bytes(*b"HQWF");

/// Bring the device up (step 2: nothing to do but answer).
pub const CMD_INIT: u32 = 1;
/// Move frames: device RX -> the RX ring, the TX ring -> device TX.
pub const CMD_POLL: u32 = 2;
/// Test only: misbehave as a hostile driver would — leave the RX ring inconsistent (the kernel must refuse it).
pub const CMD_SELFTEST_BAD_RING: u32 = 98;
/// Test only: fault on purpose (the supervisor's restart path).
pub const CMD_SELFTEST_FAULT: u32 = 99;

pub const ST_OK: u32 = 0;
pub const ST_BAD_CMD: u32 = 2;
pub const ST_PANIC: u32 = 0xffff_ffff;

// ---- step 2 fake device (one page) ----
/// u16: length of the frame the device has received (0 = none); the driver clears it after taking the frame.
pub const FDEV_RX_LEN: usize = 0;
pub const FDEV_RX_DATA: usize = 0x10;
/// u16: length of the last frame the driver sent to the device.
pub const FDEV_TX_LEN: usize = 0x800;
pub const FDEV_TX_DATA: usize = 0x810;
/// The largest frame the fake device holds per direction.
pub const FDEV_FRAME_MAX: usize = 0x7f0;
