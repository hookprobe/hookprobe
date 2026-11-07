//! Measured boot: a small TPM-style measurement chain.
//!
//! Each measurement `m` extends a register: `PCR[i] = SHA-256( PCR[i] || m )`.
//! Because the fold is order-dependent and one-way, the final PCR values are a
//! compact, unforgeable commitment to exactly what was measured, in order. Every
//! extend also appends a `MeasureEvent` to the log, so a verifier can replay the
//! events and confirm they reproduce the PCRs (that replay is the integrity
//! check). Unlike secure boot, this RECORDS rather than enforces — it is what a
//! local or remote attestation reasons about.
//!
//! CRTM anchor (B-7): PCR0's FIRST extend is the CRTM anchor — SHA-256 over the
//! immutable OTP-fused device identity (board serial, read via the VC mailbox),
//! done in `hboot_main` BEFORE the HBoot self-measurement. So PCR0 is rooted in
//! hardware the image can't forge, not a free-floating self-measurement, and the
//! OTP-derived AK-signed quote binds the whole chain to the device's fuses.
//! Remaining honesty: HBoot still measures itself; a *fully* immutable first
//! stage (the BCM2712 BootROM/EEPROM signed-boot) is the platform's own root and
//! sits below HBoot — the anchor ties our chain to that hardware identity.

use boot_abi::sha256;
use boot_abi::*;

/// Build the log in place at MEASURE_LOG_ADDR and return a handle to extend it.
pub struct Measurements {
    log: *mut MeasureLog,
    events: *mut MeasureEvent,
}

impl Measurements {
    /// Initialize the log header with zeroed PCRs and no events.
    pub fn init() -> Self {
        let log = MEASURE_LOG_ADDR as *mut MeasureLog;
        unsafe {
            core::ptr::write(
                log,
                MeasureLog {
                    magic: MEASURE_LOG_MAGIC,
                    version: 1,
                    num_pcr: NUM_PCR as u32,
                    count: 0,
                    _pad: 0,
                    pcr: [[0u8; 32]; NUM_PCR],
                },
            );
        }
        let events = (MEASURE_LOG_ADDR + core::mem::size_of::<MeasureLog>()) as *mut MeasureEvent;
        Measurements { log, events }
    }

    /// Extend `pcr` with `digest` and append an event of `kind`.
    pub fn extend(&mut self, pcr: u32, kind: u32, digest: &[u8; 32]) {
        let i = pcr as usize;
        unsafe {
            // PCR[i] = SHA-256( PCR[i] || digest )  (64-byte input).
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&(*self.log).pcr[i]);
            buf[32..].copy_from_slice(digest);
            (*self.log).pcr[i] = sha256::digest(&buf);

            let n = (*self.log).count;
            core::ptr::write(
                self.events.add(n as usize),
                MeasureEvent { pcr, kind, digest: *digest },
            );
            (*self.log).count = n + 1;
        }
    }

    /// Measure a byte region and extend `pcr` with its SHA-256.
    pub fn measure_region(&mut self, pcr: u32, kind: u32, base: usize, len: usize) -> [u8; 32] {
        let d = sha256::digest(unsafe { core::slice::from_raw_parts(base as *const u8, len) });
        self.extend(pcr, kind, &d);
        d
    }

    pub fn count(&self) -> u64 {
        unsafe { (*self.log).count as u64 }
    }

    pub fn pcr(&self, i: usize) -> [u8; 32] {
        unsafe { (*self.log).pcr[i] }
    }
}
