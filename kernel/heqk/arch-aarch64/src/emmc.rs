//! P15 — eMMC block device (BCM2712 second SDHCI @ 0x10_00FF_F000), READ-ONLY.
//!
//! A `broken-cd`, 8-bit, 1.8 V-VCCQ `brcm,bcm2712-sdhci` sharing `clk-emmc2` with
//! the live WiFi host. That sharing is why this driver calls the mailbox
//! `get_clock_rate` ONLY — never `set_clock_rate` (which would retune the WiFi
//! host mid-flight). It derives the SDCLK divisor from the read-back rate.
//!
//! Scope of this pass (SEALED_STORAGE.md phase A): read-only bring-up + single
//! block reads. The write path is compiled out unless `p15-write`. The driver
//! contains NO code path that can emit CMD6/SWITCH, CMD38/ERASE, CMD42/LOCK, or
//! any RPMB / boot-area partition switch — reaching those is one wrong EXT_CSD
//! index away from an unrecoverable brick, so they simply do not exist here.
//!
//! Honesty: structured off the SD/eMMC spec + the metal-proven SDHCI primitives
//! transcribed into `sdhci.rs`. Wired behind `cfg(cm5)`; flash-validated like the
//! other CM5 probes.

#![cfg(feature = "cm5")]

use crate::sdhci::{BlkErr, Host, Resp};
use hal::{BlockDev, BlockErr};

/// The eMMC controller base + cfg block (decoded from the CM5 DT `mmc@fff000`).
pub const EMMC_HOST: usize = 0x10_00FF_F000;
pub const EMMC_CFG: usize = 0x10_00FF_F400;

/// The ONLY sectors this driver may ever write (SEALED_STORAGE.md reserved
/// window): LBA 2016..2047, clear of the MBR and butting against — never
/// entering — the first partition (LBA 2048). Enforced independently of the
/// store-layer guard.
pub const RESERVED_LBA_LO: u64 = 2016;
pub const RESERVED_LBA_HI: u64 = 2048;

// eMMC command indices used (read-only set — deliberately excludes 6/38/42).
const CMD0_GO_IDLE: u16 = 0;
const CMD1_SEND_OP_COND: u16 = 1;
const CMD2_ALL_SEND_CID: u16 = 2;
const CMD3_SET_RCA: u16 = 3;
const CMD7_SELECT: u16 = 7;
const CMD8_SEND_EXT_CSD: u16 = 8; // eMMC: read the 512-byte EXT_CSD (data phase)
const CMD9_SEND_CSD: u16 = 9;
const CMD16_SET_BLOCKLEN: u16 = 16;
const CMD17_READ_SINGLE: u16 = 17;

/// Host RCA we assign the eMMC (any non-zero value; the host owns it on eMMC).
const RCA: u32 = 1;
/// CMD1 argument: sector (block) addressing + the standard voltage window.
/// bit30 = access mode SECTOR; 0x00FF8000 = OCR voltage window.
const OCR_SECTOR_MODE: u32 = 1 << 30;
const OCR_VOLT_WINDOW: u32 = 0x00FF_8000;
const OCR_BUSY: u32 = 1 << 31; // R3 bit31: 1 = power-up complete
const EXT_CSD_SEC_COUNT: usize = 212; // SEC_COUNT[215:212] LE, in 512-B sectors

/// A brought-up eMMC block device. Read-only unless built with `p15-write`.
pub struct Emmc {
    host: Host,
    #[allow(dead_code)]
    rca: u32,
    sec_count: u64,
    sector_addr: bool,
    /// One-shot narrowing write window (only present in the write build).
    #[cfg(feature = "p15-write")]
    win: Option<(u64, u64)>,
}

impl Emmc {
    /// Read-only bring-up. On success the card is selected, block length is 512,
    /// sector addressing is asserted, and `sec_count` is read from EXT_CSD. On
    /// failure returns `(step, err)` so the metal probe can localise the stall.
    /// `step`: 1=reset 2=CMD0 3=CMD1 4=CMD2 5=CMD3 6=CMD9 7=CMD7 8=CMD16
    /// 9=CMD8/EXT_CSD 10=sector-addr assert.
    pub fn probe() -> Result<Emmc, (u8, BlkErr)> {
        let host = Host::new(EMMC_HOST, EMMC_CFG);

        // dump-before-touch happens in the caller via `host.dump()`.
        // `broken-cd` quirk: force card presence — RMW ONLY the presence bits in
        // SDIO_CFG_CTRL (cfg+0x00): SDCD_N_TEST_EN(bit31)=1, LEV(bit30)=0. We touch
        // nothing else in the cfg block (this is eMMC, not the SDIO WiFi quirks).
        unsafe {
            let p = EMMC_CFG as *mut u32;
            let ctrl = core::ptr::read_volatile(p);
            core::ptr::write_volatile(p, (ctrl & !(1u32 << 30)) | (1u32 << 31));
            core::arch::asm!("dsb sy");
        }

        host.reset_all();
        // Bus power on (VDD 3.3 V; signalling stays legacy — HOST_CTRL2 untouched,
        // per the fixed-1.8 V-VCCQ board note).
        host.power_on(0b111);

        // 390 kHz init clock, divisor derived from the READ-BACK clk-emmc2 rate
        // (get_clock_rate ONLY — never set it, the WiFi host shares this clock).
        let base_hz = crate::mailbox::get_clock_rate(crate::mailbox::CLK_EMMC2)
            .filter(|&r| r != 0)
            .unwrap_or(host.caps_base_mhz().max(1) * 1_000_000);
        let mut divisor = (base_hz / (2 * 390_000)) as u16;
        if divisor == 0 {
            divisor = 0x80; // safe fallback (matches the proven WiFi init divisor)
        }
        host.set_clock(divisor);

        // CMD0: go idle.
        host.cmd(CMD0_GO_IDLE, 0, Resp::NoResp, false)
            .map_err(|e| (2u8, e))?;

        // CMD1: SEND_OP_COND — poll until power-up (bit31). R3: no CRC/index check.
        let mut ocr = 0u32;
        let mut ready = false;
        for _ in 0..100 {
            match host.cmd(
                CMD1_SEND_OP_COND,
                OCR_SECTOR_MODE | OCR_VOLT_WINDOW,
                Resp::R3,
                false,
            ) {
                Ok(r) => {
                    ocr = r;
                    if r & OCR_BUSY != 0 {
                        ready = true;
                        break;
                    }
                }
                Err(_) => {}
            }
            wait_ms(2);
        }
        if !ready {
            return Err((3, BlkErr::CmdTimeout));
        }
        // Access mode: bit30 of the (busy-complete) OCR = 1 → sector addressing.
        let sector_addr = ocr & OCR_SECTOR_MODE != 0;

        // CMD2: ALL_SEND_CID (R2 — 136-bit). We only need the ACK.
        host.cmd(CMD2_ALL_SEND_CID, 0, Resp::R2, false)
            .map_err(|e| (4u8, e))?;

        // CMD3: on eMMC the HOST assigns the RCA (arg = RCA<<16). R1.
        host.cmd(CMD3_SET_RCA, RCA << 16, Resp::R1, false)
            .map_err(|e| (5u8, e))?;

        // CMD9: SEND_CSD (R2). Informational for the read-only path.
        host.cmd(CMD9_SEND_CSD, RCA << 16, Resp::R2, false)
            .map_err(|e| (6u8, e))?;

        // CMD7: SELECT the card (R1b).
        host.cmd(CMD7_SELECT, RCA << 16, Resp::R1b, false)
            .map_err(|e| (7u8, e))?;

        // CMD16: set the block length to 512 (R1).
        host.cmd(CMD16_SET_BLOCKLEN, 512, Resp::R1, false)
            .map_err(|e| (8u8, e))?;

        // CMD8: SEND_EXT_CSD — a 512-byte data read; SEC_COUNT[215:212] is the
        // capacity in 512-B sectors (the >2 GB path; CSD C_SIZE is only for small).
        let mut ext = [0u8; 512];
        host.set_block(512, 1);
        host.set_xfer_read_single();
        host.cmd(CMD8_SEND_EXT_CSD, 0, Resp::R1, true)
            .map_err(|e| (9u8, e))?;
        host.pio_in(&mut ext, 512).map_err(|e| (9u8, e))?;
        let sec_count = u32::from_le_bytes([
            ext[EXT_CSD_SEC_COUNT],
            ext[EXT_CSD_SEC_COUNT + 1],
            ext[EXT_CSD_SEC_COUNT + 2],
            ext[EXT_CSD_SEC_COUNT + 3],
        ]) as u64;

        // Assert sector addressing — a byte-addressed fallback could MISADDRESS a
        // multi-GB card and is never acceptable for a write-capable device.
        if !sector_addr {
            return Err((10, BlkErr::CmdError));
        }

        Ok(Emmc {
            host,
            rca: RCA,
            sec_count,
            sector_addr,
            #[cfg(feature = "p15-write")]
            win: None,
        })
    }

    /// Snapshot of the controller registers before bring-up (dump-before-touch).
    pub fn dump_regs() -> [u32; 6] {
        Host::new(EMMC_HOST, EMMC_CFG).dump()
    }

    pub fn sec_count(&self) -> u64 {
        self.sec_count
    }
    pub fn sector_addressed(&self) -> bool {
        self.sector_addr
    }

    fn read_block_impl(&self, lba: u64, buf: &mut [u8; 512]) -> Result<(), BlockErr> {
        if lba >= self.sec_count {
            return Err(BlockErr::OutOfRange);
        }
        // Sector-addressed cards take the LBA directly; byte-addressed would need
        // *512 (we asserted sector addressing at probe, so this is always the LBA).
        let arg = if self.sector_addr {
            lba as u32
        } else {
            (lba * 512) as u32
        };
        self.host.set_block(512, 1);
        self.host.set_xfer_read_single();
        self.host
            .cmd(CMD17_READ_SINGLE, arg, Resp::R1, true)
            .map_err(|_| BlockErr::Io)?;
        self.host.pio_in(buf, 512).map_err(|_| BlockErr::Io)
    }

    /// Arm the one-shot, NARROWING-ONLY write window (SEALED_STORAGE.md: the
    /// driver's independent second gate). It can only ever shrink, and is hard-
    /// clamped to the reserved window regardless of the caller's request, so a
    /// store-layer arithmetic bug cannot widen it. Returns the effective window.
    #[cfg(feature = "p15-write")]
    pub fn arm_write_window(&mut self, lo: u64, hi: u64) -> (u64, u64) {
        // Clamp the request into the hard reserved window first.
        let mut lo = lo.max(RESERVED_LBA_LO);
        let mut hi = hi.min(RESERVED_LBA_HI);
        // Then intersect with any previously-armed window (narrow only).
        if let Some((plo, phi)) = self.win {
            lo = lo.max(plo);
            hi = hi.min(phi);
        }
        if lo >= hi {
            lo = RESERVED_LBA_LO;
            hi = RESERVED_LBA_LO; // empty window: refuses everything
        }
        self.win = Some((lo, hi));
        (lo, hi)
    }

    #[cfg(feature = "p15-write")]
    fn write_block_impl(&mut self, lba: u64, buf: &[u8; 512]) -> Result<(), BlockErr> {
        // Gate 1 (independent of the store layer): the compile-time hard clamp —
        // LBA 0 is never writable and nothing at/above the first partition is.
        if lba < RESERVED_LBA_LO || lba >= RESERVED_LBA_HI {
            return Err(BlockErr::WriteRefused);
        }
        // Gate 2: the armed one-shot window (must have been narrowed to fit).
        match self.win {
            Some((lo, hi)) if lba >= lo && lba < hi => {}
            _ => return Err(BlockErr::WriteRefused),
        }
        if lba >= self.sec_count {
            return Err(BlockErr::OutOfRange);
        }
        let arg = if self.sector_addr {
            lba as u32
        } else {
            (lba * 512) as u32
        };
        self.host.set_block(512, 1);
        self.host.set_xfer_write_single();
        // CMD24 WRITE_BLOCK — the sole write command; still no 6/38/42 anywhere.
        const CMD24_WRITE_SINGLE: u16 = 24;
        self.host
            .cmd(CMD24_WRITE_SINGLE, arg, Resp::R1, true)
            .map_err(|_| BlockErr::Io)?;
        self.host.pio_out(buf, 512).map_err(|_| BlockErr::Io)
    }
}

impl BlockDev for Emmc {
    fn block_count(&self) -> u64 {
        self.sec_count
    }
    fn read_block(&self, lba: u64, buf: &mut [u8; 512]) -> Result<(), BlockErr> {
        self.read_block_impl(lba, buf)
    }
    #[cfg(feature = "p15-write")]
    fn write_block(&mut self, lba: u64, buf: &[u8; 512]) -> Result<(), BlockErr> {
        self.write_block_impl(lba, buf)
    }
}

fn wait_ms(ms: u64) {
    let f: u64;
    let start: u64;
    unsafe {
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack));
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) start, options(nomem, nostack));
    }
    let ticks = f.saturating_mul(ms) / 1000;
    loop {
        let now: u64;
        unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) now, options(nomem, nostack)) };
        if now.wrapping_sub(start) >= ticks {
            break;
        }
    }
}
