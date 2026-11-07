//! VideoCore property mailbox — read device OTP + board serial from bare-metal
//! EL2 on BCM2712 (Pi 5 / CM5). The VPU firmware stays resident after the
//! SPI-EEPROM bootloader hands off and keeps servicing channel 8, so HBoot can
//! bind a per-device identity (the board serial) into attestation — closing the
//! "anonymous / identical on every device" half of audit B-1 — and read the
//! device-private-key OTP region for a future hardware-bound AK.
//!
//! Fail-safe by construction: every poll is BOUNDED; on any timeout or bad
//! response the call returns `None` and the caller keeps the software AK — the
//! mailbox can never wedge the boot chain.
//!
//! Coherency: the request/response buffer lives in HBoot's low-1 GB cached RAM.
//! The VideoCore reads/writes it non-coherently, so we CLEAN (dc cvac) before
//! the VC reads and INVALIDATE (dc ivac) after it writes. The 32-bit pointer
//! handed to the VC is the `0xC000_0000` VC-alias of the buffer (the VC aliases
//! the low 1 GB of DRAM there on every Pi incl. Pi 5); identity is tried as a
//! fallback (rpi-6.12 DT) — both address the same physical DRAM.
//!
//! Registers (base 0x10_7C01_3880) and the pointer rule are from Linux
//! `bcm2835-mailbox.c` + `raspberrypi.c` and confirmed on Pi 5 hardware.

const MBOX: usize = 0x10_7C01_3880;
const RD: usize = 0x00; // MAIL0 read (VC -> ARM)
const STA0: usize = 0x18; // MAIL0 status; EMPTY = bit30
const WRT: usize = 0x20; // MAIL1 write (ARM -> VC)
const STA1: usize = 0x38; // MAIL1 status; FULL = bit31
const EMPTY: u32 = 0x4000_0000;
const FULL: u32 = 0x8000_0000;
const CHAN: u32 = 8; // property channel
const RESP_OK: u32 = 0x8000_0000;
const POLL_MAX: u32 = 4_000_000;

/// Request/response buffer in HBoot's low-1 GB RAM. CACHE-LINE aligned + padded
/// to a whole number of 64-byte lines so the post-transaction `ivac` (which
/// invalidates by cache line, without clean) can never discard a dirty line
/// shared with a neighboring static — it owns its lines outright.
#[repr(align(64))]
struct MboxBuf([u32; 48]); // 192 B = 3 cache lines
static mut MBOX_BUF: MboxBuf = MboxBuf([0; 48]);

#[inline(always)]
unsafe fn r(off: usize) -> u32 {
    core::ptr::read_volatile((MBOX + off) as *const u32)
}
#[inline(always)]
unsafe fn w(off: usize, v: u32) {
    core::ptr::write_volatile((MBOX + off) as *mut u32, v);
}

/// Clean [base,base+len) to PoC (push the request out to DRAM for the VC).
unsafe fn cvac(base: usize, len: usize) {
    const LINE: usize = 64;
    let mut a = base & !(LINE - 1);
    let end = base + len;
    while a < end {
        core::arch::asm!("dc cvac, {}", in(reg) a);
        a += LINE;
    }
    core::arch::asm!("dsb sy");
}
/// Invalidate [base,base+len) to PoC (drop the stale clean copy so the next
/// read fetches the VC's response from DRAM). No write-back — never clobbers.
unsafe fn ivac(base: usize, len: usize) {
    const LINE: usize = 64;
    core::arch::asm!("dsb sy");
    let mut a = base & !(LINE - 1);
    let end = base + len;
    while a < end {
        core::arch::asm!("dc ivac, {}", in(reg) a);
        a += LINE;
    }
    core::arch::asm!("dsb sy");
}

/// Run one property transaction (buffer already holds the request; `nwords` is
/// its length). Returns true on a success response. Tries the VC-alias pointer
/// then identity.
unsafe fn transact(nwords: usize) -> bool {
    transact_at(core::ptr::addr_of_mut!(MBOX_BUF) as usize, nwords)
}

/// Run one property transaction on the buffer at PHYS `phys` (already holds the request).
/// Generalizes `transact` so the SEC-2 hvc proxy can run a transaction on EL1's OWN buffer.
unsafe fn transact_at(phys: usize, nwords: usize) -> bool {
    let buf = phys as *mut u32;
    // The VC pointer is 32-bit; both candidates require the buffer in the low
    // 1 GB. If HBoot were ever linked ≥1 GB the mask would silently truncate to
    // a DIFFERENT physical page — on a SET that means a garbage/irreversible
    // burn. Refuse rather than risk it.
    if phys >= 0x4000_0000 {
        return false;
    }
    let candidates = [0xC000_0000u32 | (phys as u32 & 0x3FFF_FFFF), phys as u32];
    for &vcaddr in &candidates {
        cvac(phys, nwords * 4);
        // Drain any stale channel-8 messages left by an earlier stage.
        let mut drain = 0;
        while r(STA0) & EMPTY == 0 && drain < 16 {
            let _ = r(RD);
            drain += 1;
        }
        // Send.
        let mut spin = 0;
        while r(STA1) & FULL != 0 {
            spin += 1;
            if spin >= POLL_MAX {
                break;
            }
        }
        w(WRT, (vcaddr & !0xF) | CHAN);
        // Receive our channel's reply (bounded); ignore other channels.
        let mut got = false;
        let mut outer = 0u32;
        'recv: while outer < POLL_MAX {
            let mut s = 0;
            while r(STA0) & EMPTY != 0 {
                s += 1;
                if s >= POLL_MAX {
                    break 'recv;
                }
            }
            let msg = r(RD);
            if msg & 0xF == CHAN {
                got = true;
                break 'recv;
            }
            outer += 1;
        }
        if !got {
            continue;
        }
        ivac(phys, nwords * 4);
        if core::ptr::read_volatile(buf.add(1)) == RESP_OK {
            return true;
        }
    }
    false
}

/// SEC-2 / V3 — the EL2 mailbox PROXY, called from the `hvc #2` handler in boot.s. After
/// the stage-2 carve, EL1 can no longer touch the VC mailbox MMIO directly; it hands us its
/// property buffer's PHYS address (`pa`) + word count (`nwords`) and we run the transaction
/// on its behalf — but ONLY for a WHITELIST of tags (the clock/power/reboot ops the kernel
/// legitimately needs for WiFi + A/B tryboot). Any other tag — crucially GET_CUSTOMER_OTP
/// / GET_BOARD_SERIAL — is REFUSED, so a compromised EL1 kernel cannot re-read the OTP secret
/// to reconstruct the deterministic SRK/AK. A whitelist (not a blacklist) fails closed on any
/// unknown/future tag. Returns 0 on RESP_OK; nonzero on bad-PA / refused-tag / txn-failure
/// (the kernel maps nonzero -> None/false). `pa` must be EL1 RAM (above the EL2 hole, below
/// the VC 1 GB limit) — never MMIO or the HBoot region.
#[no_mangle]
pub extern "C" fn hboot_hvc_mbox(pa: u64, nwords: u64) -> u64 {
    let pa = pa as usize;
    let n = nwords as usize;
    // PA sanity: EL1 RAM only — above the EL2 hole (0x800000), below the VC 1 GB pointer
    // limit, word-aligned, sane length (<= our 48-word buffer convention). Fail closed.
    if pa < 0x0080_0000 || pa >= 0x4000_0000 || (pa & 0x3) != 0 || n == 0 || n > 48 {
        return 1;
    }
    // The property TAG is word 2 of the buffer ([size, req/resp, TAG, ...]). EL2's read here
    // is coherent with EL1's cached write (same core, PIPT normal memory).
    let tag = unsafe { core::ptr::read_volatile((pa + 8) as *const u32) };
    // WHITELIST — exactly the kernel's arch mailbox ops. Anything else (OTP/serial/…) refused.
    const ALLOWED: [u32; 6] = [
        0x0003_0002, // GET_CLOCK_RATE
        0x0003_8002, // SET_CLOCK_RATE
        0x0002_8001, // SET_POWER_STATE (WiFi/SDIO)
        0x0003_0064, // GET_REBOOT_FLAGS (tryboot)
        0x0003_8064, // SET_REBOOT_FLAGS (tryboot)
        0x0003_0048, // NOTIFY_REBOOT
    ];
    let mut ok_tag = false;
    let mut i = 0;
    while i < ALLOWED.len() {
        if ALLOWED[i] == tag {
            ok_tag = true;
        }
        i += 1;
    }
    if !ok_tag {
        return 2; // refused: not a whitelisted op (OTP read attempt, or anything unexpected)
    }
    if unsafe { transact_at(pa, n) } {
        0
    } else {
        3
    }
}

/// GET_BOARD_SERIAL (0x00010004) — the 64-bit device-unique serial (OTP row 31).
pub fn board_serial() -> Option<u64> {
    unsafe {
        let buf = core::ptr::addr_of_mut!(MBOX_BUF) as *mut u32;
        let req = [0x20u32, 0, 0x0001_0004, 8, 0, 0, 0, 0];
        for (i, &v) in req.iter().enumerate() {
            core::ptr::write_volatile(buf.add(i), v);
        }
        if !transact(8) {
            return None;
        }
        let lo = core::ptr::read_volatile(buf.add(5)) as u64;
        let hi = core::ptr::read_volatile(buf.add(6)) as u64;
        Some(lo | (hi << 32))
    }
}

/// GET_USER_OTP (0x00030024) block 1 = customer OTP (8 words / 256 bits).
/// None if unreadable; Some(words) otherwise (all-zero = blank/unprovisioned).
pub fn get_customer_otp() -> Option<[u32; 8]> {
    unsafe {
        let buf = core::ptr::addr_of_mut!(MBOX_BUF) as *mut u32;
        // total=17 words=0x44 B; value buffer=11 words=0x2C B; block=1, words=8.
        let req = [0x44u32, 0, 0x0003_0024, 0x2C, 0, 1, 0, 8];
        for (i, &v) in req.iter().enumerate() {
            core::ptr::write_volatile(buf.add(i), v);
        }
        for i in 8..17 {
            core::ptr::write_volatile(buf.add(i), 0);
        }
        if !transact(17) {
            return None;
        }
        let mut out = [0u32; 8];
        for (i, o) in out.iter_mut().enumerate() {
            *o = core::ptr::read_volatile(buf.add(8 + i));
        }
        Some(out)
    }
}

/// SET_USER_OTP (0x00038024) block 1 = customer OTP — BURN 8 words / 256 bits.
/// IRREVERSIBLE (one-way fuses). Constrained to the customer region by block=1;
/// it cannot touch the serial/bootloader/device-key rows. Returns true iff the
/// firmware reports a success response — the caller MUST additionally read back
/// (`get_customer_otp`) and derive from the ACTUAL contents, never from intent.
pub fn set_customer_otp(words: &[u32; 8]) -> bool {
    unsafe {
        let buf = core::ptr::addr_of_mut!(MBOX_BUF) as *mut u32;
        // buf: size, req, tag, valbufsize(44), reqresp, block=1, index=0, words=8, data0..7, end.
        let hdr = [0x44u32, 0, 0x0003_8024, 0x2C, 0, 1, 0, 8];
        for (i, &v) in hdr.iter().enumerate() {
            core::ptr::write_volatile(buf.add(i), v);
        }
        for (i, &w) in words.iter().enumerate() {
            core::ptr::write_volatile(buf.add(8 + i), w);
        }
        core::ptr::write_volatile(buf.add(16), 0); // end tag
        transact(17)
    }
}

/// SET_USER_OTP (0x00038024) block 3 = 16 words / 512 bits — BURN (IRREVERSIBLE).
/// INVARIANT: block 3 is HEQK's **anti-rollback thermometer counter**, NOT an
/// RPi device private key. HEQK does not use RPi secure boot, so this region is
/// repurposed; never store key material here (a key's ~256 set bits would read
/// as a huge rollback floor and brick boot). Used ONLY by the deliberate
/// `rollback::advance_floor`; never on the boot path. Returns true iff the
/// firmware acks success.
pub fn set_device_otp(words: &[u32; 16]) -> bool {
    unsafe {
        let buf = core::ptr::addr_of_mut!(MBOX_BUF) as *mut u32;
        // total=25 words=0x64 B; value buffer=19 words=0x4C B; block=3, words=16.
        let hdr = [0x64u32, 0, 0x0003_8024, 0x4C, 0, 3, 0, 16];
        for (i, &v) in hdr.iter().enumerate() {
            core::ptr::write_volatile(buf.add(i), v);
        }
        for (i, &w) in words.iter().enumerate() {
            core::ptr::write_volatile(buf.add(8 + i), w);
        }
        core::ptr::write_volatile(buf.add(24), 0); // end tag
        transact(25)
    }
}

/// GET_USER_OTP (0x00030024) block 3 = 16 words / 512 bits. In HEQK this region
/// is the **anti-rollback thermometer counter** (see `set_device_otp`), read by
/// `rollback::OtpCounter` as a popcount — NOT a device key. None if
/// unreadable/locked; all-zero = a blank (floor 0) region.
pub fn otp_device_key() -> Option<[u32; 16]> {
    unsafe {
        let buf = core::ptr::addr_of_mut!(MBOX_BUF) as *mut u32;
        let req = [0x64u32, 0, 0x0003_0024, 0x4C, 0, 3, 0, 16];
        for (i, &v) in req.iter().enumerate() {
            core::ptr::write_volatile(buf.add(i), v);
        }
        for i in 8..25 {
            core::ptr::write_volatile(buf.add(i), 0);
        }
        if !transact(25) {
            return None;
        }
        let mut out = [0u32; 16];
        for (i, o) in out.iter_mut().enumerate() {
            *o = core::ptr::read_volatile(buf.add(8 + i));
        }
        Some(out)
    }
}
