#![no_std]
#![no_main]
//! HBoot — the HEQK boot manager (Phase 1 of the HookProbe boot architecture).
//!
//! Scope, deliberately small: console (owned by the stub), HYBRID secure-boot
//! verification (measure with SHA-256, then require BOTH an ed25519 AND an
//! SLH-DSA / FIPS-205 signature — quantum-safe: breaking boot needs breaking
//! classical ECC AND post-quantum), relocation, typed BootInfo handoff, EL1
//! launch. HBoot stays resident at EL2 as the reboot/fault gate (`hvc #0`).
//! No shell, no menus, no policy.

use boot_abi::*;
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};
use ed25519_compact::{PublicKey as EdPublicKey, Signature as EdSignature};
use fips205::slh_dsa_sha2_128s;
use fips205::traits::{SerDes, Verifier};

mod ak_derive;
mod attest;
mod attest_keys;
mod mailbox;
mod measure;
mod mmu;
mod rng;
mod rollback;
mod stage2;
mod trusted_keys;
mod watchdog;

use boot_abi::sha256;
use rollback::SecureCounter;

extern "C" {
    static __hboot_load_end: u8;
}

core::arch::global_asm!(include_str!("boot.s"));

const UART: usize = 0x1C_0003_0000;
const IMAGE_BASE: usize = 0x20_0000;

pub(crate) fn putc(b: u8) {
    unsafe {
        let mut spins = 0u32;
        while read_volatile((UART + 0x18) as *const u32) & (1 << 5) != 0 {
            spins += 1;
            if spins > 100_000 {
                return;
            }
        }
        write_volatile(UART as *mut u8, b);
    }
}

pub(crate) fn puts(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            putc(b'\r');
        }
        putc(b);
    }
}

fn puthex(v: u64) {
    puts("0x");
    for i in (0..16).rev() {
        let n = ((v >> (i * 4)) & 0xf) as u8;
        putc(if n < 10 { b'0' + n } else { b'a' + n - 10 });
    }
}

fn puthash(h: &[u8; 32]) {
    for byte in h {
        for n in [byte >> 4, byte & 0xf] {
            putc(if n < 10 { b'0' + n } else { b'a' + n - 10 });
        }
    }
}

extern "C" {
    fn hboot_launch_el1(entry: u64, bootinfo: u64) -> !;
    fn park() -> !;
}

#[no_mangle]
pub extern "C" fn hboot_main(dtb_pa: u64) -> ! {
    // Enable the EL2 MMU + caches FIRST so all crypto below runs cached — the
    // attestation SLH-DSA sign is minutes uncached, seconds cached.
    mmu::enable_identity_el2();
    puts("\n+------------------------------------------+\n");
    puts("| HBoot v1 — HEQK boot manager (EL2)       |\n");
    puts("| hybrid secure boot: ed25519 + SLH-DSA    |\n");
    puts("+------------------------------------------+\n");
    puts(" dtb : ");
    puthex(dtb_pa);
    puts("\n");

    // MEASURED BOOT (B-7): ROOT the chain in the immutable OTP-fused device
    // identity BEFORE self-measuring HBoot. PCR0's first extend is the CRTM
    // anchor = SHA-256( "HEQK-CRTM-v1" || board_serial(OTP) || hboot_version );
    // the board serial lives in OTP (read via the VC mailbox — hardware, not the
    // image), so PCR0 is no longer a free-floating self-measurement. A tampered
    // HBoot cannot forge this hardware root, and the OTP-derived AK-signed quote
    // binds it to the device's fuses. Fail-safe: an unreachable mailbox yields
    // serial 0 (a stable, if non-unique, anchor) — the AK signature stays the
    // authenticity proof.
    let mut m = measure::Measurements::init();
    let crtm_serial = mailbox::board_serial().unwrap_or(0);
    let mut anchor = [0u8; 32];
    anchor[..12].copy_from_slice(b"HEQK-CRTM-v1");
    anchor[16..24].copy_from_slice(&crtm_serial.to_le_bytes());
    anchor[24..32].copy_from_slice(&1u64.to_le_bytes()); // hboot_version
    let anchor_d = sha256::digest(&anchor);
    m.extend(PCR_FIRMWARE, EV_CRTM, &anchor_d);
    puts(" measure: PCR0 CRTM-anchored to OTP device id=");
    puthex(crtm_serial);
    puts("\n");
    let hboot_end = unsafe { core::ptr::addr_of!(__hboot_load_end) as usize };
    let hboot_self = m.measure_region(PCR_FIRMWARE, EV_HBOOT_SELF, IMAGE_BASE, hboot_end - IMAGE_BASE);
    puts(" measure: PCR0 (hboot self) extended over CRTM anchor, sha256=");
    puthash(&hboot_self);
    puts("\n");

    // Locate and validate the payload header.
    let hdr = (IMAGE_BASE + HBOOT_PAYLOAD_OFFSET) as *const PayloadHeader;
    let (magic, size, load_pa, entry_off, svn) = unsafe {
        (
            read_volatile(core::ptr::addr_of!((*hdr).magic)),
            read_volatile(core::ptr::addr_of!((*hdr).size)),
            read_volatile(core::ptr::addr_of!((*hdr).load_pa)),
            read_volatile(core::ptr::addr_of!((*hdr).entry_offset)),
            read_volatile(core::ptr::addr_of!((*hdr).svn)),
        )
    };
    if magic != PAYLOAD_MAGIC {
        puts(" payload: BAD MAGIC ");
        puthex(magic);
        puts(" — refusing to boot\n");
        unsafe { park() }
    }
    // The payload lives in the combined image below IMAGE_BASE+HBOOT_PAYLOAD_OFFSET;
    // its body must fit within the ~2 MiB region the EEPROM actually loaded.
    if size == 0 || size > 0x20_0000 {
        puts(" payload: INSANE SIZE — refusing to boot\n");
        unsafe { park() }
    }
    // SECURE-BOOT: the header's load geometry (load_pa, entry_off) governs WHERE
    // the verified payload lands and WHERE EL1 execution jumps, but is NOT part
    // of the signed message. An attacker who can rewrite flash could leave the
    // signatures intact and redirect the copy over HBoot's own EL2 code/vectors/
    // page-tables, or jump to unsigned bytes. Pin both to the fixed values every
    // legitimate image uses — any deviation is refused. (Geometry is constant in
    // this design; binding it into signed_message_input is the generalization.)
    if load_pa != KERNEL_LOAD_PA as u64 {
        puts(" secure boot: FAIL — load_pa != fixed KERNEL_LOAD_PA, refusing\n");
        unsafe { park() }
    }
    if entry_off != 0 || entry_off >= size {
        puts(" secure boot: FAIL — bad entry_offset, refusing\n");
        unsafe { park() }
    }
    puts(" payload: ");
    puthex(size);
    puts(" bytes, load ");
    puthex(load_pa);
    puts("\n");
    let floor = rollback::effective_floor();
    puts(" svn    : image=");
    puthex(svn);
    puts(" floor=");
    puthex(floor);
    puts(" (");
    puts(rollback::backend().name());
    puts(")\n");
    if rollback::floor_read_failed() {
        // P7d-c fail-closed: the OTP counter was unreadable; the floor held the
        // provisioned watermark rather than collapsing to 0. Log it loudly.
        puts(" svn    : WARN — OTP floor unreadable; held fail-closed watermark (no rollback)\n");
    }

    // MEASURE: SHA-256 over the payload body. Verification binds to THIS
    // recomputed hash, never the header's stored copy — so a tampered payload
    // fails even if the attacker also rewrites the stored hash.
    let body = (IMAGE_BASE + HBOOT_PAYLOAD_OFFSET + core::mem::size_of::<PayloadHeader>()) as *const u8;
    let computed = sha256::digest(unsafe { core::slice::from_raw_parts(body, size as usize) });
    puts(" measure: sha256=");
    puthash(&computed);
    puts("\n");

    // SEC-8/V7b: software stack guard. HBoot's stack grows DOWN from __stack_top
    // (0x800000) toward the payload image with the **MMU OFF**, so a HW guard page is
    // impossible, and the SLH-DSA/ed25519 verify below is stack-hungry. Lay a canary
    // band in the free RAM just above the payload; if the stack overruns down into it
    // during verify/sign, the payload we measured has been corrupted. Checked right
    // before the EL1 handoff (GUARD_MAGIC ^ index, so a memset can't fake it).
    const GUARD_WORDS: usize = 512; // 4 KiB band
    const GUARD_MAGIC: u64 = 0x5354_4B47_5244_0001; // "STKGRD\0\1"
    let guard = (((body as usize) + size as usize + 0xFFF) & !0xFFF) as *mut u64;
    unsafe {
        for k in 0..GUARD_WORDS {
            core::ptr::write_volatile(guard.add(k), GUARD_MAGIC ^ k as u64);
        }
    }

    // The signed message binds the SVN: SHA-256( LE64(svn) || sha256(payload) ).
    // Because svn is inside what's signed, an attacker cannot bump the version
    // on an old payload to clear the floor — that breaks both signatures.
    let signed = sha256::digest(&signed_message_input(svn, &computed));

    // HYBRID VERIFY: both signatures over `signed`, with the trusted public
    // keys embedded in HBoot (never taken from the image).
    let ed_sig_bytes: [u8; ED25519_SIG_LEN] =
        unsafe { read_volatile(core::ptr::addr_of!((*hdr).ed25519_sig)) };
    let pq_sig_bytes: [u8; SLHDSA_SIG_LEN] =
        unsafe { read_volatile(core::ptr::addr_of!((*hdr).slhdsa_sig)) };

    // Classical: ed25519.
    let ed_ok = (|| {
        let pk = EdPublicKey::from_slice(&trusted_keys::ED25519_PUBKEY).ok()?;
        let sig = EdSignature::from_slice(&ed_sig_bytes).ok()?;
        pk.verify(signed, &sig).ok()
    })()
    .is_some();
    puts(if ed_ok { " verify : ed25519  OK\n" } else { " verify : ed25519  FAIL\n" });

    // Post-quantum: SLH-DSA-SHA2-128s (FIPS 205) — hash-based, quantum-safe.
    let pq_ok = match slh_dsa_sha2_128s::PublicKey::try_from_bytes(&trusted_keys::SLHDSA_PUBKEY) {
        Ok(pk) => pk.verify(&signed, &pq_sig_bytes, SIG_CTX),
        Err(_) => false,
    };
    puts(if pq_ok { " verify : SLH-DSA OK (quantum-safe)\n" } else { " verify : SLH-DSA FAIL\n" });

    // BOTH signatures required. Either failing = refuse to boot.
    if !ed_ok || !pq_ok {
        puts(" secure boot: FAIL — hybrid signature invalid, refusing to boot\n");
        unsafe { park() }
    }

    // ANTI-ROLLBACK: refuse a validly-signed but downlevel image. The floor is
    // embedded in HBoot (root of trust). Because svn is bound into the signed
    // message, this comparison cannot be bypassed by editing the header.
    if svn < floor {
        puts(" secure boot: FAIL — image svn below anti-rollback floor, refusing\n");
        unsafe { park() }
    }
    puts(" secure boot: PASS (ed25519 AND SLH-DSA, svn OK)\n");

    // MEASURE the launched software into the attestation chain:
    //   PCR1 = the kernel payload (its measured identity — reuse `computed`)
    //   PCR2 = the boot configuration (svn, floor, load addr, verify result)
    m.extend(PCR_KERNEL, EV_KERNEL, &computed);
    let mut cfg = [0u8; 40];
    cfg[..8].copy_from_slice(&svn.to_le_bytes());
    cfg[8..16].copy_from_slice(&floor.to_le_bytes());
    cfg[16..24].copy_from_slice(&load_pa.to_le_bytes());
    cfg[24..32].copy_from_slice(&(entry_off).to_le_bytes());
    cfg[32..40].copy_from_slice(&(VERIFY_ED25519 | VERIFY_SLHDSA).to_le_bytes());
    let cfg_hash = sha256::digest(&cfg);
    m.extend(PCR_CONFIG, EV_CONFIG, &cfg_hash);
    m.extend(PCR_CONFIG, EV_VERIFY, &computed); // bind verified-identity into config PCR
    puts(" measure: PCR1 (kernel) + PCR2 (config) extended, ");
    puthex(m.count());
    puts(" events logged\n");

    // B-1 (extractability): provision (once) + derive the per-device AK bound to
    // the OTP secret — non-extractable from the image. Burns customer OTP on the
    // first boot only; idempotent thereafter; falls back to the software AK if
    // the mailbox/burn does not deliver a secret. MUST run before any AK signing.
    let mut ak = ak_derive::provision_and_derive();

    // B-1 (identity): this device's unique serial (fail-safe: 0 if unreachable).
    let device_id = mailbox::board_serial().unwrap_or(0);
    let otp_provisioned = u64::from(ak.hw_bound);
    puts(" attest : device_id (board serial)=");
    puthex(device_id);
    puts(if ak.hw_bound {
        " AK=hardware-bound (per-device, OTP-derived)\n"
    } else {
        " AK=software (OTP unprovisioned/unreachable)\n"
    });

    // REMOTE ATTESTATION: sign nonce||svn||PCRs with the (per-device) AK (hybrid,
    // quantum-safe) so an off-device verifier can attest the exact boot state.
    let pcrs = [m.pcr(0), m.pcr(1), m.pcr(2), m.pcr(3)];
    let _ak_ed = attest::emit_quote(svn, &pcrs, &ak);
    puts(" attest : AK-signed quote (ed25519 + SLH-DSA) @ ");
    puthex(ATTEST_QUOTE_ADDR as u64);
    puts("\n");

    // B-2: mint a per-boot ephemeral key, AK-certify it (hybrid) binding this
    // device_id, publish it + the per-device AK pubkeys for the kernel's runtime
    // challenge service, then SCRUB all AK private material from RAM (neither the
    // derived nor the software AK persists post-boot; the kernel holds only the
    // ephemeral key).
    attest::emit_ephemeral_cert(svn, device_id, otp_provisioned, &pcrs, &ak);
    ak.zeroize();
    attest_keys::scrub();

    // Relocate the payload to its link address.
    unsafe {
        core::ptr::copy_nonoverlapping(body, load_pa as *mut u8, size as usize);
    }

    // SEC-4/V7a: close the measure->launch TOCTOU. The hash (`computed`, line 186)
    // and the signature were taken over the payload AT ITS SOURCE; we then copied it
    // to `load_pa` and are about to ENTER EL1 there. Verification and execution are
    // of DIFFERENT memory — any corruption or transient write to the destination
    // between hash and jump would execute unverified code that still reports the good
    // hash. Re-hash the payload AT ITS DESTINATION and refuse to launch on a mismatch.
    let recheck = sha256::digest(unsafe { core::slice::from_raw_parts(load_pa as *const u8, size as usize) });
    if recheck != computed {
        // AUDIT R4 (defense in depth): scrub the derived SRK off HBoot's stack before we
        // halt, so a live master seal key does not linger in RAM on a refused boot.
        for b in ak.srk.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
        unsafe { core::arch::asm!("dsb sy") };
        puts(" secure boot: FAIL — payload hash mismatch after relocation (SEC-4), refusing to boot\n");
        unsafe { park() }
    }

    // A/B TRIAL-BOOT WATCHDOG (reliability keystone): arm the PM watchdog before
    // handing off to EL1. A healthy kernel confirms via `hvc #1` (the EL2 gate
    // disarms it) once its detection plane is up; a kernel that hangs or panics
    // before confirming trips the watchdog -> full SoC reset -> the firmware's
    // consumed one-shot `tryboot` flag boots the KNOWN-GOOD slot (config.txt).
    // Automatic A/B fallback with no mutable persistent store in HBoot.
    const TRIAL_WDOG_SECS: u32 = 15;
    let wdog_secs = watchdog::arm(TRIAL_WDOG_SECS);
    puts(" a/b    : trial watchdog armed ");
    puthex(wdog_secs as u64);
    puts("s — kernel must hvc#1-confirm or fall back to the known-good slot\n");

    // BootInfo — the typed handoff (the kernel never parses the DTB).
    let bi = BOOTINFO_ADDR as *mut BootInfo;
    unsafe {
        write_volatile(
            bi,
            BootInfo {
                magic: BOOTINFO_MAGIC,
                version: 6,
                dtb_pa,
                kernel_pa: load_pa,
                kernel_size: size,
                kernel_hash: computed,
                hboot_version: 1,
                el2_gate: 1,
                verify_flags: VERIFY_ED25519 | VERIFY_SLHDSA,
                svn,
                svn_floor: floor,
                measure_log_pa: MEASURE_LOG_ADDR as u64,
                measure_count: m.count(),
                quote_pa: ATTEST_QUOTE_ADDR as u64,
                eph_pa: ATTEST_EPH_ADDR as u64,
                boot_flags: BOOT_FLAG_TRIAL_WDOG,
                watchdog_secs: wdog_secs as u64,
            },
        );
    }

    // PH2a: hand the sealing root key to the kernel via the SealHandoff page. HBoot
    // derived the SRK from the OTP secret (SRK = SHA256("HEQK-SEAL-SRK-v1" || OTP)); the
    // kernel derives every per-policy key from it and NEVER sees the OTP secret. bit1
    // (FROM_OTP) marks the SRK real + per-device; bit0 (HW_DERIVED = tamper-proof) is set
    // only once V3/SEC-2 closes (EL1 can no longer read OTP) — PH2b.
    unsafe {
        write_volatile(
            SEAL_HANDOFF_ADDR as *mut SealHandoff,
            SealHandoff {
                magic: if ak.hw_bound { SEAL_HANDOFF_MAGIC } else { 0 },
                srk: ak.srk,
                device_id,
                svn_floor: floor,
                pcr: pcrs,
                flags: if ak.hw_bound { SEAL_FLAG_SRK_FROM_OTP } else { 0 },
            },
        );
    }
    // Scrub HBoot's copy of the SRK now it is handed off (defense in depth).
    for b in ak.srk.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    puts(if ak.hw_bound {
        " seal   : SRK handed to kernel (per-device, OTP-derived); V3/SEC-2 open -> not yet tamper-proof\n"
    } else {
        " seal   : no OTP secret -> no SRK handoff (kernel keeps its synthetic seal key)\n"
    });

    // Cache coherency: flush the relocated kernel and the handoff structures
    // (SealHandoff/eph-cert/quote/measure-log/BootInfo, contiguous below 0x40000000)
    // from HBoot's D-cache to DRAM, so the kernel sees them when it reads non-cacheably
    // at EL1 before enabling its own MMU. (I-cache is invalidated in the launch.)
    mmu::clean_dcache_range(load_pa as usize, size as usize);
    // Start at SEAL_HANDOFF_ADDR (0x3FFA_0000) — one page below ATTEST_EPH_ADDR — so the
    // seal handoff is flushed too: 0x3FFA_0000..0x4000_0000.
    mmu::clean_dcache_range(SEAL_HANDOFF_ADDR, 0x0006_0000);

    // P7e: install stage-2 isolation (EL1 walled off from HBoot's EL2 region).
    // Programs VTCR/VTTBR; HCR_EL2.VM is flipped in hboot_launch_el1 before eret.
    stage2::enable();
    puts(" stage2 : EL1<->EL2 isolation armed (HBoot region 0x200000..0x800000 hidden)\n");

    // SEC-8/V7b: verify the stack never overran into the payload guard band during
    // the stack-hungry verify/sign. A mismatch means HBoot's stack corrupted the
    // measured payload — refuse to launch rather than hand off corrupt-but-attested
    // code.
    let guard_ok = unsafe {
        (0..GUARD_WORDS).all(|k| core::ptr::read_volatile(guard.add(k)) == GUARD_MAGIC ^ k as u64)
    };
    if !guard_ok {
        puts(" secure boot: FAIL — HBoot stack overran the payload guard (SEC-8), refusing to boot\n");
        unsafe { park() }
    }

    puts(" launch : EL1 entry ");
    puthex(load_pa + entry_off);
    puts("\n\n");
    unsafe { hboot_launch_el1(load_pa + entry_off, BOOTINFO_ADDR as u64) }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    puts("\nHBoot PANIC\n");
    unsafe { park() }
}
