// SPDX-License-Identifier: AGPL-3.0-only
//! ADR 0067 D11 / build-plan item L0.1 — the Wi-Fi chip's vendor files are NOT part of the kernel.
//!
//! The CYW43455 firmware, its regulatory (CLM) blob and the board NVRAM text are third-party files
//! under their owners' terms. With the `fwfiles` feature they are read from the boot partition at
//! run time instead of being linked into the image.
//!
//! Trust: an embedded file was covered by the image signature; a file on the boot partition is not.
//! So the signed kernel pins the SHA-256 of each file (a digest is a fact about the file, not the
//! file) and a file that does not match exactly is refused. A device with a missing, truncated,
//! oversized or altered file boots normally with Wi-Fi reported unavailable; it never panics and
//! never downloads an unpinned firmware to the chip.
//!
//! The pins are the files staged by `tools/ci/stage-firmware.sh` (same firmware digest as its
//! `BIN_SHA256`). Changing the firmware means changing these pins in a reviewed commit.

// Without the feature only `verify_one` and the self-test are used: the FAT read path and the names
// have no caller. They are compiled anyway so that every build type-checks the loader.
#![cfg_attr(not(feature = "fwfiles"), allow(dead_code))]

use hal::BlockDev;

/// 8.3 names on the boot partition.
pub const FW_NAME: &[u8; 11] = b"CYW43455BIN";
pub const NVRAM_NAME: &[u8; 11] = b"CYW43455NVR";
pub const CLM_NAME: &[u8; 11] = b"CYW43455CLM";

/// One pinned file: its exact length and SHA-256.
#[derive(Clone, Copy)]
pub struct Pin {
    pub len: usize,
    pub sha256: [u8; 32],
}

const fn hex32(s: &[u8; 64]) -> [u8; 32] {
    const fn nib(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            _ => c - b'a' + 10,
        }
    }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nib(s[2 * i]) << 4 | nib(s[2 * i + 1]);
        i += 1;
    }
    out
}

/// cyw43455-sdio.bin (== `BIN_SHA256` in tools/ci/stage-firmware.sh).
pub const FW_PIN: Pin = Pin { len: 609_309, sha256: hex32(b"d608f866582519c0a28d86db43040f4f1b98dd1d153e72e9752586546b4a36c3") };
/// cyw43455-sdio-cm5.nvram.txt
pub const NVRAM_PIN: Pin = Pin { len: 2_378, sha256: hex32(b"8048875ea93faedaa5096757fffe733d4824387392715f6c8e710fe7129d7521") };
/// cyw43455-sdio.clm_blob
pub const CLM_PIN: Pin = Pin { len: 2_676, sha256: hex32(b"9823842cae9fb9a5dd1e5fb31f595516ec7deee341354bef30bb3026eee29cc1") };

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FwErr {
    /// No boot partition / not FAT32.
    NoVolume,
    /// The file is not on the boot partition (or is empty).
    Missing(u8),
    /// The file's length is not the pinned length (truncated or oversized).
    Size(u8),
    /// A sector could not be read.
    Read(u8),
    /// Right length, wrong content.
    Digest(u8),
}

/// Which file an error names: 0 firmware, 1 NVRAM, 2 CLM.
pub const F_FW: u8 = 0;
pub const F_NVRAM: u8 = 1;
pub const F_CLM: u8 = 2;

/// Check one file against its pin. Length first (cheap, and it names truncation precisely).
pub fn verify_one(which: u8, data: &[u8], pin: &Pin) -> Result<(), FwErr> {
    if data.is_empty() {
        return Err(FwErr::Missing(which));
    }
    if data.len() != pin.len {
        return Err(FwErr::Size(which));
    }
    if boot_abi::sha256::digest(data) != pin.sha256 {
        return Err(FwErr::Digest(which));
    }
    Ok(())
}

/// Check the three files against the pins of this build.
pub fn verify(fw: &[u8], nvram: &[u8], clm: &[u8]) -> Result<(), FwErr> {
    verify_one(F_FW, fw, &FW_PIN)?;
    verify_one(F_NVRAM, nvram, &NVRAM_PIN)?;
    verify_one(F_CLM, clm, &CLM_PIN)
}

/// Read one whole file from the FAT32 boot partition into `buf`. Returns its length in bytes.
/// The file's size comes from its directory entry; a file larger than `buf` is a size error, not a
/// silent truncation.
pub fn read_file<D: BlockDev>(dev: &D, fs: &crate::fat::Fat32, which: u8, name: &[u8; 11], buf: &mut [u8]) -> Result<usize, FwErr> {
    let file = crate::fat::find_file(dev, fs, name).ok_or(FwErr::Missing(which))?;
    let size = file.size_bytes as usize;
    if size == 0 {
        return Err(FwErr::Missing(which));
    }
    if size > buf.len() {
        return Err(FwErr::Size(which));
    }
    let mut done = 0usize;
    let mut sec = [0u8; 512];
    for &(lba, count) in file.runs[..file.n].iter() {
        for k in 0..count {
            if done >= size {
                break;
            }
            dev.read_block(lba + k, &mut sec).map_err(|_| FwErr::Read(which))?;
            let n = (size - done).min(512);
            buf[done..done + n].copy_from_slice(&sec[..n]);
            done += n;
        }
    }
    if done != size {
        return Err(FwErr::Size(which)); // the cluster chain is shorter than the directory entry says
    }
    Ok(size)
}

/// The run-time copies (BSS: nothing of the vendor files is in the image).
#[cfg(feature = "fwfiles")]
mod bufs {
    pub static mut FW: [u8; 640 * 1024] = [0; 640 * 1024];
    pub static mut NVRAM: [u8; 4096] = [0; 4096];
    pub static mut CLM: [u8; 4096] = [0; 4096];
}

/// Boot: read the three files from the boot partition, verify them against the pins and hand them
/// to the Wi-Fi driver. On any error nothing is installed and Wi-Fi stays unavailable.
/// Call once, before the first Wi-Fi bring-up.
#[cfg(feature = "fwfiles")]
pub fn load<D: BlockDev>(dev: &D) -> Result<(), FwErr> {
    let mut sec = [0u8; 512];
    let p1 = if dev.read_block(0, &mut sec).is_ok() { crate::store::parse_mbr(&sec)[0].start } else { 0 };
    if p1 == 0 {
        return Err(FwErr::NoVolume);
    }
    let fs = crate::fat::parse(dev, p1).ok_or(FwErr::NoVolume)?;
    let (fw, nvram, clm) = unsafe { (&mut *core::ptr::addr_of_mut!(bufs::FW), &mut *core::ptr::addr_of_mut!(bufs::NVRAM), &mut *core::ptr::addr_of_mut!(bufs::CLM)) };
    let nf = read_file(dev, &fs, F_FW, FW_NAME, fw)?;
    let nn = read_file(dev, &fs, F_NVRAM, NVRAM_NAME, nvram)?;
    let nc = read_file(dev, &fs, F_CLM, CLM_NAME, clm)?;
    verify(&fw[..nf], &nvram[..nn], &clm[..nc])?;
    arch_aarch64::cyw43::install_firmware(&fw[..nf], &nvram[..nn], &clm[..nc]);
    Ok(())
}

/// `[P-fwfiles]` — the verification every file goes through, on synthetic files with their own pins
/// (the real vendor files are not in the repository): present, absent, truncated, oversized, one
/// byte changed; and the pins of this build are well-formed.
pub fn selftest() -> bool {
    static mut T: [u8; 4096] = [0; 4096];
    let t = unsafe { &mut *core::ptr::addr_of_mut!(T) };
    for (i, b) in t.iter_mut().enumerate() {
        *b = (i * 31 + 7) as u8;
    }
    let pin = Pin { len: 3000, sha256: boot_abi::sha256::digest(&t[..3000]) };
    let present = verify_one(F_FW, &t[..3000], &pin) == Ok(());
    let absent = verify_one(F_FW, &[], &pin) == Err(FwErr::Missing(F_FW));
    let truncated = verify_one(F_NVRAM, &t[..2999], &pin) == Err(FwErr::Size(F_NVRAM));
    let oversized = verify_one(F_CLM, &t[..3001], &pin) == Err(FwErr::Size(F_CLM));
    t[1500] ^= 0x01;
    let altered = verify_one(F_FW, &t[..3000], &pin) == Err(FwErr::Digest(F_FW));
    t[1500] ^= 0x01;
    // the three files are checked in order and the first failure is the one reported
    let order = verify(&[], &[], &[]) == Err(FwErr::Missing(F_FW));
    // the pins: the decoder is right (a known vector), and each pin is distinct and non-zero
    let hex_ok = hex32(b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        .iter()
        .enumerate()
        .all(|(i, &b)| b as usize == i);
    let pins_ok = FW_PIN.sha256 != [0; 32] && FW_PIN.sha256 != NVRAM_PIN.sha256 && NVRAM_PIN.sha256 != CLM_PIN.sha256 && FW_PIN.len > NVRAM_PIN.len;
    let pass = present && absent && truncated && oversized && altered && order && hex_ok && pins_ok;
    arch_aarch64::_print(format_args!(
        " [P-fwfiles] {} — ADR 0067 L0.1: the Wi-Fi vendor files are read from the boot partition and checked against SHA-256 pins carried in the signed kernel (on synthetic files): the pinned file is accepted={} an absent file is refused={} a truncated one={} an oversized one={} one changed byte={} the first failing file is the one reported={} pin decoding and the three pins are well-formed={} | the FAT read and the hand-over to the driver are metal (batch B1)\n",
        if pass { "PASS" } else { "FAIL" }, present, absent, truncated, oversized, altered, order, hex_ok && pins_ok
    ));
    pass
}
