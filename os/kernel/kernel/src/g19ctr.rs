// SPDX-License-Identifier: AGPL-3.0-only
//! ADR 0069: the G19 msg1 counter. Each new handshake (a fresh msg1) carries `fp ‖ ctr` (ctr = LE u64,
//! strictly increasing per device) inside the encrypted, authenticated msg1 payload. The super-PoP refuses a msg1
//! whose counter is not above the highest it accepted for the device, so a recorded msg1 cannot tear down the
//! device's live session — not even after a PoP restart.
//!
//! The counter lives in the DataVolume `G19Ctr` region: two sectors written alternately (slot = ctr % 2), each
//! `HQG19C1\0 | ctr LE64 | sha256(the 16 bytes before)`. The newest valid record wins, so a torn write leaves the
//! previous value. `next()` persists ctr + 1 and reads it back BEFORE the msg1 is built; a counter that is not
//! durable is never sent (a reused counter would only be refused by the PoP, but the rule keeps the two sides
//! simple). Retransmits of the same msg1 reuse the pre-built datagrams, so they carry the same counter.

use hal::BlockDev;

const MAGIC: &[u8; 8] = b"HQG19C1\0";

fn encode(ctr: u64) -> [u8; 512] {
    let mut s = [0u8; 512];
    s[..8].copy_from_slice(MAGIC);
    s[8..16].copy_from_slice(&ctr.to_le_bytes());
    let h = boot_abi::sha256::digest(&s[..16]);
    s[16..48].copy_from_slice(&h);
    s
}

fn decode(s: &[u8; 512]) -> Option<u64> {
    (&s[..8] == MAGIC && boot_abi::sha256::digest(&s[..16])[..] == s[16..48]).then(|| u64::from_le_bytes(s[8..16].try_into().unwrap()))
}

/// The highest valid counter in the two sectors at `lo` (0 = never written / both torn).
pub fn load<D: BlockDev + ?Sized>(d: &D, lo: u64) -> Result<u64, ()> {
    let mut best = 0u64;
    let mut read_any = false;
    for i in 0..2 {
        let mut s = [0u8; 512];
        if d.read_block(lo + i, &mut s).is_ok() {
            read_any = true;
            if let Some(c) = decode(&s) {
                best = best.max(c);
            }
        }
    }
    if read_any { Ok(best) } else { Err(()) }
}

/// Persist the next counter (current + 1) into the older sector and read it back. None = not durable: send nothing.
pub fn advance<D: BlockDev + ?Sized>(d: &mut D, lo: u64) -> Option<u64> {
    let cur = load(d, lo).ok()?;
    let next = cur.checked_add(1)?;
    let slot = next % 2;
    let s = encode(next);
    d.write_block(lo + slot, &s).ok()?;
    let mut r = [0u8; 512];
    d.read_block(lo + slot, &mut r).ok()?;
    (r == s).then_some(next)
}

/// An eMMC handle whose only writable sectors are the two counter sectors (its own Gate-2 window).
#[cfg(all(feature = "cm5", feature = "p15-write"))]
fn dev() -> Option<(arch_aarch64::emmc::Emmc, u64)> {
    let mut dev = arch_aarch64::emmc::Emmc::probe().ok()?;
    let mut mbr = [0u8; 512];
    dev.read_block(0, &mut mbr).ok()?;
    let dv = crate::datavol::DataVol::from_mbr(&mbr)?;
    let (lo, hi) = dv.region(crate::datavol::Region::G19Ctr);
    let (blo, bhi) = dv.bounds();
    dev.set_data_volume(blo, bhi);
    if dev.arm_write_window(lo, hi) != (lo, hi) {
        return None;
    }
    Some((dev, lo))
}

/// The counter source for the G19 control plane on metal: the next durable counter, or None (no DataVolume, write
/// or read-back failure) — then no msg1 is sent and the control plane retries with its backoff.
#[cfg(all(feature = "cm5", feature = "p15-write"))]
pub fn next() -> Option<u64> {
    let (mut d, lo) = dev()?;
    let c = advance(&mut d, lo);
    match c {
        Some(c) => arch_aarch64::_print(format_args!(" [G19] msg1 counter {} (sealed before send, ADR 0069)\n", c)),
        None => arch_aarch64::_print(format_args!(" [G19] msg1 counter NOT persisted (DataVolume write / read-back failed): no handshake this attempt\n")),
    }
    c
}

/// `[P-g19ctr]`: the record layer on an in-memory disk — fresh = 0, strictly increasing across calls, alternating
/// sectors, a torn (corrupted) newest sector falls back to the previous value and the next counter still exceeds
/// everything ever sent before the tear only if that value was durable, a refused write yields None.
pub fn selftest() -> bool {
    struct Mem {
        s: [[u8; 512]; 2],
        fail: bool,
    }
    impl BlockDev for Mem {
        fn block_count(&self) -> u64 {
            2
        }
        fn read_block(&self, lba: u64, buf: &mut [u8; 512]) -> Result<(), hal::BlockErr> {
            *buf = *self.s.get(lba as usize).ok_or(hal::BlockErr::OutOfRange)?;
            Ok(())
        }
        fn write_block(&mut self, lba: u64, buf: &[u8; 512]) -> Result<(), hal::BlockErr> {
            if self.fail {
                return Err(hal::BlockErr::Io);
            }
            *self.s.get_mut(lba as usize).ok_or(hal::BlockErr::OutOfRange)? = *buf;
            Ok(())
        }
    }
    let mut m = Mem { s: [[0u8; 512]; 2], fail: false };
    let fresh = load(&m, 0) == Ok(0);
    let a = advance(&mut m, 0);
    let b = advance(&mut m, 0);
    let c = advance(&mut m, 0);
    let increasing = a == Some(1) && b == Some(2) && c == Some(3) && load(&m, 0) == Ok(3);
    // 3 is in slot 1, 2 in slot 0
    let alternating = decode(&m.s[1]) == Some(3) && decode(&m.s[0]) == Some(2);
    // a torn newest record: the older one stands, and the next counter is still above it
    m.s[1][20] ^= 0xFF;
    let torn = load(&m, 0) == Ok(2) && advance(&mut m, 0) == Some(3);
    m.fail = true;
    let refused = advance(&mut m, 0).is_none() && load(&m, 0) == Ok(3);
    let pass = fresh && increasing && alternating && torn && refused;
    arch_aarch64::_print(format_args!(
        " [P-g19ctr] {} — ADR 0069 msg1 counter record: fresh=0 {} strictly increasing {} alternating sectors {} torn newest falls back {} refused write sends nothing {}\n",
        if pass { "PASS" } else { "FAIL" }, fresh, increasing, alternating, torn, refused
    ));
    pass
}
