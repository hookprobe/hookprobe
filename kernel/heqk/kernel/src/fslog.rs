//! M3.2 — a minimal crash-safe, log-structured record store over a `DataVolume`
//! region. This is what lets the evidence graph + QSecBit history PERSIST (today
//! they only reach the serial/SIEM ring + RAM). NOT a POSIX filesystem — a
//! purpose-built ring of self-validating fixed-size records, which is the right
//! shape for append-mostly security telemetry on a block device.
//!
//! ## On-disk layout (all sectors go through the M3.1 multi-region write-guard)
//! ```text
//!   region:  [ lo | slot 0 | slot 1 | ... | slot nslots-1 )   (each = 1 sector)
//!            ^superblock                                  ^hi (exclusive)
//! ```
//!  * **Superblock** (sector `lo`): `HQKFSLOG` magic, version, `nslots`, digest.
//!  * **Slots** (`lo+1 .. hi`): one 512-B RECORD each. Record `seq` maps to slot
//!    `seq % nslots`, so the log is a RING — appending past capacity overwrites
//!    the oldest slot (bounded, honest retention).
//!
//! ## Record (512 B, sector-atomic)
//! ```text
//!   0   magic u32 (REC_MAGIC)     16  len u16       24  digest[8]  (SHA-256[..8])
//!   8   seq u64                   18  rtype u16     32  payload (<= 480 B)
//!                                 20  reserved u32
//! ```
//! The digest covers header bytes `0..24` (digest slot excluded) + `payload[..len]`,
//! so ANY torn payload/header fails validation. A fresh (zeroed) slot has magic 0
//! and is simply "empty".
//!
//! ## Crash recovery (the load-bearing property)
//! Every record is SELF-VALIDATING by digest, so recovery needs no separate write
//! cursor to get torn: on `mount`, scan all slots, keep the valid ones, and set
//! the next seq = (max valid seq)+1. A power-loss torn write leaves exactly one
//! invalid slot at the write frontier — it fails its digest and is DROPPED; every
//! intact prior record survives, and the store is immediately writable again
//! (the next append reuses the torn slot). Integrity here is a keyless DIGEST
//! (CRC-grade); per-record/volume ENCRYPTION is M3.3 (seal.rs), not this phase.

use crate::seal; // M3.3 — HQKSEAL1 Encrypt-then-MAC for record confidentiality
use crate::store::{SealedStore, StoreErr};
#[cfg(feature = "p15-write")]
use crate::store::RegionKind; // only the guarded write path names the region kind
use boot_abi::sha256::Hasher;
use hal::BlockDev;

pub const SEC: usize = 512;
pub const REC_MAGIC: u32 = 0x4652_4543; // b"CERF" LE — a live record slot
pub const SB_MAGIC: &[u8; 8] = b"HQKFSLOG";
pub const SB_VERSION: u32 = 1;
pub const REC_HDR: usize = 32;
pub const MAX_PAYLOAD: usize = SEC - REC_HDR; // 480

// --- M3.3: sealed data-volume (encryption at rest) ---------------------------
//
// The record PAYLOAD is sealed with `seal.rs` HQKSEAL1 (Encrypt-then-MAC) before
// it lands in the slot, so a raw block read of the DataVolume yields ciphertext,
// not the evidence Event / QSecBit fields. The framing (magic/seq/len/rtype/
// digest) stays cleartext so the key-free ring scan + torn-tail recovery
// (`mount`) still work with no key. Two integrity layers, distinct jobs:
//   * the keyless framing digest — cheap, key-free TORN-write detection at mount
//     (an attacker CAN forge it; it is not an authenticity claim);
//   * the seal's HMAC tag over the ciphertext — the real, keyed TAMPER check.
//     `mount_sealed` verifies it and DROPS any record that fails (fail-closed,
//     never revealing plaintext), so a forged-digest ciphertext edit is caught.
//
// The Volume Encryption Key (VEK) plays the role of seal.rs's SRK for per-record
// sealing; it is itself SEALED (under the boot-measurement SRK + policy) into the
// keystore, so it never lands cleartext on the DataVolume and a wrong measurement
// cannot even load it.

/// Largest plaintext a sealed record holds: the 480-B slot payload minus the
/// 128-B HQKSEAL1 header = 352 B (the seal's own ciphertext == plaintext length).
pub const MAX_SEALED_PAYLOAD: usize = MAX_PAYLOAD - seal::SEAL_HDR_LEN; // 352

/// Keystore LBA holding the SEALED Volume Encryption Key blob. Distinct from the
/// P15-persist cookie at `RESERVED_LBA_LO` (2016); both live inside the always-
/// registered `Keystore` region [2016, 2048), so the guarded write is admitted.
pub const VEK_LBA: u64 = 2024;

/// The per-volume sealing context threaded through the sealed read/write paths.
/// `vek` is the 32-B Volume Encryption Key (used AS the seal SRK per record);
/// `policy` binds each record to the device measurement — defence in depth, since
/// the VEK is already sealed under the same policy in the keystore.
pub struct SealCtx<'a> {
    pub vek: &'a [u8; 32],
    pub policy: &'a seal::Policy,
}

// Record-type tags (evidence graph + QSecBit history + a test record).
pub const RT_EVIDENCE: u16 = 1;
pub const RT_QSECBIT: u16 = 2;
pub const RT_TEST: u16 = 0x00FF;

// Record header field offsets.
const R_MAGIC: usize = 0;
const R_SEQ: usize = 8;
const R_LEN: usize = 16;
const R_TYPE: usize = 18;
const R_DIGEST: usize = 24; // 8 bytes
const R_DIGEST_END: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsErr {
    /// The region holds no valid superblock (mount before format).
    NotFormatted,
    /// The region is too small for a superblock + at least one slot.
    RegionTooSmall,
    /// Payload longer than MAX_PAYLOAD.
    TooBig,
    /// A computed slot LBA fell outside the log region (should be impossible).
    OutsideRegion,
    /// A block read/write failed, or the guard refused the write.
    Io,
    /// Read-back after a write did not match.
    VerifyFailed,
}

impl From<StoreErr> for FsErr {
    fn from(e: StoreErr) -> Self {
        match e {
            StoreErr::VerifyFailed => FsErr::VerifyFailed, // read-back mismatch
            StoreErr::WindowEscape => FsErr::OutsideRegion, // guard refused the LBA
            _ => FsErr::Io,
        }
    }
}

#[inline]
fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
#[inline]
fn get_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
#[inline]
fn get_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
#[inline]
fn get_u64(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(a)
}

/// Keyless 8-byte record digest: SHA-256 over header[0..24] (digest slot omitted)
/// + payload[..len]. Integrity only (M3.3 adds the keyed seal); enough to detect
/// any torn/partial write.
fn record_digest(sec: &[u8; SEC], len: usize) -> [u8; 8] {
    let mut h = Hasher::new();
    h.update(&sec[0..R_DIGEST]); // magic, seq, len, rtype, reserved
    h.update(&sec[REC_HDR..REC_HDR + len]);
    let d = h.finish();
    let mut out = [0u8; 8];
    out.copy_from_slice(&d[..8]);
    out
}

/// Is `sec` a valid, non-torn record? Returns its `(seq, rtype, len)` if so.
fn parse_record(sec: &[u8; SEC]) -> Option<(u64, u16, usize)> {
    if get_u32(sec, R_MAGIC) != REC_MAGIC {
        return None; // empty/zeroed slot or foreign data
    }
    let len = get_u16(sec, R_LEN) as usize;
    if len > MAX_PAYLOAD {
        return None;
    }
    let want = record_digest(sec, len);
    // Constant-time not required (integrity, not secrecy) — a plain compare.
    if sec[R_DIGEST..R_DIGEST_END] != want {
        return None; // torn / corrupt — drop it
    }
    Some((get_u64(sec, R_SEQ), get_u16(sec, R_TYPE), len))
}

fn superblock_valid(sec: &[u8; SEC]) -> Option<u32> {
    if &sec[0..8] != SB_MAGIC || get_u32(sec, 8) != SB_VERSION {
        return None;
    }
    // Superblock digest over bytes 0..24.
    let mut h = Hasher::new();
    h.update(&sec[0..24]);
    let d = h.finish();
    if sec[24..32] != d[..8] {
        return None;
    }
    Some(get_u32(sec, 12)) // nslots
}

/// A mounted crash-safe log over `[lo, hi)`. Holds only geometry + the derived
/// head; the actual bytes live on the block device (behind the guard).
pub struct LogStore {
    lo: u64,
    hi: u64,
    nslots: u64,
    next_seq: u64,
    count: u64,
}

impl LogStore {
    /// Live record count (bounded by `nslots`).
    #[inline]
    pub fn count(&self) -> u64 {
        self.count
    }
    /// The next sequence number that will be assigned.
    #[inline]
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }
    #[inline]
    pub fn capacity(&self) -> u64 {
        self.nslots
    }

    #[inline]
    fn slot_lba(&self, seq: u64) -> u64 {
        self.lo + 1 + (seq % self.nslots)
    }

    /// Shared mount scan for `mount` (key-free) and `mount_sealed` (keyed). Read
    /// the superblock, scan every slot, and keep the records that self-validate by
    /// framing digest AND — when `ctx` is `Some` — also authenticate under the
    /// volume seal. Derive the head (next seq = max valid seq + 1). Read-only.
    fn scan<D: BlockDev>(
        store: &SealedStore<D>,
        lo: u64,
        hi: u64,
        ctx: Option<&SealCtx>,
    ) -> Result<LogStore, FsErr> {
        if hi <= lo + 1 {
            return Err(FsErr::RegionTooSmall);
        }
        let mut sb = [0u8; SEC];
        store.read_sector(lo, &mut sb)?;
        let nslots = match superblock_valid(&sb) {
            Some(n) => n as u64,
            None => return Err(FsErr::NotFormatted),
        };
        if nslots != hi - lo - 1 {
            return Err(FsErr::NotFormatted); // geometry mismatch — refuse to guess
        }
        let mut count = 0u64;
        let mut max_seq: Option<u64> = None;
        for i in 0..nslots {
            let mut sec = [0u8; SEC];
            store.read_sector(lo + 1 + i, &mut sec)?;
            if let Some((seq, _rt, len)) = parse_record(&sec) {
                // Ring-placement sanity: a record with sequence `seq` lives ONLY in slot
                // `seq % nslots`. A record whose `seq` does not map home to the slot it
                // was READ from is misplaced — a torn write, foreign data, or a FORGED
                // record (e.g. a `seq = u64::MAX` planted to poison `max_seq`/`next_seq`).
                // Dropping it here both preserves ordering integrity and denies the
                // overflow/underflow the forged-seq DoS relied on. (Keyless framing can't
                // authenticate content — that's the sealed path — but a forger can no
                // longer choose an arbitrary `seq` for a given slot.)
                if seq % nslots != i {
                    continue;
                }
                if let Some(c) = ctx {
                    // M3.3 fail-closed authentication: a record whose ciphertext/tag
                    // does not verify under the volume seal is DROPPED exactly like a
                    // torn one — no plaintext is ever recovered from it. This catches
                    // a ciphertext edit that recomputes the (keyless, forgeable)
                    // framing digest, which the digest alone would let pass.
                    let mut scratch = [0u8; MAX_SEALED_PAYLOAD];
                    if len < seal::SEAL_HDR_LEN
                        || seal::unseal(
                            c.vek,
                            c.policy,
                            &sec[REC_HDR..REC_HDR + len],
                            &mut scratch,
                        )
                        .is_err()
                    {
                        continue; // tampered/forged — exclude, reveal nothing
                    }
                }
                count += 1;
                max_seq = Some(max_seq.map_or(seq, |m| if seq > m { seq } else { m }));
            }
        }
        // saturating_add: even if a record survived with seq == u64::MAX, the head must
        // not overflow (dev builds compile with overflow-checks + panic=abort → a plain
        // `m + 1` would ABORT the boot on hostile disk content). The ring-placement check
        // above already rejects an arbitrary forged seq, so this is belt-and-suspenders.
        let next_seq = max_seq.map_or(0, |m| m.saturating_add(1));
        Ok(LogStore {
            lo,
            hi,
            nslots,
            next_seq,
            count,
        })
    }

    /// Mount an already-formatted log: read the superblock, then SCAN every slot,
    /// keep valid records, and derive the head (next seq = max valid seq + 1).
    /// Read-only — always available (no `p15-write`). This IS the crash-recovery
    /// path: torn slots fail their digest and are silently excluded. Key-free, so
    /// it works on an encrypted volume too (the framing is cleartext); use
    /// `mount_sealed` when the volume key is available to ALSO reject tampered
    /// ciphertext at mount.
    pub fn mount<D: BlockDev>(store: &SealedStore<D>, lo: u64, hi: u64) -> Result<LogStore, FsErr> {
        Self::scan(store, lo, hi, None)
    }

    /// M3.3 — mount an ENCRYPTED log: like `mount`, but additionally MAC-verifies
    /// every record's sealed payload under `ctx`. A record whose seal does not
    /// authenticate (tampered ciphertext/tag, or the wrong volume key) is dropped
    /// fail-closed — never counted, never decrypted. Read-only.
    pub fn mount_sealed<D: BlockDev>(
        store: &SealedStore<D>,
        ctx: &SealCtx,
        lo: u64,
        hi: u64,
    ) -> Result<LogStore, FsErr> {
        Self::scan(store, lo, hi, Some(ctx))
    }

    /// Iterate the live records in logical (oldest-first) order, calling `cb(seq,
    /// rtype, payload)`. Reads the contiguous live seq range and validates each
    /// slot again (defensive against a mid-ring torn slot). Read-only.
    pub fn for_each<D, F>(&self, store: &SealedStore<D>, mut cb: F) -> Result<(), FsErr>
    where
        D: BlockDev,
        F: FnMut(u64, u16, &[u8]),
    {
        if self.count == 0 {
            return Ok(());
        }
        let start = self.next_seq.saturating_sub(self.count);
        for seq in start..self.next_seq {
            let mut sec = [0u8; SEC];
            store.read_sector(self.slot_lba(seq), &mut sec)?;
            if let Some((s, rt, len)) = parse_record(&sec) {
                if s == seq {
                    cb(seq, rt, &sec[REC_HDR..REC_HDR + len]);
                }
            }
        }
        Ok(())
    }

    /// M3.3 — iterate live records like `for_each`, but UNSEAL each payload under
    /// `ctx` before handing the PLAINTEXT to `cb`. A record that fails to
    /// authenticate (tamper/wrong key) is SKIPPED fail-closed — its plaintext is
    /// never produced. Read-only. Use this (not `for_each`) on an encrypted volume.
    pub fn for_each_sealed<D, F>(
        &self,
        store: &SealedStore<D>,
        ctx: &SealCtx,
        mut cb: F,
    ) -> Result<(), FsErr>
    where
        D: BlockDev,
        F: FnMut(u64, u16, &[u8]),
    {
        if self.count == 0 {
            return Ok(());
        }
        let start = self.next_seq.saturating_sub(self.count);
        for seq in start..self.next_seq {
            let mut sec = [0u8; SEC];
            store.read_sector(self.slot_lba(seq), &mut sec)?;
            if let Some((s, rt, len)) = parse_record(&sec) {
                if s == seq && len >= seal::SEAL_HDR_LEN {
                    let mut pt = [0u8; MAX_SEALED_PAYLOAD];
                    if let Ok(n) =
                        seal::unseal(ctx.vek, ctx.policy, &sec[REC_HDR..REC_HDR + len], &mut pt)
                    {
                        cb(seq, rt, &pt[..n]); // authenticated plaintext only
                    }
                    // unseal failure => skip (fail-closed; no plaintext leaked)
                }
            }
        }
        Ok(())
    }
}

// --- M3.3: the sealed Volume Encryption Key in the keystore -------------------

/// Load the VEK: read the sealed blob at `VEK_LBA` and unseal it under (`srk`,
/// `policy`). Returns the 32-byte key, or `None` if absent / measurement-mismatch
/// / tampered (fail-closed — a bad or missing VEK yields no key, never a panic).
pub fn load_vek<D: BlockDev>(
    store: &SealedStore<D>,
    srk: &[u8; 32],
    policy: &seal::Policy,
) -> Option<[u8; 32]> {
    let mut sec = [0u8; SEC];
    store.read_sector(VEK_LBA, &mut sec).ok()?;
    if &sec[..8] != seal::SEAL_MAGIC {
        return None; // no VEK blob written yet
    }
    // ct_len lives at HQKSEAL1 header offset 68 (little-endian).
    let ct_len = get_u32(&sec, 68) as usize;
    let total = seal::SEAL_HDR_LEN + ct_len;
    if total > SEC {
        return None;
    }
    let mut vek = [0u8; 32];
    match seal::unseal(srk, policy, &sec[..total], &mut vek) {
        Ok(32) => Some(vek),
        _ => None, // wrong length / tag / policy — fail closed
    }
}

// --- Write path (behind `p15-write`, like the rest of the store) -------------

/// Format `[lo, hi)` as a fresh empty log (writes the superblock). Every sector
/// goes through `store_sector`, so a region outside the `DataVolume` allowlist is
/// refused by the M3.1 guard.
#[cfg(feature = "p15-write")]
pub fn format<D: BlockDev>(
    store: &mut SealedStore<D>,
    lo: u64,
    hi: u64,
) -> Result<LogStore, FsErr> {
    if hi <= lo + 1 {
        return Err(FsErr::RegionTooSmall);
    }
    let nslots = hi - lo - 1;
    let mut sb = [0u8; SEC];
    sb[0..8].copy_from_slice(SB_MAGIC);
    put_u32(&mut sb, 8, SB_VERSION);
    put_u32(&mut sb, 12, nslots as u32);
    let mut h = Hasher::new();
    h.update(&sb[0..24]);
    let d = h.finish();
    sb[24..32].copy_from_slice(&d[..8]);
    match store.store_sector(lo, &sb)? {
        RegionKind::DataVolume => {}
        _ => return Err(FsErr::OutsideRegion), // superblock must land in the data volume
    }
    // Zero the slot area so a re-format over stale records leaves no valid ghosts.
    let zero = [0u8; SEC];
    for i in 0..nslots {
        store.store_sector(lo + 1 + i, &zero)?;
    }
    Ok(LogStore {
        lo,
        hi,
        nslots,
        next_seq: 0,
        count: 0,
    })
}

/// Mount if formatted, else format — the normal open path.
#[cfg(feature = "p15-write")]
pub fn open_or_format<D: BlockDev>(
    store: &mut SealedStore<D>,
    lo: u64,
    hi: u64,
) -> Result<LogStore, FsErr> {
    match LogStore::mount(store, lo, hi) {
        Ok(log) => Ok(log),
        Err(FsErr::NotFormatted) => format(store, lo, hi),
        Err(e) => Err(e),
    }
}

impl LogStore {
    /// Append one record; returns its assigned `seq`. Ring semantics: writes to
    /// slot `seq % nslots`, overwriting the oldest when full (bounded retention).
    /// Routes through `store_sector` (guard + read-back verify): the target LBA is
    /// asserted inside `[lo, hi)` AND inside the `DataVolume` allowlist.
    #[cfg(feature = "p15-write")]
    pub fn append<D: BlockDev>(
        &mut self,
        store: &mut SealedStore<D>,
        rtype: u16,
        payload: &[u8],
    ) -> Result<u64, FsErr> {
        if payload.len() > MAX_PAYLOAD {
            return Err(FsErr::TooBig);
        }
        let seq = self.next_seq;
        let lba = self.slot_lba(seq);
        if lba < self.lo + 1 || lba >= self.hi {
            return Err(FsErr::OutsideRegion); // ring math escaped the region
        }
        let mut sec = [0u8; SEC];
        put_u32(&mut sec, R_MAGIC, REC_MAGIC);
        put_u64(&mut sec, R_SEQ, seq);
        sec[R_LEN..R_LEN + 2].copy_from_slice(&(payload.len() as u16).to_le_bytes());
        sec[R_TYPE..R_TYPE + 2].copy_from_slice(&rtype.to_le_bytes());
        sec[REC_HDR..REC_HDR + payload.len()].copy_from_slice(payload);
        let dg = record_digest(&sec, payload.len());
        sec[R_DIGEST..R_DIGEST_END].copy_from_slice(&dg);
        // The guard authorizes only the DataVolume region; anything else escapes.
        match store.store_sector(lba, &sec)? {
            RegionKind::DataVolume => {}
            _ => return Err(FsErr::OutsideRegion),
        }
        self.next_seq += 1;
        if self.count < self.nslots {
            self.count += 1;
        }
        Ok(seq)
    }

    /// M3.3 — append an ENCRYPTED record: seal `plaintext` with the volume key
    /// (`ctx`) via HQKSEAL1, then write the resulting blob (header + ciphertext +
    /// MAC) as the record's opaque payload through the normal guarded `append`.
    /// The framing (magic/seq/len/rtype/digest) stays cleartext; the payload bytes
    /// are ciphertext, so a raw block read reveals no Event/QSecBit fields.
    #[cfg(feature = "p15-write")]
    pub fn append_sealed<D: BlockDev>(
        &mut self,
        store: &mut SealedStore<D>,
        ctx: &SealCtx,
        rtype: u16,
        plaintext: &[u8],
    ) -> Result<u64, FsErr> {
        if plaintext.len() > MAX_SEALED_PAYLOAD {
            return Err(FsErr::TooBig);
        }
        let mut blob = seal::SealBlob::new();
        // Encrypt-then-MAC under the VEK (as SRK) + volume policy.
        if seal::seal(ctx.vek, ctx.policy, plaintext, &mut blob).is_err() {
            return Err(FsErr::TooBig); // only TooLong is reachable (guarded above)
        }
        // Reuse the framing/digest/guarded-write path — the blob IS the payload.
        self.append(store, rtype, blob.as_slice())
    }
}

/// M3.3 — generate a fresh Volume Encryption Key and PERSIST it sealed.
///
/// Best-effort entropy = `cntpct_el0 || SRK` through SHA-256. HONESTY: QEMU has no
/// TRNG, so this is adequate to prove the mechanism but is NOT hardware-grade
/// entropy; a real RNG/OTP seed is metal (Gate R), the same caveat seal.rs already
/// carries for its nonce. The key is SEALED under (`srk`,`policy`) and written to
/// `VEK_LBA` through the guard (Keystore region) — it never lands cleartext on disk.
#[cfg(feature = "p15-write")]
pub fn create_vek<D: BlockDev>(
    store: &mut SealedStore<D>,
    srk: &[u8; 32],
    policy: &seal::Policy,
) -> Result<[u8; 32], FsErr> {
    let t: u64;
    unsafe {
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) t, options(nomem, nostack));
    }
    let mut h = Hasher::new();
    h.update(b"HEQK-M3.3-VEK-v1");
    h.update(srk); // fold the 256-bit SRK in so weak cntpct entropy is not the floor
    h.update(&t.to_le_bytes());
    let vek = h.finish();

    let mut blob = seal::SealBlob::new();
    seal::seal(srk, policy, &vek, &mut blob).map_err(|_| FsErr::Io)?;
    let mut sec = [0u8; SEC];
    sec[..blob.len].copy_from_slice(blob.as_slice());
    match store.store_sector(VEK_LBA, &sec)? {
        RegionKind::Keystore => Ok(vek),
        _ => Err(FsErr::OutsideRegion), // VEK must land in the keystore window
    }
}

/// M3.3 — the normal volume-open path for the key: load the sealed VEK, or create
/// + persist a fresh one on first mount. Returns `(vek, created)` — `created` is
/// true only on the very first open of a volume (proves cross-restart survival:
/// a second boot must return `false`).
#[cfg(feature = "p15-write")]
pub fn load_or_create_vek<D: BlockDev>(
    store: &mut SealedStore<D>,
    srk: &[u8; 32],
    policy: &seal::Policy,
) -> Result<([u8; 32], bool), FsErr> {
    if let Some(v) = load_vek(store, srk, policy) {
        return Ok((v, false));
    }
    let v = create_vek(store, srk, policy)?;
    Ok((v, true))
}
