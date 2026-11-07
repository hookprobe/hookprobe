//! B2 (M3.4 OTA delivery) — a MINIMAL, READ-ONLY FAT32 LOCATOR. No writer, no `alloc`,
//! fixed buffers, fail-closed.
//!
//! WHY: the CM5 boot partition (`/dev/sda1`) is a FAT32 filesystem SHARED with the Pi
//! firmware (`bootcode.bin`/`start4.elf`/DTBs) — the A/B kernel images `heqk8.img` /
//! `heqk8-b.img` live inside it as ordinary files, at whatever sectors FAT allocation
//! placed them (NOT guaranteed contiguous, NOT a known LBA). To DELIVER an OTA candidate
//! into the inactive slot, heqk must find where `heqk8-b.img` actually lives on disk. This
//! locator parses the BPB, walks the root directory to the target 8.3 file, follows its
//! FAT cluster chain, and returns the ordered LBA runs it occupies. Those runs are then
//! registered as `RegionKind::InactiveSlot` and handed to the EXISTING guarded raw-sector
//! writer (`ota::write_candidate_to_inactive`) — so brick-safety (the LBA guard) still
//! authorizes every write, and we NEVER mutate FAT metadata (table or directory entry):
//! the candidate is the SAME size as the file already there, so overwriting its existing
//! data clusters in place needs no allocation.
//!
//! This is a *reader*: it touches only the BPB, the FAT, and directory entries, all
//! read-only. Any malformation (bad signature, non-512 sectors, absurd counts, a chain
//! that loops or overruns our fixed run capacity) fails closed to `None` — the OTA path
//! then reports "delivery unavailable, use the host tool" rather than writing anything.

use hal::BlockDev;

/// The parsed FAT32 BIOS Parameter Block + derived geometry (all in LBA / sectors).
#[derive(Clone, Copy)]
pub struct Fat32 {
    pub part_start: u64,          // partition start LBA (from the MBR)
    pub sectors_per_cluster: u32, // BPB+13
    pub fat_start: u64,           // part_start + reserved_sectors
    pub data_start: u64,          // fat_start + num_fats * fat_size_32
    pub root_cluster: u32,        // BPB+44
}

impl Fat32 {
    /// First LBA of a data cluster (clusters are numbered from 2).
    #[inline]
    fn cluster_lba(&self, cluster: u32) -> u64 {
        self.data_start + (cluster as u64 - 2) * self.sectors_per_cluster as u64
    }
}

#[inline]
fn rd_u16(b: &[u8; 512], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
#[inline]
fn rd_u32(b: &[u8; 512], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Parse + VALIDATE the FAT32 BPB at sector 0 of the partition. Fail-closed: only a
/// genuine 512-byte-sector FAT32 with a 0xAA55 signature and sane geometry is accepted.
pub fn parse<D: BlockDev>(dev: &D, part_start: u64) -> Option<Fat32> {
    let mut b = [0u8; 512];
    dev.read_block(part_start, &mut b).ok()?;
    if rd_u16(&b, 510) != 0xAA55 {
        return None; // no boot signature
    }
    if rd_u16(&b, 11) != 512 {
        return None; // we only support 512-byte sectors
    }
    let spc = b[13] as u32;
    if spc == 0 || !spc.is_power_of_two() || spc > 128 {
        return None;
    }
    let reserved = rd_u16(&b, 14) as u64;
    if reserved == 0 {
        return None;
    }
    let num_fats = b[16] as u64;
    if num_fats == 0 || num_fats > 2 {
        return None;
    }
    // FAT32 has root_entry_count == 0 and total_sectors_16 == 0; the 32-bit FAT size lives
    // at +36 (the 16-bit one at +22 is 0). Reject FAT12/16 (non-zero root entries).
    if rd_u16(&b, 17) != 0 {
        return None; // a FAT12/16 fixed root dir -> not FAT32
    }
    let fat_size_32 = rd_u32(&b, 36) as u64;
    if fat_size_32 == 0 {
        return None;
    }
    let root_cluster = rd_u32(&b, 44);
    if root_cluster < 2 {
        return None;
    }
    let fat_start = part_start + reserved;
    let data_start = fat_start + num_fats * fat_size_32;
    Some(Fat32 { part_start, sectors_per_cluster: spc, fat_start, data_start, root_cluster })
}

/// FAT32 end-of-chain marker (>= 0x0FFF_FFF8) or a bad/free entry (< 2).
#[inline]
fn is_chain_end(entry: u32) -> bool {
    let e = entry & 0x0FFF_FFFF;
    e >= 0x0FFF_FFF8 || e < 2
}

/// Read the FAT entry (next cluster) for `cluster`. `None` on I/O error or a nonsensical
/// FAT LBA. The 28-bit value is masked; callers use `is_chain_end` to stop.
fn fat_next<D: BlockDev>(dev: &D, fs: &Fat32, cluster: u32) -> Option<u32> {
    let byte = cluster as u64 * 4;
    let lba = fs.fat_start + byte / 512;
    let off = (byte % 512) as usize;
    let mut b = [0u8; 512];
    dev.read_block(lba, &mut b).ok()?;
    Some(rd_u32(&b, off) & 0x0FFF_FFFF)
}

/// A located file's on-disk layout: the coalesced contiguous LBA runs of its data
/// clusters, plus the directory-entry size in bytes. `runs[..n]` = (start_lba, sectors).
pub const MAX_RUNS: usize = 8;
#[derive(Clone, Copy)]
pub struct FileRuns {
    pub runs: [(u64, u64); MAX_RUNS],
    pub n: usize,
    pub size_bytes: u32,
}

impl FileRuns {
    /// The single contiguous [start_lba, sector_count) if the file occupies exactly one
    /// run — the simple, brick-safe case OTA registers as an InactiveSlot region. `None`
    /// if fragmented (fail-closed: OTA declines rather than writing scattered sectors).
    pub fn contiguous(&self) -> Option<(u64, u64)> {
        if self.n == 1 {
            Some(self.runs[0])
        } else {
            None
        }
    }
}

/// A 32-byte directory entry's 8.3 name is at offset 0; attr at +11 (0x0F == a long-name
/// fragment, skipped); first-cluster hi/lo at +20/+26; size at +28. name[0]==0 ends the
/// directory; 0xE5 is a deleted slot.
#[inline]
fn dir_name_matches(e: &[u8], name_8_3: &[u8; 11]) -> bool {
    e[0..11] == name_8_3[..]
}

/// Walk the root directory chain and locate `name_8_3` (an 8.3, space-padded, UPPERCASE
/// name, e.g. b"HEQK8-B IMG"). Returns its cluster runs, or `None` if absent / malformed /
/// fragmented beyond MAX_RUNS. LFN (attr 0x0F) entries are skipped — we match the 8.3
/// short-name alias that always accompanies them.
pub fn find_file<D: BlockDev>(dev: &D, fs: &Fat32, name_8_3: &[u8; 11]) -> Option<FileRuns> {
    let mut cluster = fs.root_cluster;
    let mut guard = 0u32; // chain-length backstop (never loop forever on a cyclic FAT)
    let mut sect = [0u8; 512];
    while !is_chain_end(cluster) {
        guard += 1;
        if guard > 1_000_000 {
            return None;
        }
        let base = fs.cluster_lba(cluster);
        for s in 0..fs.sectors_per_cluster as u64 {
            dev.read_block(base + s, &mut sect).ok()?;
            let mut i = 0usize;
            while i + 32 <= 512 {
                let e = &sect[i..i + 32];
                if e[0] == 0x00 {
                    return None; // end of directory — file not found
                }
                if e[0] != 0xE5 && (e[11] & 0x0F) != 0x0F && dir_name_matches(e, name_8_3) {
                    let first = ((rd_u32_slice(e, 20) & 0xFFFF) << 16) | (rd_u32_slice(e, 26) & 0xFFFF);
                    let size = rd_u32_slice(e, 28);
                    return chain_runs(dev, fs, first, size);
                }
                i += 32;
            }
        }
        cluster = fat_next(dev, fs, cluster)?;
    }
    None
}

#[inline]
fn rd_u32_slice(e: &[u8], off: usize) -> u32 {
    // dir entries use 16-bit cluster halves; we read 2 bytes via a 4-byte helper by
    // zeroing the top — callers mask 0xFFFF for the cluster halves; size reads all 4.
    match off {
        20 | 26 => u16::from_le_bytes([e[off], e[off + 1]]) as u32,
        _ => u32::from_le_bytes([e[off], e[off + 1], e[off + 2], e[off + 3]]),
    }
}

/// Follow `first_cluster`'s FAT chain and coalesce contiguous clusters into LBA runs.
fn chain_runs<D: BlockDev>(dev: &D, fs: &Fat32, first_cluster: u32, size: u32) -> Option<FileRuns> {
    let mut runs = [(0u64, 0u64); MAX_RUNS];
    let mut n = 0usize;
    let spc = fs.sectors_per_cluster as u64;
    let mut cluster = first_cluster;
    let mut guard = 0u32;
    while !is_chain_end(cluster) {
        guard += 1;
        if guard > 1_000_000 {
            return None;
        }
        let lba = fs.cluster_lba(cluster);
        // Extend the current run if this cluster is physically contiguous with it.
        if n > 0 && runs[n - 1].0 + runs[n - 1].1 == lba {
            runs[n - 1].1 += spc;
        } else {
            if n == MAX_RUNS {
                return None; // too fragmented for our fixed capacity — fail closed
            }
            runs[n] = (lba, spc);
            n += 1;
        }
        cluster = fat_next(dev, fs, cluster)?;
    }
    if n == 0 {
        return None;
    }
    Some(FileRuns { runs, n, size_bytes: size })
}

/// One-shot convenience: parse the partition at `part_start`, locate `name_8_3`, and
/// require it be a SINGLE contiguous run — returning (start_lba, sector_count) ready to
/// register as an InactiveSlot region. `None` on any malformation / absence / fragmentation
/// (fail-closed). This is the brick-safe path the OTA delivery uses.
pub fn locate_contiguous<D: BlockDev>(
    dev: &D,
    part_start: u64,
    name_8_3: &[u8; 11],
) -> Option<(u64, u64)> {
    let fs = parse(dev, part_start)?;
    let file = find_file(dev, &fs, name_8_3)?;
    file.contiguous()
}
