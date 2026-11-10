//! A/B OTA — which sectors may an OS-image update write? (production phase 1, step 3)
//!
//! Pure FAT32 walk over a sector reader, shared by the CM5 eMMC driver's Gate 1 (it re-derives the
//! answer from the card itself, independent of the store layer) and host tests / fuzzing.
//!
//! The factory boot partition (p1, FAT32) holds `config.txt` (`kernel=heqk8-a.img`, the cold-boot
//! slot), `tryboot.txt`, and the two slot files `heqk8-a.img` / `heqk8-b.img`. The INACTIVE slot is
//! the file `config.txt` does NOT name. It is writable only when it is ONE contiguous cluster run
//! (the device has no FAT writer: it overwrites the file's data in place, never the FAT, the
//! directory, the BPB or the MBR) — so the answer is that run and nothing else.

/// The writable range of the inactive slot file, plus the geometry it was derived from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotRun {
    /// First sector of the inactive slot file's cluster run (absolute LBA).
    pub lo: u64,
    /// One past the last sector of the run (whole clusters).
    pub hi: u64,
    /// The file size in the directory entry — the firmware loads exactly this many bytes.
    pub size: u32,
    /// The slot `config.txt` names (b'a' or b'b'): the cold-boot slot, never writable.
    pub active: u8,
    /// The active slot's run (for overlap checks and for hashing the fallback image).
    pub active_lo: u64,
    pub active_hi: u64,
}

const EOC: u32 = 0x0FFF_FFF8;
const MAX_ROOT_CLUSTERS: usize = 16;
const MAX_CONFIG_BYTES: u32 = 64 * 1024;
/// A slot file is one boot image (the hboot load window is 5 MiB); anything larger is not ours.
const MAX_SLOT_BYTES: u32 = 8 * 1024 * 1024;

struct Fat {
    fat_lo: u64,
    data: u64,
    end: u64,
    spc: u64,
    root: u32,
}

impl Fat {
    fn cluster_lba(&self, c: u32) -> u64 {
        self.data + (c as u64 - 2) * self.spc
    }
}

fn le16(b: &[u8], o: usize) -> u64 {
    u16::from_le_bytes([b[o], b[o + 1]]) as u64
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn geometry<F: FnMut(u64, &mut [u8; 512]) -> bool>(read: &mut F) -> Option<Fat> {
    let mut s = [0u8; 512];
    if !read(0, &mut s) || s[510] != 0x55 || s[511] != 0xAA {
        return None;
    }
    let e = &s[446..462];
    if !matches!(e[4], 0x0b | 0x0c) {
        return None;
    }
    let start = le32(e, 8) as u64;
    let size = le32(e, 12) as u64;
    if start == 0 || size == 0 {
        return None;
    }
    if !read(start, &mut s) || s[510] != 0x55 || s[511] != 0xAA {
        return None;
    }
    let spc = s[13] as u64;
    let (rsvd, nfats, fatsz, root) = (le16(&s, 14), s[16] as u64, le32(&s, 36) as u64, le32(&s, 44));
    if le16(&s, 11) != 512 || spc == 0 || !spc.is_power_of_two() || rsvd == 0 || nfats == 0 || fatsz == 0
        || le16(&s, 22) != 0 || root < 2
    {
        return None;
    }
    let data = start + rsvd + nfats * fatsz;
    if data >= start + size {
        return None;
    }
    Some(Fat { fat_lo: start + rsvd, data, end: start + size, spc, root })
}

fn next<F: FnMut(u64, &mut [u8; 512]) -> bool>(f: &Fat, read: &mut F, c: u32) -> Option<u32> {
    let mut s = [0u8; 512];
    let off = c as u64 * 4;
    if !read(f.fat_lo + off / 512, &mut s) {
        return None;
    }
    Some(le32(&s, (off % 512) as usize) & 0x0FFF_FFFF)
}

/// A file's single contiguous run: (lo, hi) in sectors, or None if fragmented / out of range.
fn contiguous_run<F: FnMut(u64, &mut [u8; 512]) -> bool>(f: &Fat, read: &mut F, first: u32, size: u32) -> Option<(u64, u64)> {
    let csz = f.spc * 512;
    let n = (size as u64).div_ceil(csz).max(1);
    let max_c = ((f.end - f.data) / f.spc + 2) as u32;
    if first < 2 || first as u64 + n > max_c as u64 {
        return None;
    }
    let mut c = first;
    for i in 0..n {
        let nx = next(f, read, c)?;
        if i + 1 == n {
            if nx < EOC {
                return None; // the chain is longer than the size says
            }
        } else if nx != c + 1 {
            return None; // fragmented (or EOC early)
        }
        c += 1;
    }
    let lo = f.cluster_lba(first);
    Some((lo, lo + n * f.spc))
}

#[derive(Clone, Copy, Default)]
struct Ent {
    first: u32,
    size: u32,
    found: bool,
}

/// Find CONFIG.TXT and the two slot files (8.3 names) in the root directory.
fn scan_root<F: FnMut(u64, &mut [u8; 512]) -> bool>(f: &Fat, read: &mut F) -> Option<[Ent; 3]> {
    const NAMES: [&[u8; 11]; 3] = [b"CONFIG  TXT", b"HEQK8-A IMG", b"HEQK8-B IMG"];
    let mut out = [Ent::default(); 3];
    let mut c = f.root;
    let mut s = [0u8; 512];
    for _ in 0..MAX_ROOT_CLUSTERS {
        for k in 0..f.spc {
            if !read(f.cluster_lba(c) + k, &mut s) {
                return None;
            }
            for e in s.chunks_exact(32) {
                if e[0] == 0 {
                    return Some(out); // end of directory
                }
                if e[0] == 0xE5 || e[11] == 0x0F || e[11] & 0x18 != 0 {
                    continue; // deleted, long-name part, directory or volume label
                }
                for (i, n) in NAMES.iter().enumerate() {
                    if &e[..11] == *n {
                        if out[i].found {
                            return None; // a duplicate name is never a factory layout
                        }
                        let first = ((le16(e, 20) as u32) << 16) | le16(e, 26) as u32;
                        out[i] = Ent { first, size: le32(e, 28), found: true };
                    }
                }
            }
        }
        let nx = next(f, read, c)?;
        if nx >= EOC {
            return Some(out);
        }
        if nx < 2 {
            return None;
        }
        c = nx;
    }
    None
}

/// The slot `config.txt` names: exactly one uncommented `kernel=heqk8-[ab].img` line in the file.
fn config_slot<F: FnMut(u64, &mut [u8; 512]) -> bool>(f: &Fat, read: &mut F, e: Ent) -> Option<u8> {
    if e.size == 0 || e.size > MAX_CONFIG_BYTES {
        return None;
    }
    let (lo, hi) = contiguous_run(f, read, e.first, e.size)?;
    let used = (e.size as u64).div_ceil(512);
    let mut letter = None;
    let mut s = [0u8; 512];
    for lba in lo..(lo + used).min(hi) {
        if !read(lba, &mut s) {
            return None;
        }
        if let Some(p) = crate::slot_line_letter(&s) {
            if letter.is_some() {
                return None;
            }
            letter = Some(s[p]);
        }
    }
    letter
}

/// The inactive slot file's writable run, derived only from what is on the card. None when the
/// layout is not the factory A/B layout (a legacy single-image card, a fragmented slot file, a
/// missing or ambiguous `config.txt` line) — the caller then refuses the update.
pub fn inactive_slot_run<F: FnMut(u64, &mut [u8; 512]) -> bool>(mut read: F) -> Option<SlotRun> {
    let f = geometry(&mut read)?;
    let [cfg, a, b] = scan_root(&f, &mut read)?;
    if !(cfg.found && a.found && b.found) {
        return None;
    }
    let active = config_slot(&f, &mut read, cfg)?;
    let (act, ina) = if active == b'a' { (a, b) } else { (b, a) };
    if ina.size == 0 || act.size == 0 || ina.size > MAX_SLOT_BYTES || act.size > MAX_SLOT_BYTES {
        return None;
    }
    let (alo, ahi) = contiguous_run(&f, &mut read, act.first, act.size)?;
    let (lo, hi) = contiguous_run(&f, &mut read, ina.first, ina.size)?;
    let root_lo = f.cluster_lba(f.root);
    let overlaps = |x: u64, y: u64| lo < y && x < hi;
    if lo < f.data || hi > f.end || overlaps(alo, ahi) || overlaps(root_lo, root_lo + f.spc) {
        return None;
    }
    Some(SlotRun { lo, hi, size: ina.size, active, active_lo: alo, active_hi: ahi })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec;
    use std::vec::Vec;

    const P1: u64 = 8;
    const RSVD: u64 = 4;
    const FATSZ: u64 = 4;
    const SPC: u64 = 2;

    struct Img(Vec<[u8; 512]>);
    impl Img {
        fn new() -> Img {
            let mut v = vec![[0u8; 512]; 400];
            v[0][510] = 0x55;
            v[0][511] = 0xAA;
            v[0][446 + 4] = 0x0c;
            v[0][446 + 8..446 + 12].copy_from_slice(&(P1 as u32).to_le_bytes());
            v[0][446 + 12..446 + 16].copy_from_slice(&(390u32).to_le_bytes());
            let b = &mut v[P1 as usize];
            b[11..13].copy_from_slice(&512u16.to_le_bytes());
            b[13] = SPC as u8;
            b[14..16].copy_from_slice(&(RSVD as u16).to_le_bytes());
            b[16] = 1;
            b[36..40].copy_from_slice(&(FATSZ as u32).to_le_bytes());
            b[44..48].copy_from_slice(&2u32.to_le_bytes());
            b[510] = 0x55;
            b[511] = 0xAA;
            let mut i = Img(v);
            i.fat(2, 0x0FFF_FFFF); // root dir: one cluster
            i
        }
        fn data() -> u64 {
            P1 + RSVD + FATSZ
        }
        fn clba(c: u32) -> usize {
            (Self::data() + (c as u64 - 2) * SPC) as usize
        }
        fn fat(&mut self, c: u32, v: u32) {
            let off = c as usize * 4;
            let s = (P1 + RSVD) as usize + off / 512;
            self.0[s][off % 512..off % 512 + 4].copy_from_slice(&v.to_le_bytes());
        }
        fn chain(&mut self, first: u32, n: u32) {
            for k in 0..n {
                self.fat(first + k, if k + 1 == n { 0x0FFF_FFFF } else { first + k + 1 });
            }
        }
        fn ent(&mut self, slot: usize, name: &[u8; 11], first: u32, size: u32) {
            let r = Self::clba(2);
            let e = &mut self.0[r][slot * 32..slot * 32 + 32];
            e[..11].copy_from_slice(name);
            e[11] = 0x20;
            e[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
            e[26..28].copy_from_slice(&(first as u16).to_le_bytes());
            e[28..32].copy_from_slice(&size.to_le_bytes());
        }
        fn config(&mut self, text: &[u8]) {
            let s = Self::clba(3);
            self.0[s] = [0; 512];
            self.0[s][..text.len()].copy_from_slice(text);
        }
        fn read(&self) -> impl FnMut(u64, &mut [u8; 512]) -> bool + '_ {
            move |l, b| match self.0.get(l as usize) {
                Some(s) => {
                    *b = *s;
                    true
                }
                None => false,
            }
        }
    }

    /// config at cluster 3 (1 cluster), slot A at 4..8 (4 clusters), slot B at 8..12.
    fn factory(cfg: &[u8]) -> Img {
        let mut i = Img::new();
        i.chain(3, 1);
        i.chain(4, 4);
        i.chain(8, 4);
        i.ent(0, b"CONFIG  TXT", 3, cfg.len() as u32);
        i.ent(1, b"HEQK8-A IMG", 4, 4 * 1024);
        i.ent(2, b"HEQK8-B IMG", 8, 3 * 1024 + 7);
        i.config(cfg);
        i
    }

    #[test]
    fn inactive_is_the_slot_config_does_not_name() {
        let i = factory(b"arm_64bit=1\nkernel=heqk8-a.img\n");
        let r = inactive_slot_run(i.read()).unwrap();
        assert_eq!(r.active, b'a');
        assert_eq!((r.lo, r.hi), (Img::clba(8) as u64, Img::clba(8) as u64 + 8));
        assert_eq!(r.size, 3 * 1024 + 7);
        assert_eq!((r.active_lo, r.active_hi), (Img::clba(4) as u64, Img::clba(4) as u64 + 8));
        let i = factory(b"kernel=heqk8-b.img\n");
        let r = inactive_slot_run(i.read()).unwrap();
        assert_eq!(r.active, b'b');
        assert_eq!(r.lo, Img::clba(4) as u64);
    }

    #[test]
    fn refusals() {
        // commented / missing / duplicate line
        assert!(inactive_slot_run(factory(b"#kernel=heqk8-a.img\n").read()).is_none());
        assert!(inactive_slot_run(factory(b"kernel=heqk8.img\n").read()).is_none());
        assert!(inactive_slot_run(factory(b"kernel=heqk8-a.img\nkernel=heqk8-b.img\n").read()).is_none());
        // fragmented inactive slot
        let mut i = factory(b"kernel=heqk8-a.img\n");
        i.fat(9, 20);
        assert!(inactive_slot_run(i.read()).is_none());
        // chain longer than the size
        let mut i = factory(b"kernel=heqk8-a.img\n");
        i.ent(2, b"HEQK8-B IMG", 8, 1024);
        assert!(inactive_slot_run(i.read()).is_none());
        // slot B overlapping slot A
        let mut i = factory(b"kernel=heqk8-a.img\n");
        i.ent(2, b"HEQK8-B IMG", 5, 1024);
        i.chain(5, 1);
        assert!(inactive_slot_run(i.read()).is_none());
        // missing slot file, duplicate entry
        let mut i = factory(b"kernel=heqk8-a.img\n");
        i.0[Img::clba(2)][64] = 0xE5;
        assert!(inactive_slot_run(i.read()).is_none());
        let mut i = factory(b"kernel=heqk8-a.img\n");
        i.ent(3, b"HEQK8-B IMG", 8, 1024);
        assert!(inactive_slot_run(i.read()).is_none());
        // not FAT32 / no MBR signature
        let mut i = factory(b"kernel=heqk8-a.img\n");
        i.0[0][446 + 4] = 0x83;
        assert!(inactive_slot_run(i.read()).is_none());
        let mut i = factory(b"kernel=heqk8-a.img\n");
        i.0[0][510] = 0;
        assert!(inactive_slot_run(i.read()).is_none());
    }

    #[test]
    fn never_panics_on_garbage() {
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        for _ in 0..300 {
            let mut i = factory(b"kernel=heqk8-a.img\n");
            for _ in 0..40 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let s = (x % 40) as usize;
                let o = ((x >> 16) % 512) as usize;
                i.0[if s < 2 { 0 } else { s + 6 }][o] = (x >> 40) as u8;
            }
            let _ = inactive_slot_run(i.read());
        }
    }
}
