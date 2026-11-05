#![no_std]
//! HookProbe HAL — the strict hardware-abstraction boundary.
//!
//! The `kernel` crate depends ONLY on these traits and contains NO
//! `cfg(target_arch)`. Each arch crate (`arch-aarch64`, later `arch-x86_64`)
//! implements them. Porting = implementing this trait set, not editing `kernel`.

/// A byte-oriented debug console (early UART, etc.).
pub trait Console {
    /// Emit one byte to the console.
    fn putc(&self, byte: u8);

    /// Emit a string (translating `\n` to CRLF for serial terminals).
    fn write_str(&self, s: &str) {
        for b in s.bytes() {
            if b == b'\n' {
                self.putc(b'\r');
            }
            self.putc(b);
        }
    }
}

/// An interrupt controller (GICv2/v3 on aarch64, APIC on x86).
pub trait IrqController {
    /// Bring the controller up (distributor + CPU interface).
    fn init(&self);
    /// Route + unmask a specific interrupt id.
    fn enable(&self, intid: u32);
    /// Acknowledge the pending interrupt; returns its id.
    fn ack(&self) -> u32;
    /// Signal end-of-interrupt for `intid`.
    fn eoi(&self, intid: u32);
}

/// A periodic tick source for the scheduler (ARM generic timer / HPET).
pub trait Timer {
    /// Start a periodic interrupt at `hz` ticks per second.
    fn start(&self, hz: u32);
    /// Re-arm for the next period (called from the timer IRQ handler).
    fn rearm(&self);
}

/// The MMU + physical frame allocator (aarch64 stage-1, x86 CR3 paging later).
pub trait Mmu {
    /// Build the identity map + init the physical frame allocator. MMU still off.
    fn init(&self);
    /// Turn the MMU on (aarch64: SCTLR_EL1.M/C/I). Safe under an identity map.
    fn enable(&self);
    /// Is translation currently on?
    fn enabled(&self) -> bool;
    /// Allocate one zeroed physical frame; 0 = out of memory.
    fn alloc_frame(&self) -> usize;
    /// Map one 4 KiB page `va -> pa` (`device` selects MMIO vs normal memory).
    fn map_page(&self, va: usize, pa: usize, device: bool) -> bool;
}

/// Error from a block-device operation (P15 sealed storage).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockErr {
    /// LBA is outside the device (>= block_count).
    OutOfRange,
    /// The transfer did not complete (SDHCI error / timeout).
    Io,
    /// The device is not initialised / not present.
    NotReady,
    /// A write was refused (read-only build, or a write-window guard rejected it).
    WriteRefused,
}

/// A 512-byte-sector block device (P15). The read path is always available; the
/// write path is compiled out by default (`p15-write`) and, where present, is
/// additionally bounded by an independent LBA guard — LBA 0 and any partition
/// sector are never writable. All blocks are exactly 512 bytes.
pub trait BlockDev {
    /// Number of 512-byte sectors on the device.
    fn block_count(&self) -> u64;
    /// Read one 512-byte sector at `lba` into `buf`.
    fn read_block(&self, lba: u64, buf: &mut [u8; 512]) -> Result<(), BlockErr>;
    /// Write one 512-byte sector at `lba`. Default: refuse (read-only). An arch
    /// driver only overrides this behind its own `p15-write` feature.
    fn write_block(&mut self, _lba: u64, _buf: &[u8; 512]) -> Result<(), BlockErr> {
        Err(BlockErr::WriteRefused)
    }
}

// Still to come alongside their phase (the boundary exists from commit one):
//   P3:  syscall entry


// ── A/B commit content rule (shared by the CM5 eMMC driver's Gate 1 and the QEMU self-test) ──
const SLOT_KEY: &[u8; 13] = b"kernel=heqk8-";

/// Offset of the slot letter of the ONE uncommented `kernel=heqk8-[ab].img` line in a sector
/// (start of sector or right after a newline), or None if there is none or more than one.
pub fn slot_line_letter(sec: &[u8; 512]) -> Option<usize> {
    let mut found = None;
    let mut o = 0usize;
    while o + SLOT_KEY.len() + 5 <= 512 {
        if &sec[o..o + SLOT_KEY.len()] == SLOT_KEY
            && (o == 0 || sec[o - 1] == b'\n')
            && matches!(sec[o + 13], b'a' | b'b')
            && &sec[o + 14..o + 18] == b".img"
        {
            if found.is_some() {
                return None;
            }
            found = Some(o + 13);
        }
        o += 1;
    }
    found
}

/// The A/B-commit content rule: `new` equals `cur` except for exactly ONE byte, and that byte is
/// the slot letter of `cur`'s single `kernel=heqk8-?.img` line, flipped a<->b.
pub fn is_slot_letter_flip(cur: &[u8; 512], new: &[u8; 512]) -> bool {
    let Some(p) = slot_line_letter(cur) else { return false };
    let mut diffs = 0usize;
    for k in 0..512 {
        if cur[k] != new[k] {
            diffs += 1;
            if k != p {
                return false;
            }
        }
    }
    diffs == 1 && matches!((cur[p], new[p]), (b'a', b'b') | (b'b', b'a'))
}

// ── Wi-Fi AP channel selection (ACS) — pure, shared by the CM5 AP bring-up and the QEMU self-test ──

/// One candidate the AP can actually run on this chip: UNII-1 (DFS fails on the CYW43455 CLM) and
/// the three non-overlapping 2.4 GHz channels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcsChoice {
    /// Primary (control) channel.
    pub channel: u8,
    /// d11ac chanspec to program.
    pub chanspec: u16,
    /// 80 / 20 MHz.
    pub mhz: u8,
    /// Interference score (sum of overlapping neighbours, power-weighted).
    pub score: u64,
}

/// Power-ish weight of a neighbour: doubles every 3 dB (≈ linear mW), -100 dBm → 1.
fn acs_weight(rssi: i16) -> u64 {
    let x = (rssi as i32 + 100).clamp(0, 60) as u32;
    1u64 << (x / 3)
}

/// The 20 MHz primaries a 5 GHz neighbour occupies, from its d11ac chanspec (center + bandwidth).
fn occ5(cs: u16) -> ([u8; 4], usize) {
    let c = (cs & 0xff) as i16;
    let ch = |d: i16| (c + d).clamp(0, 255) as u8;
    match cs & 0x3800 {
        0x1000 => ([ch(0), 0, 0, 0], 1),
        0x1800 => ([ch(-2), ch(2), 0, 0], 2),
        _ => ([ch(-6), ch(-2), ch(2), ch(6)], 4), // 80 MHz (and wider: treat as 80 — conservative)
    }
}

/// Choose the AP channel + width from a scan: `neigh` = (chanspec, rssi) of every BSS heard.
/// Candidates: 5 GHz 80 MHz on the UNII-1 block (36-48), 5 GHz 20 MHz on 36/40/44/48, 2.4 GHz
/// 20 MHz on 1/6/11. Neighbours weaker than ~-80 dBm count as a floor (ignorable); 20 MHz 5 GHz
/// pays a x2 handicap and 2.4 GHz a x8 handicap (throughput), so 5 GHz/80 wins whenever its block
/// is reasonably clear and a strong co-channel neighbour pushes the AP off it.
pub fn acs_choose(neigh: &[(u16, i16)]) -> AcsChoice {
    const FLOOR: u64 = 64; // ≈ one -82 dBm neighbour
    let mut best = AcsChoice { channel: 0, chanspec: 0, mhz: 0, score: u64::MAX };
    let mut best_eff = u64::MAX;
    let mut consider = |channel: u8, chanspec: u16, mhz: u8, score: u64, handicap: u64| {
        let eff = score.max(FLOOR).saturating_mul(handicap);
        if eff < best_eff {
            best_eff = eff;
            best = AcsChoice { channel, chanspec, mhz, score };
        }
    };
    let score5 = |prim: &[u8]| -> u64 {
        let mut sc = 0u64;
        for &(cs, rssi) in neigh {
            if cs & 0xc000 != 0xc000 {
                continue; // not 5 GHz
            }
            let (o, n) = occ5(cs);
            if o[..n].iter().any(|c| prim.contains(c)) {
                sc = sc.saturating_add(acs_weight(rssi));
            }
        }
        sc
    };
    // 5 GHz 80 MHz, UNII-1 block, primary 36 (chanspec 42 | BW80 | 5G, sideband LL).
    consider(36, 42 | 0x2000 | 0xc000, 80, score5(&[36, 40, 44, 48]), 1);
    for ch in [36u8, 40, 44, 48] {
        consider(ch, ch as u16 | 0x1000 | 0xc000, 20, score5(&[ch]), 2);
    }
    for ch in [1u8, 6, 11] {
        let mut sc = 0u64;
        for &(cs, rssi) in neigh {
            if cs & 0xc000 == 0xc000 {
                continue;
            }
            let c = (cs & 0xff) as i16;
            let reach = if cs & 0x3800 == 0x1800 { 6 } else { 4 }; // 40 MHz neighbours reach further
            if (c - ch as i16).abs() <= reach {
                sc = sc.saturating_add(acs_weight(rssi));
            }
        }
        consider(ch, ch as u16 | 0x1000, 20, sc, 8);
    }
    best
}

// ── SDPCM RX glomming (superframes) — a port of brcmfmac brcmf_sdio_rxglom's framing rules. ──
// Pure: shared by the CM5 Wi-Fi driver and the QEMU self-test.

/// SDPCM: 4-B hardware tag + 8-B software header.
pub const SDPCM_HDRLEN: usize = 12;
/// SDPCM channel of a glom descriptor / superframe.
pub const SDPCM_GLOM_CHANNEL: u8 = 3;
/// Max subframes per superframe we accept.
pub const GLOM_MAX_SUBS: usize = 32;

/// From a glom DESCRIPTOR body (the u16 LE sub-frame lengths after the 12-B header), compute the
/// sub-frame lengths and the superframe read length. Mirrors brcmf_sdio_rxglom: dlen must be
/// non-zero and even; every sublen >= SDPCM_HDRLEN and the first >= 2*SDPCM_HDRLEN (it also carries
/// the superframe header); the LAST sublen is padded so the total is a whole number of `blk`-byte
/// blocks. Returns (n, total) or None (brcmfmac then ignores the descriptor).
pub fn glom_plan(desc: &[u8], blk: usize, out: &mut [u16; GLOM_MAX_SUBS]) -> Option<(usize, usize)> {
    if desc.is_empty() || desc.len() % 2 != 0 || blk == 0 {
        return None;
    }
    let n = desc.len() / 2;
    if n > GLOM_MAX_SUBS {
        return None;
    }
    let mut total = 0usize;
    for k in 0..n {
        let sl = u16::from_le_bytes([desc[2 * k], desc[2 * k + 1]]) as usize;
        if sl < SDPCM_HDRLEN || (k == 0 && sl < 2 * SDPCM_HDRLEN) {
            return None;
        }
        out[k] = sl as u16;
        total += sl;
    }
    let padded = total.div_ceil(blk) * blk;
    let last = out[n - 1] as usize + (padded - total);
    if last > u16::MAX as usize {
        return None;
    }
    out[n - 1] = last as u16;
    Some((n, padded))
}

/// One validated sub-frame of a superframe: its bytes are `sup[start .. start + len]`, laid out as
/// a normal SDPCM frame (its own 12-B header at `start`), payload at `start + doff`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct GlomSub {
    pub start: u16,
    pub len: u16,
    pub chan: u8,
    pub doff: u8,
}

fn sdpcm_tag_ok(b: &[u8]) -> Option<usize> {
    if b.len() < SDPCM_HDRLEN {
        return None;
    }
    let len = u16::from_le_bytes([b[0], b[1]]);
    let ck = u16::from_le_bytes([b[2], b[3]]);
    if len == 0 || (len ^ ck) != 0xffff {
        return None;
    }
    Some(len as usize)
}

/// Validate a SUPERFRAME read against its plan and list its sub-frames (brcmf_sdio_hdparse SUPER
/// then SUB for each). Superframe header: valid tag, channel 3, not itself a descriptor, data offset
/// in [12, sublen0]. Sub-frame k occupies the planned region (sub-frame 0 starts after the superframe
/// header); its header must have a valid tag, length within its region, channel 1 (event) or 2
/// (data), data offset in [12, len]. Any violation -> None (brcmfmac terminates the whole superframe).
pub fn glom_split(sup: &[u8], subl: &[u16], out: &mut [GlomSub; GLOM_MAX_SUBS]) -> Option<usize> {
    let n = subl.len();
    if n == 0 || n > GLOM_MAX_SUBS {
        return None;
    }
    let total: usize = subl.iter().map(|&x| x as usize).sum();
    if sup.len() < total || sdpcm_tag_ok(sup).is_none() {
        return None;
    }
    let chan = sup[5] & 0x0f;
    let sdoff = sup[7] as usize;
    if chan != SDPCM_GLOM_CHANNEL || sup[5] & 0x80 != 0 || sdoff < SDPCM_HDRLEN || sdoff > subl[0] as usize {
        return None;
    }
    let mut cum = 0usize;
    for k in 0..n {
        let region_end = cum + subl[k] as usize;
        let start = if k == 0 { sdoff } else { cum };
        let reg = &sup[start..region_end];
        let len = sdpcm_tag_ok(reg)?;
        let c = reg[5] & 0x0f;
        let doff = reg[7] as usize;
        if len > reg.len() || (c != 1 && c != 2) || doff < SDPCM_HDRLEN || doff > len {
            return None;
        }
        out[k] = GlomSub { start: start as u16, len: len as u16, chan: c, doff: doff as u8 };
        cum = region_end;
    }
    Some(n)
}

// ── Internet checksum (RFC 1071) + IPv4 pseudo-header sum — pure, shared by the Wi-Fi driver,
// the NAT engine and the QEMU self-tests. ──

/// One's-complement checksum of `data` starting from the partial sum `init`.
pub fn inet_csum(data: &[u8], init: u32) -> u16 {
    let mut sum = init;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// TCP/UDP pseudo-header partial sum (src, dst, proto, L4 length).
pub fn pseudo_sum(sip: &[u8; 4], dip: &[u8; 4], proto: u8, l4len: u16) -> u32 {
    let mut s = 0u32;
    s += u16::from_be_bytes([sip[0], sip[1]]) as u32;
    s += u16::from_be_bytes([sip[2], sip[3]]) as u32;
    s += u16::from_be_bytes([dip[0], dip[1]]) as u32;
    s += u16::from_be_bytes([dip[2], dip[3]]) as u32;
    s += proto as u32;
    s += l4len as u32;
    s
}
