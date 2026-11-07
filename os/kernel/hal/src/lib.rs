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
    /// Strong (>= ACS_STRONG_DBM) co-channel networks sharing this candidate's airtime.
    pub score: u64,
    /// Estimated share of the peak 1x1 PHY rate, Mbps: peak / (1 + strong co-channel networks).
    pub est_mbps: u32,
}

/// A neighbour weaker than this does not meaningfully contend for airtime.
pub const ACS_STRONG_DBM: i16 = -82;

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
///
/// Policy = maximise the EXPECTED THROUGHPUT, not minimise neighbour loudness. Co-channel BSSs
/// share airtime (CSMA), so a candidate's estimate is its peak 1x1 PHY rate divided by
/// (1 + the strong networks overlapping it): VHT80 433, VHT20 87, HT20 72 Mbps. Measured on the
/// bench (2026-11-04/05, iPhone): 5 GHz/80 shared with a -51 dBm 80-MHz neighbour = 22 Mbps vs a
/// clean 2.4 GHz/20 = 15 Mbps — the previous loudness-weighted policy picked the slower one.
/// This is a MODEL of airtime, not a measurement of channel busy time.
/// Candidates: 5 GHz 80 MHz on the UNII-1 block, 5 GHz 20 MHz on 36/40/44/48, 2.4 GHz 1/6/11.
pub fn acs_choose(neigh: &[(u16, i16)]) -> AcsChoice {
    acs_choose_allowed(neigh, &[])
}

/// `acs_choose` restricted to the regulatory domain: a candidate is considered only if its exact
/// chanspec is in `allowed` (the firmware's `chanspecs` list for the configured country). An
/// EMPTY `allowed` means "no list available" and applies no restriction (QEMU vectors / a
/// firmware that does not answer); if NO candidate is allowed the result has channel 0.
pub fn acs_choose_allowed(neigh: &[(u16, i16)], allowed: &[u16]) -> AcsChoice {
    let mut best = AcsChoice { channel: 0, chanspec: 0, mhz: 0, score: 0, est_mbps: 0 };
    let mut consider = |channel: u8, chanspec: u16, mhz: u8, strong: u64, peak: u32| {
        if !allowed.is_empty() && !allowed.contains(&chanspec) {
            return;
        }
        let est = peak / (1 + strong as u32);
        if est > best.est_mbps {
            best = AcsChoice { channel, chanspec, mhz, score: strong, est_mbps: est };
        }
    };
    let strong5 = |prim: &[u8]| -> u64 {
        neigh.iter().filter(|&&(cs, rssi)| {
            cs & 0xc000 == 0xc000 && rssi >= ACS_STRONG_DBM && {
                let (o, n) = occ5(cs);
                o[..n].iter().any(|c| prim.contains(c))
            }
        }).count() as u64
    };
    // Order = tie preference: 5 GHz/80 first, then 5 GHz/20, then 2.4 GHz.
    consider(36, 42 | 0x2000 | 0xc000, 80, strong5(&[36, 40, 44, 48]), 433);
    for ch in [36u8, 40, 44, 48] {
        consider(ch, ch as u16 | 0x1000 | 0xc000, 20, strong5(&[ch]), 87);
    }
    for ch in [1u8, 6, 11] {
        let strong = neigh.iter().filter(|&&(cs, rssi)| {
            cs & 0xc000 != 0xc000 && rssi >= ACS_STRONG_DBM && {
                let c = (cs & 0xff) as i16;
                let reach = if cs & 0x3800 == 0x1800 { 6 } else { 4 }; // 40 MHz neighbours reach further
                (c - ch as i16).abs() <= reach
            }
        }).count() as u64;
        consider(ch, ch as u16 | 0x1000, 20, strong, 72);
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
pub const GLOM_MAX_SUBS: usize = 64; // 48-KB superframes of ~1.5-KB sub-frames need > 32

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

// ── WAN configuration (WAN.TXT on the boot partition) — pure parser, QEMU-tested. ──

/// First line of WAN.TXT.
pub const WAN_CFG_MAGIC: &[u8] = b"HQWAN1";
/// WAN.TXT is exactly one 512-B sector (patched in place by the flasher / Mission Control).
pub const WAN_CFG_LEN: usize = 512;
/// Max PPPoE username / password length.
pub const WAN_CRED_MAX: usize = 64;

/// How the WAN port (end0) gets its address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WanMode {
    /// DHCP client (the default).
    Dhcp,
    /// Static address: `ip/prefix`, default gateway, resolver.
    Static { ip: [u8; 4], prefix: u8, gw: [u8; 4], dns: [u8; 4] },
    /// PPPoE client (RFC 2516) with PAP/CHAP credentials.
    Pppoe { user: [u8; WAN_CRED_MAX], user_len: u8, pass: [u8; WAN_CRED_MAX], pass_len: u8 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WanCfgErr {
    /// First non-empty line is not `HQWAN1`.
    NoMagic,
    /// A line is not `key=value`, or the key is unknown.
    BadLine,
    /// `mode=` missing or not dhcp/static/pppoe.
    BadMode,
    /// A field the mode needs is missing.
    Missing,
    /// An address is not a dotted quad.
    BadAddr,
    /// Prefix outside 8..=30.
    BadPrefix,
    /// Address is the network or broadcast address of its subnet.
    BadHost,
    /// Gateway not inside the subnet, or equal to the address.
    BadGateway,
    /// Credential empty / too long / not printable.
    BadCred,
}

fn parse_quad(v: &[u8]) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut k = 0usize;
    let mut cur: u32 = 0;
    let mut digits = 0;
    for &c in v.iter().chain(core::iter::once(&b'.')) {
        if c == b'.' {
            if digits == 0 || k >= 4 || cur > 255 {
                return None;
            }
            out[k] = cur as u8;
            k += 1;
            cur = 0;
            digits = 0;
        } else if c.is_ascii_digit() {
            cur = cur * 10 + (c - b'0') as u32;
            digits += 1;
            if digits > 3 {
                return None;
            }
        } else {
            return None;
        }
    }
    if k == 4 { Some(out) } else { None }
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if first.is_ascii_whitespace() { s = rest } else { break }
    }
    while let [rest @ .., last] = s {
        if last.is_ascii_whitespace() { s = rest } else { break }
    }
    s
}

/// Parse WAN.TXT. Format (one `key=value` per line, `#` comments, blank lines and trailing
/// padding ignored, CRLF accepted):
/// ```text
/// HQWAN1
/// mode=dhcp | static | pppoe
/// ip=192.0.2.10/24     (static)
/// gw=192.0.2.1         (static)
/// dns=192.0.2.1        (static, optional: defaults to the gateway)
/// pppoe_user=...       (pppoe)
/// pppoe_pass=...       (pppoe, may be empty)
/// ```
pub fn parse_wan_cfg(buf: &[u8]) -> Result<WanMode, WanCfgErr> {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let mut magic = false;
    let (mut mode, mut ip, mut prefix, mut gw, mut dns) = (None::<&[u8]>, None, None, None, None);
    let (mut user, mut pass) = (None::<&[u8]>, None::<&[u8]>);
    for raw in buf[..end].split(|&b| b == b'\n') {
        let line = trim(raw);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        if !magic {
            if line != WAN_CFG_MAGIC {
                return Err(WanCfgErr::NoMagic);
            }
            magic = true;
            continue;
        }
        let eq = line.iter().position(|&b| b == b'=').ok_or(WanCfgErr::BadLine)?;
        let (k, v) = (trim(&line[..eq]), trim(&line[eq + 1..]));
        match k {
            b"mode" => mode = Some(v),
            b"ip" => {
                let slash = v.iter().position(|&b| b == b'/').ok_or(WanCfgErr::BadPrefix)?;
                ip = Some(parse_quad(&v[..slash]).ok_or(WanCfgErr::BadAddr)?);
                let p = &v[slash + 1..];
                if p.is_empty() || p.len() > 2 || !p.iter().all(|c| c.is_ascii_digit()) {
                    return Err(WanCfgErr::BadPrefix);
                }
                prefix = Some(p.iter().fold(0u8, |a, &c| a * 10 + (c - b'0')));
            }
            b"gw" => gw = Some(parse_quad(v).ok_or(WanCfgErr::BadAddr)?),
            b"dns" => dns = Some(parse_quad(v).ok_or(WanCfgErr::BadAddr)?),
            b"pppoe_user" => user = Some(v),
            b"pppoe_pass" => pass = Some(v),
            // link-level keys: parsed by parse_wan_link
            b"vlan" | b"vlan_outer" | b"pcp" | b"mgmt_vlan" | b"mgmt" | b"mgmt_ip" | b"mgmt_gw" | b"mgmt_floor" => {}
            _ => return Err(WanCfgErr::BadLine),
        }
    }
    if !magic {
        return Err(WanCfgErr::NoMagic);
    }
    match mode {
        Some(b"dhcp") => Ok(WanMode::Dhcp),
        Some(b"static") => {
            let (ip, prefix, gw) = (ip.ok_or(WanCfgErr::Missing)?, prefix.ok_or(WanCfgErr::Missing)?, gw.ok_or(WanCfgErr::Missing)?);
            if !(8..=30).contains(&prefix) {
                return Err(WanCfgErr::BadPrefix);
            }
            let mask: u32 = u32::MAX << (32 - prefix as u32);
            let (a, g) = (u32::from_be_bytes(ip), u32::from_be_bytes(gw));
            if a & !mask == 0 || a & !mask == !mask {
                return Err(WanCfgErr::BadHost);
            }
            if a & mask != g & mask || g == a || g & !mask == 0 || g & !mask == !mask {
                return Err(WanCfgErr::BadGateway);
            }
            Ok(WanMode::Static { ip, prefix, gw, dns: dns.unwrap_or(gw) })
        }
        Some(b"pppoe") => {
            let u = user.ok_or(WanCfgErr::Missing)?;
            let p = pass.unwrap_or(b"");
            let ok = |s: &[u8]| s.len() <= WAN_CRED_MAX && s.iter().all(|&c| (0x21..0x7f).contains(&c));
            if u.is_empty() || !ok(u) || !ok(p) {
                return Err(WanCfgErr::BadCred);
            }
            let mut ub = [0u8; WAN_CRED_MAX];
            let mut pb = [0u8; WAN_CRED_MAX];
            ub[..u.len()].copy_from_slice(u);
            pb[..p.len()].copy_from_slice(p);
            Ok(WanMode::Pppoe { user: ub, user_len: u.len() as u8, pass: pb, pass_len: p.len() as u8 })
        }
        _ => Err(WanCfgErr::BadMode),
    }
}

/// The management sub-interface on the WAN port (a separate VLAN; never the internet one).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtIf {
    pub vlan: u16,
    /// None = DHCP; Some = static (ip, prefix, gateway).
    pub stat: Option<([u8; 4], u8, [u8; 4])>,
}

/// Link-level WAN settings from WAN.TXT: how the internet sub-interface is tagged, and the optional
/// management sub-interface. Keys: `vlan=<1-4094>`, `vlan_outer=<1-4094>` (QinQ S-tag, needs `vlan`),
/// `pcp=<0-7>`, `mgmt_vlan=<1-4094>` (must differ from `vlan`), `mgmt=dhcp|static`,
/// `mgmt_ip=<a.b.c.d/len>`, `mgmt_gw=<a.b.c.d>`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WanLink {
    pub vlan: u16,
    pub outer: u16,
    pub pcp: u8,
    pub mgmt: Option<MgmtIf>,
    /// `mgmt_floor=a.b.c.d/len` — the management allowlist floor (never enforced against), /8../32.
    pub floor: Option<([u8; 4], u8)>,
    /// A `mgmt_floor=` line was present but invalid (ignored; reported at boot).
    pub floor_bad: bool,
}

pub fn parse_wan_link(buf: &[u8]) -> Result<WanLink, WanCfgErr> {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let mut l = WanLink::default();
    let (mut mvlan, mut mmode, mut mip, mut mgw) = (0u16, None::<&[u8]>, None::<([u8; 4], u8)>, None::<[u8; 4]>);
    let vid = |v: &[u8]| -> Result<u16, WanCfgErr> {
        if v.is_empty() || v.len() > 4 || !v.iter().all(|c| c.is_ascii_digit()) {
            return Err(WanCfgErr::BadLine);
        }
        let n = v.iter().fold(0u32, |a, &c| a * 10 + (c - b'0') as u32);
        if (1..=4094).contains(&n) { Ok(n as u16) } else { Err(WanCfgErr::BadLine) }
    };
    let mut magic = false;
    for raw in buf[..end].split(|&b| b == b'\n') {
        let line = trim(raw);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        if !magic {
            if line != WAN_CFG_MAGIC {
                return Err(WanCfgErr::NoMagic);
            }
            magic = true;
            continue;
        }
        let eq = line.iter().position(|&b| b == b'=').ok_or(WanCfgErr::BadLine)?;
        let (k, v) = (trim(&line[..eq]), trim(&line[eq + 1..]));
        match k {
            b"vlan" => l.vlan = vid(v)?,
            b"vlan_outer" => l.outer = vid(v)?,
            b"pcp" => {
                if v.len() != 1 || !(b'0'..=b'7').contains(&v[0]) {
                    return Err(WanCfgErr::BadLine);
                }
                l.pcp = v[0] - b'0';
            }
            b"mgmt_vlan" => mvlan = vid(v)?,
            b"mgmt" => mmode = Some(v),
            b"mgmt_ip" => {
                let slash = v.iter().position(|&b| b == b'/').ok_or(WanCfgErr::BadPrefix)?;
                let ip = parse_quad(&v[..slash]).ok_or(WanCfgErr::BadAddr)?;
                let p = &v[slash + 1..];
                if p.is_empty() || p.len() > 2 || !p.iter().all(|c| c.is_ascii_digit()) {
                    return Err(WanCfgErr::BadPrefix);
                }
                let pl = p.iter().fold(0u8, |a, &c| a * 10 + (c - b'0'));
                if !(8..=30).contains(&pl) {
                    return Err(WanCfgErr::BadPrefix);
                }
                mip = Some((ip, pl));
            }
            b"mgmt_gw" => mgw = Some(parse_quad(v).ok_or(WanCfgErr::BadAddr)?),
            b"mgmt_floor" => 'mf: {
                let Some(slash) = v.iter().position(|&b| b == b'/') else { l.floor_bad = true; break 'mf };
                let Some(ip) = parse_quad(&v[..slash]) else { l.floor_bad = true; break 'mf };
                let p = &v[slash + 1..];
                if p.is_empty() || p.len() > 2 || !p.iter().all(|c| c.is_ascii_digit()) {
                    l.floor_bad = true;
                    break 'mf;
                }
                let pl = p.iter().fold(0u8, |a, &c| a * 10 + (c - b'0'));
                // /8../32 (a /32 = one admin host is the NARROWEST, safest floor — re-review M4). A bad
                // value is ignored (flagged by `floor_bad`), never fatal: it must not untag the internet.
                if (8..=32).contains(&pl) {
                    l.floor = Some((ip, pl));
                } else {
                    l.floor_bad = true;
                }
            }
            _ => {}
        }
    }
    if !magic {
        return Err(WanCfgErr::NoMagic);
    }
    if l.outer != 0 && l.vlan == 0 {
        return Err(WanCfgErr::Missing); // QinQ needs the inner (customer) tag
    }
    if mvlan != 0 {
        if mvlan == l.vlan {
            return Err(WanCfgErr::BadLine); // management must be its own VLAN
        }
        let stat = match mmode {
            None | Some(b"dhcp") => None,
            Some(b"static") => {
                let (ip, pl) = mip.ok_or(WanCfgErr::Missing)?;
                let gw = mgw.ok_or(WanCfgErr::Missing)?;
                let mask: u32 = u32::MAX << (32 - pl as u32);
                if u32::from_be_bytes(ip) & mask != u32::from_be_bytes(gw) & mask || ip == gw {
                    return Err(WanCfgErr::BadGateway);
                }
                Some((ip, pl, gw))
            }
            _ => return Err(WanCfgErr::BadMode),
        };
        l.mgmt = Some(MgmtIf { vlan: mvlan, stat });
    } else if mmode.is_some() || mip.is_some() {
        return Err(WanCfgErr::Missing); // management settings without a management VLAN
    }
    Ok(l)
}

// ── MD5 (RFC 1321) — needed ONLY for PPP CHAP-MD5 (RFC 1994), which ISPs still require. Not used
// for any integrity or security decision of heqk's own. ──

/// MD5 digest of `data` (RFC 1321).
pub fn md5(data: &[u8]) -> [u8; 16] {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];
    let mut st: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    let bitlen = (data.len() as u64).wrapping_mul(8);
    let total = (data.len() + 9).div_ceil(64) * 64;
    let mut blk = [0u8; 64];
    let mut off = 0;
    while off < total {
        for i in 0..64 {
            let k = off + i;
            blk[i] = if k < data.len() {
                data[k]
            } else if k == data.len() {
                0x80
            } else if k >= total - 8 {
                (bitlen >> (8 * (k - (total - 8)))) as u8
            } else {
                0
            };
        }
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([blk[4 * i], blk[4 * i + 1], blk[4 * i + 2], blk[4 * i + 3]]);
        }
        let (mut a, mut b, mut c, mut d) = (st[0], st[1], st[2], st[3]);
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let t = d;
            d = c;
            c = b;
            b = b.wrapping_add(a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]).rotate_left(S[i]));
            a = t;
        }
        st[0] = st[0].wrapping_add(a);
        st[1] = st[1].wrapping_add(b);
        st[2] = st[2].wrapping_add(c);
        st[3] = st[3].wrapping_add(d);
        off += 64;
    }
    let mut out = [0u8; 16];
    for i in 0..4 {
        out[4 * i..4 * i + 4].copy_from_slice(&st[i].to_le_bytes());
    }
    out
}

/// WAN policy engine: prefix lists, ACLs, routes, sub-interface encapsulation (POLICY.TXT).
pub mod policy;
pub mod defer;
pub mod tlsabi;
