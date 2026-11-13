//! Bounded, allocation-free Flattened Device Tree (DTB) reader for HBoot's platform discovery
//! (ADR 0061 D1, ADR 0062 T0). HBoot owns platform discovery; the kernel never parses a raw DTB.
//!
//! Extracts only what the T0 inventory and memory discovery need:
//! - `/memory*` (device_type = "memory"): `reg` ranges, using the ROOT `#address-cells` / `#size-cells`;
//! - `/reserved-memory/*`: `reg` ranges (own cells) plus the header's memory-reservation block, and `no-map`;
//! - `/cpus/cpu@*` (device_type = "cpu"): `reg` (MPIDR affinity), `enable-method`, `cpu-release-addr`, `status`;
//! - `/psci`: `method` ("smc" | "hvc") and whether `compatible` names PSCI 0.2 / 1.0.
//!
//! Hostile-input rules (ADR 0050 D3): every offset and length is checked against the blob AND the header's
//! own section bounds; the token walk is bounded by the struct-block size; nesting depth is capped; a node or
//! property the fixed tables cannot hold sets a `truncated` flag (reported, never silently dropped); any
//! malformation returns `Err` and NOTHING partial is used. No unsafe, no allocation, no recursion.

pub const FDT_MAGIC: u32 = 0xd00d_feed;
/// A DTB larger than this is refused (the Pi firmware DTB is tens of KiB).
pub const MAX_BLOB: usize = 1 << 20;
pub const MAX_DEPTH: usize = 16;
pub const MAX_MEM: usize = 16;
pub const MAX_RESV: usize = 32;
pub const MAX_CPUS: usize = 64;

const TOK_BEGIN: u32 = 1;
const TOK_END: u32 = 2;
const TOK_PROP: u32 = 3;
const TOK_NOP: u32 = 4;
const TOK_FINISH: u32 = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FdtErr {
    TooSmall,
    BadMagic,
    BadVersion,
    BadHeader,
    BadToken,
    BadName,
    BadProp,
    TooDeep,
    Unbalanced,
    NoEnd,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Range {
    pub base: u64,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EnableMethod {
    /// No `enable-method` property.
    #[default]
    None,
    Psci,
    SpinTable,
    /// Present but neither "psci" nor "spin-table".
    Other,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cpu {
    /// `reg`: the MPIDR affinity value (1 or 2 cells per `/cpus` `#address-cells`).
    pub mpidr: u64,
    pub method: EnableMethod,
    /// `cpu-release-addr` (spin-table), 0 if absent.
    pub release_addr: u64,
    /// `status` absent, "okay" or "ok".
    pub enabled: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Conduit {
    /// No `/psci` node, or no `method`.
    #[default]
    None,
    Smc,
    Hvc,
    Other,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Psci {
    pub present: bool,
    pub method: Conduit,
    /// `compatible` lists "arm,psci-0.2" or "arm,psci-1.0" (function ids are then the standard ones).
    pub v02_plus: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Inventory {
    pub mem: [Range; MAX_MEM],
    pub nmem: usize,
    pub resv: [Range; MAX_RESV],
    pub nresv: usize,
    /// How many `resv` entries came from `/reserved-memory` with `no-map`.
    pub resv_nomap: usize,
    pub cpus: [Cpu; MAX_CPUS],
    pub ncpus: usize,
    pub psci: Psci,
    pub boot_cpuid_phys: u32,
    /// Some table was full: the inventory is INCOMPLETE and must be reported as such.
    pub truncated: bool,
}

impl Default for Inventory {
    fn default() -> Self {
        Inventory {
            mem: [Range::default(); MAX_MEM],
            nmem: 0,
            resv: [Range::default(); MAX_RESV],
            nresv: 0,
            resv_nomap: 0,
            cpus: [Cpu::default(); MAX_CPUS],
            ncpus: 0,
            psci: Psci::default(),
            boot_cpuid_phys: 0,
            truncated: false,
        }
    }
}

impl Inventory {
    /// Sum of all `/memory` range sizes (saturating).
    pub fn mem_total(&self) -> u64 {
        self.mem[..self.nmem].iter().fold(0u64, |a, r| a.saturating_add(r.size))
    }
}

fn be32(b: &[u8], o: usize) -> Option<u32> {
    let s = b.get(o..o.checked_add(4)?)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn be64(b: &[u8], o: usize) -> Option<u64> {
    Some(((be32(b, o)? as u64) << 32) | be32(b, o + 4)? as u64)
}

fn align4(x: usize) -> Option<usize> {
    x.checked_add(3).map(|v| v & !3)
}

/// Read a `cells`-cell big-endian number (1 or 2 cells; anything else is refused).
fn cells_val(v: &[u8], cells: u32) -> Option<u64> {
    match cells {
        1 => be32(v, 0).map(u64::from),
        2 => be64(v, 0),
        _ => None,
    }
}

/// Node kinds we care about, decided from the path (depth + name) and, for memory/cpu, device_type.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Other,
    Root,
    MaybeMemory,
    ResvParent,
    ResvChild,
    Cpus,
    MaybeCpu,
    Psci,
}

#[derive(Clone, Copy)]
struct Frame<'a> {
    kind: Kind,
    reg: &'a [u8],
    dev_type: &'a [u8],
    status_ok: bool,
    method: EnableMethod,
    release: u64,
    no_map: bool,
    psci_method: Conduit,
    psci_v02: bool,
    addr_cells: u32,
    size_cells: u32,
}

impl<'a> Frame<'a> {
    fn new(kind: Kind) -> Self {
        Frame {
            kind,
            reg: &[],
            dev_type: &[],
            status_ok: true,
            method: EnableMethod::None,
            release: 0,
            no_map: false,
            psci_method: Conduit::None,
            psci_v02: false,
            // Devicetree spec defaults when a node does not set them.
            addr_cells: 2,
            size_cells: 1,
        }
    }
}

/// A NUL-terminated string property's bytes without the terminator (first string only).
fn str0(v: &[u8]) -> &[u8] {
    match v.iter().position(|&c| c == 0) {
        Some(i) => &v[..i],
        None => v,
    }
}

/// Does a NUL-separated string list contain `want`?
fn strlist_has(v: &[u8], want: &[u8]) -> bool {
    v.split(|&c| c == 0).any(|s| s == want)
}

fn node_base(name: &[u8]) -> &[u8] {
    match name.iter().position(|&c| c == b'@') {
        Some(i) => &name[..i],
        None => name,
    }
}

/// Push `reg` ranges into `out` using the PARENT's cells. Returns false if the reg is malformed.
fn push_ranges(reg: &[u8], ac: u32, sc: u32, out: &mut [Range], n: &mut usize, trunc: &mut bool) -> bool {
    if !(1..=2).contains(&ac) || !(1..=2).contains(&sc) {
        return reg.is_empty();
    }
    let stride = 4 * (ac + sc) as usize;
    if !reg.len().is_multiple_of(stride) {
        return false;
    }
    for e in reg.chunks_exact(stride) {
        let base = cells_val(e, ac).unwrap_or(0);
        let size = cells_val(&e[4 * ac as usize..], sc).unwrap_or(0);
        if size == 0 {
            continue;
        }
        if *n == out.len() {
            *trunc = true;
            return true;
        }
        out[*n] = Range { base, size };
        *n += 1;
    }
    true
}

/// Parse a DTB blob. `blob` may be longer than the DTB (the header's `totalsize` bounds the walk).
pub fn parse(blob: &[u8]) -> Result<Inventory, FdtErr> {
    if blob.len() < 40 {
        return Err(FdtErr::TooSmall);
    }
    if be32(blob, 0) != Some(FDT_MAGIC) {
        return Err(FdtErr::BadMagic);
    }
    let h = |i: usize| be32(blob, 4 * i).unwrap_or(0) as usize;
    let (total, off_struct, off_strings, off_rsv, version, last_comp) = (h(1), h(2), h(3), h(4), h(5), h(6));
    let boot_cpuid = h(7) as u32;
    let (size_strings, size_struct) = (h(8), h(9));
    // version >= 17 carries size_dt_struct; last_comp_version must be <= 17 for us to understand it.
    if version < 17 || last_comp > 17 {
        return Err(FdtErr::BadVersion);
    }
    if total > blob.len() || !(40..=MAX_BLOB).contains(&total) {
        return Err(FdtErr::BadHeader);
    }
    let blob = &blob[..total];
    let end_struct = off_struct.checked_add(size_struct).ok_or(FdtErr::BadHeader)?;
    let end_strings = off_strings.checked_add(size_strings).ok_or(FdtErr::BadHeader)?;
    if !off_struct.is_multiple_of(4) || !off_rsv.is_multiple_of(8) || end_struct > total || end_strings > total || off_rsv >= total {
        return Err(FdtErr::BadHeader);
    }
    let strings = &blob[off_strings..end_strings];

    let mut inv = Inventory { boot_cpuid_phys: boot_cpuid, ..Inventory::default() };

    // Memory reservation block: (address, size) pairs of u64 until (0, 0).
    let mut o = off_rsv;
    loop {
        let (a, s) = (be64(blob, o).ok_or(FdtErr::BadHeader)?, be64(blob, o + 8).ok_or(FdtErr::BadHeader)?);
        if a == 0 && s == 0 {
            break;
        }
        if inv.nresv == MAX_RESV {
            inv.truncated = true;
        } else {
            inv.resv[inv.nresv] = Range { base: a, size: s };
            inv.nresv += 1;
        }
        o += 16;
        if o + 16 > total {
            return Err(FdtErr::BadHeader);
        }
    }

    let mut stack: [Frame; MAX_DEPTH] = [Frame::new(Kind::Other); MAX_DEPTH];
    let mut depth = 0usize;
    let mut p = off_struct;
    let mut finished = false;
    while p < end_struct {
        let tok = be32(blob, p).ok_or(FdtErr::BadToken)?;
        p += 4;
        match tok {
            TOK_BEGIN => {
                let rest = blob.get(p..end_struct).ok_or(FdtErr::BadName)?;
                let nl = rest.iter().position(|&c| c == 0).ok_or(FdtErr::BadName)?;
                let name = &rest[..nl];
                p = align4(p + nl + 1).ok_or(FdtErr::BadName)?;
                if depth == MAX_DEPTH {
                    return Err(FdtErr::TooDeep);
                }
                let parent = if depth == 0 { None } else { Some(stack[depth - 1].kind) };
                let base = node_base(name);
                let kind = match (depth, parent) {
                    (0, _) => Kind::Root,
                    (1, _) if base == b"memory" => Kind::MaybeMemory,
                    (1, _) if base == b"reserved-memory" => Kind::ResvParent,
                    (1, _) if base == b"cpus" => Kind::Cpus,
                    (1, _) if base == b"psci" => Kind::Psci,
                    (2, Some(Kind::ResvParent)) => Kind::ResvChild,
                    (2, Some(Kind::Cpus)) if base == b"cpu" => Kind::MaybeCpu,
                    _ => Kind::Other,
                };
                stack[depth] = Frame::new(kind);
                depth += 1;
            }
            TOK_END => {
                if depth == 0 {
                    return Err(FdtErr::Unbalanced);
                }
                depth -= 1;
                let f = stack[depth];
                let (pac, psc) = if depth > 0 { (stack[depth - 1].addr_cells, stack[depth - 1].size_cells) } else { (2, 1) };
                match f.kind {
                    Kind::MaybeMemory if f.dev_type == b"memory" && f.status_ok => {
                        if !push_ranges(f.reg, pac, psc, &mut inv.mem, &mut inv.nmem, &mut inv.truncated) {
                            return Err(FdtErr::BadProp);
                        }
                    }
                    Kind::ResvChild if f.status_ok => {
                        let before = inv.nresv;
                        if !push_ranges(f.reg, pac, psc, &mut inv.resv, &mut inv.nresv, &mut inv.truncated) {
                            return Err(FdtErr::BadProp);
                        }
                        if f.no_map {
                            inv.resv_nomap += inv.nresv - before;
                        }
                    }
                    Kind::MaybeCpu if f.dev_type == b"cpu" => {
                        let mpidr = match pac {
                            1 | 2 if f.reg.len() >= 4 * pac as usize => cells_val(f.reg, pac).ok_or(FdtErr::BadProp)?,
                            _ => return Err(FdtErr::BadProp),
                        };
                        if inv.ncpus == MAX_CPUS {
                            inv.truncated = true;
                        } else {
                            inv.cpus[inv.ncpus] = Cpu { mpidr, method: f.method, release_addr: f.release, enabled: f.status_ok };
                            inv.ncpus += 1;
                        }
                    }
                    Kind::Psci => {
                        inv.psci = Psci { present: true, method: f.psci_method, v02_plus: f.psci_v02 };
                    }
                    _ => {}
                }
                if depth == 0 {
                    // The root closed: only NOPs and FDT_END may follow.
                    while p < end_struct {
                        match be32(blob, p).ok_or(FdtErr::BadToken)? {
                            TOK_NOP => p += 4,
                            TOK_FINISH => {
                                finished = true;
                                break;
                            }
                            _ => return Err(FdtErr::Unbalanced),
                        }
                    }
                    break;
                }
            }
            TOK_PROP => {
                let len = be32(blob, p).ok_or(FdtErr::BadProp)? as usize;
                let nameoff = be32(blob, p + 4).ok_or(FdtErr::BadProp)? as usize;
                let vstart = p + 8;
                let vend = vstart.checked_add(len).ok_or(FdtErr::BadProp)?;
                if vend > end_struct || depth == 0 {
                    return Err(FdtErr::BadProp);
                }
                let v = &blob[vstart..vend];
                p = align4(vend).ok_or(FdtErr::BadProp)?;
                let pn_all = strings.get(nameoff..).ok_or(FdtErr::BadProp)?;
                let pn = &pn_all[..pn_all.iter().position(|&c| c == 0).ok_or(FdtErr::BadProp)?];
                let f = &mut stack[depth - 1];
                match pn {
                    b"#address-cells" => f.addr_cells = be32(v, 0).ok_or(FdtErr::BadProp)?,
                    b"#size-cells" => f.size_cells = be32(v, 0).ok_or(FdtErr::BadProp)?,
                    b"reg" => f.reg = v,
                    b"device_type" => f.dev_type = str0(v),
                    b"status" => {
                        let s = str0(v);
                        f.status_ok = s == b"okay" || s == b"ok";
                    }
                    b"no-map" => f.no_map = true,
                    b"enable-method" => {
                        f.method = if strlist_has(v, b"psci") {
                            EnableMethod::Psci
                        } else if strlist_has(v, b"spin-table") {
                            EnableMethod::SpinTable
                        } else {
                            EnableMethod::Other
                        }
                    }
                    b"cpu-release-addr" => {
                        f.release = match v.len() {
                            4 => be32(v, 0).map(u64::from).ok_or(FdtErr::BadProp)?,
                            8 => be64(v, 0).ok_or(FdtErr::BadProp)?,
                            _ => return Err(FdtErr::BadProp),
                        }
                    }
                    b"method" if f.kind == Kind::Psci => {
                        f.psci_method = match str0(v) {
                            b"smc" => Conduit::Smc,
                            b"hvc" => Conduit::Hvc,
                            _ => Conduit::Other,
                        }
                    }
                    b"compatible" if f.kind == Kind::Psci => {
                        f.psci_v02 = strlist_has(v, b"arm,psci-0.2") || strlist_has(v, b"arm,psci-1.0");
                    }
                    _ => {}
                }
            }
            TOK_NOP => {}
            TOK_FINISH => {
                if depth != 0 {
                    return Err(FdtErr::Unbalanced);
                }
                finished = true;
                break;
            }
            _ => return Err(FdtErr::BadToken),
        }
    }
    if !finished {
        return Err(FdtErr::NoEnd);
    }
    Ok(inv)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    /// Minimal FDT builder for tests (version 17).
    struct B {
        st: Vec<u8>,
        strs: Vec<u8>,
        rsv: Vec<(u64, u64)>,
    }
    impl B {
        fn new() -> Self {
            B { st: Vec::new(), strs: Vec::new(), rsv: Vec::new() }
        }
        fn tok(&mut self, t: u32) {
            self.st.extend_from_slice(&t.to_be_bytes());
        }
        fn pad(&mut self) {
            while self.st.len() % 4 != 0 {
                self.st.push(0);
            }
        }
        fn begin(&mut self, name: &str) -> &mut Self {
            self.tok(TOK_BEGIN);
            self.st.extend_from_slice(name.as_bytes());
            self.st.push(0);
            self.pad();
            self
        }
        fn end(&mut self) -> &mut Self {
            self.tok(TOK_END);
            self
        }
        fn prop(&mut self, name: &str, v: &[u8]) -> &mut Self {
            let off = match self.strs.windows(name.len() + 1).position(|w| &w[..name.len()] == name.as_bytes() && w[name.len()] == 0) {
                Some(o) => o,
                None => {
                    let o = self.strs.len();
                    self.strs.extend_from_slice(name.as_bytes());
                    self.strs.push(0);
                    o
                }
            };
            self.tok(TOK_PROP);
            self.st.extend_from_slice(&(v.len() as u32).to_be_bytes());
            self.st.extend_from_slice(&(off as u32).to_be_bytes());
            self.st.extend_from_slice(v);
            self.pad();
            self
        }
        fn u32p(&mut self, name: &str, x: u32) -> &mut Self {
            self.prop(name, &x.to_be_bytes())
        }
        fn s(&mut self, name: &str, x: &str) -> &mut Self {
            let mut v = x.as_bytes().to_vec();
            v.push(0);
            self.prop(name, &v)
        }
        fn build(&mut self) -> Vec<u8> {
            self.tok(TOK_FINISH);
            let mut rsv = Vec::new();
            for &(a, s) in &self.rsv {
                rsv.extend_from_slice(&a.to_be_bytes());
                rsv.extend_from_slice(&s.to_be_bytes());
            }
            rsv.extend_from_slice(&[0u8; 16]);
            let off_rsv = 40usize;
            let off_struct = off_rsv + rsv.len();
            let off_strings = off_struct + self.st.len();
            let total = off_strings + self.strs.len();
            let mut h = Vec::new();
            for v in [FDT_MAGIC, total as u32, off_struct as u32, off_strings as u32, off_rsv as u32, 17, 16, 0, self.strs.len() as u32, self.st.len() as u32] {
                h.extend_from_slice(&v.to_be_bytes());
            }
            h.extend_from_slice(&rsv);
            h.extend_from_slice(&self.st);
            h.extend_from_slice(&self.strs);
            h
        }
    }

    fn regs(pairs: &[(u64, u64)]) -> Vec<u8> {
        let mut v = Vec::new();
        for &(a, s) in pairs {
            v.extend_from_slice(&a.to_be_bytes());
            v.extend_from_slice(&s.to_be_bytes());
        }
        v
    }

    /// A CM5-shaped tree: 2/2 cells, two memory ranges, PSCI over SMC, four PSCI cores, a no-map reservation.
    fn sample() -> Vec<u8> {
        let mut b = B::new();
        b.rsv.push((0x0, 0x1000));
        b.begin("").u32p("#address-cells", 2).u32p("#size-cells", 2);
        b.begin("memory@0").s("device_type", "memory").prop("reg", &regs(&[(0, 0x3f80_0000), (0x4000_0000, 0xc000_0000)])).end();
        b.begin("reserved-memory").u32p("#address-cells", 2).u32p("#size-cells", 2);
        b.begin("atf@0").prop("reg", &regs(&[(0, 0x8_0000)])).prop("no-map", &[]).end();
        b.begin("disabled@1").prop("reg", &regs(&[(0x10_0000, 0x1000)])).s("status", "disabled").end();
        b.end();
        b.begin("cpus").u32p("#address-cells", 1).u32p("#size-cells", 0);
        for i in 0..4u32 {
            let n = std::format!("cpu@{}", i * 0x100);
            b.begin(&n).s("device_type", "cpu").u32p("reg", i * 0x100).s("enable-method", "psci").end();
        }
        b.begin("l2-cache").s("compatible", "cache").end();
        b.end();
        b.begin("psci").prop("compatible", b"arm,psci-1.0\0arm,psci-0.2\0arm,psci\0").s("method", "smc").end();
        b.begin("soc").begin("memory@99").s("device_type", "memory").prop("reg", &regs(&[(0xdead, 0x1)])).end().end();
        b.end();
        b.build()
    }

    #[test]
    fn parses_cm5_shaped_tree() {
        let inv = parse(&sample()).unwrap();
        assert_eq!(inv.nmem, 2);
        assert_eq!(inv.mem[1], Range { base: 0x4000_0000, size: 0xc000_0000 });
        assert_eq!(inv.mem_total(), 0x3f80_0000 + 0xc000_0000);
        // header reservation + the one okay /reserved-memory child (the disabled one is skipped)
        assert_eq!(inv.nresv, 2);
        assert_eq!(inv.resv_nomap, 1);
        assert_eq!(inv.ncpus, 4);
        assert_eq!(inv.cpus[3].mpidr, 0x300);
        assert!(inv.cpus.iter().take(4).all(|c| c.method == EnableMethod::Psci && c.enabled));
        assert_eq!(inv.psci, Psci { present: true, method: Conduit::Smc, v02_plus: true });
        assert!(!inv.truncated);
    }

    #[test]
    fn spin_table_and_one_cell_root() {
        let mut b = B::new();
        b.begin("").u32p("#address-cells", 1).u32p("#size-cells", 1);
        let mut r = Vec::new();
        r.extend_from_slice(&0u32.to_be_bytes());
        r.extend_from_slice(&0x2000_0000u32.to_be_bytes());
        b.begin("memory").s("device_type", "memory").prop("reg", &r).end();
        b.begin("cpus").u32p("#address-cells", 2).u32p("#size-cells", 0);
        b.begin("cpu@1").s("device_type", "cpu").prop("reg", &1u64.to_be_bytes()).s("enable-method", "spin-table").prop("cpu-release-addr", &0xd8u64.to_be_bytes()).end();
        b.end();
        b.end();
        let inv = parse(&b.build()).unwrap();
        assert_eq!(inv.mem[0], Range { base: 0, size: 0x2000_0000 });
        assert_eq!(inv.cpus[0], Cpu { mpidr: 1, method: EnableMethod::SpinTable, release_addr: 0xd8, enabled: true });
        assert!(!inv.psci.present);
    }

    #[test]
    fn refuses_malformed() {
        let good = sample();
        assert_eq!(parse(&good[..39]).err(), Some(FdtErr::TooSmall));
        let mut bad = good.clone();
        bad[0] ^= 1;
        assert_eq!(parse(&bad).err(), Some(FdtErr::BadMagic));
        let mut big = good.clone();
        big[4..8].copy_from_slice(&((good.len() + 4) as u32).to_be_bytes()); // totalsize past the buffer
        assert_eq!(parse(&big).err(), Some(FdtErr::BadHeader));
        // truncated struct block: no FDT_END
        let mut b = B::new();
        b.begin("").end();
        let mut nb = b.build();
        let sz = u32::from_be_bytes([nb[36], nb[37], nb[38], nb[39]]) - 4;
        nb[36..40].copy_from_slice(&sz.to_be_bytes());
        assert!(parse(&nb).is_err());
        // memory reg not a multiple of the cell stride
        let mut b = B::new();
        b.begin("").u32p("#address-cells", 2).u32p("#size-cells", 2);
        b.begin("memory").s("device_type", "memory").prop("reg", &[0u8; 12]).end();
        b.end();
        assert_eq!(parse(&b.build()).err(), Some(FdtErr::BadProp));
    }

    #[test]
    fn depth_and_capacity_bounds() {
        let mut b = B::new();
        for i in 0..=MAX_DEPTH {
            b.begin(if i == 0 { "" } else { "n" });
        }
        for _ in 0..=MAX_DEPTH {
            b.end();
        }
        assert_eq!(parse(&b.build()).err(), Some(FdtErr::TooDeep));
        let mut b = B::new();
        b.begin("").begin("cpus").u32p("#address-cells", 1).u32p("#size-cells", 0);
        for i in 0..(MAX_CPUS as u32 + 3) {
            b.begin("cpu@x").s("device_type", "cpu").u32p("reg", i).end();
        }
        b.end().end();
        let inv = parse(&b.build()).unwrap();
        assert_eq!(inv.ncpus, MAX_CPUS);
        assert!(inv.truncated, "overflow is reported, never silently dropped");
    }

    /// Deterministic mutation sweep: no input may panic (the libFuzzer target runs the same entry point).
    #[test]
    fn mutation_sweep_never_panics() {
        let base = sample();
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..20_000 {
            let mut m = base.clone();
            for _ in 0..4 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let i = (x as usize) % m.len();
                m[i] = (x >> 32) as u8;
            }
            let cut = (x as usize >> 8) % (m.len() + 1);
            let _ = parse(&m[..cut.max(1).min(m.len())]);
            let _ = parse(&m);
        }
    }
}
