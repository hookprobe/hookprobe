//! Kernel side of the EL0 LAN-services server (ADR 0050 D4 step 2): Shield's DNS parsing — every client query and
//! every upstream answer — runs in `el0-lansvc`, one bounded excursion per message. The kernel only rebuilds the
//! result from a fixed record (bounds-checked against its own copy) and keeps every DECISION (Shield, policy).
//! D5: a fault or timeout resets the server and the message is treated as unparseable — a query passes un-inspected
//! exactly as an unparseable one always did (ADR 0023: never a self-inflicted outage), counted and reported.
//! Builds without the EL0 substrate (`mctls` off) parse in-kernel with the same code (`dnswire`).

use crate::dnswire::{Walk, Q};

#[cfg(feature = "mctls")]
mod el0 {
    use hal::lansvcabi::*;

    static LANSVC_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/el0_lansvc.elf"));

    #[cfg(feature = "cm5")]
    pub const BASE: usize = BASE_CM5;
    #[cfg(not(feature = "cm5"))]
    pub const BASE: usize = BASE_QEMU;
    const IO_PAGES: usize = IO_SIZE / 0x1000;
    const STACK_PAGES: usize = STACK_SIZE / 0x1000;
    const RW_MAX: usize = 8;
    #[cfg(feature = "cm5")]
    const BUDGET_US: u64 = 20_000;
    #[cfg(not(feature = "cm5"))]
    const BUDGET_US: u64 = 2_000_000;

    pub struct Server {
        entry: usize,
        sp_top: usize,
        io: [usize; IO_PAGES],
        rw: [(usize, usize, usize); RW_MAX],
        nrw: usize,
        pub calls: u64,
        pub faults: u64,
        pub restarts: u64,
    }
    pub static mut SRV: Option<Server> = None;
    static mut TRIED: bool = false;

    fn alloc() -> usize {
        #[cfg(feature = "cm5")]
        {
            arch_aarch64::mmu_cm5::alloc_frame()
        }
        #[cfg(not(feature = "cm5"))]
        {
            use hal::Mmu as _;
            arch_aarch64::Mmu.alloc_frame()
        }
    }
    fn map(va: usize, pa: usize, exec: bool, write: bool) -> bool {
        #[cfg(feature = "cm5")]
        {
            use arch_aarch64::mmu_cm5 as m;
            if exec {
                m::map_user_code(va, pa);
                true
            } else if write {
                m::map_user_data(va, pa)
            } else {
                m::map_user_data_ro(va, pa)
            }
        }
        #[cfg(not(feature = "cm5"))]
        {
            let m = arch_aarch64::Mmu;
            if exec {
                m.map_user_code_page(va, pa)
            } else if write {
                m.map_user_data_page(va, pa)
            } else {
                m.map_user_data_ro_page(va, pa)
            }
        }
    }

    /// The server, loaded on first use (once; a failed load is reported and the kernel parses in-kernel).
    pub fn server() -> Option<&'static mut Server> {
        unsafe {
            if !TRIED {
                TRIED = true;
                match load() {
                    Ok(s) => {
                        SRV = Some(s);
                        arch_aarch64::_print(format_args!(" [LANSVC] EL0 LAN-services server loaded at {:#x}: Shield's DNS query / answer parsing runs in EL0 (ADR 0050 D4 step 2)\n", BASE));
                    }
                    Err(why) => arch_aarch64::_print(format_args!(" [LANSVC] EL0 server FAILED to load ({}) — DNS parsing stays in-kernel (reported in /api/health)\n", why)),
                }
            }
            (*core::ptr::addr_of_mut!(SRV)).as_mut()
        }
    }

    fn load() -> Result<Server, &'static str> {
        let parsed = crate::elf::parse(LANSVC_ELF).map_err(|_| "ELF parse")?;
        let mut s = Server { entry: parsed.entry, sp_top: BASE + STACK_OFF + STACK_SIZE, io: [0; IO_PAGES], rw: [(0, 0, 0); RW_MAX], nrw: 0, calls: 0, faults: 0, restarts: 0 };
        for g in parsed.segs[..parsed.nsegs].iter() {
            if g.vaddr < BASE || g.vaddr + g.memsz > BASE + IMAGE_MAX {
                return Err("segment outside the window"); // the image must stay inside its own window
            }
            for p in 0..(g.memsz + 0xFFF) >> 12 {
                let f = alloc();
                if f == 0 {
                    return Err("out of frames (image)");
                }
                let voff = p * 0x1000;
                let n = g.filesz.saturating_sub(voff).min(0x1000);
                unsafe { core::ptr::write_bytes(f as *mut u8, 0, 0x1000) };
                if n > 0 {
                    unsafe { core::ptr::copy_nonoverlapping(LANSVC_ELF.as_ptr().add(g.offset + voff), f as *mut u8, n) };
                }
                if g.executable() {
                    arch_aarch64::mmu::sync_instruction_cache(f, 0x1000);
                } else if g.writable() {
                    if s.nrw == RW_MAX {
                        return Err("too many RW pages");
                    }
                    s.rw[s.nrw] = (f, g.offset + voff, n);
                    s.nrw += 1;
                }
                if !map(g.vaddr + voff, f, g.executable(), g.writable()) {
                    return Err("map image page refused");
                }
            }
        }
        for p in 0..STACK_PAGES {
            let f = alloc();
            if f == 0 || !map(BASE + STACK_OFF + p * 0x1000, f, false, true) {
                return Err("map stack refused");
            }
        }
        for p in 0..IO_PAGES {
            let f = alloc();
            if f == 0 || !map(BASE + IO_OFF + p * 0x1000, f, false, true) {
                return Err("map IO refused");
            }
            s.io[p] = f;
        }
        Ok(s)
    }

    impl Server {
        fn write(&mut self, mut off: usize, mut src: &[u8]) {
            while !src.is_empty() && off < IO_SIZE {
                let (pg, po) = (off / 0x1000, off % 0x1000);
                let n = src.len().min(0x1000 - po);
                unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), (self.io[pg] + po) as *mut u8, n) };
                off += n;
                src = &src[n..];
            }
        }
        pub fn read(&self, mut off: usize, mut out: &mut [u8]) {
            while !out.is_empty() && off < IO_SIZE {
                let (pg, po) = (off / 0x1000, off % 0x1000);
                let n = out.len().min(0x1000 - po);
                unsafe { core::ptr::copy_nonoverlapping((self.io[pg] + po) as *const u8, out.as_mut_ptr(), n) };
                off += n;
                out = &mut out[n..];
            }
        }
        fn r32(&self, off: usize) -> u32 {
            let mut b = [0u8; 4];
            self.read(off, &mut b);
            u32::from_le_bytes(b)
        }
        /// One command; `(status, out_len)`. A fault / timeout resets the server and reports ST_PANIC.
        pub fn call(&mut self, cmd: u32, input: &[u8]) -> (u32, usize) {
            let n = input.len().min(IN_MAX);
            self.write(H_MAGIC, &MAGIC.to_le_bytes());
            self.write(H_CMD, &cmd.to_le_bytes());
            self.write(H_IN_LEN, &(n as u32).to_le_bytes());
            self.write(H_STATUS, &ST_PANIC.to_le_bytes());
            self.write(IN_OFF, &input[..n]);
            self.calls += 1;
            let how = crate::excursion_bounded(self.entry, self.sp_top, BUDGET_US);
            let st = if how == crate::Excursion::Exited { self.r32(H_STATUS) } else { ST_PANIC };
            if st == ST_PANIC {
                self.faults += 1;
                self.reset();
                return (ST_PANIC, 0);
            }
            (st, (self.r32(H_OUT_LEN) as usize).min(OUT_MAX))
        }
        /// Fail closed and recover: restore the image's data/bss pages and zero the IO region.
        fn reset(&mut self) {
            self.restarts += 1;
            for i in 0..self.nrw {
                let (f, off, n) = self.rw[i];
                unsafe {
                    core::ptr::write_bytes(f as *mut u8, 0, 0x1000);
                    if n > 0 {
                        core::ptr::copy_nonoverlapping(LANSVC_ELF.as_ptr().add(off), f as *mut u8, n);
                    }
                }
            }
            for f in self.io.iter() {
                unsafe { core::ptr::write_bytes(*f as *mut u8, 0, 0x1000) };
            }
        }
    }
}

static mut IN_KERNEL: u64 = 0;

/// (where, messages parsed in EL0, EL0 faults, EL0 restarts, messages parsed in-kernel)
pub fn stats() -> (&'static str, u64, u64, u64, u64) {
    #[cfg(feature = "mctls")]
    if let Some(s) = unsafe { (*core::ptr::addr_of!(el0::SRV)).as_ref() } {
        return ("el0", s.calls, s.faults, s.restarts, unsafe { IN_KERNEL });
    }
    ("el1", 0, 0, 0, unsafe { IN_KERNEL })
}

/// A client DNS query → its question facts (None = not a standard one-question query, or the parser failed).
pub fn dns_query(dns: &[u8]) -> Option<Q> {
    #[cfg(feature = "mctls")]
    if let Some(s) = el0::server() {
        use hal::lansvcabi::*;
        if dns.len() > IN_MAX {
            return None;
        }
        let (st, n) = s.call(CMD_DNS_QUERY, dns);
        if st != ST_OK || n < Q_REC_HDR {
            return None;
        }
        let mut h = [0u8; Q_REC_HDR];
        s.read(OUT_OFF, &mut h);
        let nl = u16::from_le_bytes([h[0], h[1]]) as usize;
        let qend = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
        if nl > 255 || n != Q_REC_HDR + nl || qend > dns.len() || qend < 12 + 5 {
            return None; // a record that cannot be right: treat as unparseable
        }
        let mut q = Q { name: [0; 256], nl, qtype: u16::from_le_bytes([h[2], h[3]]), qend, edns: h[8] != 0 };
        s.read(OUT_OFF + Q_REC_HDR, &mut q.name[..nl]);
        return Some(q);
    }
    unsafe { IN_KERNEL += 1 };
    crate::dnswire::parse_query(dns)
}

/// An upstream DNS answer → question name + end + CNAME targets (None = malformed: Shield passes it untouched).
pub fn dns_walk(dns: &[u8], w: &mut Walk) -> Option<()> {
    #[cfg(feature = "mctls")]
    if let Some(s) = el0::server() {
        use hal::lansvcabi::*;
        if dns.len() > IN_MAX {
            return None;
        }
        let (st, n) = s.call(CMD_DNS_WALK, dns);
        if st != ST_OK || n < WALK_HDR {
            return None;
        }
        let mut h = [0u8; 8];
        s.read(OUT_OFF, &mut h);
        let qnl = u16::from_le_bytes([h[0], h[1]]) as usize;
        let k = u16::from_le_bytes([h[2], h[3]]) as usize;
        let qend = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
        if qnl > 255 || k > WALK_MAX_CNAMES || k > crate::dnswire::MAX_CNAMES || n != WALK_HDR + k * WALK_STRIDE || qend > dns.len() {
            return None;
        }
        w.qnl = qnl;
        w.qend = qend;
        s.read(OUT_OFF + 8, &mut w.qname);
        w.ncname = k;
        for i in 0..k {
            let o = OUT_OFF + WALK_HDR + i * WALK_STRIDE;
            let mut l = [0u8; 2];
            s.read(o, &mut l);
            let len = u16::from_le_bytes(l) as usize;
            if len > 255 {
                return None;
            }
            w.cnl[i] = len;
            s.read(o + 2, &mut w.cnames[i]);
        }
        return Some(());
    }
    unsafe { IN_KERNEL += 1 };
    crate::dnswire::walk_answers(dns, w)
}

/// [P-lansvc] ADR 0050 D4 step 2: Shield's DNS parsing in the EL0 server gives the SAME facts as the in-kernel
/// parser (a query; an answer with a CNAME chain), and a server fault is contained: the server resets, the message
/// reads as unparseable, and the next message parses again.
#[cfg(feature = "mctls")]
pub fn selftest() -> bool {
    use crate::dnswire::{parse_query, walk_answers, WALK0};
    // query: id 0x1234, RD, 1 question "ads.example.com" A, EDNS OPT
    let mut q = [0u8; 64];
    let hdr = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
    q[..12].copy_from_slice(&hdr);
    let mut n = 12;
    for l in [&b"ads"[..], b"example", b"com"] {
        q[n] = l.len() as u8;
        q[n + 1..n + 1 + l.len()].copy_from_slice(l);
        n += 1 + l.len();
    }
    q[n] = 0;
    q[n + 1..n + 5].copy_from_slice(&[0, 1, 0, 1]);
    n += 5;
    q[n..n + 11].copy_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
    n += 11;
    let k = parse_query(&q[..n]);
    let e = dns_query(&q[..n]);
    let same_q = matches!((&k, &e), (Some(a), Some(b)) if a.nl == b.nl && a.name[..a.nl] == b.name[..b.nl] && a.qtype == b.qtype && a.qend == b.qend && a.edns == b.edns);
    // answer: the same question, 2 answers: CNAME -> tracker.bad.example, A
    let mut r = [0u8; 160];
    r[..n - 11].copy_from_slice(&q[..n - 11]);
    r[2] = 0x81;
    r[3] = 0x80;
    r[7] = 2;
    r[11] = 0;
    let mut m = n - 11;
    r[m..m + 12].copy_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 0]);
    let rdl_at = m + 10;
    m += 12;
    let t0 = m;
    for l in [&b"tracker"[..], b"bad", b"example"] {
        r[m] = l.len() as u8;
        r[m + 1..m + 1 + l.len()].copy_from_slice(l);
        m += 1 + l.len();
    }
    r[m] = 0;
    m += 1;
    let rdl = (m - t0) as u16;
    r[rdl_at..rdl_at + 2].copy_from_slice(&rdl.to_be_bytes());
    r[m..m + 16].copy_from_slice(&[0xc0, t0 as u8, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 9]);
    m += 16;
    let mut wk = WALK0;
    let mut we = WALK0;
    let ok_k = walk_answers(&r[..m], &mut wk).is_some();
    let ok_e = dns_walk(&r[..m], &mut we).is_some();
    let same_w = ok_k && ok_e && wk.qnl == we.qnl && wk.qname[..wk.qnl] == we.qname[..we.qnl] && wk.qend == we.qend
        && wk.ncname == 1 && we.ncname == 1 && we.cnames[0][..we.cnl[0]] == *b"tracker.bad.example";
    // a malformed message is unparseable in both
    let bad = dns_query(&[0xff; 7]).is_none() && dns_walk(&[0xc0; 40], &mut we).is_none();
    // fault containment: deliberate EL0 fault -> reset, counted; the next query parses again
    let (where_, _, f0, r0, _) = stats();
    let faulted = match el0::server() {
        Some(s) => s.call(hal::lansvcabi::CMD_SELFTEST_FAULT, &[]).0 == hal::lansvcabi::ST_PANIC,
        None => false,
    };
    let (_, _, f1, r1, _) = stats();
    let recovered = faulted && f1 == f0 + 1 && r1 == r0 + 1 && dns_query(&q[..n]).is_some();
    let pass = where_ == "el0" && same_q && same_w && bad && recovered;
    arch_aarch64::_print(format_args!(
        " [P-lansvc] {} — ADR 0050 D4 step 2: Shield DNS parsing in the EL0 LAN-services server (placement={}): a query gives the same facts as the in-kernel parser={} | an answer's CNAME chain is walked identically={} | malformed messages are unparseable in EL0 too={} | a deliberate EL0 fault resets the server (counted) and the next query parses={}\n",
        if pass { "PASS" } else { "FAIL" }, where_, same_q, same_w, bad, recovered
    ));
    pass
}
