//! Kernel side of `hsh`, the native management shell (ADR 0059 step 4a; docs/design/hsh-native-management-shell.md).
//! The shell is an EL0 excursion server (`el0-hsh`); each command line runs in two bounded excursions:
//!   1. the line goes in; the shell returns text, or ONE management request (a `hal::mgmtabi` message id);
//!   2. the kernel serves the request through `mgmtabi::dispatch` with the SESSION's role (the shell never decides
//!      authority) and re-enters the shell with the fixed reply record; the shell formats it.
//! A shell fault costs that command only (the server resets, ADR 0050 D5); forwarding never notices.
//! Transport (R6 is an operator decision): Mission Control's authenticated session (`POST /api/hsh`) today; UART RX
//! stays off until the operator decides.

#[cfg(feature = "mctls")]
mod el0 {
    use hal::hshabi::*;

    static HSH_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/el0_hsh.elf"));

    #[cfg(feature = "cm5")]
    pub const BASE: usize = BASE_CM5;
    #[cfg(not(feature = "cm5"))]
    pub const BASE: usize = BASE_QEMU;
    const IO_PAGES: usize = IO_SIZE / 0x1000;
    const STACK_PAGES: usize = STACK_SIZE / 0x1000;
    const RW_MAX: usize = 8;
    #[cfg(feature = "cm5")]
    const BUDGET_US: u64 = 50_000;
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
        pub role: u8,
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
                        arch_aarch64::_print(format_args!(" [HSH] EL0 management shell loaded at {:#x} (ADR 0059 step 4a: untrusted command lines are parsed in EL0)\n", BASE));
                    }
                    Err(why) => arch_aarch64::_print(format_args!(" [HSH] EL0 shell FAILED to load ({}) — the shell is unavailable\n", why)),
                }
            }
            (*core::ptr::addr_of_mut!(SRV)).as_mut()
        }
    }

    fn load() -> Result<Server, &'static str> {
        let parsed = crate::elf::parse(HSH_ELF).map_err(|_| "ELF parse")?;
        let mut s = Server { entry: parsed.entry, sp_top: BASE + STACK_OFF + STACK_SIZE, io: [0; IO_PAGES], rw: [(0, 0, 0); RW_MAX], nrw: 0, calls: 0, faults: 0, restarts: 0, role: 0 };
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
                    unsafe { core::ptr::copy_nonoverlapping(HSH_ELF.as_ptr().add(g.offset + voff), f as *mut u8, n) };
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
            self.write(H_ROLE, &(self.role as u32).to_le_bytes());
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
                        core::ptr::copy_nonoverlapping(HSH_ELF.as_ptr().add(off), f as *mut u8, n);
                    }
                }
            }
            for f in self.io.iter() {
                unsafe { core::ptr::write_bytes(*f as *mut u8, 0, 0x1000) };
            }
        }
    }
}


/// Run one command line for a caller holding `role`; the text answer goes into `out`. Returns its length.
#[cfg(feature = "mctls")]
pub fn run_line(line: &[u8], role: u8, tag: [u8; 4], now_ms: u64, out: &mut [u8]) -> usize {
    use hal::hshabi::*;
    let msg_unavail = b"ERROR: Management service unavailable.\n";
    let Some(s) = el0::server() else {
        let n = msg_unavail.len().min(out.len());
        out[..n].copy_from_slice(&msg_unavail[..n]);
        return n;
    };
    s.role = role;
    let (st, n) = s.call(CMD_LINE, &line[..line.len().min(IN_MAX)]);
    let n = match st {
        ST_TEXT => n,
        ST_REQUEST if n == REQ_LEN => {
            let mut rq = [0u8; REQ_LEN];
            s.read(OUT_OFF, &mut rq);
            let msg = u16::from_le_bytes([rq[0], rq[1]]);
            let arg = u64::from_le_bytes(rq[4..12].try_into().unwrap());
            let pl = &rq[12..12 + (rq[3] as usize).min(64)];
            // phase 2: the kernel authorises + serves; the shell formats
            let mut rep = [0u8; IN_MAX];
            rep[..2].copy_from_slice(&msg.to_le_bytes());
            rep[3] = rq[2];
            let (res, len) = crate::mgmtabi::dispatch(msg, role, tag, now_ms, arg, pl, &mut rep[4..]);
            rep[2] = res;
            let (st2, n2) = s.call(CMD_REPLY, &rep[..4 + len]);
            if st2 == ST_TEXT { n2 } else { 0 }
        }
        _ => 0,
    };
    if n == 0 && st != ST_TEXT {
        let k = msg_unavail.len().min(out.len());
        out[..k].copy_from_slice(&msg_unavail[..k]);
        return k;
    }
    let k = n.min(out.len()).min(OUT_MAX);
    s.read(OUT_OFF, &mut out[..k]);
    k
}

/// (loaded, commands, faults, restarts)
pub fn stats() -> (bool, u64, u64, u64) {
    #[cfg(feature = "mctls")]
    if let Some(s) = unsafe { (*core::ptr::addr_of!(el0::SRV)).as_ref() } {
        return (true, s.calls, s.faults, s.restarts);
    }
    (false, 0, 0, 0)
}

/// [P-hsh] + [P-mgmtabi] (QEMU and metal): the parser's limits (§9, §15), every read command through the two-phase
/// path, role enforcement in the kernel, unknown messages, and EL0 fault containment.
#[cfg(feature = "mctls")]
pub fn selftest(now_ms: u64) -> bool {
    use hal::mgmtabi as m;
    let mut o = [0u8; 2048];
    let mut run = |l: &[u8], role: u8| -> ([u8; 2048], usize) {
        let mut b = [0u8; 2048];
        let n = run_line(l, role, [0x5e, 0x1f, 0, 0], now_ms, &mut b);
        (b, n)
    };
    let has = |r: &([u8; 2048], usize), s: &[u8]| r.0[..r.1].windows(s.len()).any(|w| w == s);
    let v = m::ROLE_VIEW;
    // parser (§9 / §15)
    let empty = run(b"", v).1 == 0 && run(b"    ", v).1 == 0;
    let long = [b'a'; 256];
    let at_max = {
        let mut l = [b' '; 255];
        l[..4].copy_from_slice(b"help");
        has(&run(&l, v), b"version")
    };
    let over = has(&run(&long, v), b"longer than 255");
    let toks = has(&run(b"a b c d e f g h i j k l m", v), b"more than 12 tokens");
    let big = {
        let mut l = [b'x'; 70];
        l[0] = b'h';
        has(&run(&l, v), b"longer than 64")
    };
    let nonascii = has(&run("info \u{e9}".as_bytes(), v), b"printable ASCII") && has(&run(b"info\0", v), b"printable ASCII")
        && has(&run(b"info\x1b[2J", v), b"printable ASCII");
    let ops = [&b"info | cat"[..], b"info; reboot", b"info && x", b"info > f", b"$(id)", b"`id`", b"info*", b"'q'"]
        .iter()
        .all(|l| has(&run(l, v), b"not supported") || has(&run(l, v), b"Invalid argument"));
    let unknown = has(&run(b"rm -rf", v), b"Unknown command");
    let later = has(&run(b"config history", v), b"not supported") && has(&run(b"reboot", v), b"not supported");
    let parser = empty && at_max && over && toks && big && nonascii && ops && unknown && later;
    // every read command, formatted from the ABI reply (never printed before it)
    let reads = has(&run(b"info", v), b"HEQK Management Environment") && has(&run(b"version", v), b"HEQK ")
        && has(&run(b"uptime", v), b"up ") && has(&run(b"wan status", v), b"wan:") && has(&run(b"interface show wan", v), b"wan:")
        && has(&run(b"qsecbit status", v), b"qsecbit:") && has(&run(b"config status", v), b"config:")
        && has(&run(b"owner status", v), b"vendor key:") && has(&run(b"security posture", v), b"LAN/WAN parsers:")
        && has(&run(b"help", v), b"config status");
    // role enforcement is the KERNEL's: a session without a role is denied; help shows only what the role allows
    let denied = has(&run(b"info", 0), b"Permission denied") && !has(&run(b"help", 0), b"config status");
    // the ABI directly: every read message replies with exactly its record; an unknown id is refused
    let mut rec = [0u8; 256];
    let abi = [m::GET_INFO, m::GET_WAN, m::GET_QSECBIT, m::GET_CONFIG, m::GET_ANCHOR, m::GET_PARSERS]
        .iter()
        .all(|&id| crate::mgmtabi::dispatch(id, v, [0; 4], now_ms, 0, &[], &mut rec) == (m::R_OK, m::reply_len(id).unwrap()))
        && crate::mgmtabi::dispatch(999, m::ROLE_OWNER, [0; 4], now_ms, 0, &[], &mut rec).0 == m::R_UNKNOWN
        && crate::mgmtabi::dispatch(m::GET_INFO, 0, [0; 4], now_ms, 0, &[], &mut rec).0 == m::R_DENIED;
    // step 4b: configuration operations — denied below their role (view), answered with an Act record at owner; with
    // nothing on trial / no store (QEMU) the refusal is honest; an unknown upload id cannot be staged
    let cfg_denied = has(&run(b"config confirm", v), b"Permission denied") && has(&run(b"config rollback", v), b"Permission denied")
        && has(&run(b"config stage 00000000000000aa", v), b"Permission denied");
    let act = |msg: u16, arg: u64| -> Option<m::Act> {
        let mut r = [0u8; 256];
        match crate::mgmtabi::dispatch(msg, m::ROLE_OWNER, [0; 4], now_ms, arg, &[], &mut r) {
            (m::R_OK, n) if n == m::ACT_LEN => Some(m::Act::decode(r[..m::ACT_LEN].try_into().unwrap())),
            _ => None,
        }
    };
    let cfg_owner = act(m::CFG_CONFIRM, 0).is_some_and(|a| !a.ok) && act(m::CFG_STAGE, 0xaa).is_some_and(|a| !a.ok && a.reason_str().contains("upload id"));
    let abi = abi && cfg_denied && cfg_owner;
    // step 4c: HQCHAL1 elevation — challenge, the ENROLLED owner key signs off-device, the session gains the owner role
    // (config confirm is no longer denied); the nonce is single-use; a wrong key is refused; no owner key = nothing
    let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([0x4c; 32]));
    let other = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([0x4d; 32]));
    let saved = (crate::anchor::owner(), crate::anchor::owner_gen());
    let t = [0xe1, 0xe7, 0, 1];
    let chal = |tag: [u8; 4]| -> Option<m::Challenge> {
        let mut r = [0u8; 256];
        match crate::mgmtabi::dispatch(m::OWNER_CHALLENGE, v, tag, now_ms, 0, &[], &mut r) {
            (m::R_OK, n) if n == m::CHAL_LEN => Some(m::Challenge::decode(r[..m::CHAL_LEN].try_into().unwrap())),
            _ => None,
        }
    };
    let elev = |tag: [u8; 4], sig: &[u8]| -> bool {
        let mut r = [0u8; 256];
        matches!(crate::mgmtabi::dispatch(m::OWNER_ELEVATE, v, tag, now_ms, 0, sig, &mut r), (m::R_OK, n) if n == m::ACT_LEN && m::Act::decode(r[..m::ACT_LEN].try_into().unwrap()).ok)
    };
    let sign = |k: &ed25519_compact::KeyPair, c: &m::Challenge| -> [u8; 64] { *k.sk.sign(&m::challenge_msg(&c.device_id, &c.nonce)[..], Some(ed25519_compact::Noise::from_slice(&[9u8; 16]).unwrap())) };
    crate::mgmtabi::test_reset();
    crate::anchor::install_owner(None, 0);
    let no_owner = chal(t).is_some_and(|c| !c.owner_enrolled && !elev(t, &sign(&kp, &c)));
    crate::anchor::install_owner(Some(*kp.pk), 1);
    let c1 = chal(t);
    let wrong = c1.is_some_and(|c| !elev(t, &sign(&other, &c)));
    let c2 = chal(t);
    let good = c2.is_some_and(|c| elev(t, &sign(&kp, &c))) && crate::mgmtabi::elevated(t, now_ms) == m::ROLE_OWNER;
    let replay = c2.is_some_and(|c| !elev(t, &sign(&kp, &c)));
    let mut r = [0u8; 256];
    let allowed = crate::mgmtabi::dispatch(m::CFG_CONFIRM, v, t, now_ms, 0, &[], &mut r).0 == m::R_OK
        && crate::mgmtabi::dispatch(m::CFG_CONFIRM, v, [0x99, 0, 0, 0], now_ms, 0, &[], &mut r).0 == m::R_DENIED;
    let expired = crate::mgmtabi::elevated(t, now_ms + m::ELEVATE_TTL_S * 1000 + 1) == 0;
    let shell = has(&run(b"owner challenge", v), b"HQCHAL1") && has(&run(b"owner elevate 00 11", v), b"Invalid argument");
    crate::mgmtabi::test_reset();
    crate::anchor::install_owner(saved.0, saved.1);
    let elevation = no_owner && wrong && good && replay && allowed && expired && shell;
    let abi = abi && elevation;
    // fault containment: a deliberate EL0 fault resets the shell, counted; the next command answers
    let (_, _, f0, r0) = stats();
    let faulted = el0::server().is_some_and(|s| s.call(hal::hshabi::CMD_SELFTEST_FAULT, &[]).0 == hal::hshabi::ST_PANIC);
    let (_, _, f1, r1) = stats();
    let contained = faulted && f1 == f0 + 1 && r1 == r0 + 1 && has(&run(b"version", v), b"HEQK ");
    let _ = &mut o;
    let pass = parser && reads && denied && abi && contained;
    arch_aarch64::_print(format_args!(
        " [P-hsh] {} — ADR 0059 step 4a hsh (EL0 excursion shell, two-phase line -> mgmtabi -> text): parser limits (empty, 255 B at/over, 12 tokens, 64-B token, non-ASCII / NUL / control, shell operators, unknown, 4b/4c not supported)={} every read command formatted from its ABI reply={} the kernel enforces the role (no role -> denied, help hides)={} a deliberate EL0 fault is contained and the next command answers={}\n",
        if pass { "PASS" } else { "FAIL" }, parser, reads, denied, contained
    ));
    arch_aarch64::_print(format_args!(
        " [P-mgmtabi] {} — ADR 0059 D9 management ABI: every read message answers with exactly its fixed record from the /api producers, an unknown id is refused, a caller without the role is denied; 4b config confirm / rollback / stage denied below their role and answered (honestly refused here) at owner | 4c HQCHAL1 elevation (no owner key = nothing, a wrong key refused, the owner key grants the owner role to THAT session only, nonce single-use, expires)={}\n",
        if abi { "PASS" } else { "FAIL" }, abi
    ));
    pass && abi
}
