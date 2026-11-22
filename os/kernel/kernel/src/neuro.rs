// SPDX-License-Identifier: AGPL-3.0-only
//! HookProbe Neuro, stage 1 (N0), hosted by heqk: the `el0-neuro` EL0 excursion server and its EL1 host
//! (the repo-root design doc heqk-neuro-integration.md). Feature `neuro`, OFF in every shipping image.
//!
//! The boundary, in one place:
//! - **EL1 owns everything that matters**: device attribution (MAC -> slot), fingerprinting (the server never sees an
//!   address or a name), the clock, the batch, the budget, the restart policy, and what is kept of a reply.
//! - **el0-neuro observes and scores.** It holds no capability: no network, no storage, no policy, no device. Its
//!   state is its own `.bss`; a fault resets it from the signed ELF and the behavioural memory relearns (Volatile).
//! - **A reply is untrusted input.** Status, lengths and every record are validated (`hal::neuroabi`); a reply that
//!   breaks the protocol is refused, journaled as a complaint and the server reset (autoheal H4c).
//! - **Evidence only.** A deviant hour becomes a "behaviour deviation" evidence record (doc 20). This module has no
//!   path to a verdict, an alert, a notification, a Shield action or a policy change, and must never grow one: a
//!   recommendation needs the validated, owner-authorised path of the design doc §7 (not built).
//! - **Fail-open for the data plane.** Nothing here blocks the caller: a held-off, throttled or absent server makes
//!   `observe_*` drop the event and count it (backpressure is visible, never a stall).

#[cfg(feature = "neuro")]
pub use el0::*;

#[cfg(feature = "neuro")]
mod el0 {
    use hal::neuroabi::*;

    macro_rules! kprint { ($($t:tt)*) => { arch_aarch64::_print(format_args!($($t)*)) }; }

    static NEURO_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/el0_neuro.elf"));
    const NAME: &str = "el0-neuro";
    const C: u8 = hal::superv::C_NEURO;

    #[cfg(feature = "cm5")]
    pub const BASE: usize = BASE_CM5;
    #[cfg(not(feature = "cm5"))]
    pub const BASE: usize = BASE_QEMU;
    const IO_PAGES: usize = IO_SIZE / 0x1000;
    const STACK_PAGES: usize = STACK_SIZE / 0x1000;
    /// The 64-device behavioural memory is ~83 KB of .bss (21 pages); hsh needs 8.
    const RW_MAX: usize = 32;
    /// Per excursion. A full 512-event batch is ~45 us and a 64-device hour close ~150 us in QEMU (P3/P4); the CM5
    /// budget is sized at 20x the worst QEMU excursion and is still far under the AP loop's 2 s gap gate.
    #[cfg(feature = "cm5")]
    const BUDGET_US: u64 = 5_000;
    #[cfg(not(feature = "cm5"))]
    const BUDGET_US: u64 = 2_000_000;

    pub struct Server {
        entry: usize,
        aspace: crate::el0as::El0As,
        sp_top: usize,
        io: [usize; IO_PAGES],
        rw: [(usize, usize, usize); RW_MAX],
        nrw: usize,
        pub calls: u64,
        pub faults: u64,
        pub complaints: u64,
        pub restarts: u64,
        sup: hal::superv::Sup,
        pub info: Option<Info>,
    }

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
    fn map(a: &crate::el0as::El0As, va: usize, pa: usize, exec: bool, write: bool) -> bool {
        use crate::el0as::Map;
        a.map(va, pa, if exec { Map::Code } else if write { Map::Data } else { Map::DataRo })
    }

    fn load() -> Result<Server, &'static str> {
        let parsed = crate::elf::parse(NEURO_ELF).map_err(|_| "ELF parse")?;
        let aspace = crate::el0as::El0As::new().ok_or("no address space")?;
        let entry = hal::superv::entry(NAME).ok_or("no supervisor entry")?;
        let mut s = Server { entry: parsed.entry, aspace, sp_top: BASE + STACK_OFF + STACK_SIZE, io: [0; IO_PAGES], rw: [(0, 0, 0); RW_MAX], nrw: 0, calls: 0, faults: 0, complaints: 0, restarts: 0, sup: hal::superv::Sup::new(entry), info: None };
        for g in parsed.segs[..parsed.nsegs].iter() {
            if g.vaddr < BASE || g.vaddr + g.memsz > BASE + IMAGE_MAX {
                return Err("segment outside the window");
            }
            if g.executable() && g.writable() {
                return Err("a W+X segment");
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
                    unsafe { core::ptr::copy_nonoverlapping(NEURO_ELF.as_ptr().add(g.offset + voff), f as *mut u8, n) };
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
                if !map(&aspace, g.vaddr + voff, f, g.executable(), g.writable()) {
                    return Err("map image page refused");
                }
            }
        }
        for p in 0..STACK_PAGES {
            let f = alloc();
            if f == 0 || !map(&aspace, BASE + STACK_OFF + p * 0x1000, f, false, true) {
                return Err("map stack refused");
            }
        }
        for p in 0..IO_PAGES {
            let f = alloc();
            if f == 0 || !map(&aspace, BASE + IO_OFF + p * 0x1000, f, false, true) {
                return Err("map IO refused");
            }
            s.io[p] = f;
        }
        crate::el0as::register(NAME, s.entry, s.aspace);
        Ok(s)
    }

    /// What a call returned, already validated.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Reply {
        /// ST_OK with an output of `n` bytes at OUT_OFF (checked against the command's shape).
        Ok(usize),
        /// The server refused the input (ST_BAD_INPUT / ST_BAD_CMD / ST_BAD_VERSION).
        Refused(u32),
        /// Not run (held off / over budget) or it faulted / broke the protocol (journaled, server reset).
        Failed,
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
        /// May a call run now (not held off, CPU budget left)?
        pub fn ready(&self) -> bool {
            self.sup.ready(crate::superv::now_ms())
        }

        /// One command. The reply's status and length are checked against the command (`expect` = the exact output
        /// length ST_OK must carry, or None for CLOSE_HOUR, checked record by record by the caller).
        pub fn call(&mut self, cmd: u32, input: &[u8], expect: Option<usize>) -> Reply {
            if !self.sup.ready(crate::superv::now_ms()) || !crate::superv::cpu_admit(C) {
                return Reply::Failed; // fail closed for Neuro, fail open for the caller: nothing waits on us
            }
            let n = input.len().min(IN_MAX);
            self.write(H_MAGIC, &MAGIC.to_le_bytes());
            self.write(H_CMD, &cmd.to_le_bytes());
            self.write(H_IN_LEN, &(n as u32).to_le_bytes());
            self.write(H_STATUS, &ST_PANIC.to_le_bytes());
            self.write(H_OUT_LEN, &0u32.to_le_bytes());
            self.write(H_ABI, &ABI_WORD.to_le_bytes());
            self.write(IN_OFF, &input[..n]);
            self.calls += 1;
            let t0 = crate::clock::ticks();
            let how = crate::el0as::excursion(&self.aspace, self.entry, self.sp_top, BUDGET_US);
            crate::superv::cpu_charge(C, t0);
            let st = if how == crate::Excursion::Exited { self.r32(H_STATUS) } else { ST_PANIC };
            if st == ST_PANIC {
                self.faults += 1;
                let _ = crate::superv::server_fault(NAME, how == crate::Excursion::Timeout);
                if crate::superv::fault_counts() {
                    let _ = self.sup.fault(crate::superv::now_ms());
                } else {
                    self.sup.fault_uncounted();
                }
                self.reset();
                return Reply::Failed;
            }
            let injected = crate::superv::take_injected(C);
            let len = if injected { OUT_MAX + 1 } else { self.r32(H_OUT_LEN) as usize };
            let why = match st {
                ST_OK if len > OUT_MAX || expect.is_some_and(|e| e != len && !(cmd == CMD_INFO && len == INFO_LEN_V10)) => Some(crate::superv::WHY_BAD_LENGTH),
                ST_OK => None,
                ST_BAD_INPUT | ST_BAD_CMD | ST_BAD_VERSION if len == 0 => None,
                ST_BAD_INPUT | ST_BAD_CMD | ST_BAD_VERSION => Some(crate::superv::WHY_BAD_LENGTH),
                _ => Some(crate::superv::WHY_BAD_STATUS),
            };
            if let Some(why) = why {
                self.complain(why, injected);
                return Reply::Failed;
            }
            if self.sup.ok() {
                crate::superv::server_ok(NAME);
            }
            if st == ST_OK { Reply::Ok(len) } else { Reply::Refused(st) }
        }

        /// H4c: the reply broke the protocol (status / length / a record that does not validate): refused, journaled,
        /// the server reset.
        fn complain(&mut self, why: u8, injected: bool) {
            self.complaints += 1;
            let _ = crate::superv::server_complaint(NAME, why);
            if injected || !crate::superv::fault_counts() {
                self.sup.fault_uncounted();
            } else {
                let _ = self.sup.fault(crate::superv::now_ms());
            }
            self.reset();
        }

        /// Back to the signed ELF: writable pages re-copied, .bss zeroed (the behavioural memory is lost and relearns).
        fn reset(&mut self) {
            self.restarts += 1;
            for i in 0..self.nrw {
                let (f, off, n) = self.rw[i];
                unsafe {
                    core::ptr::write_bytes(f as *mut u8, 0, 0x1000);
                    if n > 0 {
                        core::ptr::copy_nonoverlapping(NEURO_ELF.as_ptr().add(off), f as *mut u8, n);
                    }
                }
            }
            for f in self.io.iter() {
                unsafe { core::ptr::write_bytes(*f as *mut u8, 0, 0x1000) };
            }
        }
    }

    /// One "behaviour deviation" evidence record (doc 20): kept only for deviant hours. Never an alert.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Evidence {
        pub mac: [u8; 6],
        /// UTC epoch hour (seconds / 3600) the score covers.
        pub utc_hour: u32,
        pub driver: u8,
        pub score_q8: u32,
        pub parts: [u16; 5],
    }

    pub const EVIDENCE_RING: usize = 64;

    /// Host counters (all monotonic since boot).
    #[derive(Clone, Copy, Debug, Default)]
    pub struct Counters {
        pub events_fed: u64,
        /// Backpressure: events not delivered because the server was held off / throttled / faulted, or the clock
        /// is not set (no UTC hour to attribute them to).
        pub events_dropped: u64,
        pub batches: u64,
        pub batches_refused: u64,
        pub hours_closed: u64,
        pub hours_failed: u64,
        pub results: u64,
        pub deviant: u64,
        /// The server lost its memory (fault / complaint reset): every device relearns.
        pub server_resets: u64,
        pub slot_evictions: u64,
    }

    /// The EL1 side: MAC -> slot attribution, the pending batch, the hour clock, the evidence ring.
    pub struct Host {
        pub srv: Server,
        slots: [[u8; 6]; DEVICES],
        used: u64,
        last_seen: [u32; DEVICES],
        batch: [u8; IN_MAX],
        nb: usize,
        /// Devices with at least one delivered event in the open hour (the only ones a CLOSE_HOUR may report).
        fed: u64,
        /// Devices with events still in `batch` (become `fed` when the batch is delivered).
        pending: u64,
        /// The UTC epoch hour currently open (None = no hour open yet).
        hour: Option<u32>,
        pub c: Counters,
        ev: [Evidence; EVIDENCE_RING],
        nev: u64,
        /// `srv.restarts` when last checked: a change means the server lost its memory.
        seen_restarts: u64,
        out: [u8; OUT_MAX],
    }

    static mut HOST: Option<Host> = None;
    static mut TRIED: bool = false;

    fn host_opt() -> Option<&'static mut Host> {
        unsafe { (*core::ptr::addr_of_mut!(HOST)).as_mut() }
    }

    /// The host, loading the server on first use (once; a failed load leaves Neuro off — nothing depends on it).
    pub fn host() -> Option<&'static mut Host> {
        unsafe {
            if !TRIED {
                TRIED = true;
                match load() {
                    Ok(s) => {
                        HOST = Some(Host { srv: s, slots: [[0; 6]; DEVICES], used: 0, last_seen: [0; DEVICES], batch: [0; IN_MAX], nb: 0, fed: 0, pending: 0, hour: None, c: Counters::default(), ev: [Evidence::default(); EVIDENCE_RING], nev: 0, seen_restarts: 0, out: [0; OUT_MAX] });
                        let h = host_opt()?;
                        h.handshake();
                        kprint!(" [NEURO] el0-neuro loaded at {:#x}: ABI v{}.{} devices={} bytes/device={} rw_pages={} (observe + score only; evidence, never an alert)\n",
                            BASE, h.srv.info.map_or(0, |i| i.major), h.srv.info.map_or(0, |i| i.minor), h.srv.info.map_or(0, |i| i.devices), h.srv.info.map_or(0, |i| i.bytes_per_device), h.srv.nrw);
                    }
                    Err(why) => kprint!(" [NEURO] el0-neuro FAILED to load ({}) — Neuro is off; nothing depends on it\n", why),
                }
            }
            host_opt()
        }
    }

    impl Host {
        /// One supervised call; notices a server reset (fault / complaint) and drops what it invalidated.
        pub fn call(&mut self, cmd: u32, input: &[u8], expect: Option<usize>) -> Reply {
            let r = self.srv.call(cmd, input, expect);
            self.sync();
            r
        }
        fn sync(&mut self) {
            if self.srv.restarts != self.seen_restarts {
                self.seen_restarts = self.srv.restarts;
                self.server_lost();
            }
        }

        /// INFO: the server must speak ABI major 1 and keep the kernel's device table.
        fn handshake(&mut self) -> bool {
            self.srv.info = None;
            if let Reply::Ok(n) = self.call(CMD_INFO, &[], Some(INFO_LEN)) {
                let mut o = [0u8; INFO_LEN];
                self.srv.read(OUT_OFF, &mut o[..n]);
                self.srv.info = parse_info(&o[..n]);
            }
            self.srv.info.is_some()
        }

        /// The server's state is gone (reset): the open hour and the pending batch cannot be scored any more.
        fn server_lost(&mut self) {
            self.c.server_resets += 1;
            self.nb = 0;
            self.fed = 0;
            self.pending = 0;
        }

        /// The slot of `mac`, assigning one (the least recently seen is evicted: RESET_DEV makes the server forget it).
        fn slot(&mut self, mac: &[u8; 6], now_s: u32) -> Option<u16> {
            for i in 0..DEVICES {
                if self.used & (1u64 << i) != 0 && self.slots[i] == *mac {
                    self.last_seen[i] = now_s;
                    return Some(i as u16);
                }
            }
            let i = if self.used != u64::MAX {
                (!self.used).trailing_zeros() as usize
            } else {
                let mut o = 0;
                for i in 1..DEVICES {
                    if self.last_seen[i] < self.last_seen[o] {
                        o = i;
                    }
                }
                self.flush();
                let bit = 1u64 << o;
                if self.fed & bit != 0 {
                    return None; // never evict a device with an open hour; the event is dropped
                }
                if !matches!(self.call(CMD_RESET_DEV, &(o as u16).to_le_bytes(), Some(0)), Reply::Ok(_)) {
                    return None;
                }
                self.c.slot_evictions += 1;
                o
            };
            self.slots[i] = *mac;
            self.used |= 1u64 << i;
            self.last_seen[i] = now_s;
            Some(i as u16)
        }

        #[allow(clippy::too_many_arguments)] // one event record's fields, spelled out (encode_event's shape)
        /// Queue one event for the open UTC hour. Drops (and counts) when the clock is unset or the server cannot run.
        fn observe(&mut self, mac: &[u8; 6], utc_s: Option<u64>, kind: u8, flags: u8, fp: u32, bytes: u64, conns: u16) {
            let Some(t) = utc_s else {
                self.c.events_dropped += 1;
                return;
            };
            self.roll((t / 3600) as u32);
            if !self.srv.ready() {
                self.c.events_dropped += 1;
                return;
            }
            let Some(dev) = self.slot(mac, t as u32) else {
                self.c.events_dropped += 1;
                return;
            };
            let Some(rec) = encode_event(kind, flags, dev, fp, bytes, conns) else {
                self.c.events_dropped += 1;
                return;
            };
            if self.nb + EV_SIZE > IN_MAX {
                self.flush();
            }
            self.batch[self.nb..self.nb + EV_SIZE].copy_from_slice(&rec);
            self.nb += EV_SIZE;
            self.pending |= 1u64 << dev;
        }

        /// A new connection (doc 20: SYN, or UDP after >= 120 s idle) from `mac` to peer fingerprint `fp`.
        pub fn observe_flow(&mut self, mac: &[u8; 6], utc_s: Option<u64>, fp: u32, bytes: u64, conns: u16) {
            self.observe(mac, utc_s, EV_FLOW, 0, fp, bytes, conns)
        }
        /// One DNS query for registered-domain fingerprint `fp` (`nx` = rcode 3).
        pub fn observe_dns(&mut self, mac: &[u8; 6], utc_s: Option<u64>, fp: u32, nx: bool) {
            self.observe(mac, utc_s, EV_DNS, nx as u8, fp, 0, 1)
        }

        /// Deliver the pending batch (one excursion).
        pub fn flush(&mut self) {
            if self.nb == 0 {
                return;
            }
            let n = self.nb / EV_SIZE;
            self.nb = 0;
            let pend = core::mem::take(&mut self.pending);
            let r = self.srv.call(CMD_EVENTS, &self.batch[..n * EV_SIZE], Some(0));
            self.sync();
            match r {
                Reply::Ok(_) => {
                    self.c.batches += 1;
                    self.c.events_fed += n as u64;
                    self.fed |= pend;
                }
                Reply::Refused(_) => {
                    // every record was built by encode_event: a refusal is the server disagreeing with a valid batch
                    self.c.batches_refused += 1;
                    self.c.events_dropped += n as u64;
                }
                Reply::Failed => self.c.events_dropped += n as u64,
            }
        }

        /// Advance the clock: when the UTC hour changes, close the open one.
        fn roll(&mut self, utc_hour: u32) {
            match self.hour {
                Some(h) if h == utc_hour => {}
                Some(h) if utc_hour > h => {
                    self.close(h);
                    self.hour = Some(utc_hour);
                }
                Some(_) => {} // the clock stepped back: keep the open hour (events count toward it), never re-close one
                None => self.hour = Some(utc_hour),
            }
        }

        /// Called by the owner of the clock (the AP loop) about once a second: closes the hour when it is over.
        pub fn tick(&mut self, utc_s: Option<u64>) {
            if let Some(t) = utc_s {
                self.roll((t / 3600) as u32);
            }
        }

        /// CLOSE_HOUR for epoch hour `h`; validated results -> counters + evidence. Returns the records kept.
        pub fn close(&mut self, h: u32) -> usize {
            self.flush();
            let fed = core::mem::take(&mut self.fed);
            if fed == 0 {
                return 0;
            }
            let hr = (h % 24) as u8;
            match self.call(CMD_CLOSE_HOUR, &[hr], None) {
                Reply::Ok(n) => {
                    self.srv.read(OUT_OFF, &mut self.out[..n]);
                    let (mut res, mut dev) = (0u64, 0u64);
                    let mut keep = [Evidence::default(); DEVICES];
                    let mut nk = 0;
                    let slots = self.slots;
                    match parse_close_reply(&self.out[..n], fed, |d| {
                        res += 1;
                        if d.deviant {
                            dev += 1;
                            keep[nk] = Evidence { mac: slots[d.dev as usize], utc_hour: h, driver: d.driver, score_q8: d.score_q8, parts: d.parts };
                            nk += 1;
                        }
                    }) {
                        Ok(_) => {
                            self.c.hours_closed += 1;
                            self.c.results += res;
                            self.c.deviant += dev;
                            for e in keep[..nk].iter() {
                                self.ev[(self.nev % EVIDENCE_RING as u64) as usize] = *e;
                                self.nev += 1;
                            }
                            res as usize
                        }
                        Err(_) => {
                            self.c.hours_failed += 1;
                            self.srv.complain(crate::superv::WHY_BAD_LENGTH, false);
                            self.sync();
                            0
                        }
                    }
                }
                _ => {
                    self.c.hours_failed += 1;
                    0
                }
            }
        }

        /// The evidence records kept, newest first.
        pub fn evidence(&self) -> impl Iterator<Item = &Evidence> + '_ {
            let n = self.nev.min(EVIDENCE_RING as u64);
            (0..n).map(move |k| &self.ev[((self.nev - 1 - k) % EVIDENCE_RING as u64) as usize])
        }

        /// HEALTH (v1.1 servers).
        pub fn health(&mut self) -> Option<Health> {
            if self.srv.info.is_none_or(|i| i.caps & CAP_HEALTH == 0) {
                return None;
            }
            match self.call(CMD_HEALTH, &[], Some(HEALTH_LEN)) {
                Reply::Ok(n) => {
                    let mut o = [0u8; HEALTH_LEN];
                    self.srv.read(OUT_OFF, &mut o[..n]);
                    let h = parse_health(&o);
                    if h.is_none() {
                        self.srv.complain(crate::superv::WHY_BAD_LENGTH, false);
                        self.sync();
                    }
                    h
                }
                _ => None,
            }
        }
    }

    // ------------------------------------------------------------------ QEMU self-tests ---------------------------

    #[cfg(not(feature = "cm5"))]
    static GOLDEN: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../neuro/neuro-core/tests/golden.txt"));

    #[cfg(not(feature = "cm5"))]
    fn num(s: &str) -> i64 {
        s.parse::<i64>().unwrap_or(-1)
    }
    #[cfg(not(feature = "cm5"))]
    fn hex32(s: &str) -> u32 {
        u32::from_str_radix(s, 16).unwrap_or(0)
    }

    /// [P-neuro-golden]: the 1,200 golden hour closes of neuro-core (host-proven bit-exact against the integer
    /// reference) replayed through the REAL ABI and the REAL validation path, each score and part bit-exact.
    #[cfg(not(feature = "cm5"))]
    fn golden(s: &mut Server) -> bool {
        let mut batch = [0u8; IN_MAX];
        let (mut nb, mut closes, mut ok, mut events) = (0usize, 0u32, 0u32, 0u64);
        let mut fed = 0u64;
        let mut first_bad = 0usize;
        fn flush(s: &mut Server, batch: &mut [u8; IN_MAX], nb: &mut usize) -> bool {
            if *nb > 0 {
                let r = s.call(CMD_EVENTS, &batch[..*nb], Some(0));
                *nb = 0;
                r == Reply::Ok(0)
            } else {
                true
            }
        }
        let mut all_batches_ok = true;
        for (ln, line) in GOLDEN.lines().enumerate() {
            let mut t = line.split_ascii_whitespace();
            let Some(tag) = t.next() else { continue };
            let f: [&str; 9] = core::array::from_fn(|_| t.next().unwrap_or(""));
            let rec = match tag {
                "R" => {
                    all_batches_ok &= flush(s, &mut batch, &mut nb);
                    let _ = s.call(CMD_RESET_DEV, &(num(f[0]) as u16).to_le_bytes(), Some(0));
                    None
                }
                "F" => encode_event(EV_FLOW, 0, num(f[0]) as u16, hex32(f[1]), num(f[2]) as u64, num(f[3]) as u16),
                "N" => encode_event(EV_VOLUME, 0, num(f[0]) as u16, 0, num(f[1]) as u64, num(f[2]) as u16),
                "D" => encode_event(EV_DNS, (f[2] == "1") as u8, num(f[0]) as u16, hex32(f[1]), 0, 1),
                "C" => {
                    all_batches_ok &= flush(s, &mut batch, &mut nb);
                    let (dev, hr) = (num(f[0]), num(f[1]));
                    closes += 1;
                    let want_parts: [u16; 5] = core::array::from_fn(|i| num(f[3 + i]).clamp(0, 65535) as u16);
                    let mut good = false;
                    if let Reply::Ok(n) = s.call(CMD_CLOSE_HOUR, &[hr as u8], None) {
                        let mut out = [0u8; RES_SIZE * 2];
                        s.read(OUT_OFF, &mut out[..n.min(RES_SIZE * 2)]);
                        let _ = parse_close_reply(&out[..n.min(RES_SIZE * 2)], fed, |d| {
                            good = n == RES_SIZE && d.dev as i64 == dev && d.score_q8 as i64 == num(f[2]) && d.parts == want_parts;
                        });
                    }
                    fed = 0;
                    if good {
                        ok += 1;
                    } else if first_bad == 0 {
                        first_bad = ln + 1;
                    }
                    None
                }
                _ => None, // S/L/P/X lines are checked by the host test (neuro-core/tests/golden.rs)
            };
            if let Some(r) = rec {
                if nb + EV_SIZE > IN_MAX {
                    all_batches_ok &= flush(s, &mut batch, &mut nb);
                }
                batch[nb..nb + EV_SIZE].copy_from_slice(&r);
                nb += EV_SIZE;
                fed |= 1u64 << (r[2] as u64 | (r[3] as u64) << 8);
                events += 1;
            }
        }
        let pass = closes == 1200 && ok == closes && all_batches_ok;
        kprint!(" [P-neuro-golden] {} — {}/{} hour closes bit-exact through the real ABI + the EL1 reply validation ({} events; every batch accepted={}){}\n",
            if pass { "PASS" } else { "FAIL" }, ok, closes, events, all_batches_ok, if first_bad > 0 { " — first mismatch at golden line (see below)" } else { "" });
        if first_bad > 0 {
            kprint!(" [P-neuro-golden] first mismatch: golden.txt line {}\n", first_bad);
        }
        pass
    }

    /// The whole N0 integration in QEMU. Run from the Mission Control boot self-tests (the serve-loop context, after
    /// the other EL0 servers), like hsh / lansvc.
    #[cfg(not(feature = "cm5"))]
    pub fn selftest() -> bool {
        let Some(h) = host() else {
            kprint!(" [P-neuro] FAIL — el0-neuro did not load\n");
            return false;
        };
        // ---- ABI handshake: v1.1, HEALTH, and a kernel speaking a future major is refused by the server ----
        let info = h.srv.info;
        let health0 = h.health();
        h.srv.write(H_ABI, &(2u32 << 16).to_le_bytes());
        let st_future = {
            // a raw excursion with a major-2 version word (the call path always writes ABI_WORD, so do it by hand)
            let s = &mut h.srv;
            s.write(H_MAGIC, &MAGIC.to_le_bytes());
            s.write(H_CMD, &CMD_INFO.to_le_bytes());
            s.write(H_IN_LEN, &0u32.to_le_bytes());
            s.write(H_STATUS, &ST_PANIC.to_le_bytes());
            let how = crate::el0as::excursion(&s.aspace, s.entry, s.sp_top, BUDGET_US);
            if how == crate::Excursion::Exited { s.r32(H_STATUS) } else { ST_PANIC }
        };
        let abi = info.is_some_and(|i| i.major == 1 && i.minor >= 1 && i.caps & CAP_HEALTH != 0) && health0.is_some() && st_future == ST_BAD_VERSION;
        kprint!(" [P-neuro-abi] {} — INFO v{}.{} caps={:#x} devices={} bytes/device={}; HEALTH answered={}; a major-2 kernel is refused by the server (status {} = ST_BAD_VERSION)\n",
            if abi { "PASS" } else { "FAIL" }, info.map_or(0, |i| i.major), info.map_or(0, |i| i.minor), info.map_or(0, |i| i.caps), info.map_or(0, |i| i.devices), info.map_or(0, |i| i.bytes_per_device), health0.is_some(), st_future);

        // ---- golden replay ----
        let gold = golden(&mut h.srv);

        // ---- fault containment: bad input refused (no reset), a forced panic contained + journaled, relearn ----
        let saved = crate::superv::swap(hal::superv::Journal::new());
        let r_short = h.call(CMD_EVENTS, &[1u8; 15], Some(0));
        let mut bad = [0u8; EV_SIZE];
        bad[0] = EV_FLOW;
        bad[2..4].copy_from_slice(&999u16.to_le_bytes());
        let r_dev = h.call(CMD_EVENTS, &bad, Some(0));
        bad[0] = 77;
        bad[2..4].copy_from_slice(&0u16.to_le_bytes());
        let r_kind = h.call(CMD_EVENTS, &bad, Some(0));
        let r_hour = h.call(CMD_CLOSE_HOUR, &[24], None);
        let r_cmd = h.call(1234, &[], Some(0));
        let refused = [r_short, r_dev, r_kind, r_hour].iter().all(|r| *r == Reply::Refused(ST_BAD_INPUT)) && r_cmd == Reply::Refused(ST_BAD_CMD);
        let (f0, rs0) = (h.srv.faults, h.c.server_resets);
        let r_panic = crate::superv::deliberate(|| h.call(CMD_SELFTEST_FAULT, &[], Some(0)));
        let after = h.handshake();
        let health1 = h.health();
        let journaled = crate::superv::journal().newest_first().any(|e| e.component == C && e.kind == hal::superv::Kind::Planned);
        let fault = refused && r_panic == Reply::Failed && h.srv.faults == f0 + 1 && h.c.server_resets == rs0 + 1 && after && journaled
            && health1.is_some_and(|x| x.slots_used == 0 && x.events_ok == 0);
        kprint!(" [P-neuro-fault] {} — short batch / bad device / bad kind / bad hour refused ST_BAD_INPUT, unknown command ST_BAD_CMD (no reset)={}; forced panic contained={} journaled={} server reset from the signed ELF, memory gone (slots {} events {})={}; kernel alive, next INFO answers={}\n",
            if fault { "PASS" } else { "FAIL" }, refused, r_panic == Reply::Failed, journaled, health1.map_or(99, |x| x.slots_used), health1.map_or(99, |x| x.events_ok), h.c.server_resets == rs0 + 1, after);

        // ---- reply validation: a broken length is refused (complaint, reset) and never reaches the evidence ----
        let (cp0, nev0) = (h.srv.complaints, h.nev);
        crate::superv::inject_bad_reply(C);
        let r_inj = crate::superv::deliberate(|| h.call(CMD_INFO, &[], Some(INFO_LEN)));
        let complaint = crate::superv::journal().newest_first().any(|e| e.component == C && e.kind == hal::superv::Kind::Planned);
        let validate = r_inj == Reply::Failed && h.srv.complaints == cp0 + 1 && complaint && h.nev == nev0 && h.handshake();
        kprint!(" [P-neuro-validate] {} — a reply with a length past OUT is refused={} journaled={} server reset, no evidence kept={}; the EL1 record checks (device not fed / duplicate / driver / flag-vs-score / rsv / length) are the hal::neuroabi unit tests\n",
            if validate { "PASS" } else { "FAIL" }, r_inj == Reply::Failed, complaint, h.nev == nev0);
        let _ = crate::superv::swap(saved);

        // ---- the host path: attribution, batching, hour roll, evidence; backpressure; no clock -> dropped ----
        let base_s: u64 = 1_795_000_000 / 3600 * 3600; // an hour boundary in 2026
        let macs: [[u8; 6]; 3] = [[2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2], [2, 0, 0, 0, 0, 3]];
        let c0 = h.c;
        h.observe_flow(&macs[0], None, 1, 100, 1); // no clock: dropped, counted
        let no_clock = h.c.events_dropped == c0.events_dropped + 1;
        // 30 calm hours of the same few peers per device (learning), then one hour with a burst of novel peers
        for hr in 0..30u64 {
            for (k, m) in macs.iter().enumerate() {
                for p in 0..6u32 {
                    h.observe_flow(m, Some(base_s + hr * 3600 + 60 + p as u64), 0x1000 + p + k as u32 * 16, 2_000, 1);
                }
                h.observe_dns(m, Some(base_s + hr * 3600 + 120), 0xAB00 + k as u32, false);
            }
        }
        for p in 0..400u32 {
            h.observe_flow(&macs[1], Some(base_s + 30 * 3600 + 60), 0xBAD0_0000u32.wrapping_add(p.wrapping_mul(2_654_435_761)), 50_000, 1);
        }
        h.tick(Some(base_s + 31 * 3600)); // the hour rolls: CLOSE_HOUR for hour 30
        let h30 = (base_s / 3600 + 30) as u32;
        let novel_flagged = h.evidence().any(|e| e.mac == macs[1] && e.utc_hour == h30);
        let closed = h.c.hours_closed - c0.hours_closed;
        let path = no_clock && closed == 31 && h.c.hours_failed == c0.hours_failed && novel_flagged && h.c.events_fed > c0.events_fed;
        let top = h.evidence().find(|e| e.mac == macs[1] && e.utc_hour == h30).copied().unwrap_or_default();
        kprint!(" [P-neuro-host] {} — no clock -> dropped+counted={}; {} UTC hours closed by the hour roll ({} results, {} deviant, 0 failed={}); the burst of 400 novel peers on device 2 is a behaviour-deviation evidence record for hour 30={} (driver {} score {}/256); evidence only — no alert, no verdict, no action\n",
            if path { "PASS" } else { "FAIL" }, no_clock, closed, h.c.results - c0.results, h.c.deviant - c0.deviant, h.c.hours_failed == c0.hours_failed, novel_flagged,
            DRIVERS.get(top.driver as usize).copied().unwrap_or("?"), top.score_q8);

        // backpressure: a held-off server (a counted fault streak past the grace) drops events, never blocks
        let saved2 = crate::superv::swap(hal::superv::Journal::new()); // the drill's entries are not this boot's
        let d0 = h.c.events_dropped;
        let _ = crate::superv::drill(|| h.call(CMD_SELFTEST_FAULT, &[], Some(0)));
        let _ = crate::superv::drill(|| h.call(CMD_SELFTEST_FAULT, &[], Some(0)));
        let held = !h.srv.ready();
        let t1 = base_s + 31 * 3600 + 10;
        for p in 0..10u32 {
            h.observe_flow(&macs[0], Some(t1), p, 1, 1);
        }
        let dropped = h.c.events_dropped - d0;
        let bp = held && dropped == 10;
        kprint!(" [P-neuro-backpressure] {} — after a fault streak the server is held off by its supervisor entry={}; {} of 10 events dropped and counted, the caller never waited\n",
            if bp { "PASS" } else { "FAIL" }, held, dropped);
        let _ = crate::superv::swap(saved2);

        let pass = abi && gold && fault && validate && path && bp;
        kprint!(" [P-neuro] {} — el0-neuro hosted by heqk (QEMU): abi={} golden={} fault={} validate={} host={} backpressure={} (CM5 metal: not run)\n",
            if pass { "PASS" } else { "FAIL" }, abi, gold, fault, validate, path, bp);
        pass
    }
}
