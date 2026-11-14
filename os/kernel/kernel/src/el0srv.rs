//! ADR 0065 step 2 — the RESIDENT EL0 driver-server substrate, first used by `el0-wifi`.
//!
//! What the kernel keeps (ADR 0065 D1) is all here:
//! - one device-mapping grant (step 2: a fake device, one RAM page; step 4: the SDHCI register page);
//! - the two frame rings (`hal::el0ring`), reached through the physical frames — every index and length the
//!   server wrote is re-checked on the way in;
//! - supervision: a fault (or a budget overrun) resets the server's writable memory, zeroes its control page and
//!   rings, counts the restart and holds the next call off for a backoff that doubles per fault (bounded), so a
//!   crashing driver cannot spin the CPU.
//!
//! "Resident": the server is mapped once and keeps its `.data` / `.bss` between commands (unlike `el0-lansvc`, which
//! is stateless by contract). Each command is still one bounded synchronous excursion (the heqk model; measured on
//! metal at 388 ns per round trip, ADR 0065 step 1).

#[cfg(feature = "mctls")]
pub use imp::*;

#[cfg(feature = "mctls")]
mod imp {
    use hal::el0ring::{self as ring, RingMem};
    use hal::wifisrvabi::*;

    static WIFI_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/el0_wifi.elf"));

    #[cfg(feature = "cm5")]
    pub const BASE: usize = BASE_CM5;
    #[cfg(not(feature = "cm5"))]
    pub const BASE: usize = BASE_QEMU;
    // the whole window must stay inside the platform's EL0 window
    const _: () = assert!(BASE + WINDOW_END <= crate::elf::USER_VA_HI && BASE >= crate::elf::USER_VA_LO);
    const _: () = assert!(CTRL_OFF >= STACK_OFF + STACK_SIZE && DEV_OFF > CTRL_OFF && RX_OFF > DEV_OFF);

    const STACK_PAGES: usize = STACK_SIZE / 0x1000;
    const RING_PAGES: usize = ring::RING_BYTES / 0x1000;
    const RW_MAX: usize = 8;
    #[cfg(feature = "cm5")]
    const BUDGET_US: u64 = 20_000;
    #[cfg(not(feature = "cm5"))]
    const BUDGET_US: u64 = 2_000_000;
    /// First restart backoff; doubles per consecutive fault up to BACKOFF_MAX_MS.
    pub const BACKOFF_MS: u64 = 50;
    pub const BACKOFF_MAX_MS: u64 = 5_000;

    /// A ring as the kernel sees it: its physical frames, in order.
    pub struct PagedRing {
        frames: [usize; RING_PAGES],
    }
    impl RingMem for PagedRing {
        fn read(&self, mut off: usize, mut out: &mut [u8]) {
            while !out.is_empty() && off < ring::RING_BYTES {
                let (pg, po) = (off / 0x1000, off % 0x1000);
                let n = out.len().min(0x1000 - po);
                unsafe { core::ptr::copy_nonoverlapping((self.frames[pg] + po) as *const u8, out.as_mut_ptr(), n) };
                off += n;
                out = &mut out[n..];
            }
        }
        fn write(&mut self, mut off: usize, mut data: &[u8]) {
            while !data.is_empty() && off < ring::RING_BYTES {
                let (pg, po) = (off / 0x1000, off % 0x1000);
                let n = data.len().min(0x1000 - po);
                unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), (self.frames[pg] + po) as *mut u8, n) };
                off += n;
                data = &data[n..];
            }
        }
    }

    /// The outcome of one command.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Call {
        /// The server answered: (status, r0, commands this incarnation has served).
        Done(u32, u32, u32),
        /// It faulted or overran: it was reset; the next call waits for the backoff.
        Fault,
        /// Refused: still inside the restart backoff.
        Backoff,
    }

    pub struct Server {
        entry: usize,
        sp_top: usize,
        ctrl: usize,
        dev: usize,
        pub rx: PagedRing,
        pub tx: PagedRing,
        rw: [(usize, usize, usize); RW_MAX],
        nrw: usize,
        pub calls: u64,
        pub faults: u64,
        pub restarts: u64,
        /// Frames the kernel refused from a bad RX ring (resyncs).
        pub bad_rings: u64,
        next_ok: u64,
        streak: u32,
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
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Kind {
        Code,
        Data,
        DataRo,
        /// A device grant. Step 2's fake device is RAM, so it maps as data; step 4 maps the SDHCI page as Device.
        Dev,
    }
    fn map(va: usize, pa: usize, k: Kind) -> bool {
        #[cfg(feature = "cm5")]
        {
            use arch_aarch64::mmu_cm5 as m;
            match k {
                Kind::Code => {
                    m::map_user_code(va, pa);
                    true
                }
                Kind::Data | Kind::Dev => m::map_user_data(va, pa),
                Kind::DataRo => m::map_user_data_ro(va, pa),
            }
        }
        #[cfg(not(feature = "cm5"))]
        {
            let m = arch_aarch64::Mmu;
            match k {
                Kind::Code => m.map_user_code_page(va, pa),
                Kind::Data | Kind::Dev => m.map_user_data_page(va, pa),
                Kind::DataRo => m.map_user_data_ro_page(va, pa),
            }
        }
    }
    fn zero(f: usize) {
        unsafe { core::ptr::write_bytes(f as *mut u8, 0, 0x1000) };
    }
    fn now_ms() -> u64 {
        crate::clock::ticks() / (crate::clock::freq() / 1000).max(1)
    }

    /// Load `el0-wifi` and grant it the device page at physical `dev_pa` (a frame the caller owns).
    pub fn load(dev_pa: usize) -> Result<Server, &'static str> {
        let parsed = crate::elf::parse(WIFI_ELF).map_err(|_| "ELF parse")?;
        let mut s = Server {
            entry: parsed.entry,
            sp_top: BASE + STACK_OFF + STACK_SIZE,
            ctrl: 0,
            dev: dev_pa,
            rx: PagedRing { frames: [0; RING_PAGES] },
            tx: PagedRing { frames: [0; RING_PAGES] },
            rw: [(0, 0, 0); RW_MAX],
            nrw: 0,
            calls: 0,
            faults: 0,
            restarts: 0,
            bad_rings: 0,
            next_ok: 0,
            streak: 0,
        };
        for g in parsed.segs[..parsed.nsegs].iter() {
            if g.vaddr < BASE || g.vaddr + g.memsz > BASE + IMAGE_MAX {
                return Err("segment outside the window");
            }
            for p in 0..(g.memsz + 0xFFF) >> 12 {
                let f = alloc();
                if f == 0 {
                    return Err("out of frames (image)");
                }
                let voff = p * 0x1000;
                let n = g.filesz.saturating_sub(voff).min(0x1000);
                zero(f);
                if n > 0 {
                    unsafe { core::ptr::copy_nonoverlapping(WIFI_ELF.as_ptr().add(g.offset + voff), f as *mut u8, n) };
                }
                let k = if g.executable() {
                    arch_aarch64::mmu::sync_instruction_cache(f, 0x1000);
                    Kind::Code
                } else if g.writable() {
                    if s.nrw == RW_MAX {
                        return Err("too many RW pages");
                    }
                    s.rw[s.nrw] = (f, g.offset + voff, n);
                    s.nrw += 1;
                    Kind::Data
                } else {
                    Kind::DataRo
                };
                if !map(g.vaddr + voff, f, k) {
                    return Err("map image page refused");
                }
            }
        }
        for p in 0..STACK_PAGES {
            let f = alloc();
            if f == 0 || !map(BASE + STACK_OFF + p * 0x1000, f, Kind::Data) {
                return Err("map stack refused");
            }
        }
        let c = alloc();
        if c == 0 || !map(BASE + CTRL_OFF, c, Kind::Data) {
            return Err("map control page refused");
        }
        zero(c);
        s.ctrl = c;
        if !map(BASE + DEV_OFF, dev_pa, Kind::Dev) {
            return Err("map device refused");
        }
        for (off, r) in [(RX_OFF, &mut s.rx), (TX_OFF, &mut s.tx)] {
            for p in 0..RING_PAGES {
                let f = alloc();
                if f == 0 || !map(BASE + off + p * 0x1000, f, Kind::Data) {
                    return Err("map ring refused");
                }
                zero(f);
                r.frames[p] = f;
            }
        }
        Ok(s)
    }

    impl Server {
        fn w32(&self, off: usize, v: u32) {
            unsafe { core::ptr::write_volatile((self.ctrl + off) as *mut u32, v) };
        }
        fn r32(&self, off: usize) -> u32 {
            unsafe { core::ptr::read_volatile((self.ctrl + off) as *const u32) }
        }
        /// One command: a bounded excursion; a fault or overrun resets the server and starts the backoff.
        pub fn call(&mut self, cmd: u32) -> Call {
            let t = now_ms();
            if t < self.next_ok {
                return Call::Backoff;
            }
            self.w32(H_MAGIC, MAGIC);
            self.w32(H_CMD, cmd);
            self.w32(H_STATUS, ST_PANIC);
            self.calls += 1;
            let how = crate::excursion_bounded(self.entry, self.sp_top, BUDGET_US);
            let st = if how == crate::Excursion::Exited { self.r32(H_STATUS) } else { ST_PANIC };
            if st == ST_PANIC {
                self.faults += 1;
                self.reset();
                self.streak = self.streak.saturating_add(1);
                let b = (BACKOFF_MS << (self.streak - 1).min(10)).min(BACKOFF_MAX_MS);
                self.next_ok = now_ms() + b;
                return Call::Fault;
            }
            self.streak = 0;
            Call::Done(st, self.r32(H_R0), self.r32(H_SERVED))
        }
        /// Restore the image's writable pages, zero the control page and both rings (nothing a crashed driver left
        /// behind is trusted by its next incarnation).
        fn reset(&mut self) {
            self.restarts += 1;
            for i in 0..self.nrw {
                let (f, off, n) = self.rw[i];
                zero(f);
                if n > 0 {
                    unsafe { core::ptr::copy_nonoverlapping(WIFI_ELF.as_ptr().add(off), f as *mut u8, n) };
                }
            }
            zero(self.ctrl);
            ring::reset(&mut self.rx);
            ring::reset(&mut self.tx);
        }
        /// The kernel takes one received frame (the driver's RX ring; every value in it re-checked).
        pub fn rx_pop(&mut self, out: &mut [u8]) -> ring::Pop {
            let p = ring::pop(&mut self.rx, out);
            if p == ring::Pop::Bad {
                self.bad_rings += 1;
            }
            p
        }
        /// The kernel queues one frame for the driver to send.
        pub fn tx_push(&mut self, frame: &[u8]) -> bool {
            ring::push(&mut self.tx, frame)
        }
        /// Milliseconds until the next call is allowed (0 = now).
        pub fn backoff_left_ms(&self) -> u64 {
            self.next_ok.saturating_sub(now_ms())
        }
        /// Physical address of the granted device page.
        pub fn dev_pa(&self) -> usize {
            self.dev
        }
    }

    /// `[P-el0srv]` (QEMU): the resident substrate with the fake device.
    pub fn selftest() -> bool {
        let dev = alloc();
        if dev == 0 {
            return false;
        }
        zero(dev);
        let mut s = match load(dev) {
            Ok(s) => s,
            Err(why) => {
                arch_aarch64::_print(format_args!(" [P-el0srv] FAIL — el0-wifi did not load: {}\n", why));
                return false;
            }
        };
        let d16 = |off: usize| unsafe { core::ptr::read_volatile((dev + off) as *const u16) };
        let set_d16 = |off: usize, v: u16| unsafe { core::ptr::write_volatile((dev + off) as *mut u16, v) };
        let d = |off: usize, n: usize| unsafe { core::slice::from_raw_parts_mut((dev + off) as *mut u8, n) };
        let init = s.call(CMD_INIT) == Call::Done(ST_OK, 0, 1);
        // device RX -> the driver -> the RX ring -> the kernel
        let frame: [u8; 60] = core::array::from_fn(|i| i as u8 ^ 0xa5);
        d(FDEV_RX_DATA, 60).copy_from_slice(&frame);
        set_d16(FDEV_RX_LEN, 60);
        let p1 = s.call(CMD_POLL);
        let mut out = [0u8; 1600];
        let rx = p1 == Call::Done(ST_OK, 1, 2) && s.rx_pop(&mut out) == ring::Pop::Frame(60) && out[..60] == frame && d16(FDEV_RX_LEN) == 0;
        // the kernel -> the TX ring -> the driver -> device TX
        let big = [0x3cu8; 1514];
        let tx = s.tx_push(&big) && s.call(CMD_POLL) == Call::Done(ST_OK, 1, 3) && d16(FDEV_TX_LEN) == 1514 && d(FDEV_TX_DATA, 1514)[..] == big[..];
        // resident: the served counter kept counting across the three calls above (its .bss persisted)
        let resident = matches!(s.call(CMD_INIT), Call::Done(ST_OK, 0, 4));
        // a hostile driver's RX ring is refused, counted, resynced
        let hostile = s.call(CMD_SELFTEST_BAD_RING) == Call::Done(ST_OK, 0, 5)
            && s.rx_pop(&mut out) == ring::Pop::Bad && s.bad_rings == 1 && s.rx_pop(&mut out) == ring::Pop::Empty;
        // a fault: reset + restart counted, the next call held off by the backoff, then a fresh incarnation
        let tx_left = s.tx_push(&[1, 2, 3]);
        let fault = s.call(CMD_SELFTEST_FAULT) == Call::Fault && s.faults == 1 && s.restarts == 1 && s.call(CMD_INIT) == Call::Backoff;
        let t0 = now_ms();
        while now_ms() < t0 + BACKOFF_MS + 5 {}
        let fresh = s.call(CMD_INIT) == Call::Done(ST_OK, 0, 1);
        // the rings were wiped by the reset: the frame queued before the fault is not handed to the new incarnation
        let wiped = tx_left && s.call(CMD_POLL) == Call::Done(ST_OK, 0, 2) && ring::pending(&s.rx) == 0;
        // a second fault in a row doubles the backoff
        let doubled = s.call(CMD_SELFTEST_FAULT) == Call::Fault && s.backoff_left_ms() > BACKOFF_MS;
        let pass = init && rx && tx && resident && hostile && fault && fresh && wiped && doubled;
        arch_aarch64::_print(format_args!(
            " [P-el0srv] {} — ADR 0065 step 2, the resident EL0 driver substrate (el0-wifi + a fake device): loads with a device grant + two rings, INIT answers={} device RX -> driver -> RX ring -> kernel={} kernel -> TX ring -> driver -> device (1514 B)={} resident (served counter kept across calls)={} a hostile RX ring is refused, counted, resynced={} a fault resets + is counted + the next call waits for the backoff={} then a fresh incarnation (counter from 1)={} rings wiped by the reset={} consecutive faults double the backoff={}\n",
            if pass { "PASS" } else { "FAIL" }, init, rx, tx, resident, hostile, fault, fresh, wiped, doubled
        ));
        pass
    }
}
