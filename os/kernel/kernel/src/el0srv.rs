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
    /// ADR 0065 step 4g (S1): el0-wpa, the separate WPA security server.
    static WPA_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/el0_wpa.elf"));
    const WPA_STATE_PAGES: usize = hal::wpasrvabi::STATE_PAGES;
    #[cfg(feature = "cm5")]
    pub const WPA_BASE: usize = hal::wpasrvabi::BASE_CM5;
    #[cfg(not(feature = "cm5"))]
    pub const WPA_BASE: usize = hal::wpasrvabi::BASE_QEMU;
    const _: () = assert!(WPA_BASE + hal::wpasrvabi::WINDOW_END <= crate::elf::USER_VA_HI);
    // both servers' images, stacks and control pages sit at the same offsets from their bases
    const _: () = assert!(hal::wpasrvabi::IMAGE_MAX == IMAGE_MAX && hal::wpasrvabi::STACK_OFF == STACK_OFF
        && hal::wpasrvabi::STACK_SIZE == STACK_SIZE && hal::wpasrvabi::CTRL_OFF == CTRL_OFF);

    /// The key-transfer page (one frame, shared: RW in el0-wpa, RO in el0-wifi; never in any other space).
    static mut KEYX_FRAME: usize = 0;
    fn keyx_frame() -> usize {
        unsafe {
            if KEYX_FRAME == 0 {
                KEYX_FRAME = alloc();
                if KEYX_FRAME != 0 {
                    zero(KEYX_FRAME);
                }
            }
            KEYX_FRAME
        }
    }
    /// Selftests only (QEMU `[P-el0srv-keyer]` / `[P-el0srv-sae]`; never called on the CM5): the key-transfer record in
    /// `slot` — the test station knows that key anyway. No product path reads the page.
    #[cfg_attr(feature = "cm5", allow(dead_code))]
    pub fn keyx_test_read(slot: u8) -> Option<hal::wpasrvabi::keyx::Rec> {
        let f = keyx_frame();
        let off = slot as usize * hal::wpasrvabi::keyx::SLOT_SIZE;
        hal::wpasrvabi::keyx::decode(unsafe { core::slice::from_raw_parts((f + off) as *const u8, hal::wpasrvabi::keyx::SLOT_SIZE) })
    }
    /// Zero the key-transfer page (the kernel writes zeros; it never reads it).
    pub fn keyx_zero() {
        let f = unsafe { KEYX_FRAME };
        if f != 0 {
            zero(f);
        }
    }

    /// What a resident server is: its image, its window, and what the kernel maps for it.
    struct Spec {
        name: &'static str,
        elf: &'static [u8],
        #[cfg_attr(not(feature = "cm5"), allow(dead_code))]
        base: usize,
        magic: u32,
        /// RX / TX frame rings (el0-wifi).
        rings: bool,
        /// Persistent state pages at `state_off` (el0-wpa): kept across a restart, zeroed by a full wipe.
        state_off: usize,
        state_pages: usize,
        /// The key-transfer page: (offset, writable).
        keyx: Option<(usize, bool)>,
        /// The excursion budget per call (µs).
        budget_us: u64,
    }
    /// el0-wpa's budget: management calls only (a handful per join), the heaviest = setup (H2E PT + the PBKDF2 PSK)
    /// — never the frame path. A larger budget than the bus server's, so a slow setup is not a fault (a fault in a
    /// call about no station full-wipes).
    #[cfg(feature = "cm5")]
    const WPA_BUDGET_US: u64 = 250_000;
    #[cfg(not(feature = "cm5"))]
    const WPA_BUDGET_US: u64 = BUDGET_US;

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
        #[allow(dead_code)] // name() — reports
        name: &'static str,
        elf: &'static [u8],
        #[cfg_attr(not(feature = "cm5"), allow(dead_code))]
        base: usize,
        magic: u32,
        /// The excursion budget per call (µs).
        budget_us: u64,
        /// Has frame rings (el0-wifi); never touch `rx` / `tx` otherwise (their frames are 0).
        rings: bool,
        state: [usize; WPA_STATE_PAGES],
        pub nstate: usize,
        /// Full wipes (persistent state zeroed: every secret it held is gone).
        pub wipes: u64,
        entry: usize,
        aspace: crate::el0as::El0As,
        sp_top: usize,
        ctrl: usize,
        pub rx: PagedRing,
        pub tx: PagedRing,
        rw: [(usize, usize, usize); RW_MAX],
        nrw: usize,
        pub calls: u64,
        pub faults: u64,
        pub restarts: u64,
        /// Frames the kernel refused from a bad RX ring (resyncs).
        pub bad_rings: u64,
        /// `crate::clock::ticks()` at the last fault / overrun (0 = none) — `/api/health` wifi_driver.
        pub last_fault_ticks: u64,
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
        /// A real MMIO grant (step 4: the SDHCI register page): Device-nGnRE, EL0 RW, never executable.
        Dev,
        /// Step 2's fake device: a RAM page, mapped as data.
        FakeDev,
    }
    /// Map one page into THIS server's own address space (ADR 0065 S0).
    fn map(a: &crate::el0as::El0As, va: usize, pa: usize, k: Kind) -> bool {
        use crate::el0as::Map;
        a.map(va, pa, match k {
            Kind::Code => Map::Code,
            Kind::Data | Kind::FakeDev => Map::Data,
            Kind::DataRo => Map::DataRo,
            Kind::Dev => Map::Dev,
        })
    }
    fn zero(f: usize) {
        unsafe { core::ptr::write_bytes(f as *mut u8, 0, 0x1000) };
    }
    fn now_ms() -> u64 {
        crate::clock::ticks() / (crate::clock::freq() / 1000).max(1)
    }

    /// Load `el0-wifi` with its device grant (step 2: a fake device;
    /// step 3 needs none: the bus stays in EL1; step 4 grants the SDHCI page).
    /// What device page, if any, the server is granted.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum Grant {
        None,
        /// Step 2's fake device: a RAM frame the caller owns.
        Fake(usize),
        /// A real MMIO page (step 4: the SDHCI registers), mapped Device-nGnRE. Granted on the CM5 AP boot only.
        #[cfg_attr(not(feature = "cm5"), allow(dead_code))]
        Mmio(usize),
    }

    pub fn load(grant: Grant) -> Result<Server, &'static str> {
        load_spec(&Spec { name: "el0-wifi", elf: WIFI_ELF, base: BASE, magic: MAGIC, rings: true, state_off: 0, state_pages: 0,
            keyx: Some((KEYX_OFF, false)), budget_us: BUDGET_US }, grant)
    }
    /// ADR 0065 step 4g (S1): load el0-wpa — its own address space, persistent state pages, the key-transfer page RW,
    /// no device, no rings.
    pub fn load_wpa() -> Result<Server, &'static str> {
        load_spec(&Spec { name: "el0-wpa", elf: WPA_ELF, base: WPA_BASE, magic: hal::wpasrvabi::MAGIC, rings: false,
            state_off: hal::wpasrvabi::STATE_OFF, state_pages: WPA_STATE_PAGES, keyx: Some((hal::wpasrvabi::KEYX_OFF, true)),
            budget_us: WPA_BUDGET_US }, Grant::None)
    }

    fn load_spec(sp: &Spec, grant: Grant) -> Result<Server, &'static str> {
        const BASE: usize = 0; // shadow the el0-wifi constant: every address below comes from the spec
        let _ = BASE;
        let base = sp.base;
        let parsed = crate::elf::parse(sp.elf).map_err(|_| "ELF parse")?;
        let aspace = crate::el0as::El0As::new().ok_or("no address space")?;
        let mut s = Server {
            name: sp.name,
            elf: sp.elf,
            base,
            magic: sp.magic,
            budget_us: sp.budget_us,
            rings: sp.rings,
            state: [0; WPA_STATE_PAGES],
            nstate: 0,
            wipes: 0,
            entry: parsed.entry,
            aspace,
            sp_top: base + STACK_OFF + STACK_SIZE,
            ctrl: 0,
            rx: PagedRing { frames: [0; RING_PAGES] },
            tx: PagedRing { frames: [0; RING_PAGES] },
            rw: [(0, 0, 0); RW_MAX],
            nrw: 0,
            calls: 0,
            faults: 0,
            restarts: 0,
            bad_rings: 0,
            last_fault_ticks: 0,
            next_ok: 0,
            streak: 0,
        };
        for g in parsed.segs[..parsed.nsegs].iter() {
            if g.vaddr < base || g.vaddr + g.memsz > base + IMAGE_MAX {
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
                    unsafe { core::ptr::copy_nonoverlapping(sp.elf.as_ptr().add(g.offset + voff), f as *mut u8, n) };
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
                if !map(&aspace, g.vaddr + voff, f, k) {
                    return Err("map image page refused");
                }
            }
        }
        for p in 0..STACK_PAGES {
            let f = alloc();
            if f == 0 || !map(&aspace, base + STACK_OFF + p * 0x1000, f, Kind::Data) {
                return Err("map stack refused");
            }
        }
        let c = alloc();
        if c == 0 || !map(&aspace, base + CTRL_OFF, c, Kind::Data) {
            return Err("map control page refused");
        }
        zero(c);
        s.ctrl = c;
        match grant {
            Grant::None => {}
            Grant::Fake(d) => {
                if !map(&aspace, base + DEV_OFF, d, Kind::FakeDev) {
                    return Err("map device refused");
                }
            }
            Grant::Mmio(d) => {
                if !map(&aspace, base + DEV_OFF, d, Kind::Dev) {
                    return Err("map device refused");
                }
            }
        }
        for (off, r) in [(RX_OFF, &mut s.rx), (TX_OFF, &mut s.tx)].into_iter().filter(|_| sp.rings) {
            for p in 0..RING_PAGES {
                let f = alloc();
                if f == 0 || !map(&aspace, base + off + p * 0x1000, f, Kind::Data) {
                    return Err("map ring refused");
                }
                zero(f);
                r.frames[p] = f;
            }
        }
        for p in 0..sp.state_pages.min(WPA_STATE_PAGES) {
            let f = alloc();
            if f == 0 || !map(&aspace, base + sp.state_off + p * 0x1000, f, Kind::Data) {
                return Err("map state refused");
            }
            zero(f);
            s.state[p] = f;
            s.nstate = p + 1;
        }
        if let Some((off, writable)) = sp.keyx {
            let f = keyx_frame();
            if f == 0 || !map(&aspace, base + off, f, if writable { Kind::Data } else { Kind::DataRo }) {
                return Err("map key-transfer page refused");
            }
        }
        crate::el0as::register(sp.name, s.entry, s.aspace);
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
            self.w32(H_MAGIC, self.magic);
            self.w32(H_CMD, cmd);
            self.w32(H_STATUS, ST_PANIC);
            self.calls += 1;
            let how = crate::el0as::excursion(&self.aspace, self.entry, self.sp_top, self.budget_us);
            let st = if how == crate::Excursion::Exited { self.r32(H_STATUS) } else { ST_PANIC };
            if st == ST_PANIC {
                self.faults += 1;
                self.last_fault_ticks = crate::clock::ticks();
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
            self.restore();
        }
        /// `reset` without counting a restart (a full wipe right after the fault that already counted one).
        fn restore(&mut self) {
            for i in 0..self.nrw {
                let (f, off, n) = self.rw[i];
                zero(f);
                if n > 0 {
                    unsafe { core::ptr::copy_nonoverlapping(self.elf.as_ptr().add(off), f as *mut u8, n) };
                }
            }
            zero(self.ctrl);
            if self.rings {
                ring::reset(&mut self.rx);
                ring::reset(&mut self.tx);
            }
        }
        /// A full wipe (ADR 0065 step 4g): the reset, AND the persistent state pages zeroed — every secret the server
        /// held is gone. The next call starts a fresh, empty incarnation.
        pub fn full_wipe(&mut self) {
            self.restore(); // S4 metal: the fault that led here already counted the restart (it was counted twice)
            for &f in &self.state[..self.nstate] {
                zero(f);
            }
            self.wipes += 1;
        }
        /// The server's name (the isolation report, the beat).
        #[allow(dead_code)]
        pub fn name(&self) -> &'static str {
            self.name
        }
        /// Its window's base VA.
        #[cfg_attr(not(feature = "cm5"), allow(dead_code))]
        pub fn base(&self) -> usize {
            self.base
        }
        /// The kernel takes one received frame (the driver's RX ring; every value in it re-checked).
        pub fn rx_pop(&mut self, out: &mut [u8]) -> ring::Pop {
            if !self.rings {
                return ring::Pop::Empty;
            }
            let p = ring::pop(&mut self.rx, out);
            if p == ring::Pop::Bad {
                self.bad_rings += 1;
            }
            p
        }
        /// The kernel queues one frame for the driver to send.
        pub fn tx_push(&mut self, frame: &[u8]) -> bool {
            self.rings && ring::push(&mut self.tx, frame)
        }
        /// A command with input (IN area) and output (OUT area, copied into `out`, then scrubbed on the shared page:
        /// a Keyed reply carries a TK — the 2A / D3 wipe discipline). Returns the call and the output length.
        pub fn call_io(&mut self, cmd: u32, input: &[u8], out: &mut [u8]) -> (Call, usize) {
            let n = input.len().min(IN_MAX);
            unsafe { core::ptr::copy_nonoverlapping(input.as_ptr(), (self.ctrl + IN_OFF) as *mut u8, n) };
            self.w32(H_IN_LEN, n as u32);
            self.w32(H_OUT_LEN, 0);
            let c = self.call(cmd);
            let mut k = 0;
            if matches!(c, Call::Done(ST_OK, ..)) {
                k = (self.r32(H_OUT_LEN) as usize).min(OUT_MAX).min(out.len());
                unsafe { core::ptr::copy_nonoverlapping((self.ctrl + OUT_OFF) as *const u8, out.as_mut_ptr(), k) };
            }
            for i in 0..OUT_MAX {
                unsafe { core::ptr::write_volatile((self.ctrl + OUT_OFF + i) as *mut u8, 0) };
            }
            for i in 0..IN_MAX {
                unsafe { core::ptr::write_volatile((self.ctrl + IN_OFF + i) as *mut u8, 0) };
            }
            (c, k)
        }
        /// The hot-path variant of [`Self::call_io`] for commands that carry no key material (the frame read): only the
        /// bytes used are copied and cleared. The output length is still clamped by the kernel, never trusted.
        pub fn call_lean(&mut self, cmd: u32, input: &[u8], out: &mut [u8]) -> (Call, usize) {
            let n = input.len().min(IN_MAX);
            unsafe { core::ptr::copy_nonoverlapping(input.as_ptr(), (self.ctrl + IN_OFF) as *mut u8, n) };
            self.w32(H_IN_LEN, n as u32);
            self.w32(H_OUT_LEN, 0);
            let c = self.call(cmd);
            let mut k = 0;
            if matches!(c, Call::Done(ST_OK, ..)) {
                let m = (self.r32(H_OUT_LEN) as usize).min(OUT_MAX);
                k = m.min(out.len());
                unsafe { core::ptr::copy_nonoverlapping((self.ctrl + OUT_OFF) as *const u8, out.as_mut_ptr(), k) };
                unsafe { core::ptr::write_bytes((self.ctrl + OUT_OFF) as *mut u8, 0, m) };
            }
            unsafe { core::ptr::write_bytes((self.ctrl + IN_OFF) as *mut u8, 0, n) };
            (c, k)
        }
        /// Is any byte of the control page's IN / OUT areas non-zero? (the selftest's "no key left behind")
        pub fn io_clean(&self) -> bool {
            (0..IN_MAX).all(|i| unsafe { core::ptr::read_volatile((self.ctrl + IN_OFF + i) as *const u8) } == 0)
                && (0..OUT_MAX).all(|i| unsafe { core::ptr::read_volatile((self.ctrl + OUT_OFF + i) as *const u8) } == 0)
        }
        /// Milliseconds until the next call is allowed (0 = now).
        pub fn backoff_left_ms(&self) -> u64 {
            self.next_ok.saturating_sub(now_ms())
        }
    }

    /// `[P-el0srv-split]` (QEMU) — ADR 0065 step 4g S1 (operator decision 2026-11-15): the bus server (el0-wifi) and
    /// the WPA security server (el0-wpa) are independently supervised, in separate address spaces.
    pub fn split_selftest() -> bool {
        use hal::wpasrvabi as wp;
        let dev = alloc();
        zero(dev);
        let (Ok(mut w), Ok(mut p)) = (load(Grant::Fake(dev)), load_wpa()) else {
            arch_aarch64::_print(format_args!(" [P-el0srv-split] FAIL — a server did not load\n"));
            return false;
        };
        let wait = |ms: u64| {
            let t = now_ms();
            while now_ms() < t + ms {}
        };
        let init = w.call(CMD_INIT) == Call::Done(ST_OK, 0, 1) && p.call(wp::CMD_INIT) == Call::Done(ST_OK, 0, 1);
        // the security server's persistent state survives ITS OWN restart (a fault resets image + control only)
        let bumped = p.call(wp::CMD_STATE_BUMP) == Call::Done(ST_OK, 1, 2) && p.call(wp::CMD_STATE_BUMP) == Call::Done(ST_OK, 2, 3);
        let own_fault = p.call(wp::CMD_SELFTEST_FAULT) == Call::Fault && p.restarts == 1;
        wait(BACKOFF_MS + 5);
        // a fresh incarnation (served counter from 1) still holds the state
        let kept = p.call(wp::CMD_STATE_READ) == Call::Done(ST_OK, 2, 1);
        // a BUS fault (and its reset) never touches the security server: its restarts, faults and state unchanged
        let (pr, pf) = (p.restarts, p.faults);
        let bus_fault = w.call(CMD_SELFTEST_FAULT) == Call::Fault && w.restarts == 1;
        let untouched = bus_fault && p.restarts == pr && p.faults == pf && p.call(wp::CMD_STATE_READ) == Call::Done(ST_OK, 2, 2);
        // the key-transfer page: el0-wpa writes it, el0-wifi reads it, el0-wifi cannot write it
        let pat: [u8; 16] = core::array::from_fn(|i| 0xC0 ^ i as u8);
        let mut o = [0u8; 16];
        let put = matches!(p.call_io(wp::CMD_KEYX_PUT, &pat, &mut []), (Call::Done(ST_OK, 16, _), _));
        wait(BACKOFF_MS + 5);
        let (pc, pn) = w.call_io(CMD_KEYX_PEEK, &[], &mut o);
        let peek = matches!(pc, Call::Done(ST_OK, ..)) && pn == 16 && o == pat;
        let ro = w.call(CMD_SELFTEST_KEYX_WRITE) == Call::Fault
            && unsafe { core::slice::from_raw_parts(keyx_frame() as *const u8, 16) } == pat;
        keyx_zero();
        // S3c: the bus server installs ONLY the record the kernel asked for: a key record for station A in slot 0;
        // an install for station B is refused (R0 5); for A it builds + writes the request (the fake device refuses the
        // write: R0 4); an empty slot is refused
        let install = {
            use hal::wpasrvabi::keyx;
            let a = [2, 0x5a, 0, 0, 0, 9];
            let rec = keyx::Rec { index: 0, algo: hal::bcdc::CRYPTO_ALGO_AES_CCM, flags: 0, ea: a, klen: 16, key: [0x77; 32] };
            let mut b = [0u8; keyx::SLOT_SIZE];
            keyx::encode(&rec, &mut b);
            wait(BACKOFF_MS * 4 + 5);
            let put = matches!(p.call_io(wp::CMD_KEYX_PUT, &b, &mut []), (Call::Done(ST_OK, ..), _));
            let r0 = |w: &mut Server, ea: &[u8; 6]| match w.call_lean(hal::wpasrvabi::CMD_KEY_INSTALL, &keyx::encode_install(1, 0, 7, keyx::SLOT_TK, ea, 0), &mut []).0 {
                Call::Done(ST_OK, r, _) => r,
                _ => 0,
            };
            let wrong = r0(&mut w, &[2, 0x5b, 0, 0, 0, 0x0b]) == 5;
            let right = r0(&mut w, &a) == 4;
            keyx_zero();
            let empty = r0(&mut w, &a) == 5;
            put && wrong && right && empty
        };
        // a full wipe zeroes the persistent state (every secret gone): a fresh, empty incarnation
        wait(BACKOFF_MS + 5);
        p.full_wipe();
        wait(4 * BACKOFF_MS + 5);
        let wiped = p.call(wp::CMD_STATE_READ) == Call::Done(ST_OK, 0, 1) && p.wipes == 1;
        // both are in their own address spaces (the el0as report, run after this, covers them)
        let spaces = w.aspace != p.aspace;
        let pass = init && bumped && own_fault && kept && untouched && put && peek && ro && wiped && spaces && install;
        arch_aarch64::_print(format_args!(
            " [P-el0srv-split] {} — ADR 0065 step 4g S1: bus server el0-wifi + WPA security server el0-wpa, supervised apart: both load + answer={} el0-wpa persistent state written={} its own fault resets it={} and the restarted server still holds the state={} a BUS fault leaves el0-wpa's restarts / faults / state untouched={} key-transfer page: el0-wpa writes={} el0-wifi reads={} el0-wifi cannot write (faults, page intact)={} a full wipe zeroes the state={} separate address spaces={} S3c: the bus server installs only the record asked for (other station refused, right one written, empty slot refused)={}\n",
            if pass { "PASS" } else { "FAIL" }, init, bumped, own_fault, kept, untouched, put, peek, ro, wiped, spaces, install
        ));
        pass
    }

    /// `[P-el0srv]` (QEMU): the resident substrate with the fake device.
    pub fn selftest() -> bool {
        let dev = alloc();
        if dev == 0 {
            return false;
        }
        zero(dev);
        let mut s = match load(Grant::Fake(dev)) {
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
        // step 4a: the server reads the granted page's identity registers (here: a known pattern in the fake device)
        for (i, off) in PROBE_REGS.iter().enumerate() {
            unsafe { core::ptr::write_volatile((dev + off) as *mut u32, 0x4a00_0000 | (i as u32) << 8 | *off as u32) };
        }
        let mut po = [0u8; PROBE_REGS.len() * 4];
        let (pc, pn) = s.call_io(CMD_BUS_PROBE, &[], &mut po);
        let probe = matches!(pc, Call::Done(ST_OK, ..)) && pn == po.len()
            && PROBE_REGS.iter().enumerate().all(|(i, off)| u32::from_le_bytes([po[i * 4], po[i * 4 + 1], po[i * 4 + 2], po[i * 4 + 3]]) == 0x4a00_0000 | (i as u32) << 8 | *off as u32);
        // step 4b-2b: the frame read runs `hal::sdio::Bus::read_frame` over the grant. On the fake page every SDHCI
        // command fails at once (the all-ones INT_STATUS clear reads back as an error), so the first read reports the
        // mailbox interrupt (all ones includes I_HMB_HOST_INT) and a re-read past it reports dry; the lean call
        // leaves no bytes on the IO page
        let rxr = |skip: bool, s: &mut Server| {
            let mut i = [0u8; hal::wifisrvabi::rxmsg::IN_LEN];
            hal::wifisrvabi::rxmsg::encode_in(0x1800_2000, 0, skip, false, 2048, &mut i);
            let mut o = [0u8; OUT_MAX];
            let (c, n) = s.call_lean(CMD_RX_READ, &i, &mut o);
            let mut rx = [0u8; 2048];
            (matches!(c, Call::Done(ST_OK, ..))).then(|| hal::wifisrvabi::rxmsg::decode_out(&o[..n], &mut rx)).flatten().map(|r| r.0)
        };
        let rx_el0 = rxr(false, &mut s) == Some(hal::sdio::RxRead::HostInt) && rxr(true, &mut s) == Some(hal::sdio::RxRead::Dry) && s.io_clean();
        // a dry budget never makes the server wait or touch the counter (metal k4d: it trapped on the CM5, where EL0 has
        // no counter access; QEMU grants it for P17) — it polls once and answers
        let f0 = s.faults;
        // as on the CM5: no EL0 counter access during this call (QEMU's P17 grants it); restored after
        let kctl: u64;
        unsafe {
            core::arch::asm!("mrs {}, cntkctl_el1", out(reg) kctl, options(nomem, nostack));
            core::arch::asm!("msr cntkctl_el1, {}", "isb", in(reg) kctl & !0b11, options(nomem, nostack));
        }
        let rx_nowait = {
            let mut i = [0u8; hal::wifisrvabi::rxmsg::IN_LEN];
            hal::wifisrvabi::rxmsg::encode_in(0x1800_2000, 800, true, false, 2048, &mut i);
            let mut o = [0u8; OUT_MAX];
            let (c, n) = s.call_lean(CMD_RX_READ, &i, &mut o);
            let mut rx = [0u8; 2048];
            matches!(c, Call::Done(ST_OK, ..)) && hal::wifisrvabi::rxmsg::decode_out(&o[..n], &mut rx).map(|r| r.0) == Some(hal::sdio::RxRead::Dry)
        } && s.faults == f0;
        unsafe { core::arch::asm!("msr cntkctl_el1, {}", "isb", in(reg) kctl, options(nomem, nostack)) };
        let rx_el0 = rx_el0 && rx_nowait;
        // step 4c: a data frame built + written in EL0 over the grant: a small frame is attempted (the fake page fails
        // every command: Failed, byte mode); a 1514-B frame with block TX off is refused before the bus (TooBig); a
        // malformed request is refused (BAD_CMD); the lean call leaves no bytes on the IO page
        let txw = |eth: &[u8], big: bool, s: &mut Server| {
            let mut i = [0u8; hal::wifisrvabi::txmsg::HDR + hal::wifisrvabi::txmsg::ETH_MAX];
            let n = hal::wifisrvabi::txmsg::encode_in(5, 0, big, eth, &mut i).unwrap_or(0);
            match s.call_lean(CMD_TX_DATA, &i[..n], &mut []).0 {
                Call::Done(ST_OK, r0, _) => hal::wifisrvabi::txmsg::decode_r0(r0),
                _ => None,
            }
        };
        let tx_el0 = txw(&[0x66; 60], false, &mut s) == Some(hal::sdio::TxWrite::Failed { block: false })
            && txw(&[0x66; 1514], false, &mut s) == Some(hal::sdio::TxWrite::TooBig)
            && matches!(s.call_lean(CMD_TX_DATA, &[1, 2], &mut []).0, Call::Done(ST_BAD_CMD, ..))
            && s.io_clean();
        // step 4d: a control request built + written in EL0: attempted (the fake page fails the write: R0 4); a
        // malformed request is refused; the lean call leaves no bytes on the IO page
        let ctl_el0 = {
            let mut i = [0u8; hal::wifisrvabi::ctlmsg::HDR + 8];
            let n = hal::wifisrvabi::ctlmsg::encode_in(7, 0, 262, 0, 0x55, 64, b"ver\0", &mut i).unwrap_or(0);
            matches!(s.call_lean(CMD_TX_CTL, &i[..n], &mut []).0, Call::Done(ST_OK, 4, _))
                && matches!(s.call_lean(CMD_TX_CTL, &[1, 2, 3], &mut []).0, Call::Done(ST_BAD_CMD, ..))
                && s.io_clean()
        };
        // a fault: reset + restart counted, the next call held off by the backoff, then a fresh incarnation
        let tx_left = s.tx_push(&[1, 2, 3]);
        let fault = s.call(CMD_SELFTEST_FAULT) == Call::Fault && s.faults == 1 && s.restarts == 1 && s.call(CMD_INIT) == Call::Backoff;
        let t0 = now_ms();
        while now_ms() < t0 + BACKOFF_MS + 5 {}
        let fresh = s.call(CMD_INIT) == Call::Done(ST_OK, 0, 1);
        // the rings were wiped by the reset: the frame queued before the fault is not handed to the new incarnation
        let wiped = tx_left && s.call(CMD_POLL) == Call::Done(ST_OK, 0, 2) && ring::pending(&s.rx) == 0;
        // consecutive faults (no good call between them) double the backoff; a good call resets the streak
        let f1 = s.call(CMD_SELFTEST_FAULT) == Call::Fault && s.backoff_left_ms() <= BACKOFF_MS;
        let t1 = now_ms();
        while now_ms() < t1 + BACKOFF_MS + 5 {}
        let doubled = f1 && s.call(CMD_SELFTEST_FAULT) == Call::Fault && s.backoff_left_ms() > BACKOFF_MS;
        let pass = init && rx && tx && resident && hostile && probe && rx_el0 && tx_el0 && ctl_el0 && fault && fresh && wiped && doubled;
        arch_aarch64::_print(format_args!(
            " [P-el0srv] {} — ADR 0065 step 2, the resident EL0 driver substrate (el0-wifi + a fake device): loads with a device grant + two rings, INIT answers={} device RX -> driver -> RX ring -> kernel={} kernel -> TX ring -> driver -> device (1514 B)={} resident (served counter kept across calls)={} a hostile RX ring is refused, counted, resynced={} step 4a: the device page's identity registers read through the grant={} step 4b-2b: a frame read in EL0 over the grant (mailbox, then dry; a dry budget never waits in EL0; IO page clean)={} step 4c: a data frame written in EL0 (attempted, too-big refused, bad request refused; IO page clean)={} step 4d: a control request written in EL0 (attempted, bad request refused; IO page clean)={} a fault resets + is counted + the next call waits for the backoff={} then a fresh incarnation (counter from 1)={} rings wiped by the reset={} consecutive faults double the backoff={}\n",
            if pass { "PASS" } else { "FAIL" }, init, rx, tx, resident, hostile, probe, rx_el0, tx_el0, ctl_el0, fault, fresh, wiped, doubled
        ));
        pass
    }
}

// ---------------------------------------------------------------------------------------------------------------
// ADR 0065 step 3b: the WPA 4-way authenticator runs in el0-wifi (its keys live there, operator D3 2026-11-15). The
// driver calls it through the hook below; when the server is absent, faulted or in backoff the hook answers None and
// the driver uses its in-kernel copy of the same state machine (D5). A fault forgets the server's handshakes: those
// stations' 4-ways time out and they re-associate.
#[cfg(feature = "mctls")]
// the bridge is reached through the CM5 driver hook (and, for SAE, the wpa3 selftest): unused in other QEMU builds
#[cfg_attr(not(feature = "cm5"), allow(dead_code))]
pub mod keyer {
    use super::imp::{Call, Server};
    #[cfg(feature = "cm5")]
    use super::imp::{load, Grant};
    use hal::wifisrvabi::{keymsg, saemsg, *};
    use hal::wpakeyer::{Out, Start};

    pub static mut WIFI: Option<Server> = None;
    /// ADR 0065 step 4g (S1): the WPA security server, loaded beside el0-wifi in its own address space (S2 moves the
    /// authenticator, SAE and PMKSA into it).
    pub static mut WPA: Option<Server> = None;
    /// Handshakes started in el0-wifi (the metal proof that the EL0 path, not the in-kernel copy, served them).
    pub static mut EL0_STARTS: u64 = 0;

    /// The WPA security server (S2: every keying / SAE / PMKSA call goes here — never to the bus server).
    fn srv() -> Option<&'static mut Server> {
        unsafe { (*core::ptr::addr_of_mut!(WPA)).as_mut() }
    }
    /// The bus server (frames, control requests, the SDHCI grant).
    fn bus_srv() -> Option<&'static mut Server> {
        unsafe { (*core::ptr::addr_of_mut!(WIFI)).as_mut() }
    }

    // ---- S2: fault containment for the security server (design docs/design/wifi-el0-split.md §4) ----
    /// The station whose call faulted last, and the follow-up owed once the backoff is over: (station, poisoned =
    /// its second fault in a row: its PMKSA entry goes too).
    static mut FAULT_STA: Option<[u8; 6]> = None;
    static mut PENDING: Option<([u8; 6], bool)> = None;
    static mut CONSEC: u32 = 0;
    /// Contained faults (one station forgotten), poisoned stations (PMKSA entry dropped), full wipes signalled.
    pub static mut CONTAINED: u64 = 0;
    pub static mut POISONED: u64 = 0;
    /// Set by a full wipe; the driver takes it (deauthenticate everyone, re-provision the passphrase).
    static mut WIPED: bool = false;
    /// A full wipe: every secret el0-wpa held is gone, every station must re-authenticate.
    fn full_wipe() {
        let mut pages = 0;
        if let Some(s) = srv() {
            s.full_wipe();
            pages = s.nstate;
        }
        super::imp::keyx_zero();
        arch_aarch64::_print(format_args!(" [EL0-WPA] FULL WIPE: {} state page(s) + the key-transfer page zeroed (the PMKSA cache, SAE state, PMKs and group keys are gone)\n", pages));
        unsafe {
            WIPED = true;
            PENDING = None;
            FAULT_STA = None;
            CONSEC = 0;
        }
    }
    /// Taken by the driver after a full wipe (it then deauthenticates every station and re-sends the passphrase).
    #[cfg_attr(not(feature = "cm5"), allow(dead_code))]
    pub(crate) fn take_wiped() -> bool {
        unsafe { core::mem::replace(&mut *core::ptr::addr_of_mut!(WIPED), false) }
    }
    /// One call to the security server with containment. `sta` = the station the call is about (None = a call about
    /// no single station: a fault there is not containable and wipes).
    fn wpa_call(cmd: u32, inp: &[u8], out: &mut [u8], sta: Option<[u8; 6]>) -> Option<(Call, usize)> {
        let s = srv()?;
        // S4 metal: another station's fault must not reach this one. Right after a contained fault the server sits
        // out a short backoff (50 ms, doubling per consecutive fault); a call about a station inside it would fail
        // and, at the keying decision, turn into "unknown PMKID — refused" for a station whose PMKSA is intact. Wait a
        // short backoff out (<= 100 ms: well inside the loop-gap gate) instead of failing.
        if sta.is_some() {
            let left = s.backoff_left_ms();
            if left > 0 && left <= 100 {
                let ms = |t: u64| t / (crate::clock::freq() / 1000).max(1);
                let until = ms(crate::clock::ticks()) + left + 1;
                while ms(crate::clock::ticks()) < until {
                    core::hint::spin_loop();
                }
            }
        }
        // the follow-up owed for a contained fault, once the server answers again
        if s.backoff_left_ms() == 0 {
            if let Some((p, poison)) = unsafe { (*core::ptr::addr_of_mut!(PENDING)).take() } {
                let _ = s.call_io(CMD_KEY_ABORT, &p, &mut []);
                let mut f = [0u8; 15];
                f[..6].copy_from_slice(&p);
                f[14] = 1; // forget this station's SAE state outright
                let _ = s.call_io(CMD_SAE_FORGET, &f, &mut [0u8; 1]);
                if poison {
                    let mut r = [0u8; 7];
                    r[..6].copy_from_slice(&p);
                    let _ = s.call_io(CMD_PMKSA_REMOVE, &r, &mut []);
                    unsafe { POISONED += 1 };
                }
            }
        }
        let (c, n) = s.call_io(cmd, inp, out);
        match c {
            Call::Done(st, ..) if st == hal::wpasrvabi::ST_STATE_BAD => {
                full_wipe();
                return Some((Call::Fault, 0));
            }
            Call::Fault => unsafe {
                CONSEC += 1;
                match sta {
                    Some(x) if CONSEC < 3 => {
                        let poison = FAULT_STA == Some(x);
                        FAULT_STA = Some(x);
                        PENDING = Some((x, poison));
                        CONTAINED += 1;
                    }
                    _ => full_wipe(),
                }
            },
            Call::Done(..) => unsafe { CONSEC = 0 },
            Call::Backoff => {}
        }
        Some((c, n))
    }

    fn out_call(cmd: u32, inp: &[u8], frame: &mut [u8], sta: Option<[u8; 6]>) -> Option<Out> {
        let mut o = [0u8; keymsg::OUT_MAX];
        let (c, n) = wpa_call(cmd, inp, &mut o, sta)?;
        let r = match c {
            Call::Done(ST_OK, ..) => keymsg::decode_out(&o[..n], frame),
            _ => None,
        };
        hal::wpaauth::wipe(&mut o);
        r
    }
    fn start(st: &Start, now: u64, frame: &mut [u8]) -> Option<Out> {
        let mut inp = [0u8; keymsg::START_LEN + 8];
        keymsg::encode_start(st, &mut inp);
        inp[keymsg::START_LEN..].copy_from_slice(&now.to_le_bytes());
        let r = out_call(CMD_KEY_START, &inp, frame, Some(st.sta));
        hal::wpaauth::wipe(&mut inp);
        if r.is_some() {
            unsafe { EL0_STARTS += 1 };
        }
        r
    }
    fn expect(sta: &[u8; 6]) -> Option<Option<(bool, u64)>> {
        let mut o = [0u8; 10];
        let (c, n) = wpa_call(CMD_KEY_EXPECT, sta, &mut o, Some(*sta))?;
        if !matches!(c, Call::Done(ST_OK, ..)) || n != 10 {
            return None;
        }
        let mut r = [0u8; 8];
        r.copy_from_slice(&o[2..10]);
        Some((o[0] != 0).then_some((o[1] != 0, u64::from_le_bytes(r))))
    }
    pub(crate) fn eapol(sta: &[u8; 6], m: &[u8], now: u64, frame: &mut [u8]) -> Option<Out> {
        let mut inp = [0u8; IN_MAX];
        if m.len() > IN_MAX - 14 {
            return Some(Out::None);
        }
        inp[..6].copy_from_slice(sta);
        inp[6..14].copy_from_slice(&now.to_le_bytes());
        inp[14..14 + m.len()].copy_from_slice(m);
        let r = out_call(CMD_KEY_EAPOL, &inp[..14 + m.len()], frame, Some(*sta));
        hal::wpaauth::wipe(&mut inp);
        r
    }
    #[cfg(feature = "cm5")] // only the CM5 AP loop (main.rs cm5_p10_probe) wires the keyer in
    fn tick(now: u64, frame: &mut [u8]) -> Option<Out> {
        out_call(CMD_KEY_TICK, &now.to_le_bytes(), frame, None)
    }
    #[cfg(feature = "cm5")] // only the CM5 AP loop (main.rs cm5_p10_probe) wires the keyer in
    fn abort(sta: &[u8; 6]) {
        let _ = wpa_call(CMD_KEY_ABORT, sta, &mut [], Some(*sta));
    }

    // ---- steps 3c / 3d: SAE + PMKSA in el0-wifi (the SAE PMK never enters the kernel) ----
    /// A security-server call that answers ST_OK + bytes; the station it is about comes from the message layout.
    fn ok_call(cmd: u32, inp: &[u8], out: &mut [u8]) -> Option<usize> {
        let mac = |o: usize| inp.get(o..o + 6).map(|b| <[u8; 6]>::try_from(b).unwrap_or([0; 6]));
        let sta = match cmd {
            CMD_SAE_RX => mac(6),
            CMD_SAE_KEYING | CMD_SAE_FORGET | CMD_PMKSA_REMOVE => mac(0),
            _ => None,
        };
        let (c, n) = wpa_call(cmd, inp, out, sta)?;
        matches!(c, Call::Done(ST_OK, ..)).then_some(n)
    }
    pub(crate) fn sae_setup(mode: u8, clear: bool, ssid: &[u8], pw: &[u8]) -> bool {
        let mut inp = [0u8; 1 + 1 + 1 + 32 + 1 + 64];
        let (sl, pl) = (ssid.len().min(32), pw.len().min(64));
        inp[0] = mode;
        inp[1] = clear as u8;
        inp[2] = sl as u8;
        inp[3..3 + sl].copy_from_slice(&ssid[..sl]);
        inp[35] = pl as u8;
        inp[36..36 + pl].copy_from_slice(&pw[..pl]);
        let mut o = [0u8; 1];
        let r = ok_call(CMD_SAE_SETUP, &inp, &mut o) == Some(1) && o[0] == 1;
        hal::wpaauth::wipe(&mut inp);
        r
    }
    pub(crate) fn sae_rx(ap: &[u8; 6], sta: &[u8; 6], now: u64, rnd: &[u8; SAE_RND], body: &[u8]) -> Option<saemsg::SaeRx> {
        let pre = 6 + 6 + 8 + SAE_RND;
        if body.len() > IN_MAX - pre {
            return None;
        }
        let mut inp = [0u8; IN_MAX];
        inp[..6].copy_from_slice(ap);
        inp[6..12].copy_from_slice(sta);
        inp[12..20].copy_from_slice(&now.to_le_bytes());
        inp[20..20 + SAE_RND].copy_from_slice(rnd);
        inp[pre..pre + body.len()].copy_from_slice(body);
        let mut o = [0u8; saemsg::RX_OUT_LEN];
        let n = ok_call(CMD_SAE_RX, &inp[..pre + body.len()], &mut o);
        hal::wpaauth::wipe(&mut inp);
        if n != Some(saemsg::RX_OUT_LEN) {
            return None;
        }
        saemsg::decode_rx(&o)
    }
    pub(crate) fn sae_keying(sta: &[u8; 6], now: u64, offers: u8, rsn: Option<&hal::rsnassoc::AssocRsn>) -> Option<(hal::rsnassoc::Keying, bool, (u8, u64))> {
        let mut inp = [0u8; 15 + saemsg::RSN_LEN];
        inp[..6].copy_from_slice(sta);
        inp[6..14].copy_from_slice(&now.to_le_bytes());
        inp[14] = offers;
        saemsg::encode_rsn(rsn, &mut inp[15..]);
        let mut o = [0u8; 12];
        if ok_call(CMD_SAE_KEYING, &inp, &mut o)? != 12 {
            return None;
        }
        let how = saemsg::keying_from(o[0], o[1])?;
        let mut a = [0u8; 8];
        a.copy_from_slice(&o[3..11]);
        Some((how, o[11] != 0, (o[2], u64::from_le_bytes(a))))
    }
    pub(crate) fn key_start_sae(st: &Start, now: u64, src: u8, pmkid: &[u8; 16], frame: &mut [u8]) -> Option<Out> {
        let mut inp = [0u8; keymsg::START_LEN + 8 + 1 + 16];
        keymsg::encode_start(st, &mut inp);
        inp[keymsg::START_LEN..keymsg::START_LEN + 8].copy_from_slice(&now.to_le_bytes());
        inp[keymsg::START_LEN + 8] = src;
        inp[keymsg::START_LEN + 9..].copy_from_slice(pmkid);
        let r = out_call(CMD_KEY_START_SAE, &inp, frame, Some(st.sta));
        hal::wpaauth::wipe(&mut inp);
        if matches!(r, Some(Out::Send(_))) {
            unsafe { EL0_STARTS += 1 };
        }
        r
    }
    pub(crate) fn sae_forget(sta: &[u8; 6], now: u64, op: u8) -> Option<bool> {
        let mut inp = [0u8; 15];
        inp[..6].copy_from_slice(sta);
        inp[6..14].copy_from_slice(&now.to_le_bytes());
        inp[14] = op;
        let mut o = [0u8; 1];
        (ok_call(CMD_SAE_FORGET, &inp, &mut o)? == 1).then_some(o[0] != 0)
    }
    fn pmksa_remove(sta: &[u8; 6], all: bool) {
        let mut inp = [0u8; 7];
        inp[..6].copy_from_slice(sta);
        inp[6] = all as u8;
        let _ = ok_call(CMD_PMKSA_REMOVE, &inp, &mut []);
    }

    // ---- step 4b-2b: the RX frame read in el0-wifi ----
    /// Frame reads served by el0-wifi; replies refused by the kernel's re-check (each terminates the frame).
    pub static mut RX_EL0: u64 = 0;
    pub static mut RX_REFUSED: u64 = 0;
    /// One frame read through el0-wifi (one poll). None = no server, backoff, a fault, or a refused reply (the driver
    /// reads in-kernel instead).
    pub(crate) fn rx_read(sdb: u32, max_dry: u32, skip: bool, block: bool, rx: &mut [u8]) -> Option<(hal::sdio::RxRead, u32)> {
        use hal::wifisrvabi::rxmsg;
        let s = bus_srv()?;
        let mut inp = [0u8; rxmsg::IN_LEN];
        rxmsg::encode_in(sdb, max_dry, skip, block, rx.len(), &mut inp);
        let mut o = [0u8; OUT_MAX];
        let (c, n) = s.call_lean(CMD_RX_READ, &inp, &mut o);
        if !matches!(c, Call::Done(ST_OK, ..)) {
            return None;
        }
        match rxmsg::decode_out(&o[..n], rx) {
            Some(r) => {
                unsafe { RX_EL0 += 1 };
                Some(r)
            }
            None => {
                unsafe { RX_REFUSED += 1 };
                None
            }
        }
    }

    /// `[P-el0wpa-contain]` (QEMU) — ADR 0065 step 4g S2, operator evidence items 4 and 5 in miniature: a fault in one
    /// station's call forgets only that station (another station's handshake and the PMKSA cache survive the server's
    /// restart); a second fault on it in a row also drops its PMKSA entry; a fault outside any station call full-wipes.
    /// Runs on the loaded el0-wpa after `sae_selftest` left a PMKSA entry for `a`.
    #[cfg(feature = "wpa3")]
    pub(crate) fn contain_selftest(a: &[u8; 6]) -> bool {
        use hal::wpakeyer::{KeyData, FRAME_MAX};
        use hal::wpasrvabi as wp;
        let wait = || {
            let ms = |t: u64| t / (crate::clock::freq() / 1000).max(1);
            let t0 = ms(crate::clock::ticks());
            while ms(crate::clock::ticks()) < t0 + super::imp::BACKOFF_MS * 4 + 5 {}
        };
        let count = || match wpa_call(wp::CMD_PMKSA_COUNT, &[], &mut [], None) {
            Some((Call::Done(ST_OK, n, _), _)) => Some(n),
            _ => None,
        };
        let b = [2, 0x5b, 0, 0, 0, 0x0b];
        let c0 = count();
        // station A also has a handshake in progress
        let mut rsne = [0u8; 40];
        rsne[..4].copy_from_slice(&[0x30, 0x02, 0x01, 0x00]);
        let st = Start { sta: *a, aa: [2, 0xaa, 0, 0, 0, 1], pmk: [0x11; 32], akm8: false, pmkid: None, anonce: [0x22; 32],
            kd: KeyData { rsne, rsne_len: 4, gtk: [0x33; 16], gtk_keyid: 1, igtk_kde: None } };
        let mut fr = [0u8; FRAME_MAX];
        let a_hs = matches!(start(&st, 6_000, &mut fr), Some(Out::Send(_))) && expect(a).is_some_and(|e| e.is_some());
        // B's call faults: contained — the follow-up (forget B) runs once the server answers again
        let (k0, p0) = unsafe { (CONTAINED, POISONED) };
        let _ = wpa_call(wp::CMD_SELFTEST_ARM_FAULT, &b, &mut [], None);
        let b_fault = matches!(wpa_call(CMD_KEY_EXPECT, &b, &mut [0u8; 10], Some(b)), Some((Call::Fault, _))) && unsafe { CONTAINED } == k0 + 1;
        wait();
        // the restarted server still has A's handshake and the PMKSA cache; B is forgotten
        let a_kept = expect(a).is_some_and(|e| e.is_some());
        let cache_kept = c0.is_some_and(|n| n >= 1) && count() == c0;
        let b_gone = expect(&b) == Some(None);
        // B faults again in a row: poisoned — its PMKSA entry is dropped too (the cache keeps A's)
        let _ = wpa_call(wp::CMD_SELFTEST_ARM_FAULT, &b, &mut [], None);
        let _ = wpa_call(CMD_KEY_EXPECT, &b, &mut [0u8; 10], Some(b));
        wait();
        let poisoned = count() == c0 && unsafe { POISONED } == p0 + 1;
        // a fault in a call about no single station: full wipe — every secret gone, the driver told to re-key everyone
        let w0 = srv().map_or(0, |s| s.wipes);
        let _ = take_wiped();
        let wiped_call = matches!(wpa_call(hal::wpasrvabi::CMD_SELFTEST_FAULT, &[], &mut [], None), Some((Call::Fault, _)));
        wait();
        let wiped = wiped_call && srv().is_some_and(|s| s.wipes == w0 + 1) && take_wiped() && count() == Some(0) && expect(a) == Some(None);
        let pass = a_hs && b_fault && a_kept && cache_kept && b_gone && poisoned && wiped;
        arch_aarch64::_print(format_args!(
            " [P-el0wpa-contain] {} — ADR 0065 step 4g S2: per-station fault containment in el0-wpa: station A keying + a PMKSA entry={} a fault in station B's call is contained (not a wipe)={} after the restart A's handshake is still there={} the PMKSA cache is intact ({:?} entries)={} B is forgotten={} B's second fault in a row drops its PMKSA entry only={} a fault outside any station call full-wipes (cache empty, A forgotten, the driver told to re-key everyone)={}\n",
            if pass { "PASS" } else { "FAIL" }, a_hs, b_fault, a_kept, c0, cache_kept, b_gone, poisoned, wiped
        ));
        pass
    }

    /// The bridge functions, for `sae_selftest`.
    #[cfg(feature = "wpa3")]
    pub mod test {
        pub(crate) use super::{eapol, key_start_sae, sae_forget, sae_keying, sae_rx, sae_setup};
    }

    /// Load el0-wifi (no device: the bus stays in EL1 in step 3) and route the driver's authenticator to it.
    #[cfg(feature = "cm5")] // only the CM5 AP loop (main.rs cm5_p10_probe) wires the keyer in
    /// (the bus server is up, el0-wpa is up and — on the CM5 — its group keys are installed).
    pub fn install() -> (bool, bool) {
        // S2: the WPA security server first and independently — the keying / SAE / PMKSA hooks go to it, the frame and
        // control hooks to the bus server; each hook falls back to the in-kernel path when its server is absent (D5)
        let wpa = match super::imp::load_wpa() {
            Ok(mut p) => {
                let ok = matches!(p.call(hal::wpasrvabi::CMD_INIT), Call::Done(ST_OK, ..));
                arch_aarch64::_print(format_args!(" [EL0-WPA] el0-wpa loaded at {:#x} in its own address space: the WPA 4-way, SAE and the PMKSA cache run here, supervised apart from the bus server (ADR 0065 step 4g S2) init={}\n", p.base(), ok));
                unsafe { WPA = Some(p) };
                ok
            }
            Err(why) => {
                arch_aarch64::_print(format_args!(" [EL0-WPA] el0-wpa FAILED to load ({}) — {}\n", why,
                    if cfg!(all(feature = "apmc", feature = "wpa3")) { "no station can key (S3d: no in-kernel fallback)" } else { "keying stays in-kernel" }));
                false
            }
        };
        let bus = match load(if cfg!(feature = "cm5") { Grant::Mmio(SDHCI_PA_CM5) } else { Grant::None }) {
            Ok(mut s) => {
                let ok = matches!(s.call(CMD_INIT), Call::Done(ST_OK, ..));
                unsafe { WIFI = Some(s) };
                arch_aarch64::_print(format_args!(" [EL0-WIFI] el0-wifi (the bus server: SDIO / SDPCM / firmware I/O, no keys) loaded at {:#x} init={}\n", super::imp::BASE, ok));
                ok
            }
            Err(why) => {
                arch_aarch64::_print(format_args!(" [EL0-WIFI] el0-wifi FAILED to load ({}) — the bus stays in-kernel\n", why));
                false
            }
        };
        #[cfg(feature = "cm5")]
        unsafe {
            arch_aarch64::cyw43::EL0_KEYER = Some(arch_aarch64::cyw43::El0Keyer { start, expect, eapol, tick, abort, sae_setup, sae_rx, sae_keying, key_start_sae, sae_forget, pmksa_remove, rx_read, tx_data, tx_ctl, wpa_wiped: take_wiped, key_install, keyx_done, group_new });
        }
        #[cfg(all(feature = "cm5", feature = "wpa3"))]
        let _ = arch_aarch64::cyw43::ap_sae_el0_sync(false); // the security installed before the server loaded
        // S3b: the AP's group keys are replaced by el0-wpa's own (no station has keyed yet: the AP loop has not run)
        #[allow(unused_mut)]
        let mut keyed = wpa;
        #[cfg(feature = "cm5")]
        if wpa {
            let g = arch_aarch64::cyw43::ap_group_keys_el0();
            keyed = g;
            // S3d: the IGTK (WPA3 modes) is installed here too — the bring-up [WPA3] line predates it ("IGTK installed=false")
            #[cfg(feature = "wpa3")]
            let igtk = match arch_aarch64::cyw43::ap_security() != arch_aarch64::cyw43::SEC_WPA2 {
                true => if arch_aarch64::cyw43::wpa3_diag().6 { "IGTK installed" } else { "IGTK FAILED" },
                false => "no IGTK (WPA2)",
            };
            #[cfg(not(feature = "wpa3"))]
            let igtk = "no IGTK (WPA2)";
            arch_aarch64::_print(format_args!(" [EL0-WPA] group keys generated in el0-wpa and installed via the key-transfer page: GTK {}, {} (the kernel holds no GTK / IGTK)\n", if g { "ok" } else { "FAILED" }, igtk));
        }
        #[cfg(feature = "cm5")]
        if bus {
            bus_probe_check();
        }
        // ADR 0065 S0: every resident EL0 server loaded by now is in its own address space (also when a load failed:
        // a failed load must not hide behind the D5 fallback)
        let _ = crate::el0as::report();
        (bus, keyed)
    }

    /// ADR 0065 step 4a: el0-wifi reads the SDHCI identity registers through its Device mapping; they must equal the
    /// kernel's own reads (the grant maps the right page with the right attributes).
    #[cfg(feature = "cm5")]
    fn bus_probe_check() -> bool {
        let el1 = arch_aarch64::cyw43::sdhci_ident();
        let mut o = [0u8; PROBE_REGS.len() * 4];
        let ok = bus_srv().is_some_and(|s| matches!(s.call_io(CMD_BUS_PROBE, &[], &mut o), (Call::Done(ST_OK, ..), n) if n == o.len()));
        let el0: [u32; 6] = core::array::from_fn(|i| u32::from_le_bytes([o[i * 4], o[i * 4 + 1], o[i * 4 + 2], o[i * 4 + 3]]));
        let same = ok && el0 == el1;
        arch_aarch64::_print(format_args!(
            " [EL0-WIFI] step 4a bus probe: el0-wifi read the SDHCI page through its Device grant: caps {:#010x}/{:#010x} ver {:#06x} present {:#010x} hostctl {:#010x} clk {:#010x} — {}\n",
            el0[0], el0[1], el0[2] >> 16, el0[3], el0[4], el0[5],
            if same { "EQUAL to the kernel's reads" } else if ok { "DIFFERS from the kernel's reads" } else { "probe call failed" }
        ));
        same
    }

    /// (calls, faults, restarts, handshakes started in EL0) for the beat / health.
    #[cfg(feature = "cm5")] // only the CM5 AP loop (main.rs cm5_p10_probe) wires the keyer in
    pub fn stats() -> (u64, u64, u64, u64) {
        match bus_srv() {
            Some(s) => (s.calls, s.faults, s.restarts, unsafe { EL0_STARTS }),
            None => (0, 0, 0, 0),
        }
    }

    /// Data frames written by el0-wifi; calls lost to a fault / timeout (the kernel then terminates the write).
    pub static mut TX_EL0: u64 = 0;
    pub static mut TX_LOST: u64 = 0;
    /// Step 4c: one data frame built and written by el0-wifi with sequence `seq`. None = no server / backoff (the
    /// driver writes in-kernel); Some(Failed) after a fault, a timeout or an unknown answer, with
    /// `cyw43::EL0_TX_LOST` set so the driver terminates a write that may have been cut off.
    pub(crate) fn tx_data(seq: u8, ifidx: u8, big: bool, eth: &[u8]) -> Option<hal::sdio::TxWrite> {
        use hal::wifisrvabi::txmsg;
        let s = bus_srv()?;
        let mut inp = [0u8; txmsg::HDR + txmsg::ETH_MAX];
        let n = txmsg::encode_in(seq, ifidx, big, eth, &mut inp)?;
        let (c, _) = s.call_lean(CMD_TX_DATA, &inp[..n], &mut []);
        let w = match c {
            Call::Backoff => return None,
            Call::Done(ST_OK, r0, _) => txmsg::decode_r0(r0),
            _ => None,
        };
        match w {
            Some(w) => {
                unsafe { TX_EL0 += 1 };
                Some(w)
            }
            None => {
                unsafe { TX_LOST += 1 };
                #[cfg(feature = "cm5")]
                unsafe {
                    arch_aarch64::cyw43::EL0_TX_LOST = true;
                }
                Some(hal::sdio::TxWrite::Failed { block: eth.len() + 16 > 512 })
            }
        }
    }

    /// Control requests written by el0-wifi; control writes lost to a fault / timeout.
    pub static mut CTL_EL0: u64 = 0;
    pub static mut CTL_LOST: u64 = 0;
    /// Step 4d: one control request built and written by el0-wifi. None = no server / backoff (the driver writes
    /// in-kernel); Some(false) = the write failed, or the call faulted (then `cyw43::EL0_TX_LOST` is set so the
    /// driver terminates a write that may have been cut off).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn tx_ctl(seq: u8, ifidx: u8, cmd: u32, flags: u32, reqid: u16, reply_len: usize, payload: &[u8]) -> Option<bool> {
        use hal::wifisrvabi::ctlmsg;
        let s = bus_srv()?;
        let mut inp = [0u8; ctlmsg::HDR + hal::bcdc::PAYLOAD_MAX];
        let n = ctlmsg::encode_in(seq, ifidx, cmd, flags, reqid, reply_len, payload, &mut inp)?;
        let (c, _) = s.call_lean(CMD_TX_CTL, &inp[..n], &mut []);
        match c {
            Call::Backoff => None,
            Call::Done(ST_OK, 1, _) => {
                unsafe { CTL_EL0 += 1 };
                Some(true)
            }
            Call::Done(ST_OK, 4, _) => {
                unsafe { CTL_EL0 += 1 };
                Some(false)
            }
            _ => {
                unsafe { CTL_LOST += 1 };
                #[cfg(feature = "cm5")]
                unsafe {
                    arch_aarch64::cyw43::EL0_TX_LOST = true;
                }
                Some(false)
            }
        }
    }

    /// `/api/health` wifi_driver.bus: (state, restarts, faults, ticks of the last fault or 0). State: "absent" = the
    /// server is not loaded (the in-kernel driver serves — D5), "handed_to_wifiheal" = Wi-Fi was degraded after a
    /// failed recovery, "backoff" = restarting after a fault, else "running". Only counters, nothing derived.
    pub fn bus_health() -> (&'static str, u64, u64, u64) {
        let Some(s) = bus_srv() else { return ("absent", 0, 0, 0) };
        let st = if crate::wifiheal::status().0.starts_with("degraded") {
            "handed_to_wifiheal"
        } else if s.backoff_left_ms() > 0 {
            "backoff"
        } else {
            "running"
        };
        (st, s.restarts, s.faults, s.last_fault_ticks)
    }

    /// S3c: ask the bus server to install key-transfer slot `slot` (it must hold the key of `ea` / `index`) as a
    /// WLC_SET_KEY request with this SDPCM seq / request id. No key byte passes through here. Some(1) = written.
    pub(crate) fn key_install(seq: u8, ifidx: u8, reqid: u16, slot: u8, ea: &[u8; 6], index: u32) -> Option<u32> {
        let s = bus_srv()?;
        let inp = hal::wpasrvabi::keyx::encode_install(seq, ifidx, reqid, slot, ea, index);
        match s.call_lean(hal::wpasrvabi::CMD_KEY_INSTALL, &inp, &mut []).0 {
            Call::Done(ST_OK, r, _) => Some(r),
            _ => None,
        }
    }
    /// S3b: new group keys in el0-wpa from 32 B of kernel TRNG entropy (D-c); their install records land in the
    /// key-transfer page. `igtk` = an IGTK too (PMF). The entropy buffer is the caller's to wipe.
    pub(crate) fn group_new(entropy: &[u8; 32], igtk: bool) -> bool {
        let mut inp = [0u8; 33];
        inp[..32].copy_from_slice(entropy);
        inp[32] = igtk as u8;
        let r = matches!(wpa_call(hal::wpasrvabi::CMD_GROUP_NEW, &inp, &mut [], None), Some((Call::Done(ST_OK, 1, _), _)));
        hal::wpaauth::wipe(&mut inp);
        r
    }
    /// S3c: zero the key-transfer page after an install (the kernel writes zeros; it never reads it).
    pub(crate) fn keyx_done() {
        super::imp::keyx_zero();
    }

    /// (station faults contained, stations poisoned) — the `[WIFI-SPLIT]` line.
    pub fn containment() -> (u64, u64) {
        unsafe { (CONTAINED, POISONED) }
    }

    /// ADR 0065 S4 bench fault injection (feature `wifi-inject`; the request comes from `/api/bench/wifi-inject`).
    /// Returns what was done, for the log and the API reply.
    #[cfg(feature = "wifi-inject")]
    pub fn inject(kind: &str, sta: Option<[u8; 6]>) -> Result<&'static str, &'static str> {
        let r = match kind {
            // 1: the bus server's next CMD53 read stalls (an injected CMD53 timeout) — its budget faults it
            "cmd53-stall" => match bus_srv().map(|s| s.call_lean(CMD_INJECT_CMD53_STALL, &[], &mut []).0) {
                Some(Call::Done(ST_OK, ..)) => "armed: the bus server's next CMD53 read stalls",
                _ => return Err("bus server unavailable"),
            },
            "bus-fault" => match bus_srv().map(|s| s.call_lean(CMD_SELFTEST_FAULT, &[], &mut []).0) {
                Some(Call::Fault) => "the bus server faulted (restart pending)",
                _ => return Err("bus server unavailable"),
            },
            // 4: el0-wpa faults on this station's next EAPOL-Key (its M2) — contained to that station
            "wpa-station-m2" => {
                let s = sta.ok_or("sta required")?;
                let mut inp = [0u8; 10];
                inp[..6].copy_from_slice(&s);
                inp[6..].copy_from_slice(&CMD_KEY_EAPOL.to_le_bytes());
                match wpa_call(hal::wpasrvabi::CMD_SELFTEST_ARM_FAULT, &inp, &mut [], None) {
                    Some((Call::Done(ST_OK, ..), _)) => "armed: el0-wpa faults on this station's next M2",
                    _ => return Err("security server unavailable"),
                }
            }
            // 5: a fault outside any station call — not containable: full wipe
            "wpa-fault" => match wpa_call(hal::wpasrvabi::CMD_SELFTEST_FAULT, &[], &mut [], None) {
                Some((Call::Fault, _)) => "el0-wpa faulted outside a station call: full wipe",
                _ => return Err("security server unavailable"),
            },
            // customer claim "security isolation": the bus server tries to read el0-wpa's image and its state pages (the
            // PMKSA cache, SAE state, PMKs, group keys) — each must FAULT; the key-transfer page is readable (RO, by
            // design) and must hold nothing between installs
            "bus-read-wpa" => {
                #[cfg(feature = "cm5")]
                let base = hal::wpasrvabi::BASE_CM5;
                #[cfg(not(feature = "cm5"))]
                let base = hal::wpasrvabi::BASE_QEMU;
                let probe = |va: usize| -> &'static str {
                    let Some(s) = bus_srv() else { return "no bus server" };
                    // a previous probe's fault leaves a short backoff: wait it out (bench path)
                    let ms = |t: u64| t / (crate::clock::freq() / 1000).max(1);
                    let until = ms(crate::clock::ticks()) + s.backoff_left_ms().min(500) + 1;
                    while ms(crate::clock::ticks()) < until {}
                    let mut o = [0u8; 8];
                    match s.call_io(CMD_INJECT_READ_VA, &(va as u64).to_le_bytes(), &mut o) {
                        (Call::Fault, _) => "FAULT (not mapped)",
                        (Call::Done(ST_OK, ..), 8) if o == [0; 8] => "readable, zero",
                        (Call::Done(ST_OK, ..), 8) => "READABLE WITH DATA",
                        _ => "refused",
                    }
                };
                let (img, st) = (probe(base), probe(base + hal::wpasrvabi::STATE_OFF));
                let kx = probe(super::imp::BASE + KEYX_OFF);
                let wpa = srv().map_or((0, 0), |s| (s.restarts, s.faults));
                arch_aarch64::_print(format_args!(" [WIFI-ISOLATION] bus server reading el0-wpa: image {:#x} -> {}, state pages {:#x} -> {}, key-transfer page -> {} | el0-wpa restarts={} faults={}\n",
                    base, img, base + hal::wpasrvabi::STATE_OFF, st, kx, wpa.0, wpa.1));
                if img.starts_with("FAULT") && st.starts_with("FAULT") && kx == "readable, zero" {
                    "bus server: el0-wpa image + state pages FAULT, key-transfer page empty"
                } else {
                    "ISOLATION PROBE FAILED (see [WIFI-ISOLATION])"
                }
            }
            _ => return Err("unknown kind (cmd53-stall | bus-fault | wpa-station-m2 | wpa-fault | bus-read-wpa)"),
        };
        arch_aarch64::_print(format_args!(" [WIFI-INJECT] {}: {}\n", kind, r));
        Ok(r)
    }

    /// (state, restarts, faults, full wipes, ticks of the last fault or 0, PMKSA entries).
    pub type WpaHealth = (&'static str, u64, u64, u64, u64, Option<u32>);
    /// `/api/health` wifi_driver.security (S2): (state, restarts, faults, full wipes, ticks of the last fault or 0,
    /// PMKSA cache entries or None when it could not be read). State: "absent" = not loaded (keying in-kernel, D5),
    /// "backoff" = restarting after a fault, else "running". Only counters.
    pub fn wpa_health() -> Option<WpaHealth> {
        let Some(s) = srv() else { return Some(("absent", 0, 0, 0, 0, None)) };
        let st = if s.backoff_left_ms() > 0 { "backoff" } else { "running" };
        let (r, f, w, t) = (s.restarts, s.faults, s.wipes, s.last_fault_ticks);
        let n = match wpa_call(hal::wpasrvabi::CMD_PMKSA_COUNT, &[], &mut [], None) {
            Some((Call::Done(ST_OK, n, _), _)) => Some(n),
            _ => None,
        };
        Some((st, r, f, w, t, n))
    }

    /// (frame reads served by el0-wifi, replies the kernel refused).
    #[cfg(feature = "cm5")]
    pub fn rx_stats() -> (u64, u64, u64, u64, u64, u64) {
        unsafe { (RX_EL0, RX_REFUSED, TX_EL0, TX_LOST, CTL_EL0, CTL_LOST) }
    }

    /// `[P-el0srv-keyer]` (QEMU): a full 4-way through el0-wifi against a simulated station.
    pub fn selftest() -> bool {
        use hal::wpakeyer::{FRAME_MAX, KeyData};
        let mut s = match super::imp::load_wpa() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let _ = s.call(hal::wpasrvabi::CMD_INIT);
        unsafe { WPA = Some(s) };
        let sta = [2, 0x5a, 0, 0, 0, 9];
        let aa = [2, 0xaa, 0, 0, 0, 1];
        let mut rsne = [0u8; 40];
        rsne[..4].copy_from_slice(&[0x30, 0x02, 0x01, 0x00]);
        let st = Start { sta, aa, pmk: [0x11; 32], akm8: false, pmkid: None, anonce: [0x22; 32],
            kd: KeyData { rsne, rsne_len: 4, gtk: [0x33; 16], gtk_keyid: 1, igtk_kde: None } };
        let mut fr = [0u8; FRAME_MAX];
        let m1 = matches!(start(&st, 0, &mut fr), Some(Out::Send(_))) && expect(&sta) == Some(Some((false, 1)));
        let clean1 = srv().is_some_and(|s| s.io_clean());
        // the station: PTK from our ANonce + its SNonce, M2 / M4 signed with the KCK
        let snonce = [0x55u8; 32];
        let ptk = hal::wpaauth::ptk(false, &st.pmk, &aa, &sta, &st.anonce, &snonce);
        let mut kck = [0u8; 16];
        kck.copy_from_slice(&ptk[..16]);
        let frame = |replay: u64, secure: bool| {
            let mut f = [0u8; 99];
            f[0] = 2;
            f[1] = 3;
            f[2..4].copy_from_slice(&95u16.to_be_bytes());
            f[4] = 2;
            f[5..7].copy_from_slice(&((if secure { 0x0300u16 } else { 0x0100 }) | 0x000a).to_be_bytes());
            f[9..17].copy_from_slice(&replay.to_be_bytes());
            if !secure {
                f[17..49].copy_from_slice(&snonce);
            }
            let mic = hal::wpaauth::mic(&kck, &f, false);
            f[81..97].copy_from_slice(&mic);
            f
        };
        let m3 = matches!(eapol(&sta, &frame(1, false), 10, &mut fr), Some(Out::Send(_))) && expect(&sta) == Some(Some((true, 2)));
        let keyed = match eapol(&sta, &frame(2, true), 20, &mut fr) {
            // S3c: the kernel's copy carries a ZERO TK; the key waits in key-transfer slot 0 for the bus server
            Some(Out::Keyed { done, tk }) => {
                let rec = super::imp::keyx_test_read(hal::wpasrvabi::keyx::SLOT_TK);
                let ok = tk == [0u8; 16] && done.auth.m4_mic_ok && rec.is_some_and(|r| r.ea == sta && r.index == 0 && r.key[..16] == ptk[32..48]);
                super::imp::keyx_zero();
                ok
            }
            _ => false,
        };
        let clean2 = srv().is_some_and(|s| s.io_clean());
        let gone = expect(&sta) == Some(None);
        // S2: a fault in a call about NO single station is not containable: a full wipe (the station re-associates);
        // the server is back after the backoff, empty
        let _ = start(&st, 30, &mut fr);
        // during the backoff a call about no station is refused; a call about a station (S4) waits the short backoff
        // out and is answered by the new, wiped incarnation — which has forgotten the station
        let faulted = matches!(wpa_call(CMD_SELFTEST_FAULT, &[], &mut [], None), Some((Call::Fault, _)))
            && matches!(wpa_call(hal::wpasrvabi::CMD_PMKSA_COUNT, &[], &mut [], None), Some((Call::Backoff, _)));
        let forgotten = expect(&sta) == Some(None);
        unsafe { WPA = None };
        let pass = m1 && clean1 && m3 && keyed && clean2 && gone && faulted && forgotten;
        arch_aarch64::_print(format_args!(
            " [P-el0srv-keyer] {} — ADR 0065 step 3b / 4g S2: the WPA 4-way in el0-wpa against a simulated station: M1 sent, M2 expected={} no key on the shared page after a call={} a verified M2 -> M3, M4 expected={} a verified M4 -> keyed: the kernel's copy has a zero TK, the station's TK is in key-transfer slot 0={} and no key left on the page={} the handshake ended={} a fault outside any station call -> full wipe, a non-station call refused during the backoff={} a station call waits it out and the new incarnation has forgotten the station={}\n",
            if pass { "PASS" } else { "FAIL" }, m1, clean1, m3, keyed, clean2, gone, faulted, forgotten
        ));
        pass
    }
}

/// `[P-el0srv-sae]` (QEMU): a WPA3 station does SAE + the 4-way against el0-wifi; the SAE PMK never enters the kernel.
#[cfg(all(feature = "mctls", feature = "wpa3"))]
pub fn sae_selftest() -> bool {
    use hal::rsnassoc::{AssocRsn, Keying, PMKIDS};
    use hal::wifisrvabi::*;
    use hal::wpakeyer::{KeyData, Out, Start, FRAME_MAX};
    use keyer::*;
    let mut s = match imp::load_wpa() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = s.call(hal::wpasrvabi::CMD_INIT);
    unsafe { WPA = Some(s) };
    let ap = [2, 0xaa, 0, 0, 0, 1];
    let sta = [2, 0x5a, 0, 0, 0, 9];
    let pw = b"correct horse battery";
    let setup = test::sae_setup(1, true, b"hq-test", pw);
    // the station (hunting-and-pecking; AP and station hold the same password)
    let mut st = match sae::Sae::new(pw, &sta, &ap, &[0x31; 32], &[0x32; 32]) {
        Ok(x) => x,
        Err(_) => return false,
    };
    let mut commit = [0u8; 104];
    commit[0..2].copy_from_slice(&3u16.to_le_bytes());
    commit[2..4].copy_from_slice(&1u16.to_le_bytes());
    commit[6..8].copy_from_slice(&19u16.to_le_bytes());
    commit[8..40].copy_from_slice(&st.own_scalar);
    commit[40..104].copy_from_slice(&st.own_element);
    let rnd = [0x77u8; SAE_RND];
    let r1 = test::sae_rx(&ap, &sta, 10, &rnd, &commit);
    let committed = r1.as_ref().is_some_and(|r| r.ev == 2 && r.n >= 1 && r.lens[0] == 104);
    let mut ok_peer = false;
    if let Some(r) = r1.as_ref() {
        let mut sc = [0u8; 32];
        let mut el = [0u8; 64];
        sc.copy_from_slice(&r.frames[0][8..40]);
        el.copy_from_slice(&r.frames[0][40..104]);
        ok_peer = st.process_commit(&sc, &el).is_ok();
    }
    let (ssc, scf) = st.confirm();
    let mut conf = [0u8; 40];
    conf[0..2].copy_from_slice(&3u16.to_le_bytes());
    conf[2..4].copy_from_slice(&2u16.to_le_bytes());
    conf[6..8].copy_from_slice(&ssc.to_le_bytes());
    conf[8..40].copy_from_slice(&scf);
    let r2 = test::sae_rx(&ap, &sta, 20, &rnd, &conf);
    let accepted = r2.as_ref().is_some_and(|r| {
        let mut c = [0u8; 32];
        c.copy_from_slice(&r.frames[0][8..40]);
        r.ev == 3 && r.pmkid == st.pmkid && st.check_confirm(u16::from_le_bytes([r.frames[0][6], r.frames[0][7]]), &c).is_ok()
    });
    let clean1 = srv_clean();
    // the keying decision runs in el0-wifi: AKM 8, no PMKID, a fresh SAE -> SaeFresh
    let rsn8 = AssocRsn { akm: 0x000f_ac08, n_akm: 1, n_pmkid: 0, pmkid: [[0; 16]; PMKIDS] };
    let fresh = test::sae_keying(&sta, 30, hal::rsnassoc::OFFER_SAE | hal::rsnassoc::OFFER_PSK, Some(&rsn8)).is_some_and(|(k, f, _)| k == Keying::SaeFresh && f);
    // the 4-way keyed from the server's own PMK: the kernel's Start carries none
    let mut rsne = [0u8; 40];
    rsne[..4].copy_from_slice(&[0x30, 0x02, 0x01, 0x00]);
    let start0 = Start { sta, aa: ap, pmk: [0; 32], akm8: true, pmkid: None, anonce: [0x22; 32],
        kd: KeyData { rsne, rsne_len: 4, gtk: [0x33; 16], gtk_keyid: 1, igtk_kde: None } };
    let mut fr = [0u8; FRAME_MAX];
    let m1 = matches!(test::key_start_sae(&start0, 40, 1, &[0; 16], &mut fr), Some(Out::Send(_)));
    let snonce = [0x55u8; 32];
    let ptk = hal::wpaauth::ptk(true, &st.pmk, &ap, &sta, &start0.anonce, &snonce);
    let mut kck = [0u8; 16];
    kck.copy_from_slice(&ptk[..16]);
    let frame = |replay: u64, secure: bool| {
        let mut f = [0u8; 99];
        f[0] = 2;
        f[1] = 3;
        f[2..4].copy_from_slice(&95u16.to_be_bytes());
        f[4] = 2;
        f[5..7].copy_from_slice(&((if secure { 0x0300u16 } else { 0x0100 }) | 0x0008).to_be_bytes());
        f[9..17].copy_from_slice(&replay.to_be_bytes());
        if !secure {
            f[17..49].copy_from_slice(&snonce);
        }
        let mic = hal::wpaauth::mic(&kck, &f, true);
        f[81..97].copy_from_slice(&mic);
        f
    };
    let m3 = matches!(test::eapol(&sta, &frame(1, false), 50, &mut fr), Some(Out::Send(_)));
    // S3c: a zero TK in the kernel's copy; the station's SAE-derived TK in key-transfer slot 0
    let keyed = matches!(test::eapol(&sta, &frame(2, true), 60, &mut fr), Some(Out::Keyed { tk, .. }) if tk == [0u8; 16])
        && imp::keyx_test_read(hal::wpasrvabi::keyx::SLOT_TK).is_some_and(|r| r.ea == sta && r.key[..16] == ptk[32..48]);
    k1_needle(0, &st.pmk[..16]); // S3d K1: the SAE PMK and the station's TK must exist nowhere in kernel memory
    k1_needle(1, &ptk[32..48]);
    imp::keyx_zero();
    let clean2 = srv_clean();
    // the station leaves 5 s after Accepted (past the leave-predates-SAE window): the driver's forget (op 0) frees its
    // SAE state, while the PMKSA stays cached
    let fwd = test::sae_forget(&sta, 5_000, 0);
    // a later reconnect with PMKSA caching: its PMKID names the cached PMKSA -> SaeCached (a still-fresh SAE would
    // take precedence: decide prefers SaeFresh, so this is checked after the forget)
    let mut rsnc = rsn8;
    rsnc.n_pmkid = 1;
    rsnc.pmkid[0] = st.pmkid;
    let kc = test::sae_keying(&sta, 5_000, hal::rsnassoc::OFFER_SAE, Some(&rsnc));
    let cached = fwd == Some(true) && kc.is_some_and(|(k, _, _)| k == Keying::SaeCached(0));
    // no PMKID and no SAE state -> refused (the station must redo SAE)
    let kn = test::sae_keying(&sta, 5_000, hal::rsnassoc::OFFER_SAE, Some(&rsn8));
    let nosae = kn.is_some_and(|(k, _, _)| k == Keying::SaeNoSae);
    // S3a: a WPA2-PSK station keyed from el0-wpa's OWN PMK (source 3; derived from the passphrase at setup) — the
    // kernel passes a zero PMK; M2 verifies, and M3 comes back, only if the server derived the right one
    let psk_own = {
        let sta2 = [2, 0x5c, 0, 0, 0, 0x0c];
        let pmk = hal::wpa::wpa_pmk(pw, b"hq-test");
        let mut rsne2 = [0u8; 40];
        rsne2[..4].copy_from_slice(&[0x30, 0x02, 0x01, 0x00]);
        let st2 = Start { sta: sta2, aa: ap, pmk: [0; 32], akm8: false, pmkid: None, anonce: [0x44; 32],
            kd: KeyData { rsne: rsne2, rsne_len: 4, gtk: [0x33; 16], gtk_keyid: 1, igtk_kde: None } };
        let mut fr = [0u8; FRAME_MAX];
        let m1 = matches!(test::key_start_sae(&st2, 6_000, 3, &[0; 16], &mut fr), Some(Out::Send(_)));
        let sn = [0x66u8; 32];
        let ptk = hal::wpaauth::ptk(false, &pmk, &ap, &sta2, &st2.anonce, &sn);
        let mut kck = [0u8; 16];
        kck.copy_from_slice(&ptk[..16]);
        let mut f = [0u8; 99];
        f[0] = 2;
        f[1] = 3;
        f[2..4].copy_from_slice(&95u16.to_be_bytes());
        f[4] = 2;
        f[5..7].copy_from_slice(&(0x0100u16 | 0x000a).to_be_bytes());
        f[9..17].copy_from_slice(&1u64.to_be_bytes());
        f[17..49].copy_from_slice(&sn);
        let mic = hal::wpaauth::mic(&kck, &f, false);
        f[81..97].copy_from_slice(&mic);
        let m3 = matches!(test::eapol(&sta2, &f, 6_010, &mut fr), Some(Out::Send(_)));
        k1_needle(2, &pmk[..16]); // K1: the WPA2-PSK PMK (el0-wpa derived it from the passphrase)
        m1 && m3
    };
    if !psk_own {
        arch_aarch64::_print(format_args!(" [P-el0srv-sae] S3a: the WPA2-PSK 4-way from el0-wpa's own PMK FAILED\n"));
    }
    // S3b: el0-wpa's own group keys — generated from the entropy, written to key-transfer slots 1-3, and the GTK a
    // station unwraps from M3 is el0-wpa's (the kernel's start record carried a different, dummy GTK)
    let group_own = {
        use hal::wpasrvabi::keyx;
        let mut ent = [0u8; 32];
        ent[..16].copy_from_slice(&[0x5a; 16]);
        ent[16..].copy_from_slice(&[0xa5; 16]);
        let made = keyer::group_new(&ent, true);
        // S3d: the keys are pool outputs — never the kernel's entropy bytes themselves
        let key16 = |r: &hal::wpasrvabi::keyx::Rec| {
            let mut k = [0u8; 16];
            k.copy_from_slice(&r.key[..16]);
            k
        };
        let gr = imp::keyx_test_read(keyx::SLOT_GTK);
        let gkey = gr.as_ref().map_or([0; 16], key16);
        let ir = imp::keyx_test_read(keyx::SLOT_IGTK);
        let ikey = ir.as_ref().map_or([0; 16], key16);
        let not_ent = |k: &[u8; 16]| *k != [0; 16] && *k != [0x5a; 16] && *k != [0xa5; 16];
        let g = gr.is_some_and(|r| r.index == 1 && r.flags == hal::bcdc::WSEC_PRIMARY_KEY) && not_ent(&gkey);
        let i = ir.is_some_and(|r| r.index == 4 && r.algo == hal::bcdc::CRYPTO_ALGO_BIP) && not_ent(&ikey) && ikey != gkey
            && imp::keyx_test_read(keyx::SLOT_IGTK_CCM).is_some_and(|r| r.algo == hal::bcdc::CRYPTO_ALGO_AES_CCM && key16(&r) == ikey);
        imp::keyx_zero();
        k1_needle(3, &gkey); // K1: el0-wpa's GTK and IGTK
        k1_needle(4, &ikey);
        // a WPA2 station's 4-way: M3's key data, unwrapped with its KEK, carries the GTK 0x5a.., not the kernel's 0x33..
        let sta3 = [2, 0x5d, 0, 0, 0, 0x0d];
        let pmk = hal::wpa::wpa_pmk(pw, b"hq-test");
        let mut rsne3 = [0u8; 40];
        rsne3[..4].copy_from_slice(&[0x30, 0x02, 0x01, 0x00]);
        let st3 = Start { sta: sta3, aa: ap, pmk: [0; 32], akm8: false, pmkid: None, anonce: [0x45; 32],
            kd: KeyData { rsne: rsne3, rsne_len: 4, gtk: [0x33; 16], gtk_keyid: 1, igtk_kde: None } };
        let mut fr = [0u8; FRAME_MAX];
        let m1 = matches!(test::key_start_sae(&st3, 7_000, 3, &[0; 16], &mut fr), Some(Out::Send(_)));
        let sn = [0x67u8; 32];
        let ptk = hal::wpaauth::ptk(false, &pmk, &ap, &sta3, &st3.anonce, &sn);
        let (mut kck, mut kek) = ([0u8; 16], [0u8; 16]);
        kck.copy_from_slice(&ptk[..16]);
        kek.copy_from_slice(&ptk[16..32]);
        let mut f = [0u8; 99];
        f[0] = 2;
        f[1] = 3;
        f[2..4].copy_from_slice(&95u16.to_be_bytes());
        f[4] = 2;
        f[5..7].copy_from_slice(&(0x0100u16 | 0x000a).to_be_bytes());
        f[9..17].copy_from_slice(&1u64.to_be_bytes());
        f[17..49].copy_from_slice(&sn);
        let mic = hal::wpaauth::mic(&kck, &f, false);
        f[81..97].copy_from_slice(&mic);
        let gtk_in_m3 = match test::eapol(&sta3, &f, 7_010, &mut fr) {
            Some(Out::Send(n)) if n > 99 => {
                // the keyer's frames are ethernet frames (the driver sends them as data): skip the 802.3 header
                let b = if fr[12..14] == [0x88, 0x8e] { 14 } else { 0 };
                let dl = u16::from_be_bytes([fr[b + 97], fr[b + 98]]) as usize;
                let mut plain = [0u8; 256];
                match fr.get(b + 99..b + 99 + dl).and_then(|w| hal::aes::aes_unwrap(&kek, w, &mut plain)) {
                    Some(pn) => plain[..pn].windows(16).any(|x| x == gkey) && !plain[..pn].windows(16).any(|x| x == [0x33; 16]),
                    None => false,
                }
            }
            _ => false,
        };
        // the pool ratchets: the SAME entropy again gives different group keys
        let again = keyer::group_new(&ent, true) && imp::keyx_test_read(keyx::SLOT_GTK).is_some_and(|r| key16(&r) != gkey && key16(&r) != [0; 16]);
        imp::keyx_zero();
        let ok = made && g && i && m1 && gtk_in_m3 && again;
        if !ok {
            arch_aarch64::_print(format_args!(" [P-el0srv-sae] S3b detail: made={} gtk rec={} igtk recs={} m1={} M3 carries el0-wpa's GTK={} ratchet={}\n", made, g, i, m1, gtk_in_m3, again));
        }
        ok
    };
    // S3d K1: after the joins, none of their keys is anywhere in the kernel's data / bss / heap
    let k1 = k1_scan();
    if !(cached && nosae) {
        let f = unsafe { (*core::ptr::addr_of!(keyer::WPA)).as_ref().map_or(0, |s| s.faults) };
        arch_aarch64::_print(format_args!(" [P-el0srv-sae] detail: forget -> {:?}, cached keying -> {:?}, no-PMKID keying -> {:?}, server faults {}\n",
            fwd, kc.map(|(k, _, d)| (k, d.0)), kn.map(|(k, _, d)| (k, d.0)), f));
    }
    // S2: the containment proof on this server (it holds a PMKSA entry for `sta` now)
    let _ = keyer::contain_selftest(&sta);
    unsafe { WPA = None };
    let pass = setup && committed && ok_peer && accepted && clean1 && fresh && m1 && m3 && keyed && clean2 && cached && nosae && psk_own && group_own && k1;
    arch_aarch64::_print(format_args!(
        " [P-el0srv-sae] {} — ADR 0065 steps 3c/3d + 4g S2: WPA3 in el0-wpa against a real SAE station: setup (PT derived in EL0)={} its commit answered with ours={} our commit verifies at the station={} confirm -> Accepted, PMKID = the station's, our confirm verifies={} no secret on the shared page={} keying decided in EL0 (SaeFresh)={} 4-way started from the server's own PMK (the kernel passed none)={} M2 -> M3={} M4 -> keyed with the station's SAE-derived TK={} page clean={} after the station left: PMKSA-caching reconnect -> SaeCached={} no PMKID -> SaeNoSae={} S3a: a WPA2-PSK station keyed from el0-wpa's own PMK (the kernel passed none)={} S3b: group keys generated in el0-wpa, its GTK the one in M3={}\n",
        if pass { "PASS" } else { "FAIL" }, setup, committed, ok_peer, accepted, clean1, fresh, m1, m3, keyed, clean2, cached, nosae, psk_own, group_own
    ));
    pass
}

/// S3d K1 (QEMU): the keys a selftest join produced (SAE PMK, TK, PSK PMK, GTK, IGTK — first 16 bytes). The only
/// place they may sit in kernel memory: this array, which the scan skips.
#[cfg(all(feature = "mctls", feature = "wpa3"))]
#[cfg_attr(feature = "cm5", allow(dead_code))] // the K1 scan is a QEMU selftest
static mut K1_CANARY: [u8; 16] = [0; 16];
#[cfg(all(feature = "mctls", feature = "wpa3"))]
#[cfg_attr(feature = "cm5", allow(dead_code))]
static mut K1N: [[u8; 16]; 5] = [[0; 16]; 5];
#[cfg(all(feature = "mctls", feature = "wpa3"))]
#[cfg_attr(feature = "cm5", allow(dead_code))] // the K1 scan is a QEMU selftest
fn k1_needle(i: usize, k: &[u8]) {
    unsafe { (*core::ptr::addr_of_mut!(K1N))[i].copy_from_slice(&k[..16]) };
}

/// `[P-el0wpa-k1]`: scan the kernel's whole RW image — .rodata / .data / .bss, the heap included (it is a .bss array) —
/// for each needle. The EL0 servers' frames (above the boot stack) and the stack itself are outside the range: the
/// test's own station-side copies live on the stack. PASS = every needle was set and none is found.
#[cfg(all(feature = "mctls", feature = "wpa3"))]
#[cfg_attr(feature = "cm5", allow(dead_code))] // the K1 scan is a QEMU selftest
fn k1_scan() -> bool {
    extern "C" {
        static __text_end: u8;
        static __bss_end: u8;
    }
    let lo = core::ptr::addr_of!(__text_end) as usize;
    let hi = core::ptr::addr_of!(__bss_end) as usize;
    let n = unsafe { *core::ptr::addr_of!(K1N) };
    let xlo = core::ptr::addr_of!(K1N) as usize;
    let xhi = xlo + core::mem::size_of::<[[u8; 16]; 5]>();
    let set = n.iter().all(|k| *k != [0; 16]);
    let heads: [u64; 5] = core::array::from_fn(|i| u64::from_le_bytes(n[i][..8].try_into().unwrap_or([0; 8])));
    let count = || {
        let mut hits = [0u32; 5];
        let mut a = lo;
        while a + 16 <= hi {
            if a + 16 > xlo && a < xhi {
                a = xhi;
                continue;
            }
            let w = unsafe { core::ptr::read_unaligned(a as *const u64) };
            for (i, h) in heads.iter().enumerate() {
                if w == *h && unsafe { core::slice::from_raw_parts(a as *const u8, 16) } == n[i] {
                    hits[i] += 1;
                }
            }
            a += 1;
        }
        hits
    };
    let hits = count();
    // positive control: the scanner finds a key planted in .bss (then the plant is wiped)
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(K1_CANARY), n[3]) };
    let found = count()[3] >= 1;
    unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!(K1_CANARY), [0; 16]) };
    let clean = hits.iter().all(|&h| h == 0);
    let pass = set && clean && found;
    arch_aarch64::_print(format_args!(
        " [P-el0wpa-k1] {} — ADR 0065 4g S3d K1: after SAE + WPA2 joins and new group keys, kernel memory {:#x}..{:#x} ({} KiB: rodata, data, bss, heap) holds none of the keys: SAE PMK {} TK {} PSK PMK {} GTK {} IGTK {} hit(s) (needles set={}; positive control: a GTK copy planted in .bss is found={})\n",
        if pass { "PASS" } else { "FAIL" }, lo, hi, (hi - lo) / 1024, hits[0], hits[1], hits[2], hits[3], hits[4], set, found
    ));
    // the needles themselves go too
    unsafe { *core::ptr::addr_of_mut!(K1N) = [[0; 16]; 5] };
    pass
}

#[cfg(all(feature = "mctls", feature = "wpa3"))]
fn srv_clean() -> bool {
    unsafe { (*core::ptr::addr_of!(keyer::WPA)).as_ref().is_some_and(|s| s.io_clean()) }
}
