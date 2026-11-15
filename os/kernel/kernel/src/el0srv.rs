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

    /// Load `el0-wifi`, granting it the device page at physical `dev_pa` when there is one (step 2's fake device;
    /// step 3 needs none: the bus stays in EL1; step 4 grants the SDHCI page).
    pub fn load(dev_pa: Option<usize>) -> Result<Server, &'static str> {
        let parsed = crate::elf::parse(WIFI_ELF).map_err(|_| "ELF parse")?;
        let mut s = Server {
            entry: parsed.entry,
            sp_top: BASE + STACK_OFF + STACK_SIZE,
            ctrl: 0,
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
        if let Some(d) = dev_pa {
            if !map(BASE + DEV_OFF, d, Kind::Dev) {
                return Err("map device refused");
            }
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

    /// `[P-el0srv]` (QEMU): the resident substrate with the fake device.
    pub fn selftest() -> bool {
        let dev = alloc();
        if dev == 0 {
            return false;
        }
        zero(dev);
        let mut s = match load(Some(dev)) {
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
        // consecutive faults (no good call between them) double the backoff; a good call resets the streak
        let f1 = s.call(CMD_SELFTEST_FAULT) == Call::Fault && s.backoff_left_ms() <= BACKOFF_MS;
        let t1 = now_ms();
        while now_ms() < t1 + BACKOFF_MS + 5 {}
        let doubled = f1 && s.call(CMD_SELFTEST_FAULT) == Call::Fault && s.backoff_left_ms() > BACKOFF_MS;
        let pass = init && rx && tx && resident && hostile && fault && fresh && wiped && doubled;
        arch_aarch64::_print(format_args!(
            " [P-el0srv] {} — ADR 0065 step 2, the resident EL0 driver substrate (el0-wifi + a fake device): loads with a device grant + two rings, INIT answers={} device RX -> driver -> RX ring -> kernel={} kernel -> TX ring -> driver -> device (1514 B)={} resident (served counter kept across calls)={} a hostile RX ring is refused, counted, resynced={} a fault resets + is counted + the next call waits for the backoff={} then a fresh incarnation (counter from 1)={} rings wiped by the reset={} consecutive faults double the backoff={}\n",
            if pass { "PASS" } else { "FAIL" }, init, rx, tx, resident, hostile, fault, fresh, wiped, doubled
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
    use super::imp::{load, Call, Server};
    use hal::wifisrvabi::{keymsg, saemsg, *};
    use hal::wpakeyer::{Out, Start};

    pub static mut WIFI: Option<Server> = None;
    /// Handshakes started in el0-wifi (the metal proof that the EL0 path, not the in-kernel copy, served them).
    pub static mut EL0_STARTS: u64 = 0;

    fn srv() -> Option<&'static mut Server> {
        unsafe { (*core::ptr::addr_of_mut!(WIFI)).as_mut() }
    }

    fn out_call(cmd: u32, inp: &[u8], frame: &mut [u8]) -> Option<Out> {
        let s = srv()?;
        let mut o = [0u8; keymsg::OUT_MAX];
        let (c, n) = s.call_io(cmd, inp, &mut o);
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
        let r = out_call(CMD_KEY_START, &inp, frame);
        hal::wpaauth::wipe(&mut inp);
        if r.is_some() {
            unsafe { EL0_STARTS += 1 };
        }
        r
    }
    fn expect(sta: &[u8; 6]) -> Option<Option<(bool, u64)>> {
        let s = srv()?;
        let mut o = [0u8; 10];
        let (c, n) = s.call_io(CMD_KEY_EXPECT, sta, &mut o);
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
        let r = out_call(CMD_KEY_EAPOL, &inp[..14 + m.len()], frame);
        hal::wpaauth::wipe(&mut inp);
        r
    }
    #[cfg(feature = "cm5")] // only the CM5 AP loop (main.rs cm5_p10_probe) wires the keyer in
    fn tick(now: u64, frame: &mut [u8]) -> Option<Out> {
        out_call(CMD_KEY_TICK, &now.to_le_bytes(), frame)
    }
    #[cfg(feature = "cm5")] // only the CM5 AP loop (main.rs cm5_p10_probe) wires the keyer in
    fn abort(sta: &[u8; 6]) {
        if let Some(s) = srv() {
            let _ = s.call_io(CMD_KEY_ABORT, sta, &mut []);
        }
    }

    // ---- steps 3c / 3d: SAE + PMKSA in el0-wifi (the SAE PMK never enters the kernel) ----
    fn ok_call(cmd: u32, inp: &[u8], out: &mut [u8]) -> Option<usize> {
        let s = srv()?;
        let (c, n) = s.call_io(cmd, inp, out);
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
        let r = out_call(CMD_KEY_START_SAE, &inp, frame);
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

    /// The bridge functions, for `sae_selftest`.
    #[cfg(feature = "wpa3")]
    pub mod test {
        pub(crate) use super::{eapol, key_start_sae, sae_forget, sae_keying, sae_rx, sae_setup};
    }

    /// Load el0-wifi (no device: the bus stays in EL1 in step 3) and route the driver's authenticator to it.
    #[cfg(feature = "cm5")] // only the CM5 AP loop (main.rs cm5_p10_probe) wires the keyer in
    pub fn install() -> bool {
        match load(None) {
            Ok(mut s) => {
                let ok = matches!(s.call(CMD_INIT), Call::Done(ST_OK, ..));
                unsafe { WIFI = Some(s) };
                #[cfg(feature = "cm5")]
                unsafe {
                    arch_aarch64::cyw43::EL0_KEYER = Some(arch_aarch64::cyw43::El0Keyer { start, expect, eapol, tick, abort, sae_setup, sae_rx, sae_keying, key_start_sae, sae_forget, pmksa_remove });
                }
                #[cfg(all(feature = "cm5", feature = "wpa3"))]
                let _ = arch_aarch64::cyw43::ap_sae_el0_sync(false); // the security installed before the server loaded
                arch_aarch64::_print(format_args!(" [EL0-WIFI] el0-wifi loaded at {:#x}: the WPA 4-way authenticator and its keys run in EL0 (ADR 0065 step 3b; in-kernel copy = fallback) init={}\n", super::imp::BASE, ok));
                ok
            }
            Err(why) => {
                arch_aarch64::_print(format_args!(" [EL0-WIFI] el0-wifi FAILED to load ({}) — the authenticator stays in-kernel\n", why));
                false
            }
        }
    }

    /// (calls, faults, restarts, handshakes started in EL0) for the beat / health.
    #[cfg(feature = "cm5")] // only the CM5 AP loop (main.rs cm5_p10_probe) wires the keyer in
    pub fn stats() -> (u64, u64, u64, u64) {
        match srv() {
            Some(s) => (s.calls, s.faults, s.restarts, unsafe { EL0_STARTS }),
            None => (0, 0, 0, 0),
        }
    }

    /// `[P-el0srv-keyer]` (QEMU): a full 4-way through el0-wifi against a simulated station.
    pub fn selftest() -> bool {
        use hal::wpakeyer::{FRAME_MAX, KeyData};
        let mut s = match load(None) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let _ = s.call(CMD_INIT);
        unsafe { WIFI = Some(s) };
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
            Some(Out::Keyed { done, tk }) => tk[..] == ptk[32..48] && done.auth.m4_mic_ok,
            _ => false,
        };
        let clean2 = srv().is_some_and(|s| s.io_clean());
        let gone = expect(&sta) == Some(None);
        // a fault mid-handshake forgets it (the station re-associates); the server is back after the backoff
        let _ = start(&st, 30, &mut fr);
        let faulted = srv().is_some_and(|s| s.call(CMD_SELFTEST_FAULT) == Call::Fault) && expect(&sta).is_none();
        let t0 = crate::clock::ticks() / (crate::clock::freq() / 1000).max(1);
        while crate::clock::ticks() / (crate::clock::freq() / 1000).max(1) < t0 + super::imp::BACKOFF_MS + 5 {}
        let forgotten = expect(&sta) == Some(None);
        unsafe { WIFI = None };
        let pass = m1 && clean1 && m3 && keyed && clean2 && gone && faulted && forgotten;
        arch_aarch64::_print(format_args!(
            " [P-el0srv-keyer] {} — ADR 0065 step 3b: the WPA 4-way in el0-wifi against a simulated station: M1 sent, M2 expected={} no key on the shared page after a call={} a verified M2 -> M3, M4 expected={} a verified M4 -> keyed with the station's TK={} and no key left on the page={} the handshake ended={} a fault mid-handshake -> refused during the backoff={} then the new incarnation has forgotten it={}\n",
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
    let mut s = match imp::load(None) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = s.call(CMD_INIT);
    unsafe { WIFI = Some(s) };
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
    let keyed = matches!(test::eapol(&sta, &frame(2, true), 60, &mut fr), Some(Out::Keyed { tk, .. }) if tk[..] == ptk[32..48]);
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
    if !(cached && nosae) {
        let f = unsafe { (*core::ptr::addr_of!(keyer::WIFI)).as_ref().map_or(0, |s| s.faults) };
        arch_aarch64::_print(format_args!(" [P-el0srv-sae] detail: forget -> {:?}, cached keying -> {:?}, no-PMKID keying -> {:?}, server faults {}\n",
            fwd, kc.map(|(k, _, d)| (k, d.0)), kn.map(|(k, _, d)| (k, d.0)), f));
    }
    unsafe { WIFI = None };
    let pass = setup && committed && ok_peer && accepted && clean1 && fresh && m1 && m3 && keyed && clean2 && cached && nosae;
    arch_aarch64::_print(format_args!(
        " [P-el0srv-sae] {} — ADR 0065 steps 3c/3d: WPA3 in el0-wifi against a real SAE station: setup (PT derived in EL0)={} its commit answered with ours={} our commit verifies at the station={} confirm -> Accepted, PMKID = the station's, our confirm verifies={} no secret on the shared page={} keying decided in EL0 (SaeFresh)={} 4-way started from the server's own PMK (the kernel passed none)={} M2 -> M3={} M4 -> keyed with the station's SAE-derived TK={} page clean={} after the station left: PMKSA-caching reconnect -> SaeCached={} no PMKID -> SaeNoSae={}\n",
        if pass { "PASS" } else { "FAIL" }, setup, committed, ok_peer, accepted, clean1, fresh, m1, m3, keyed, clean2, cached, nosae
    ));
    pass
}

#[cfg(all(feature = "mctls", feature = "wpa3"))]
fn srv_clean() -> bool {
    unsafe { (*core::ptr::addr_of!(keyer::WIFI)).as_ref().is_some_and(|s| s.io_clean()) }
}
