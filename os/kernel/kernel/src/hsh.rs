//! Kernel side of `hsh`, the native management shell (ADR 0059 step 4a; docs/design/hsh-native-management-shell.md).
//! The shell is an EL0 excursion server (`el0-hsh`); each command line runs in two bounded excursions:
//!   1. the line goes in; the shell returns text, or ONE management request (a `hal::mgmtabi` message id);
//!   2. the kernel serves the request through `mgmtabi::dispatch` with the SESSION's role (the shell never decides
//!      authority) and re-enters the shell with the fixed reply record; the shell formats it.
//! A shell fault costs that command only (the server resets, ADR 0050 D5); forwarding never notices.
//! Transport (R6 = D, operator 2026-11-12): the carrier carries no authority. The web carrier (`POST /api/hsh`,
//! feature `hsh`) runs lines at the VIEW role on Mission Control's authenticated owner session; a privileged command
//! (config confirm / rollback / stage) runs only with an HQMGMT1 envelope signed off-device by the owner key, which
//! the carrier hands to `mgmtabi::dispatch` (EL1) — the same verifier every client uses. No UART carrier is built.

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


/// Run one command line for a caller holding `role` (view, from the carrier's session); `env` = the carrier's HQMGMT1
/// envelope for a privileged command (empty = none). The envelope goes from the carrier straight to the EL1 verifier
/// in `mgmtabi::dispatch` — the EL0 parser never sees it. The text answer goes into `out`; returns its length.
#[cfg(feature = "mctls")]
pub fn run_line(line: &[u8], role: u8, tag: [u8; 4], now_ms: u64, env: &[u8], out: &mut [u8]) -> usize {
    use hal::hshabi::*;
    let msg_unavail = b"ERROR: Management service unavailable.\n";
    let Some(s) = el0::server() else {
        let n = msg_unavail.len().min(out.len());
        out[..n].copy_from_slice(&msg_unavail[..n]);
        return n;
    };
    s.role = role; // what `help` lists; the kernel decides every request
    let (st, n) = s.call(CMD_LINE, &line[..line.len().min(IN_MAX)]);
    let n = match st {
        ST_TEXT => n,
        ST_REQUEST if n == REQ_LEN => {
            let mut rq = [0u8; REQ_LEN];
            s.read(OUT_OFF, &mut rq);
            let msg = u16::from_le_bytes([rq[0], rq[1]]);
            let arg = u64::from_le_bytes(rq[4..12].try_into().unwrap());
            // phase 2: the kernel authorises (the session's role for view; the envelope for anything above) + serves;
            // the shell formats
            let mut rep = [0u8; IN_MAX];
            rep[..2].copy_from_slice(&msg.to_le_bytes());
            rep[3] = rq[2];
            let (res, len) = crate::mgmtabi::dispatch(msg, role, tag, now_ms, arg, env, &mut rep[4..]);
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

/// The web carrier (`POST /api/hsh`; the guards — owner session, Origin, CSRF — are the caller's): journal the command
/// words, then run the line at the VIEW role. The carrier carries no authority (R6 = D): a privileged command runs
/// only with `env`, an envelope signed by the owner key, which `mgmtabi::dispatch` verifies.
#[cfg(feature = "hsh")]
pub fn web(line: &[u8], env: &[u8], tag: [u8; 4], now_ms: u64, out: &mut [u8]) -> usize {
    let mut why = [0u8; 64];
    let k = journal_words(line, &mut why);
    let _ = crate::ownerapi::audit_artifact("hsh", 1, &why[..k], tag, now_ms);
    run_line(line, hal::mgmtabi::ROLE_VIEW, tag, now_ms, env, out)
}

/// What the journal keeps of a command line: the first two words (printable ASCII, 24 bytes each), never the
/// arguments (and never the envelope, which is not part of the line).
#[cfg(feature = "hsh")]
pub fn journal_words(line: &[u8], why: &mut [u8; 64]) -> usize {
    let mut k = 0;
    for (i, w) in line.split(|&b| b == b' ').filter(|w| !w.is_empty()).take(2).enumerate() {
        if i > 0 && k < why.len() {
            why[k] = b' ';
            k += 1;
        }
        for &c in w.iter().take(24) {
            if k < why.len() && (0x21..0x7f).contains(&c) {
                why[k] = c;
                k += 1;
            }
        }
    }
    k
}

/// A test envelope signed with `k` (QEMU self-tests only; the device never holds the real K_own).
#[cfg(all(feature = "hsh", not(feature = "cm5")))]
fn test_envelope(k: &ed25519_compact::KeyPair, e: &hal::mgmtabi::Envelope) -> [u8; hal::mgmtabi::ENV_LEN] {
    let body = e.body();
    let sig = k.sk.sign(&hal::mgmtabi::envelope_msg(&body)[..], Some(ed25519_compact::Noise::from_slice(&[7u8; 16]).unwrap()));
    let mut o = [0u8; hal::mgmtabi::ENV_LEN];
    o[..hal::mgmtabi::ENV_BODY].copy_from_slice(&body);
    o[hal::mgmtabi::ENV_BODY..].copy_from_slice(&sig[..]);
    o
}

/// [P-hsh-web] (QEMU / mc-e2e): R6 = D on the web carrier, end to end through the EL0 shell. View commands answer on
/// the session alone; confirm / rollback without an envelope are refused; a valid owner-signed envelope bound to the
/// bundle in force is accepted; a wrong key, another device, another boot, a replayed sequence, a confirm for
/// generation N while N+1 is on trial, an envelope for another operation and a tampered byte are refused; every
/// configuration request is journaled with its outcome; the journal keeps command words only.
#[cfg(all(feature = "hsh", not(feature = "cm5")))]
pub fn selftest_web(now_ms: u64) -> bool {
    use hal::mgmtabi as m;
    crate::cfgd::set_selftest(true); // an accepted confirm reaches cfgd, which then changes nothing
    let saved = (crate::anchor::owner(), crate::anchor::owner_gen());
    crate::mgmtabi::test_reset();
    let kp = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([0x6b; 32])); // test K_own (this test only)
    let other = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new([0x6c; 32]));
    crate::anchor::install_owner(Some(*kp.pk), 1);
    let dig_n = [0x4e; 32];
    let dig_n1 = [0x4f; 32];
    let posed = crate::cfgd::test_pose(8, dig_n1, true); // generation 8 (digest N+1) is on trial
    let t = [0x3e, 0xb0, 0, 1];
    let mut b = [0u8; 2048];
    let mut run = |l: &[u8], env: &[u8]| -> ([u8; 2048], usize) {
        let n = web(l, env, t, now_ms, &mut b);
        (b, n)
    };
    let has = |r: &([u8; 2048], usize), s: &[u8]| r.0[..r.1].windows(s.len()).any(|w| w == s);
    let c = crate::mgmtabi::challenge();
    let mk = |seq: u64, msg: u16, gen: u64, dig: [u8; 32]| m::Envelope { msg, device_id: c.device_id, epoch: c.epoch, seq, arg: 0, generation: gen, digest: dig };
    let j0 = crate::mgmtenv::journaled().0;
    let view = has(&run(b"info", &[]), b"HEQK Management Environment") && has(&run(b"config status", &[]), b"config:")
        && has(&run(b"owner challenge", &[]), b"HQMGMT1") && c.owner_enrolled && c.on_trial && c.generation == 8 && c.digest == dig_n1;
    let session_only = has(&run(b"config confirm", &[]), b"needs an owner-signed envelope")
        && has(&run(b"config rollback", &[]), b"needs an owner-signed envelope")
        && has(&run(b"config stage 00000000000000aa", &[]), b"needs an owner-signed envelope");
    let wrong_key = has(&run(b"config confirm", &test_envelope(&other, &mk(1, m::CFG_CONFIRM, 8, dig_n1))), b"not the owner key");
    let mut e = mk(2, m::CFG_CONFIRM, 8, dig_n1);
    e.device_id[0] ^= 1;
    let wrong_dev = has(&run(b"config confirm", &test_envelope(&kp, &e)), b"another device");
    let mut e = mk(3, m::CFG_CONFIRM, 8, dig_n1);
    e.epoch[0] ^= 1;
    let wrong_boot = has(&run(b"config confirm", &test_envelope(&kp, &e)), b"another boot");
    let stale_n = has(&run(b"config confirm", &test_envelope(&kp, &mk(4, m::CFG_CONFIRM, 7, dig_n))), b"something else is on trial");
    let other_op = has(&run(b"config confirm", &test_envelope(&kp, &mk(5, m::CFG_ROLLBACK, 8, dig_n1))), b"another operation");
    let mut tampered = test_envelope(&kp, &mk(6, m::CFG_CONFIRM, 8, dig_n1));
    tampered[40] ^= 0x01; // one byte of the sequence, after signing
    let tamper = has(&run(b"config confirm", &tampered), b"not the owner key");
    let malformed = has(&run(b"config confirm", &[0u8; 10]), b"malformed envelope");
    // the valid one: reaches cfgd (which, in self-test mode, changes nothing)
    let good_env = test_envelope(&kp, &mk(7, m::CFG_CONFIRM, 8, dig_n1));
    let good = has(&run(b"config confirm", &good_env), b"self-test: no state change");
    let replay = has(&run(b"config confirm", &good_env), b"replayed or stale");
    let older = has(&run(b"config confirm", &test_envelope(&kp, &mk(6, m::CFG_CONFIRM, 8, dig_n1))), b"replayed or stale");
    let (j1, last_msg, last_ok) = crate::mgmtenv::journaled();
    // 13 configuration requests above (3 session-only + 7 refused envelopes + valid + replay + older)
    let jn = j1 - j0;
    let journaled = jn == 13 && last_msg == m::CFG_CONFIRM && !last_ok;
    let mut w = [0u8; 64];
    let jw = journal_words(b"  config\x01 \x1bstage 00000000000000aa", &mut w);
    let words = &w[..jw] == b"config stage";
    // the owner-side tool and this verifier agree byte for byte: an envelope made by `policy-sign.py mgmt-sign` with
    // the test key (device 00..0f, epoch 0102..08, seq 42, confirm, generation 9, digest 5a..) parses to those fields,
    // re-encodes to the same body and verifies under the test public key
    const KAT: &[u8; 312] = b"48514d474d54310001001400000102030405060708090a0b0c0d0e0f01020304050607082a00000000000000000000000000000009000000000000005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5adfc7bdb7a85f4a16d96169c3d59a2637e34e004846b55873df5462fe705386a8214d8586401693da20cf3c71ee015f959484845e59d366148730d8ec761d020e";
    let mut kat = [0u8; m::ENV_LEN];
    let tool = crate::mgmtenv::unhex(KAT, &mut kat)
        && m::Envelope::parse(&kat).is_some_and(|(e, sig)| {
            let want = m::Envelope { msg: m::CFG_CONFIRM, device_id: core::array::from_fn(|i| i as u8), epoch: [1, 2, 3, 4, 5, 6, 7, 8], seq: 42, arg: 0, generation: 9, digest: [0x5a; 32] };
            e == want && e.body()[..] == kat[..m::ENV_BODY]
                && ed25519_compact::Signature::from_slice(&sig).is_ok_and(|s| kp.pk.verify(&m::envelope_msg(&e.body())[..], &s).is_ok())
        });
    // the same verifier for Mission Control's owner endpoints (factory reset, owner-key rotation, upload activate /
    // rollback): each binds its own target; a mismatch is refused, the exact binding accepted, refusals journaled
    let cur_fp = crate::mgmtenv::fp8(&kp.pk);
    let new_pk = [0x77u8; 32];
    let new_dg = boot_abi::sha256::digest(&new_pk);
    let s0 = crate::mgmtenv::next_seq();
    let env = |seq: u64, msg: u16, arg: u64, gen: u64, dg: [u8; 32]| test_envelope(&kp, &m::Envelope { msg, device_id: c.device_id, epoch: c.epoch, seq, arg, generation: gen, digest: dg });
    let auth = |e: &[u8], msg: u16, arg: u64, gen: u64, dg: &[u8; 32]| crate::mgmtenv::authorise(msg, arg, gen, dg, e, t, now_ms);
    let j2 = crate::mgmtenv::journaled().0;
    let endpoints = auth(&env(s0, m::OWNER_FACTORY_RESET, 0, 0, [0; 32]), m::OWNER_FACTORY_RESET, 0, 0, &[0; 32]).is_ok()
        && auth(&env(s0 + 1, m::OWNER_FACTORY_RESET, 1, 0, [0; 32]), m::OWNER_FACTORY_RESET, 0, 0, &[0; 32]) == Err(crate::mgmtenv::REASONS[8])
        && auth(&env(s0 + 2, m::ANCHOR_ROTATE, cur_fp, 2, [0x11; 32]), m::ANCHOR_ROTATE, cur_fp, 2, &new_dg) == Err(crate::mgmtenv::OTHER_TARGET)
        && auth(&env(s0 + 3, m::ANCHOR_ROTATE, cur_fp ^ 1, 2, new_dg), m::ANCHOR_ROTATE, cur_fp, 2, &new_dg) == Err(crate::mgmtenv::REASONS[8])
        && auth(&env(s0 + 4, m::ANCHOR_ROTATE, cur_fp, 2, new_dg), m::ANCHOR_ROTATE, cur_fp, 2, &new_dg).is_ok()
        && auth(&env(s0 + 5, m::UPLOAD_ACTIVATE, 5, 3, [0x33; 32]), m::UPLOAD_ACTIVATE, 5, 4, &[0x33; 32]) == Err(crate::mgmtenv::OTHER_TARGET)
        && auth(&env(s0 + 6, m::UPLOAD_ACTIVATE, 5, 3, [0x33; 32]), m::UPLOAD_ACTIVATE, 9, 3, &[0x33; 32]) == Err(crate::mgmtenv::REASONS[8])
        && auth(&env(s0 + 7, m::UPLOAD_ACTIVATE, 5, 3, [0x33; 32]), m::UPLOAD_ACTIVATE, 5, 3, &[0x33; 32]).is_ok()
        && auth(&env(s0 + 7, m::UPLOAD_ACTIVATE, 5, 3, [0x33; 32]), m::UPLOAD_ACTIVATE, 5, 3, &[0x33; 32]) == Err(crate::mgmtenv::REASONS[7])
        && crate::mgmtenv::journaled().0 - j2 == 5; // the five refusals (accepted ones are journaled by their handlers)
    // no owner key enrolled: nothing is privileged-capable
    crate::anchor::install_owner(None, 0);
    let no_owner = has(&run(b"config confirm", &test_envelope(&kp, &mk(8, m::CFG_CONFIRM, 8, dig_n1))), b"no owner key enrolled");
    crate::cfgd::test_pose(posed.0, posed.1, posed.2);
    crate::mgmtabi::test_reset();
    crate::anchor::install_owner(saved.0, saved.1);
    crate::cfgd::set_selftest(false);
    let pass = view && session_only && wrong_key && wrong_dev && wrong_boot && stale_n && other_op && tamper && malformed && good && replay && older && journaled && words && no_owner && tool && endpoints;
    arch_aarch64::_print(format_args!(
        " [P-hsh-web] {} — R6 = D (owner-signed HQMGMT1 envelopes; the carrier carries no authority) on the web carrier POST /api/hsh: view commands on the session alone={} confirm / rollback / stage on the session alone refused={} wrong key={} another device={} another boot={} confirm for gen N while N+1 on trial={} another operation={} tampered byte={} malformed={} all refused; a valid envelope accepted={} replay / older sequence refused={} every request journaled with its outcome={} ({} of 13) journal keeps command words only={} no owner key = nothing privileged={} policy-sign.py mgmt-sign vector verifies byte for byte={} owner endpoints (factory reset / rotate bound to current + new key / upload activate bound to type + generation + digest): exact binding accepted, other target / other operation / replay refused + journaled={}\n",
        if pass { "PASS" } else { "FAIL" }, view, session_only, wrong_key, wrong_dev, wrong_boot, stale_n, other_op, tamper, malformed, good, replay && older, journaled, jn, words, no_owner, tool, endpoints
    ));
    pass
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
    crate::cfgd::set_selftest(true);
    let r = selftest_inner(now_ms);
    crate::cfgd::set_selftest(false);
    r
}

#[cfg(feature = "mctls")]
fn selftest_inner(now_ms: u64) -> bool {
    use hal::mgmtabi as m;
    let mut o = [0u8; 2048];
    let mut run = |l: &[u8], role: u8| -> ([u8; 2048], usize) {
        let mut b = [0u8; 2048];
        let n = run_line(l, role, [0x5e, 0x1f, 0, 0], now_ms, &[], &mut b);
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
    // step 4b + R6 = D: configuration operations — refused on any session role without an owner-signed envelope
    // (the full envelope matrix is [P-hsh-web]); the challenge reports what an envelope must bind
    let refused = |msg: u16, role: u8| -> bool {
        let mut r = [0u8; 256];
        match crate::mgmtabi::dispatch(msg, role, [0; 4], now_ms, 0, &[], &mut r) {
            (m::R_OK, n) if n == m::ACT_LEN => {
                let a = m::Act::decode(r[..m::ACT_LEN].try_into().unwrap());
                !a.ok && a.reason_str().contains("envelope")
            }
            _ => false,
        }
    };
    let cfg_refused = has(&run(b"config confirm", v), b"envelope") && has(&run(b"config rollback", v), b"envelope")
        && has(&run(b"config stage 00000000000000aa", v), b"envelope")
        && [m::CFG_CONFIRM, m::CFG_ROLLBACK, m::CFG_STAGE].iter().all(|&msg| refused(msg, m::ROLE_OWNER) && refused(msg, v));
    let chal = {
        let mut r = [0u8; 256];
        crate::mgmtabi::dispatch(m::OWNER_CHALLENGE, v, [0; 4], now_ms, 0, &[], &mut r) == (m::R_OK, m::CHAL_LEN)
            && m::Challenge::decode(r[..m::CHAL_LEN].try_into().unwrap()).device_id == crate::config_device_id()
    };
    let retired = has(&run(b"owner elevate 00 11", v), b"not supported");
    let abi = abi && cfg_refused && chal && retired;
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
        " [P-mgmtabi] {} — ADR 0059 D9 management ABI: every read message answers with exactly its fixed record from the /api producers, an unknown id is refused, a caller without the role is denied; config confirm / rollback / stage refused on every session role without an owner-signed HQMGMT1 envelope, the challenge reports what to bind, session elevation retired (R6 = D)={}\n",
        if abi { "PASS" } else { "FAIL" }, abi
    ));
    pass && abi
}
