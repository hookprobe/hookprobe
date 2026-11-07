//! Kernel side of the EL0 TLS server (ADR 0050 D2 / ADR 0051): load `el0-tlshost` into EL0, then drive it
//! one command per BOUNDED excursion (`crate::excursion_bounded`, ADR 0050 D5). The kernel keeps TCP and
//! only ever passes ciphertext in / gets ciphertext + plaintext back. A timeout or fault fails the HTTPS
//! service closed (all TLS sessions dropped, the server image reset and re-initialised) — forwarding, the
//! IPS and plain-HTTP Mission Control are unaffected.

use hal::tlsabi::*;

macro_rules! kprint {
    ($($t:tt)*) => { arch_aarch64::_print(format_args!($($t)*)) };
}

static TLSHOST_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/el0_tlshost.elf"));

#[cfg(feature = "cm5")]
const BASE: usize = BASE_CM5;
#[cfg(not(feature = "cm5"))]
const BASE: usize = BASE_QEMU;

const IO_PAGES: usize = IO_SIZE / 0x1000;
const HEAP_PAGES: usize = HEAP_SIZE / 0x1000;
const STACK_PAGES: usize = STACK_SIZE / 0x1000;
/// RW image pages (data + bss) the reset path re-copies / zeroes.
const RW_MAX: usize = 16;

/// Per-command time budget. The handshake (ECDSA sign + X25519) is the slowest command; QEMU's TCG is
/// ~two orders of magnitude slower than the A76.
#[cfg(feature = "cm5")]
const BUDGET_US: u64 = 250_000;
#[cfg(not(feature = "cm5"))]
const BUDGET_US: u64 = 5_000_000;

pub struct Reply {
    pub status: u32,
    pub tls_len: usize,
    pub plain_len: usize,
    pub flags: u32,
}

pub struct TlsHost {
    entry: usize,
    sp_top: usize,
    io: [usize; IO_PAGES],
    heap: [usize; HEAP_PAGES],
    rw: [(usize, usize, usize); RW_MAX], // (frame, file offset, file bytes in this page)
    nrw: usize,
    init_blob: [u8; 4096],
    init_len: usize,
    /// TLS can serve (a certificate is installed and INIT succeeded).
    pub ready: bool,
    /// The device's TLS public key (SEC1 uncompressed) — what provisioning certifies (ADR 0051 D3).
    pub pubkey: [u8; 65],
    pub calls: u32,
    pub timeouts: u32,
    pub faults: u32,
    pub restarts: u32,
    pub tls_errors: u32,
}

static mut HOST: Option<TlsHost> = None;

/// The loaded server, if any.
#[allow(static_mut_refs)]
pub fn host() -> Option<&'static mut TlsHost> {
    unsafe { HOST.as_mut() }
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

impl TlsHost {
    /// Load the image, map heap/stack/IO, and initialise it with the device key `scalar` and an optional
    /// DER certificate chain. Returns the host even without a certificate (it publishes the public key);
    /// `None` only when loading fails (TLS then simply stays off).
    pub fn load(scalar: &[u8; 32], chain: &[&[u8]]) -> Option<&'static mut TlsHost> {
        let parsed = crate::elf::parse(TLSHOST_ELF).ok()?;
        let mut h = TlsHost {
            entry: parsed.entry,
            sp_top: BASE + STACK_OFF + STACK_SIZE,
            io: [0; IO_PAGES],
            heap: [0; HEAP_PAGES],
            rw: [(0, 0, 0); RW_MAX],
            nrw: 0,
            init_blob: [0; 4096],
            init_len: 0,
            ready: false,
            pubkey: [0; 65],
            calls: 0,
            timeouts: 0,
            faults: 0,
            restarts: 0,
            tls_errors: 0,
        };
        for s in parsed.segs[..parsed.nsegs].iter() {
            if s.vaddr < BASE || s.vaddr + s.memsz > BASE + IMAGE_MAX {
                return None; // the image must stay inside its own window
            }
            let npages = (s.memsz + 0xFFF) >> 12;
            for p in 0..npages {
                let f = alloc();
                if f == 0 {
                    return None;
                }
                let voff = p * 0x1000;
                let n = s.filesz.saturating_sub(voff).min(0x1000);
                if n > 0 {
                    unsafe { core::ptr::copy_nonoverlapping(TLSHOST_ELF.as_ptr().add(s.offset + voff), f as *mut u8, n) };
                }
                if s.executable() {
                    arch_aarch64::mmu::sync_instruction_cache(f, 0x1000);
                } else if s.writable() {
                    if h.nrw == RW_MAX {
                        return None;
                    }
                    h.rw[h.nrw] = (f, s.offset + voff, n);
                    h.nrw += 1;
                }
                if !map(s.vaddr + voff, f, s.executable(), s.writable()) {
                    return None;
                }
            }
        }
        for p in 0..HEAP_PAGES {
            let f = alloc();
            if f == 0 || !map(BASE + HEAP_OFF + p * 0x1000, f, false, true) {
                return None;
            }
            h.heap[p] = f;
        }
        for p in 0..STACK_PAGES {
            let f = alloc();
            if f == 0 || !map(BASE + STACK_OFF + p * 0x1000, f, false, true) {
                return None;
            }
        }
        for p in 0..IO_PAGES {
            let f = alloc();
            if f == 0 || !map(BASE + IO_OFF + p * 0x1000, f, false, true) {
                return None;
            }
            h.io[p] = f;
        }
        // INIT blob: [scalar 32][u16 n]{[u16 len][der]}*
        let mut b = [0u8; 4096];
        b[..32].copy_from_slice(scalar);
        let mut p = 34;
        let mut n = 0u16;
        for c in chain.iter().take(4) {
            if p + 2 + c.len() > b.len() {
                break;
            }
            b[p..p + 2].copy_from_slice(&(c.len() as u16).to_le_bytes());
            b[p + 2..p + 2 + c.len()].copy_from_slice(c);
            p += 2 + c.len();
            n += 1;
        }
        b[32..34].copy_from_slice(&n.to_le_bytes());
        h.init_blob = b;
        h.init_len = p;
        unsafe { HOST = Some(h) };
        let h = host()?;
        h.init();
        Some(h)
    }

    fn init(&mut self) {
        let blob = self.init_blob;
        let r = self.call(CMD_INIT, 0, &blob[..self.init_len], 0);
        if r.status == ST_OK && r.tls_len == 65 {
            let mut k = [0u8; 65];
            self.read(OUT_TLS_OFF, &mut k);
            self.pubkey = k;
            self.ready = r.flags & F_HANDSHAKE_DONE != 0;
        } else {
            self.ready = false;
        }
    }

    // ---- IO region access through its (not necessarily contiguous) frames
    fn write(&mut self, mut off: usize, mut src: &[u8]) {
        while !src.is_empty() && off < IO_SIZE {
            let (pg, po) = (off / 0x1000, off % 0x1000);
            let n = src.len().min(0x1000 - po);
            unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), (self.io[pg] + po) as *mut u8, n) };
            off += n;
            src = &src[n..];
        }
    }
    /// Copy `out.len()` bytes from the IO region at `off`.
    pub fn read(&self, mut off: usize, mut out: &mut [u8]) {
        while !out.is_empty() && off < IO_SIZE {
            let (pg, po) = (off / 0x1000, off % 0x1000);
            let n = out.len().min(0x1000 - po);
            unsafe { core::ptr::copy_nonoverlapping((self.io[pg] + po) as *const u8, out.as_mut_ptr(), n) };
            off += n;
            out = &mut out[n..];
        }
    }
    fn w32(&mut self, off: usize, v: u32) {
        self.write(off, &v.to_le_bytes());
    }
    fn r32(&self, off: usize) -> u32 {
        let mut b = [0u8; 4];
        self.read(off, &mut b);
        u32::from_le_bytes(b)
    }

    /// Run one command in a bounded excursion. On timeout / fault the server is reset (every TLS
    /// session is lost, which the caller sees as `ST_PANIC`) and re-initialised.
    pub fn call(&mut self, cmd: u32, conn: usize, input: &[u8], unix_secs: u64) -> Reply {
        let n = input.len().min(IN_MAX);
        self.w32(H_MAGIC, MAGIC);
        self.w32(H_CMD, cmd);
        self.w32(H_CONN, conn as u32);
        self.w32(H_IN_LEN, n as u32);
        self.w32(H_STATUS, ST_PANIC); // overwritten by a clean exit
        self.write(H_UNIX_SECS, &unix_secs.to_le_bytes());
        let mut ent = [0u8; ENT_MAX];
        let elen = if cmd == CMD_RECV { fill_entropy(&mut ent[..128]) } else { 0 };
        self.write(H_ENT, &ent[..elen]);
        self.w32(H_ENT_LEN, elen as u32);
        self.write(IN_OFF, &input[..n]);
        self.calls += 1;
        let how = crate::excursion_bounded(self.entry, self.sp_top, BUDGET_US);
        if how != crate::Excursion::Exited {
            match how {
                crate::Excursion::Timeout => self.timeouts += 1,
                _ => self.faults += 1,
            }
            self.reset();
            return Reply { status: ST_PANIC, tls_len: 0, plain_len: 0, flags: F_CLOSED };
        }
        let status = self.r32(H_STATUS);
        if status == ST_PANIC {
            self.reset();
            return Reply { status, tls_len: 0, plain_len: 0, flags: F_CLOSED };
        }
        if status == ST_TLS_ERROR {
            self.tls_errors += 1;
        }
        Reply {
            status,
            tls_len: (self.r32(H_OUT_TLS) as usize).min(OUT_TLS_MAX),
            plain_len: (self.r32(H_OUT_PLAIN) as usize).min(OUT_PLAIN_MAX),
            flags: self.r32(H_FLAGS),
        }
    }

    /// Fail closed and recover: restore the image's data/bss pages, zero the heap and IO region, re-INIT.
    fn reset(&mut self) {
        self.restarts += 1;
        for i in 0..self.nrw {
            let (f, off, n) = self.rw[i];
            unsafe {
                core::ptr::write_bytes(f as *mut u8, 0, 0x1000);
                if n > 0 {
                    core::ptr::copy_nonoverlapping(TLSHOST_ELF.as_ptr().add(off), f as *mut u8, n);
                }
            }
        }
        for f in self.heap.iter().chain(self.io.iter()) {
            unsafe { core::ptr::write_bytes(*f as *mut u8, 0, 0x1000) };
        }
        self.init();
    }
}

/// Fresh entropy for one call. CM5: the RNG200 hardware TRNG, fail-closed (a missing/failed TRNG yields
/// 0 bytes, so the handshake fails). QEMU: a test source — compiled out of every CM5 build.
fn fill_entropy(out: &mut [u8]) -> usize {
    #[cfg(feature = "cm5")]
    {
        let mut i = 0;
        while i < out.len() {
            let Some(w) = arch_aarch64::rng200::next_word_strict() else { return 0 };
            let b = w.to_le_bytes();
            let n = (out.len() - i).min(8);
            out[i..i + n].copy_from_slice(&b[..n]);
            i += n;
        }
        out.len()
    }
    #[cfg(not(feature = "cm5"))]
    {
        // QEMU ONLY (no TRNG in the virt machine): SHA-256 over a counter + the cycle counter. Fine for the
        // QEMU HTTPS proof; never present in a CM5 image.
        use core::sync::atomic::{AtomicU64, Ordering};
        static CTR: AtomicU64 = AtomicU64::new(0x51A7_E5ED);
        let mut i = 0;
        while i < out.len() {
            let c = CTR.fetch_add(1, Ordering::Relaxed);
            let t: u64;
            unsafe { core::arch::asm!("mrs {}, cntpct_el0", out(reg) t) };
            let mut m = [0u8; 16];
            m[..8].copy_from_slice(&c.to_le_bytes());
            m[8..].copy_from_slice(&t.to_le_bytes());
            let d = boot_abi::sha256::digest(&m);
            let n = (out.len() - i).min(32);
            out[i..i + n].copy_from_slice(&d[..n]);
            i += n;
        }
        out.len()
    }
}

/// The device's TLS key scalar. CM5: HKDF(SRK, label) — derived, never stored (ADR 0051 D3); no SRK => no
/// TLS. QEMU: a fixed test seed. `attempt` re-derives if a candidate is not a valid P-256 scalar.
pub fn device_tls_scalar(attempt: u8) -> Option<[u8; 32]> {
    #[cfg(feature = "cm5")]
    let ikm = crate::seal_srk()?;
    #[cfg(not(feature = "cm5"))]
    let ikm = [0x7Eu8; 32]; // QEMU test key — never a CM5 build
    let mut label = *b"HEQK-MC-TLS-p256-v1-0";
    label[20] = b'0' + attempt;
    Some(boot_abi::kdf::hkdf_expand32(&ikm, &label))
}

/// `MCTLS.CRT` on the boot partition (FAT 8.3) — the provisioned certificate chain (public data only; the
/// key never leaves the device). Fixed 4 KiB so the flasher patches it in place, like OWNER.TXT.
pub const CERT_8_3: &[u8; 11] = b"MCTLS   CRT";
pub const CERT_FILE_LEN: usize = 4096;
const CERT_MAGIC: &[u8; 8] = b"HQCRT1\0\0";

/// Read `MCTLS.CRT` (all zeros / absent = not provisioned).
pub fn load_cert_file<D: hal::BlockDev>(dev: &D, out: &mut [u8; CERT_FILE_LEN]) -> bool {
    let mut sec = [0u8; 512];
    if dev.read_block(0, &mut sec).is_err() {
        return false;
    }
    let p1 = crate::store::parse_mbr(&sec)[0].start;
    if p1 == 0 {
        return false;
    }
    let Some((lba, n)) = crate::fat::locate_contiguous(dev, p1, CERT_8_3) else { return false };
    if (n as usize) * 512 < CERT_FILE_LEN {
        return false;
    }
    for i in 0..CERT_FILE_LEN / 512 {
        if dev.read_block(lba + i as u64, &mut sec).is_err() {
            return false;
        }
        out[i * 512..(i + 1) * 512].copy_from_slice(&sec);
    }
    &out[..8] == CERT_MAGIC
}

/// Split a loaded `MCTLS.CRT` into its DER certificates (leaf first). Bounded; malformed = empty.
pub fn cert_chain(file: &[u8; CERT_FILE_LEN]) -> ([&[u8]; 4], usize) {
    let mut v: [&[u8]; 4] = [&[]; 4];
    if &file[..8] != CERT_MAGIC {
        return (v, 0);
    }
    let n = u16::from_le_bytes([file[8], file[9]]) as usize;
    let mut p = 10;
    let mut k = 0;
    while k < n.min(4) {
        if p + 2 > file.len() {
            return (v, 0);
        }
        let l = u16::from_le_bytes([file[p], file[p + 1]]) as usize;
        if l == 0 || p + 2 + l > file.len() {
            return (v, 0);
        }
        v[k] = &file[p + 2..p + 2 + l];
        p += 2 + l;
        k += 1;
    }
    (v, k)
}

/// Bring the HTTPS service up (ADR 0051): derive the device key, read `MCTLS.CRT` from `dev` (the boot
/// disk / eMMC p1), load + INIT the EL0 server, and print the public key provisioning certifies. Without a
/// certificate the server still publishes the key and HTTPS stays off (Mission Control keeps plain HTTP).
pub fn bring_up<D: hal::BlockDev>(dev: Option<&D>) {
    let Some(scalar) = device_tls_scalar(0) else {
        kprint!(" [MC-TLS] OFF — no device root key (SRK): refusing a guessable TLS key\n");
        return;
    };
    let mut file = [0u8; CERT_FILE_LEN];
    let have = dev.map_or(false, |d| load_cert_file(d, &mut file));
    let (chain, n) = cert_chain(&file);
    let Some(h) = TlsHost::load(&scalar, &chain[..n]) else {
        kprint!(" [MC-TLS] OFF — EL0 TLS server failed to load\n");
        return;
    };
    kprint!(" [MC-TLS] device TLS key (P-256, SRK-derived) pub=");
    for b in h.pubkey.iter() {
        kprint!("{:02x}", b);
    }
    kprint!("\n");
    if h.ready {
        kprint!(" [MC-TLS] HTTPS ready on :443 — certificate chain of {} from MCTLS.CRT, TLS1.3 CHACHA20_POLY1305 / X25519 / ECDSA-P256, EL0 server (ADR 0051)\n", n);
    } else if have {
        kprint!(" [MC-TLS] HTTPS OFF — MCTLS.CRT present but rejected by the server (wrong key / malformed)\n");
    } else {
        kprint!(" [MC-TLS] HTTPS OFF — no certificate provisioned (MCTLS.CRT empty); certify the key above with the owner CA\n");
    }
}
