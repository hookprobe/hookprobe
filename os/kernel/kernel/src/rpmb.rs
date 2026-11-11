//! eMMC RPMB anti-rollback anchor (decision record 2026-11-10 D-RPMB; operator 2026-11-10b: "implement the
//! approved RPMB architecture, but keep all irreversible key programming behind a separate explicit manufacturing
//! operation").
//!
//! Three parts, all host-pure (no `crate::` dependency outside the self-test):
//! 1. The JEDEC RPMB data-frame protocol (eMMC 5.1 §6.6.22): 512-byte frames, big-endian fields, an HMAC-SHA256 over
//!    bytes 228..512, a host nonce on reads, a monotonic write counter on writes. The host side verifies every
//!    response (type, nonce / counter, result, MAC) — an RPMB reply is never trusted unverified.
//! 2. `SimRpmb`, a model of the device side (write-once key, counter, auth / counter failures) for the QEMU gate.
//! 3. The high-water record the owner journal anchors in RPMB block 0 (`Hw`), and `RpmbAnchor`, which implements
//!    `ownerjournal::Anchor` over any `RpmbDev`.
//!
//! What is NOT here, on purpose:
//! - Programming the key. `program_key` exists only with `--features rpmb-provision`, a manufacturing build that
//!   the release / factory gates refuse (os/build/make-cm5-heqk-image.sh). A normal image cannot reach it.
//! - The eMMC transport (CMD6 PARTITION_ACCESS switch to RPMB, CMD23 reliable write, CMD25 / CMD18, and the
//!   always-switch-back-to-user discipline). That code needs its own review and fault tests before it exists;
//!   until then no build talks to a real RPMB partition (`emmc.rs` still has no partition-switch path).
//! - Choosing the unit to program. Metal only on an owner-designated unit after approval.

use boot_abi::kdf::{ct_eq, hkdf_expand32, hkdf_extract, hmac_sha256};

pub const FRAME: usize = 512;
const MAC_AT: usize = 196; // key (program) / MAC (everything else), 32 B
const DATA_AT: usize = 228; // 256 B
const NONCE_AT: usize = 484; // 16 B
const WCNT_AT: usize = 500; // u32 BE
const ADDR_AT: usize = 504; // u16 BE
const BCNT_AT: usize = 506; // u16 BE
const RES_AT: usize = 508; // u16 BE
const TYPE_AT: usize = 510; // u16 BE

pub const REQ_KEY: u16 = 0x0001;
pub const REQ_WCNT: u16 = 0x0002;
pub const REQ_WRITE: u16 = 0x0003;
pub const REQ_READ: u16 = 0x0004;
pub const REQ_RESULT: u16 = 0x0005;
const fn resp(req: u16) -> u16 {
    req << 8
}

pub const RES_OK: u16 = 0;
pub const RES_GENERAL: u16 = 1;
pub const RES_AUTH: u16 = 2;
pub const RES_COUNTER: u16 = 3;
pub const RES_ADDR: u16 = 4;
pub const RES_WRITE: u16 = 5;
pub const RES_READ: u16 = 6;
pub const RES_NO_KEY: u16 = 7;
/// bit 7: the write counter has expired (no more authenticated writes, ever)
pub const RES_WCNT_EXPIRED: u16 = 0x80;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpmbErr {
    /// The transport failed (no answer / I/O).
    Io,
    /// The device answered with this result code (low 7 bits).
    Result(u16),
    /// The key has never been programmed on this unit: RPMB is inactive (not an attack).
    NoKey,
    /// The write counter is exhausted: RPMB is read-only forever on this unit.
    Expired,
    /// The response does not verify (wrong type, nonce, counter, address or MAC): treated as hostile.
    BadResponse,
}

fn be16(f: &[u8; FRAME], at: usize) -> u16 {
    u16::from_be_bytes([f[at], f[at + 1]])
}
fn put16(f: &mut [u8; FRAME], at: usize, v: u16) {
    f[at..at + 2].copy_from_slice(&v.to_be_bytes());
}
fn be32(f: &[u8; FRAME], at: usize) -> u32 {
    u32::from_be_bytes([f[at], f[at + 1], f[at + 2], f[at + 3]])
}

/// The frame MAC (JEDEC: HMAC-SHA256 over bytes 228..512 of each frame; one frame here).
pub fn frame_mac(key: &[u8; 32], f: &[u8; FRAME]) -> [u8; 32] {
    hmac_sha256(key, &f[DATA_AT..])
}

/// The RPMB authentication key of a unit: derived from its sealing root key, never stored, never in an image.
pub fn unit_key(srk: &[u8; 32]) -> [u8; 32] {
    hkdf_expand32(&hkdf_extract(b"HQ-rpmb", srk), b"HQ-rpmb-key-v1")
}

/// The transport: one 512-byte frame out / in. A write is `send(frame, reliable)`; `recv` reads the response
/// frame the device prepared for the last request.
pub trait RpmbDev {
    fn send(&mut self, f: &[u8; FRAME], reliable: bool) -> Result<(), ()>;
    fn recv(&mut self, out: &mut [u8; FRAME]) -> Result<(), ()>;
}

/// The host side of the protocol, keyed with the unit key.
pub struct Rpmb<'a, D: RpmbDev + ?Sized> {
    pub dev: &'a mut D,
    pub key: [u8; 32],
}

fn result_of(f: &[u8; FRAME]) -> Result<(), RpmbErr> {
    let r = be16(f, RES_AT);
    match r & 0x7f {
        RES_OK if r & RES_WCNT_EXPIRED == 0 => Ok(()),
        RES_OK => Err(RpmbErr::Expired),
        RES_NO_KEY => Err(RpmbErr::NoKey),
        x => Err(RpmbErr::Result(x)),
    }
}

impl<D: RpmbDev + ?Sized> Rpmb<'_, D> {
    fn verify(&self, f: &[u8; FRAME], want_type: u16) -> Result<(), RpmbErr> {
        if be16(f, TYPE_AT) != resp(want_type) {
            return Err(RpmbErr::BadResponse);
        }
        // a "key not programmed" answer carries no valid MAC (there is no key): report it as such
        if be16(f, RES_AT) & 0x7f == RES_NO_KEY {
            return Err(RpmbErr::NoKey);
        }
        if !ct_eq(&f[MAC_AT..MAC_AT + 32], &frame_mac(&self.key, f)) {
            return Err(RpmbErr::BadResponse);
        }
        result_of(f)
    }

    /// The write counter, authenticated with `nonce`.
    pub fn counter(&mut self, nonce: &[u8; 16]) -> Result<u32, RpmbErr> {
        let mut f = [0u8; FRAME];
        f[NONCE_AT..NONCE_AT + 16].copy_from_slice(nonce);
        put16(&mut f, TYPE_AT, REQ_WCNT);
        self.dev.send(&f, false).map_err(|_| RpmbErr::Io)?;
        let mut r = [0u8; FRAME];
        self.dev.recv(&mut r).map_err(|_| RpmbErr::Io)?;
        self.verify(&r, REQ_WCNT)?;
        if r[NONCE_AT..NONCE_AT + 16] != nonce[..] {
            return Err(RpmbErr::BadResponse); // a replayed answer
        }
        Ok(be32(&r, WCNT_AT))
    }

    /// One authenticated 256-byte block, fresh (`nonce`).
    pub fn read(&mut self, addr: u16, nonce: &[u8; 16]) -> Result<[u8; 256], RpmbErr> {
        let mut f = [0u8; FRAME];
        f[NONCE_AT..NONCE_AT + 16].copy_from_slice(nonce);
        put16(&mut f, ADDR_AT, addr);
        put16(&mut f, TYPE_AT, REQ_READ);
        self.dev.send(&f, false).map_err(|_| RpmbErr::Io)?;
        let mut r = [0u8; FRAME];
        self.dev.recv(&mut r).map_err(|_| RpmbErr::Io)?;
        self.verify(&r, REQ_READ)?;
        if r[NONCE_AT..NONCE_AT + 16] != nonce[..] || be16(&r, ADDR_AT) != addr {
            return Err(RpmbErr::BadResponse);
        }
        let mut d = [0u8; 256];
        d.copy_from_slice(&r[DATA_AT..DATA_AT + 256]);
        Ok(d)
    }

    /// One authenticated write of block `addr`; the device's counter must advance by exactly one.
    pub fn write(&mut self, addr: u16, data: &[u8; 256], nonce: &[u8; 16]) -> Result<u32, RpmbErr> {
        let c = self.counter(nonce)?;
        let mut f = [0u8; FRAME];
        f[DATA_AT..DATA_AT + 256].copy_from_slice(data);
        f[WCNT_AT..WCNT_AT + 4].copy_from_slice(&c.to_be_bytes());
        put16(&mut f, ADDR_AT, addr);
        put16(&mut f, BCNT_AT, 1);
        put16(&mut f, TYPE_AT, REQ_WRITE);
        let m = frame_mac(&self.key, &f);
        f[MAC_AT..MAC_AT + 32].copy_from_slice(&m);
        self.dev.send(&f, true).map_err(|_| RpmbErr::Io)?;
        let mut q = [0u8; FRAME];
        put16(&mut q, TYPE_AT, REQ_RESULT);
        self.dev.send(&q, false).map_err(|_| RpmbErr::Io)?;
        let mut r = [0u8; FRAME];
        self.dev.recv(&mut r).map_err(|_| RpmbErr::Io)?;
        self.verify(&r, REQ_WRITE)?;
        let c2 = be32(&r, WCNT_AT);
        if c2 != c.wrapping_add(1) || be16(&r, ADDR_AT) != addr {
            return Err(RpmbErr::BadResponse);
        }
        Ok(c2)
    }

    /// MANUFACTURING ONLY: program the write-once key. Irreversible. Not compiled into any normal image.
    #[cfg(feature = "rpmb-provision")]
    pub fn program_key(&mut self) -> Result<(), RpmbErr> {
        let mut f = [0u8; FRAME];
        f[MAC_AT..MAC_AT + 32].copy_from_slice(&self.key);
        put16(&mut f, TYPE_AT, REQ_KEY);
        self.dev.send(&f, true).map_err(|_| RpmbErr::Io)?;
        let mut q = [0u8; FRAME];
        put16(&mut q, TYPE_AT, REQ_RESULT);
        self.dev.send(&q, false).map_err(|_| RpmbErr::Io)?;
        let mut r = [0u8; FRAME];
        self.dev.recv(&mut r).map_err(|_| RpmbErr::Io)?;
        if be16(&r, TYPE_AT) != resp(REQ_KEY) {
            return Err(RpmbErr::BadResponse);
        }
        result_of(&r)
    }
}

// ---- the device model (QEMU gate) -----------------------------------------------------------------------------

/// A model of an eMMC RPMB partition: write-once key, monotonic counter, `N` 256-byte blocks.
pub struct SimRpmb<const N: usize> {
    pub key: Option<[u8; 32]>,
    pub counter: u32,
    pub blocks: [[u8; 256]; N],
    last_req: u16,
    last_result: u16,
    last_addr: u16,
    pending: [u8; FRAME],
    /// test hook: corrupt the next response MAC (a hostile bus / device)
    pub corrupt_next: bool,
}

impl<const N: usize> SimRpmb<N> {
    pub const fn new() -> Self {
        SimRpmb { key: None, counter: 0, blocks: [[0u8; 256]; N], last_req: 0, last_result: 0, last_addr: 0, pending: [0u8; FRAME], corrupt_next: false }
    }
    /// The factory step, modelled (the real one is `program_key` in a manufacturing build).
    pub fn sim_program(&mut self, key: [u8; 32]) {
        if self.key.is_none() {
            self.key = Some(key);
        }
    }
    fn respond(&mut self, ty: u16, res: u16, addr: u16, nonce: Option<&[u8]>, data: Option<&[u8; 256]>) {
        let mut r = [0u8; FRAME];
        if let Some(d) = data {
            r[DATA_AT..DATA_AT + 256].copy_from_slice(d);
        }
        if let Some(n) = nonce {
            r[NONCE_AT..NONCE_AT + 16].copy_from_slice(n);
        }
        r[WCNT_AT..WCNT_AT + 4].copy_from_slice(&self.counter.to_be_bytes());
        put16(&mut r, ADDR_AT, addr);
        put16(&mut r, RES_AT, res);
        put16(&mut r, TYPE_AT, resp(ty));
        if let Some(k) = self.key {
            let m = frame_mac(&k, &r);
            r[MAC_AT..MAC_AT + 32].copy_from_slice(&m);
        }
        if self.corrupt_next {
            r[MAC_AT] ^= 1;
            self.corrupt_next = false;
        }
        self.pending = r;
    }
}

impl<const N: usize> RpmbDev for SimRpmb<N> {
    fn send(&mut self, f: &[u8; FRAME], reliable: bool) -> Result<(), ()> {
        let ty = be16(f, TYPE_AT);
        match ty {
            REQ_KEY => {
                // write-once: a second programming attempt fails; the model refuses programming entirely here
                // (the gate never programs through the protocol — see `sim_program`)
                self.last_req = REQ_KEY;
                self.last_result = RES_GENERAL;
            }
            REQ_WCNT => {
                let res = if self.key.is_some() { RES_OK } else { RES_NO_KEY };
                let n = f[NONCE_AT..NONCE_AT + 16].to_vec_free();
                self.respond(REQ_WCNT, res, 0, Some(&n), None);
            }
            REQ_READ => {
                let addr = be16(f, ADDR_AT);
                let n = f[NONCE_AT..NONCE_AT + 16].to_vec_free();
                match (self.key, (addr as usize) < N) {
                    (None, _) => self.respond(REQ_READ, RES_NO_KEY, addr, Some(&n), None),
                    (Some(_), false) => self.respond(REQ_READ, RES_ADDR, addr, Some(&n), None),
                    (Some(_), true) => {
                        let d = self.blocks[addr as usize];
                        self.respond(REQ_READ, RES_OK, addr, Some(&n), Some(&d))
                    }
                }
            }
            REQ_WRITE => {
                let addr = be16(f, ADDR_AT);
                self.last_req = REQ_WRITE;
                self.last_addr = addr;
                self.last_result = match self.key {
                    None => RES_NO_KEY,
                    Some(_) if !reliable || be16(f, BCNT_AT) != 1 => RES_GENERAL,
                    Some(k) if !ct_eq(&f[MAC_AT..MAC_AT + 32], &frame_mac(&k, f)) => RES_AUTH,
                    Some(_) if be32(f, WCNT_AT) != self.counter => RES_COUNTER,
                    Some(_) if self.counter == u32::MAX => RES_WRITE | RES_WCNT_EXPIRED,
                    Some(_) if addr as usize >= N => RES_ADDR,
                    Some(_) => {
                        self.blocks[addr as usize].copy_from_slice(&f[DATA_AT..DATA_AT + 256]);
                        self.counter += 1;
                        RES_OK
                    }
                };
            }
            REQ_RESULT => {
                let (req, res, addr) = (self.last_req, self.last_result, self.last_addr);
                self.respond(req, res, addr, None, None);
            }
            _ => return Err(()),
        }
        Ok(())
    }
    fn recv(&mut self, out: &mut [u8; FRAME]) -> Result<(), ()> {
        *out = self.pending;
        Ok(())
    }
}

/// `[u8]` -> `[u8; 16]` without an allocator (the model's nonce echo).
trait ToArr16 {
    fn to_vec_free(&self) -> [u8; 16];
}
impl ToArr16 for [u8] {
    fn to_vec_free(&self) -> [u8; 16] {
        let mut a = [0u8; 16];
        a.copy_from_slice(&self[..16]);
        a
    }
}

// ---- the high-water record -------------------------------------------------------------------------------------

const HW_MAGIC: &[u8; 8] = b"HQRPMB1\0";
pub const HW_ADDR: u16 = 0;

/// The owner journal's rollback state, anchored in RPMB block 0 (the RPMB MAC authenticates it; the journal's own
/// MAC chain authenticates the journal). `allow_epoch` opens exactly one next epoch (compaction / factory reset are
/// two-phase: the allowance is anchored before the new epoch header is written, so a power cut between the two is
/// not a rollback, and nothing older can ever be accepted).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Hw {
    pub epoch: u32,
    /// the last committed record's seq (`next_seq - 1`; the epoch header counts as base - 1)
    pub seq: u64,
    /// the chained MAC at `seq`
    pub mac: [u8; 32],
    /// the next epoch a compaction / factory reset is allowed to open (0 = none)
    pub allow_epoch: u32,
    /// the journal was wiped (factory reset): an EMPTY journal is the expected state
    pub wiped: bool,
}

impl Hw {
    pub fn encode(&self) -> [u8; 256] {
        let mut b = [0u8; 256];
        b[..8].copy_from_slice(HW_MAGIC);
        b[8..10].copy_from_slice(&1u16.to_le_bytes());
        b[10..14].copy_from_slice(&self.epoch.to_le_bytes());
        b[14..22].copy_from_slice(&self.seq.to_le_bytes());
        b[22..54].copy_from_slice(&self.mac);
        b[54..58].copy_from_slice(&self.allow_epoch.to_le_bytes());
        b[58] = self.wiped as u8;
        b
    }
    /// None = never anchored (an all-zero block) or an unknown version.
    pub fn decode(b: &[u8; 256]) -> Option<Hw> {
        if &b[..8] != HW_MAGIC || u16::from_le_bytes([b[8], b[9]]) != 1 || b[58] > 1 {
            return None;
        }
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&b[22..54]);
        Some(Hw {
            epoch: u32::from_le_bytes(b[10..14].try_into().unwrap()),
            seq: u64::from_le_bytes(b[14..22].try_into().unwrap()),
            mac,
            allow_epoch: u32::from_le_bytes(b[54..58].try_into().unwrap()),
            wiped: b[58] == 1,
        })
    }
}

/// Where the anchor stands this boot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorState {
    /// no RPMB (no transport, no SRK, or the key was never programmed): the journal behaves as before
    Inactive,
    /// RPMB answers but the response did not verify / the device failed: anchoring is off, alert raised
    Faulted,
    Active,
}

/// `ownerjournal::Anchor` over an RPMB device. Nonces come from the caller's entropy (`fresh`).
pub struct RpmbAnchor<'a, D: RpmbDev + ?Sized> {
    pub r: Rpmb<'a, D>,
    pub fresh: &'a mut dyn FnMut() -> [u8; 16],
    pub state: AnchorState,
    pub writes: u32,
    pub write_failures: u32,
}

impl<'a, D: RpmbDev + ?Sized> RpmbAnchor<'a, D> {
    pub fn new(dev: &'a mut D, key: [u8; 32], fresh: &'a mut dyn FnMut() -> [u8; 16]) -> Self {
        RpmbAnchor { r: Rpmb { dev, key }, fresh, state: AnchorState::Active, writes: 0, write_failures: 0 }
    }
}

impl<D: RpmbDev + ?Sized> crate::ownerjournal::Anchor for RpmbAnchor<'_, D> {
    fn load(&mut self) -> Result<Option<Hw>, ()> {
        if self.state != AnchorState::Active {
            return Err(());
        }
        let n = (self.fresh)();
        match self.r.read(HW_ADDR, &n) {
            Ok(b) => Ok(Hw::decode(&b)),
            Err(RpmbErr::NoKey) => {
                self.state = AnchorState::Inactive;
                Err(())
            }
            Err(_) => {
                self.state = AnchorState::Faulted;
                Err(())
            }
        }
    }
    fn store(&mut self, hw: &Hw) -> bool {
        if self.state != AnchorState::Active {
            return false;
        }
        let n = (self.fresh)();
        match self.r.write(HW_ADDR, &hw.encode(), &n) {
            Ok(_) => {
                self.writes += 1;
                true
            }
            Err(e) => {
                self.write_failures += 1;
                if matches!(e, RpmbErr::NoKey) {
                    self.state = AnchorState::Inactive;
                } else if matches!(e, RpmbErr::BadResponse | RpmbErr::Expired) {
                    self.state = AnchorState::Faulted;
                }
                false
            }
        }
    }
    fn active(&self) -> bool {
        self.state == AnchorState::Active
    }
    fn faulted(&self) -> bool {
        self.state == AnchorState::Faulted
    }
}

// ---- [P-rpmb] ------------------------------------------------------------------------------------------------------

pub fn selftest() -> bool {
    let key = unit_key(&[0x42u8; 32]);
    // protocol, on the device model
    let mut sim: SimRpmb<4> = SimRpmb::new();
    let n1 = [1u8; 16];
    let nokey = Rpmb { dev: &mut sim, key }.counter(&n1) == Err(RpmbErr::NoKey);
    sim.sim_program(key);
    let mut data = [0u8; 256];
    data[..5].copy_from_slice(b"hello");
    let rw = {
        let mut h = Rpmb { dev: &mut sim, key };
        h.counter(&[2; 16]) == Ok(0) && h.write(1, &data, &[3; 16]) == Ok(1) && h.read(1, &[4; 16]) == Ok(data) && h.counter(&[5; 16]) == Ok(1)
    };
    // a host without the key: the device refuses the write (the host also cannot verify the reply), nothing changes
    let wrong = Rpmb { dev: &mut sim, key: [9u8; 32] }.write(1, &[0xAA; 256], &[6; 16]).is_err() && sim.blocks[1] == data && sim.counter == 1;
    // a captured, valid write frame replayed later: the counter moved on -> COUNTER failure, nothing written
    let mut f = [0u8; FRAME];
    f[DATA_AT..DATA_AT + 256].copy_from_slice(&[0x55; 256]);
    f[WCNT_AT..WCNT_AT + 4].copy_from_slice(&1u32.to_be_bytes());
    put16(&mut f, ADDR_AT, 1);
    put16(&mut f, BCNT_AT, 1);
    put16(&mut f, TYPE_AT, REQ_WRITE);
    let m = frame_mac(&key, &f);
    f[MAC_AT..MAC_AT + 32].copy_from_slice(&m);
    let _ = sim.send(&f, true); // valid now: counter 1 -> 2
    let mut q = [0u8; FRAME];
    put16(&mut q, TYPE_AT, REQ_RESULT);
    let mut r = [0u8; FRAME];
    let first = sim.send(&q, false).is_ok() && sim.recv(&mut r).is_ok() && be16(&r, RES_AT) == RES_OK && sim.counter == 2;
    let _ = sim.send(&f, true); // the same frame again
    let replay_refused = sim.send(&q, false).is_ok() && sim.recv(&mut r).is_ok() && be16(&r, RES_AT) == RES_COUNTER && sim.counter == 2;
    // a forged / corrupted response MAC is detected by the host
    sim.corrupt_next = true;
    let forged = Rpmb { dev: &mut sim, key }.read(1, &[7; 16]) == Err(RpmbErr::BadResponse);
    // the high-water record
    let hw = Hw { epoch: 7, seq: 42, mac: [0x3c; 32], allow_epoch: 8, wiped: false };
    let rec = Hw::decode(&hw.encode()) == Some(hw) && Hw::decode(&[0u8; 256]).is_none();
    // the journal anchored in it
    let (rb, reset, ahead, compact, inactive) = crate::ownerjournal::anchor_selftest();
    // the irreversible key write is not in this image
    let no_provision = !cfg!(feature = "rpmb-provision");
    let pass = nokey && rw && wrong && first && replay_refused && forged && rec && rb && reset && ahead && compact && inactive && no_provision;
    arch_aarch64::_print(format_args!(
        " [P-rpmb] {} — decision record D-RPMB (RPMB model; no RPMB transport, no key write in this image): unprogrammed key reported={} authenticated write/read/counter={} a host without the key changes nothing={} a replayed write frame is refused (counter)={} a forged response MAC is detected={} high-water record={} | owner journal anchored: an older copy restored -> rollback, owner rules NOT applied, appends refused={} factory reset continues above the anchor, a pre-reset copy is a rollback={} power cut between journal and anchor -> accepted + caught up={} compactions anchored, a pre-compaction copy is a rollback={} unprogrammed unit -> inactive, unchanged={} | rpmb-provision absent={}\n",
        if pass { "PASS" } else { "FAIL" }, nokey, rw && first, wrong, replay_refused, forged, rec, rb, reset, ahead, compact, inactive, no_provision
    ));
    pass
}
