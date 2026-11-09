//! ADR 0055 — the owner policy journal (stage A: records, chain, append, replay, rule table, precedence).
//!
//! Durable owner settings from Mission Control, kept SEPARATE from the operator-signed baseline (operator
//! 2026-11-09). An append-only journal of fixed 256-byte records in the DataVolume `Journal` region (#54),
//! each `mac = HMAC-SHA256(K, prev_mac ‖ record)` with `K = HKDF(SRK, "HQ-owner-journal-v1")`. Replay rebuilds
//! the in-RAM rule table and stops at the first record whose MAC fails — a torn tail after power loss or
//! tampering — and reports which.
//!
//! Stage B (2026-11-09) — compaction: the region is two halves; each starts with an epoch header record and
//! every record carries its epoch inside the MAC'd body. Replay takes the half with the highest valid epoch.
//! When the active half fills, the live rules + the recent artifact audit records are rewritten as a
//! checkpoint into the other half under epoch + 1 — sectors after the first are written first, the header
//! sector LAST, so a power cut mid-compaction leaves the old half in charge. A stale record from an older
//! epoch reads as a clean end of the journal, never as damage. Full = the live state alone no longer fits a
//! half (~500 rules).
//!
//! Precedence (ADR 0055 D2) is applied by the consumers: `devpolicy::policy_of` (an owner rule may TIGHTEN
//! any signed line, LOOSEN only an unpinned one) and `shield::decide_for_dev` (an owner allow never overrides
//! the management floor, an IOC-listed domain or the encrypted-DNS / relay controls).
use hal::{BlockDev, BlockErr};

pub const REC_LEN: usize = 256;
const MAGIC: [u8; 4] = *b"HQOJ";
const BODY: usize = 224; // MAC covers prev_mac ‖ bytes[0..224]
const EPOCH_AT: usize = 192; // u32 epoch inside the MAC'd body
const KIND_HDR: u8 = 0xEE; // epoch header (target = epoch u32 ‖ base seq u64)
pub const TARGET_MAX: usize = 64;
pub const REASON_MAX: usize = 96;
pub const MAX_RULES: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    DevicePolicy = 1, // target = MAC, value = devpolicy::Pol
    ShieldAllow = 2,  // target = domain, value = 1
    ShieldBlock = 3,  // target = domain, value = 1
    ShieldProfile = 4, // target = MAC, value = devpolicy::ShieldProfile
    /// ADR 0056 D6: an artifact activation (audit only — never a rule). target = pack type name,
    /// value = 1 activated / 2 rolled back, reason = "gen A->B sha256:<16 hex>".
    Artifact = 5,
}

impl Kind {
    pub fn from_u8(v: u8) -> Option<Kind> {
        match v {
            1 => Some(Kind::DevicePolicy),
            2 => Some(Kind::ShieldAllow),
            3 => Some(Kind::ShieldBlock),
            4 => Some(Kind::ShieldProfile),
            5 => Some(Kind::Artifact),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Kind::DevicePolicy => "device_policy",
            Kind::ShieldAllow => "shield_allow",
            Kind::ShieldBlock => "shield_block",
            Kind::ShieldProfile => "shield_profile",
            Kind::Artifact => "artifact",
        }
    }
}

pub const OP_SET: u8 = 1;
pub const OP_REMOVE: u8 = 2;
pub const FLAG_CONFIRMED: u8 = 1; // the owner confirmed a permanent rule (re-auth + permanent: true)

#[derive(Clone, Copy)]
pub struct Record {
    pub seq: u64,
    pub ms: u64,
    pub session: u32,
    pub kind: u8,
    pub op: u8,
    pub flags: u8,
    pub tlen: u8,
    pub target: [u8; TARGET_MAX],
    pub value: u8,
    pub prev: u8,
    pub rlen: u8,
    pub reason: [u8; REASON_MAX],
}

pub const R0: Record = Record { seq: 0, ms: 0, session: 0, kind: 0, op: 0, flags: 0, tlen: 0, target: [0; TARGET_MAX], value: 0, prev: 0, rlen: 0, reason: [0; REASON_MAX] };

impl Record {
    fn encode_e(&self, out: &mut [u8; REC_LEN], epoch: u32) {
        self.encode(out);
        out[EPOCH_AT..EPOCH_AT + 4].copy_from_slice(&epoch.to_le_bytes());
    }
    fn encode(&self, out: &mut [u8; REC_LEN]) {
        out.fill(0);
        out[0..4].copy_from_slice(&MAGIC);
        out[4..12].copy_from_slice(&self.seq.to_le_bytes());
        out[12..20].copy_from_slice(&self.ms.to_le_bytes());
        out[20..24].copy_from_slice(&self.session.to_le_bytes());
        out[24] = self.kind;
        out[25] = self.op;
        out[26] = self.flags;
        out[27] = self.tlen;
        out[28..92].copy_from_slice(&self.target);
        out[92] = self.value;
        out[93] = self.prev;
        out[94] = self.rlen;
        out[95..191].copy_from_slice(&self.reason);
    }
    fn decode(b: &[u8]) -> Record {
        let mut r = R0;
        r.seq = u64::from_le_bytes(b[4..12].try_into().unwrap());
        r.ms = u64::from_le_bytes(b[12..20].try_into().unwrap());
        r.session = u32::from_le_bytes(b[20..24].try_into().unwrap());
        r.kind = b[24];
        r.op = b[25];
        r.flags = b[26];
        r.tlen = b[27].min(TARGET_MAX as u8);
        r.target.copy_from_slice(&b[28..92]);
        r.value = b[92];
        r.prev = b[93];
        r.rlen = b[94].min(REASON_MAX as u8);
        r.reason.copy_from_slice(&b[95..191]);
        r
    }
    pub fn target(&self) -> &[u8] {
        &self.target[..self.tlen as usize]
    }
}

/// One active owner rule (the reconciled state).
#[derive(Clone, Copy)]
pub struct Rule {
    pub kind: u8,
    pub tlen: u8,
    pub target: [u8; TARGET_MAX],
    pub value: u8,
    pub seq: u64,
}
const RULE0: Rule = Rule { kind: 0, tlen: 0, target: [0; TARGET_MAX], value: 0, seq: 0 };

static mut RULES: [Rule; MAX_RULES] = [RULE0; MAX_RULES];
static mut NRULES: usize = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Replay {
    pub records: u32,
    /// a record carried the magic but its MAC failed (tampering, or a torn write mid-record)
    pub damaged: bool,
    pub full: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JErr {
    Full,
    Io,
    Invalid,
    TooManyRules,
}

/// The journal over one region `[lo, hi)` of a block device (two halves, see the module note).
pub struct Journal {
    lo: u64,
    hi: u64,
    key: [u8; 32],
    last_mac: [u8; 32],
    next_seq: u64,
    next_idx: u64, // record index inside the active half (0 = the epoch header)
    epoch: u32,    // 0 = nothing written yet
    half: u8,
}

/// The latest artifact audit records (replayed with the rules; ADR 0056 D6).
pub const ART_N: usize = 16;
static mut ART: [Record; ART_N] = [R0; ART_N];
static mut ART_LEN: usize = 0;
pub fn for_each_artifact(f: &mut dyn FnMut(&Record)) {
    let (a, n) = unsafe { (&*core::ptr::addr_of!(ART), ART_LEN) };
    for r in a[..n].iter().rev() {
        f(r);
    }
}

fn apply(r: &Record) -> Result<(), JErr> {
    if r.kind == Kind::Artifact as u8 {
        let a = unsafe { &mut *core::ptr::addr_of_mut!(ART) };
        unsafe {
            if ART_LEN == ART_N {
                a.copy_within(1.., 0);
                ART_LEN -= 1;
            }
            a[ART_LEN] = *r;
            ART_LEN += 1;
        }
        return Ok(());
    }
    let t = unsafe { &mut *core::ptr::addr_of_mut!(RULES) };
    let n = unsafe { NRULES };
    let pos = t[..n].iter().position(|x| x.kind == r.kind && x.target[..x.tlen as usize] == *r.target());
    match (r.op, pos) {
        (OP_SET, Some(i)) => {
            t[i].value = r.value;
            t[i].seq = r.seq;
        }
        (OP_SET, None) => {
            if n >= MAX_RULES {
                return Err(JErr::TooManyRules);
            }
            t[n] = Rule { kind: r.kind, tlen: r.tlen, target: r.target, value: r.value, seq: r.seq };
            unsafe { NRULES = n + 1 };
        }
        (OP_REMOVE, Some(i)) => {
            t[i] = t[n - 1];
            unsafe { NRULES = n - 1 };
        }
        _ => {}
    }
    Ok(())
}

impl Journal {
    pub fn new(lo: u64, hi: u64, srk: &[u8; 32]) -> Journal {
        let prk = boot_abi::kdf::hkdf_extract(b"HQ-owner-journal", srk);
        let key = boot_abi::kdf::hkdf_expand32(&prk, b"HQ-owner-journal-v1");
        Journal { lo, hi, key, last_mac: [0; 32], next_seq: 1, next_idx: 0, epoch: 0, half: 0 }
    }

    fn half_sect(&self) -> u64 {
        (self.hi - self.lo) / 2
    }
    fn half_cap(&self) -> u64 {
        self.half_sect() * 2
    }
    fn half_lo(&self, h: u8) -> u64 {
        self.lo + h as u64 * self.half_sect()
    }
    /// Current epoch (0 = empty) — reported by the API.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    fn hdr(epoch: u32, base_seq: u64) -> Record {
        let mut r = R0;
        r.kind = KIND_HDR;
        r.tlen = 12;
        r.target[..4].copy_from_slice(&epoch.to_le_bytes());
        r.target[4..12].copy_from_slice(&base_seq.to_le_bytes());
        r
    }

    /// Encode + MAC one record under `epoch`, chained on `prev`.
    fn seal(&self, prev: &[u8; 32], r: &Record, epoch: u32) -> ([u8; REC_LEN], [u8; 32]) {
        let mut rec = [0u8; REC_LEN];
        r.encode_e(&mut rec, epoch);
        let mac = boot_abi::kdf::hmac_sha256_2(&self.key, prev, &rec[..BODY]);
        rec[BODY..BODY + 32].copy_from_slice(&mac);
        (rec, mac)
    }

    /// The valid epoch header of half `h`: (epoch, base seq, its MAC). Some(Err) = magic present but invalid.
    fn read_hdr<D: BlockDev + ?Sized>(&self, dev: &D, h: u8) -> Option<Result<(u32, u64, [u8; 32]), ()>> {
        let mut sec = [0u8; 512];
        dev.read_block(self.half_lo(h), &mut sec).ok()?;
        let b = &sec[..REC_LEN];
        if b[0..4] != MAGIC {
            return None;
        }
        let want = boot_abi::kdf::hmac_sha256_2(&self.key, &[0u8; 32], &b[..BODY]);
        if b[24] != KIND_HDR || b[BODY..BODY + 32] != want {
            return Some(Err(()));
        }
        let r = Record::decode(b);
        let epoch = u32::from_le_bytes(r.target[..4].try_into().unwrap());
        let e_in = u32::from_le_bytes(b[EPOCH_AT..EPOCH_AT + 4].try_into().unwrap());
        if epoch == 0 || e_in != epoch {
            return Some(Err(()));
        }
        Some(Ok((epoch, u64::from_le_bytes(r.target[4..12].try_into().unwrap()), want)))
    }

    /// Rebuild the rule table from the newest epoch: every record whose chained MAC verifies, in order.
    pub fn replay<D: BlockDev + ?Sized>(&mut self, dev: &D) -> Replay {
        unsafe {
            NRULES = 0;
            ART_LEN = 0;
        }
        self.last_mac = [0; 32];
        self.next_seq = 1;
        self.next_idx = 0;
        self.epoch = 0;
        self.half = 0;
        let mut out = Replay::default();
        let (h0, h1) = (self.read_hdr(dev, 0), self.read_hdr(dev, 1));
        let best = match (h0, h1) {
            (Some(Ok(a)), Some(Ok(b))) => Some(if b.0 > a.0 { (1u8, b) } else { (0u8, a) }),
            (Some(Ok(a)), _) => Some((0, a)),
            (_, Some(Ok(b))) => Some((1, b)),
            (x, y) => {
                out.damaged = matches!(x, Some(Err(_))) || matches!(y, Some(Err(_))); // present but not ours / forged
                None
            }
        };
        let Some((h, (epoch, base, mac))) = best else { return out };
        self.half = h;
        self.epoch = epoch;
        self.last_mac = mac;
        self.next_seq = base;
        self.next_idx = 1;
        let mut sec = [0u8; 512];
        'outer: while self.next_idx < self.half_cap() {
            let lba = self.half_lo(h) + self.next_idx / 2;
            if dev.read_block(lba, &mut sec).is_err() {
                break;
            }
            let slot = (self.next_idx % 2) as usize;
            for half in slot..2 {
                let b = &sec[half * REC_LEN..(half + 1) * REC_LEN];
                if b[0..4] != MAGIC || u32::from_le_bytes(b[EPOCH_AT..EPOCH_AT + 4].try_into().unwrap()) != epoch {
                    break 'outer; // the end of this epoch (an older epoch's leftovers are not damage)
                }
                let want = boot_abi::kdf::hmac_sha256_2(&self.key, &self.last_mac, &b[..BODY]);
                let seq = u64::from_le_bytes(b[4..12].try_into().unwrap());
                if b[BODY..BODY + 32] != want || seq != self.next_seq {
                    out.damaged = true;
                    break 'outer;
                }
                let r = Record::decode(b);
                if apply(&r).is_err() {
                    out.damaged = true;
                    break 'outer;
                }
                self.last_mac = want;
                self.next_seq += 1;
                self.next_idx += 1;
                out.records += 1;
            }
        }
        out
    }

    /// Write `recs` (already sealed, index 0 = the header) into half `h`: every sector but the first, then the
    /// first (the header) — the switch to the new epoch is that single sector write.
    fn write_half<D: BlockDev + ?Sized>(&self, dev: &mut D, h: u8, recs: &[[u8; REC_LEN]]) -> Result<(), JErr> {
        let nsec = recs.len().div_ceil(2);
        for k in (0..nsec).rev() {
            let mut sec = [0u8; 512];
            for slot in 0..2 {
                if let Some(r) = recs.get(k * 2 + slot) {
                    sec[slot * REC_LEN..(slot + 1) * REC_LEN].copy_from_slice(r);
                }
            }
            dev.write_block(self.half_lo(h) + k as u64, &sec).map_err(|_| JErr::Io)?;
        }
        Ok(())
    }

    /// Start a new epoch in the other half holding the current live state (rules + artifact audits).
    fn compact<D: BlockDev + ?Sized>(&mut self, dev: &mut D) -> Result<(), JErr> {
        let (nr, na) = unsafe { (NRULES, ART_LEN) };
        if 1 + nr as u64 + na as u64 + 1 > self.half_cap() || nr + na > 600 {
            return Err(JErr::Full);
        }
        let e2 = self.epoch + 1;
        let other = 1 - self.half;
        static mut CKPT: [[u8; REC_LEN]; 1 + MAX_RULES + ART_N] = [[0u8; REC_LEN]; 1 + MAX_RULES + ART_N];
        let recs = unsafe { &mut *core::ptr::addr_of_mut!(CKPT) };
        let (h, mut prev) = self.seal(&[0u8; 32], &Self::hdr(e2, self.next_seq), e2);
        recs[0] = h;
        let mut seq = self.next_seq;
        let rules = unsafe { &(&*core::ptr::addr_of!(RULES))[..nr] };
        let arts = unsafe { &(&*core::ptr::addr_of!(ART))[..na] };
        let mut n = 1;
        for x in rules {
            let mut r = rec(Kind::from_u8(x.kind).unwrap_or(Kind::ShieldAllow), OP_SET, &x.target[..x.tlen as usize], x.value, b"checkpoint");
            r.seq = seq;
            let (b, m) = self.seal(&prev, &r, e2);
            recs[n] = b;
            prev = m;
            seq += 1;
            n += 1;
        }
        for a in arts {
            let mut r = *a;
            r.seq = seq;
            let (b, m) = self.seal(&prev, &r, e2);
            recs[n] = b;
            prev = m;
            seq += 1;
            n += 1;
        }
        self.write_half(dev, other, &recs[..n])?;
        // the new epoch is live: rebuild the RAM state from exactly what was written (rule seq numbers change)
        let base = self.next_seq;
        unsafe {
            NRULES = 0;
            ART_LEN = 0;
        }
        for b in &recs[1..n] {
            let _ = apply(&Record::decode(b));
        }
        self.half = other;
        self.epoch = e2;
        self.last_mac = prev;
        self.next_idx = n as u64;
        self.next_seq = base + (n as u64 - 1);
        Ok(())
    }

    /// Append one record (seq + MAC are assigned here) and apply it. The device must be armed for the region.
    pub fn append<D: BlockDev + ?Sized>(&mut self, dev: &mut D, mut r: Record) -> Result<u64, JErr> {
        if Kind::from_u8(r.kind).is_none() || !(r.op == OP_SET || r.op == OP_REMOVE) || r.tlen == 0 {
            return Err(JErr::Invalid);
        }
        if self.half_cap() < 4 {
            return Err(JErr::Full);
        }
        if self.epoch == 0 {
            // first write ever: epoch 1 in half 0
            let (h, m) = self.seal(&[0u8; 32], &Self::hdr(1, self.next_seq), 1);
            self.write_half(dev, 0, &[h])?;
            self.epoch = 1;
            self.half = 0;
            self.last_mac = m;
            self.next_idx = 1;
        }
        if self.next_idx >= self.half_cap() {
            self.compact(dev)?;
        }
        r.seq = self.next_seq;
        let (rec, mac) = self.seal(&self.last_mac, &r, self.epoch);
        let lba = self.half_lo(self.half) + self.next_idx / 2;
        let half = (self.next_idx % 2) as usize;
        let mut sec = [0u8; 512];
        if half == 1 {
            dev.read_block(lba, &mut sec).map_err(|_| JErr::Io)?;
        }
        sec[half * REC_LEN..(half + 1) * REC_LEN].copy_from_slice(&rec);
        dev.write_block(lba, &sec).map_err(|_| JErr::Io)?;
        apply(&r)?;
        self.last_mac = mac;
        self.next_seq += 1;
        self.next_idx += 1;
        Ok(r.seq)
    }
}

// ---- lookups used by the enforcement points (ADR 0055 D2) ----

fn lookup(kind: Kind, target: &[u8]) -> Option<u8> {
    let t = unsafe { &(&*core::ptr::addr_of!(RULES))[..NRULES] };
    t.iter().find(|x| x.kind == kind as u8 && x.target[..x.tlen as usize] == *target).map(|x| x.value)
}

/// The owner's device policy for `mac`, if any (raw `devpolicy::Pol` value).
pub fn device_policy(mac: &[u8; 6]) -> Option<u8> {
    lookup(Kind::DevicePolicy, mac)
}

/// The owner's Shield profile for `mac`, if any.
pub fn shield_profile(mac: &[u8; 6]) -> Option<u8> {
    lookup(Kind::ShieldProfile, mac)
}

/// Does an owner rule of `kind` cover `name` (exact, or a parent on a label boundary)?
fn domain_rule(kind: Kind, name: &[u8]) -> bool {
    let name = name.strip_suffix(b".").unwrap_or(name);
    let t = unsafe { &(&*core::ptr::addr_of!(RULES))[..NRULES] };
    t.iter().any(|x| {
        if x.kind != kind as u8 {
            return false;
        }
        let d = &x.target[..x.tlen as usize];
        name.len() >= d.len()
            && name[name.len() - d.len()..].eq_ignore_ascii_case(d)
            && (name.len() == d.len() || name[name.len() - d.len() - 1] == b'.')
    })
}

pub fn shield_allowed(name: &[u8]) -> bool {
    domain_rule(Kind::ShieldAllow, name)
}
pub fn shield_blocked(name: &[u8]) -> bool {
    domain_rule(Kind::ShieldBlock, name)
}

pub fn rule_count() -> usize {
    unsafe { NRULES }
}

pub fn for_each(f: &mut dyn FnMut(&Rule)) {
    let t = unsafe { &(&*core::ptr::addr_of!(RULES))[..NRULES] };
    for r in t {
        f(r);
    }
}

/// Test hook: forget every rule (the selftests share the global table).
pub fn clear() {
    unsafe {
        NRULES = 0;
        ART_LEN = 0;
    }
}

// ---- [P-ownerjournal] ----

struct MemDisk {
    s: [[u8; 512]; 8],
    writes: u32,
    /// refuse writes once `writes` reaches this (power-cut simulation)
    fail_at: u32,
}
impl MemDisk {
    fn new() -> MemDisk {
        MemDisk { s: [[0u8; 512]; 8], writes: 0, fail_at: u32::MAX }
    }
}
impl BlockDev for MemDisk {
    fn block_count(&self) -> u64 {
        8
    }
    fn read_block(&self, lba: u64, buf: &mut [u8; 512]) -> Result<(), BlockErr> {
        *buf = *self.s.get(lba as usize).ok_or(BlockErr::OutOfRange)?;
        Ok(())
    }
    fn write_block(&mut self, lba: u64, buf: &[u8; 512]) -> Result<(), BlockErr> {
        if self.writes >= self.fail_at {
            return Err(BlockErr::Io);
        }
        *self.s.get_mut(lba as usize).ok_or(BlockErr::OutOfRange)? = *buf;
        self.writes += 1;
        Ok(())
    }
}

pub fn rec(kind: Kind, op: u8, target: &[u8], value: u8, reason: &[u8]) -> Record {
    let mut r = R0;
    r.kind = kind as u8;
    r.op = op;
    r.flags = FLAG_CONFIRMED;
    r.tlen = target.len().min(TARGET_MAX) as u8;
    r.target[..r.tlen as usize].copy_from_slice(&target[..r.tlen as usize]);
    r.value = value;
    r.rlen = reason.len().min(REASON_MAX) as u8;
    r.reason[..r.rlen as usize].copy_from_slice(&reason[..r.rlen as usize]);
    r
}

pub fn selftest() -> bool {
    use crate::devpolicy::{self, Pol};
    let srk = [0x42u8; 32];
    // 8 sectors = two halves of 4 sectors = 8 records each (1 header + 7)
    let mut d = MemDisk::new();
    let mut j = Journal::new(0, 8, &srk);
    let kid = [0x02u8, 0, 0, 0, 0, 0x71];
    let tv = [0x02u8, 0, 0, 0, 0, 0x72];
    // 1. append + apply (the first write also lays down the epoch-1 header)
    let a1 = j.append(&mut d, rec(Kind::DevicePolicy, OP_SET, &kid, Pol::Quarantine as u8, b"kids tablet at night")).is_ok();
    let a2 = j.append(&mut d, rec(Kind::ShieldAllow, OP_SET, b"school.example", 1, b"wrongly blocked")).is_ok();
    let a3 = j.append(&mut d, rec(Kind::ShieldBlock, OP_SET, b"games.example", 1, b"homework")).is_ok();
    let appended = a1 && a2 && a3 && rule_count() == 3 && j.epoch() == 1;
    // 2. replay into a fresh table reproduces the state (deterministic reconcile)
    clear();
    let mut j2 = Journal::new(0, 8, &srk);
    let r = j2.replay(&d);
    let replayed = r.records == 3 && !r.damaged && rule_count() == 3 && device_policy(&kid) == Some(Pol::Quarantine as u8)
        && shield_allowed(b"www.school.example") && !shield_allowed(b"notschool.example") && shield_blocked(b"games.example");
    // 3. removal is a record too; replay agrees
    let rm = j2.append(&mut d, rec(Kind::ShieldBlock, OP_REMOVE, b"games.example", 0, b"done")).is_ok() && !shield_blocked(b"games.example");
    clear();
    let mut j3 = Journal::new(0, 8, &srk);
    let after_rm = j3.replay(&d).records == 4 && !shield_blocked(b"games.example") && rule_count() == 2;
    // 4. a different device key reads nothing; tampering stops replay at the bad record
    clear();
    let foreign = Journal::new(0, 8, &[0x43u8; 32]).replay(&d);
    let keyed = foreign.records == 0 && foreign.damaged;
    let mut t = MemDisk { s: d.s, writes: 0, fail_at: u32::MAX };
    t.s[1][100] ^= 1; // record 2 (sector 1, slot 0)
    clear();
    let tampered = Journal::new(0, 8, &srk).replay(&t);
    let tamper_ok = tampered.records == 1 && tampered.damaged;
    // a torn tail (record 4's MAC never written) recovers the verified prefix
    let mut torn = MemDisk { s: d.s, writes: 0, fail_at: u32::MAX };
    for b in torn.s[2][BODY..REC_LEN].iter_mut() {
        *b = 0;
    }
    clear();
    let tr = Journal::new(0, 8, &srk).replay(&torn);
    let torn_ok = tr.records == 3 && tr.damaged;
    // 5. precedence (ADR 0055 D2): an owner rule tightens any signed line, loosens only an unpinned one
    clear();
    let mut jp = Journal::new(0, 8, &srk);
    let mut dp = MemDisk::new();
    devpolicy::load_text(b"02:00:00:00:00:71 quarantine pin\n02:00:00:00:00:72 internet_only\n");
    let _ = jp.append(&mut dp, rec(Kind::DevicePolicy, OP_SET, &kid, Pol::Full as u8, b"try to loosen a pinned line"));
    let _ = jp.append(&mut dp, rec(Kind::DevicePolicy, OP_SET, &tv, Pol::Full as u8, b"loosen an unpinned line"));
    let pinned_holds = devpolicy::policy_of(&kid) == Pol::Quarantine;
    let unpinned_loosened = devpolicy::policy_of(&tv) == Pol::Full;
    let _ = jp.append(&mut dp, rec(Kind::DevicePolicy, OP_SET, &[0x02, 0, 0, 0, 0, 0x73], Pol::Quarantine as u8, b"tighten an unlisted device"));
    let tightened = devpolicy::policy_of(&[0x02, 0, 0, 0, 0, 0x73]) == Pol::Quarantine;
    devpolicy::load_text(b"");
    // 6. compaction (stage B): 40 changes through a 7-record half — the journal never fills while the live
    // state fits; every epoch switch keeps exactly the live rules; a fresh replay reproduces them
    clear();
    let mut jc = Journal::new(0, 8, &srk);
    let mut dc = MemDisk::new();
    let mut churn = jc.append(&mut dc, rec(Kind::ShieldBlock, OP_SET, b"keep.example", 1, b"long-lived")).is_ok()
        && jc.append(&mut dc, rec(Kind::DevicePolicy, OP_SET, &kid, Pol::LanOnly as u8, b"long-lived")).is_ok();
    for i in 0..38u8 {
        let op = if i % 2 == 0 { OP_SET } else { OP_REMOVE };
        churn &= jc.append(&mut dc, rec(Kind::ShieldAllow, op, b"churn.example", 1, b"toggle")).is_ok();
    }
    let epochs = jc.epoch();
    let live = rule_count() == 2 && shield_blocked(b"keep.example") && !shield_allowed(b"churn.example") && device_policy(&kid) == Some(Pol::LanOnly as u8);
    clear();
    let mut jr = Journal::new(0, 8, &srk);
    let rr = jr.replay(&dc);
    let compacted = churn && epochs >= 5 && live && !rr.damaged && jr.epoch() == epochs && rule_count() == 2 && shield_blocked(b"keep.example")
        && device_policy(&kid) == Some(Pol::LanOnly as u8) && !shield_allowed(b"churn.example");
    // 7. power cut in the middle of a compaction: the header sector (written last) never lands -> the old
    // epoch is still what boots, with every rule it had
    let mut jx = Journal::new(0, 8, &srk);
    let _ = jx.replay(&dc);
    let mut n = 0;
    while jx.next_idx < jx.half_cap() && n < 20 {
        let _ = jx.append(&mut dc, rec(Kind::ShieldAllow, OP_SET, b"fill.example", 1, b"fill"));
        n += 1;
    }
    let e_before = jx.epoch();
    let rules_before = rule_count();
    dc.fail_at = dc.writes + 1; // the compaction writes its data sector, then the header write fails
    let cut = jx.append(&mut dc, rec(Kind::ShieldAllow, OP_SET, b"after-cut.example", 1, b"x")).is_err();
    dc.fail_at = u32::MAX;
    clear();
    let mut jy = Journal::new(0, 8, &srk);
    let ry = jy.replay(&dc);
    let power_cut = cut && jy.epoch() == e_before && rule_count() == rules_before && !shield_allowed(b"after-cut.example") && !ry.damaged;
    // 8. full: only when the live state itself no longer fits a half
    clear();
    let mut jf = Journal::new(0, 8, &srk);
    let mut df = MemDisk::new();
    let mut ok_n = 0;
    let mut full = false;
    for i in 0..12u8 {
        let mut t = *b"r0.example";
        t[1] = b'a' + i;
        match jf.append(&mut df, rec(Kind::ShieldAllow, OP_SET, &t, 1, b"x")) {
            Ok(_) => ok_n += 1,
            Err(JErr::Full) => {
                full = true;
                break;
            }
            Err(_) => break,
        }
    }
    let full_ok = full && ok_n >= 6 && rule_count() == ok_n;
    clear();
    let pass = appended && replayed && rm && after_rm && keyed && tamper_ok && torn_ok && pinned_holds && unpinned_loosened && tightened && compacted && power_cut && full_ok;
    arch_aarch64::_print(format_args!(
        " [P-ownerjournal] {} — ADR 0055 owner policy journal (stage A + B compaction): append + apply={} replay reproduces the rules (deterministic reconcile)={} removal is a record={} another device key reads nothing={} tampering stops replay at the bad record={} torn tail -> verified prefix={} | precedence: a pinned signed line holds={} an unpinned one is loosened={} an owner rule tightens={} | compaction: 40 changes through a 7-record half, {} epochs, live rules kept, replay identical={} power cut mid-compaction -> the old epoch boots intact={} full only when the live state no longer fits ({} rules)={}\n",
        if pass { "PASS" } else { "FAIL" }, appended, replayed, rm && after_rm, keyed, tamper_ok, torn_ok, pinned_holds, unpinned_loosened, tightened, epochs, compacted, power_cut, ok_n, full_ok
    ));
    pass
}
