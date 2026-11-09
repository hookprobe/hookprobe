//! ADR 0055 — the owner policy journal (stage A: records, chain, append, replay, rule table, precedence).
//!
//! Durable owner settings from Mission Control, kept SEPARATE from the operator-signed baseline (operator
//! 2026-11-09). An append-only journal of fixed 256-byte records in the DataVolume `Journal` region (#54),
//! each `mac = HMAC-SHA256(K, prev_mac ‖ record)` with `K = HKDF(SRK, "HQ-owner-journal-v1")`. Replay rebuilds
//! the in-RAM rule table and stops at the first record whose MAC fails — a torn tail after power loss or
//! tampering — and reports which. Stage A has no compaction: the 256 KiB region holds ~1000 records and a
//! full journal refuses new writes (honest error) — checkpoints + compaction are stage B.
//!
//! Precedence (ADR 0055 D2) is applied by the consumers: `devpolicy::policy_of` (an owner rule may TIGHTEN
//! any signed line, LOOSEN only an unpinned one) and `shield::decide_for_dev` (an owner allow never overrides
//! the management floor, an IOC-listed domain or the encrypted-DNS / relay controls).
use hal::{BlockDev, BlockErr};

pub const REC_LEN: usize = 256;
const MAGIC: [u8; 4] = *b"HQOJ";
const BODY: usize = 224; // MAC covers prev_mac ‖ bytes[0..224]
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
}

impl Kind {
    pub fn from_u8(v: u8) -> Option<Kind> {
        match v {
            1 => Some(Kind::DevicePolicy),
            2 => Some(Kind::ShieldAllow),
            3 => Some(Kind::ShieldBlock),
            4 => Some(Kind::ShieldProfile),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Kind::DevicePolicy => "device_policy",
            Kind::ShieldAllow => "shield_allow",
            Kind::ShieldBlock => "shield_block",
            Kind::ShieldProfile => "shield_profile",
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

/// The journal over one region `[lo, hi)` of a block device.
pub struct Journal {
    lo: u64,
    hi: u64,
    key: [u8; 32],
    last_mac: [u8; 32],
    next_seq: u64,
    next_idx: u64, // record index from `lo`
}

fn apply(r: &Record) -> Result<(), JErr> {
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
        Journal { lo, hi, key, last_mac: [0; 32], next_seq: 1, next_idx: 0 }
    }

    fn capacity(&self) -> u64 {
        (self.hi - self.lo) * 2
    }

    /// Rebuild the rule table from the region: every record whose chained MAC verifies, in order.
    pub fn replay<D: BlockDev + ?Sized>(&mut self, dev: &D) -> Replay {
        unsafe { NRULES = 0 };
        self.last_mac = [0; 32];
        self.next_seq = 1;
        self.next_idx = 0;
        let mut out = Replay::default();
        let mut sec = [0u8; 512];
        'outer: for lba in self.lo..self.hi {
            if dev.read_block(lba, &mut sec).is_err() {
                break;
            }
            for half in 0..2 {
                let b = &sec[half * REC_LEN..(half + 1) * REC_LEN];
                if b[0..4] != MAGIC {
                    break 'outer; // the end of the journal
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
        out.full = self.next_idx >= self.capacity();
        out
    }

    /// Append one record (seq + MAC are assigned here) and apply it. The device must be armed for the region.
    pub fn append<D: BlockDev + ?Sized>(&mut self, dev: &mut D, mut r: Record) -> Result<u64, JErr> {
        if Kind::from_u8(r.kind).is_none() || !(r.op == OP_SET || r.op == OP_REMOVE) || r.tlen == 0 {
            return Err(JErr::Invalid);
        }
        if self.next_idx >= self.capacity() {
            return Err(JErr::Full);
        }
        r.seq = self.next_seq;
        let mut rec = [0u8; REC_LEN];
        r.encode(&mut rec);
        let mac = boot_abi::kdf::hmac_sha256_2(&self.key, &self.last_mac, &rec[..BODY]);
        rec[BODY..BODY + 32].copy_from_slice(&mac);
        let lba = self.lo + self.next_idx / 2;
        let half = (self.next_idx % 2) as usize;
        let mut sec = [0u8; 512];
        if half == 1 {
            dev.read_block(lba, &mut sec).map_err(|_| JErr::Io)?;
        }
        sec[half * REC_LEN..(half + 1) * REC_LEN].copy_from_slice(&rec);
        dev.write_block(lba, &sec).map_err(|e| if e == BlockErr::WriteRefused { JErr::Io } else { JErr::Io })?;
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
    unsafe { NRULES = 0 };
}

// ---- [P-ownerjournal] ----

struct MemDisk {
    s: [[u8; 512]; 8],
    writes: u32,
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
    let mut d = MemDisk { s: [[0u8; 512]; 8], writes: 0 };
    let mut j = Journal::new(0, 8, &srk);
    let kid = [0x02u8, 0, 0, 0, 0, 0x71];
    let tv = [0x02u8, 0, 0, 0, 0, 0x72];
    // 1. append + apply
    let a1 = j.append(&mut d, rec(Kind::DevicePolicy, OP_SET, &kid, Pol::Quarantine as u8, b"kids tablet at night")).is_ok();
    let a2 = j.append(&mut d, rec(Kind::ShieldAllow, OP_SET, b"school.example", 1, b"wrongly blocked")).is_ok();
    let a3 = j.append(&mut d, rec(Kind::ShieldBlock, OP_SET, b"games.example", 1, b"homework")).is_ok();
    let appended = a1 && a2 && a3 && rule_count() == 3 && d.writes == 3;
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
    // 4. a different device key cannot read (or forge) this journal; tampering stops replay at the bad record
    clear();
    let foreign = Journal::new(0, 8, &[0x43u8; 32]).replay(&d);
    let keyed = foreign.records == 0 && foreign.damaged;
    let mut t = MemDisk { s: d.s, writes: 0 };
    t.s[0][300] ^= 1; // the 2nd record's target byte
    clear();
    let tampered = Journal::new(0, 8, &srk).replay(&t);
    let tamper_ok = tampered.records == 1 && tampered.damaged;
    // a torn tail (the last record's second half never written) recovers the verified prefix
    let mut torn = MemDisk { s: d.s, writes: 0 };
    for b in torn.s[1][384..512].iter_mut() { // record 4 = sector 1 bytes 256..512: its second half (incl. MAC) lost
        *b = 0;
    }
    clear();
    let tr = Journal::new(0, 8, &srk).replay(&torn);
    let torn_ok = tr.records == 3 && tr.damaged;
    // 5. precedence (ADR 0055 D2): an owner rule tightens any signed line, loosens only an unpinned one
    clear();
    let mut jp = Journal::new(0, 8, &srk);
    let mut dp = MemDisk { s: [[0u8; 512]; 8], writes: 0 };
    devpolicy::load_text(b"02:00:00:00:00:71 quarantine pin\n02:00:00:00:00:72 internet_only\n");
    let _ = jp.append(&mut dp, rec(Kind::DevicePolicy, OP_SET, &kid, Pol::Full as u8, b"try to loosen a pinned line"));
    let _ = jp.append(&mut dp, rec(Kind::DevicePolicy, OP_SET, &tv, Pol::Full as u8, b"loosen an unpinned line"));
    let pinned_holds = devpolicy::policy_of(&kid) == Pol::Quarantine;
    let unpinned_loosened = devpolicy::policy_of(&tv) == Pol::Full;
    let _ = jp.append(&mut dp, rec(Kind::DevicePolicy, OP_SET, &[0x02, 0, 0, 0, 0, 0x73], Pol::Quarantine as u8, b"tighten an unlisted device"));
    let tightened = devpolicy::policy_of(&[0x02, 0, 0, 0, 0, 0x73]) == Pol::Quarantine;
    devpolicy::load_text(b"");
    // 6. capacity: a full journal refuses (no silent overwrite)
    clear();
    let mut jf = Journal::new(0, 1, &srk);
    let mut df = MemDisk { s: [[0u8; 512]; 8], writes: 0 };
    let f1 = jf.append(&mut df, rec(Kind::ShieldAllow, OP_SET, b"a.example", 1, b"x")).is_ok();
    let f2 = jf.append(&mut df, rec(Kind::ShieldAllow, OP_SET, b"b.example", 1, b"x")).is_ok();
    let f3 = jf.append(&mut df, rec(Kind::ShieldAllow, OP_SET, b"c.example", 1, b"x")) == Err(JErr::Full);
    clear();
    let pass = appended && replayed && rm && after_rm && keyed && tamper_ok && torn_ok && pinned_holds && unpinned_loosened && tightened && f1 && f2 && f3;
    arch_aarch64::_print(format_args!(
        " [P-ownerjournal] {} — ADR 0055 owner policy journal (stage A): append + apply={} replay reproduces the rules (deterministic reconcile)={} removal is a record={} another device key reads nothing={} tampering stops replay at the bad record={} torn tail -> verified prefix={} | precedence: a pinned signed line holds={} an unpinned one is loosened={} an owner rule tightens={} | a full journal refuses={}\n",
        if pass { "PASS" } else { "FAIL" }, appended, replayed, rm && after_rm, keyed, tamper_ok, torn_ok, pinned_holds, unpinned_loosened, tightened, f1 && f2 && f3
    ));
    pass
}
