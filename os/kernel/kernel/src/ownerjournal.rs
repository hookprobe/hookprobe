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
    /// G28: the owner rotated the Mission Control owner key (target = salt 16 ‖ verifier 32 ‖ sha256(OWNER.TXT)[..16]
    /// at rotation time). Never a rule; `revoke_all` does not touch it; the latest one wins.
    OwnerKey = 6,
    /// Owner alert webhook (operator 2026-11-10): target = alerthook::Hook::encode (ip|port|fmt|min_sev|key),
    /// reason = the request path / topic. OP_SET installs, OP_REMOVE turns it off. Never a rule.
    AlertHook = 7,
    /// Factory reset (owner, re-authenticated, confirm=ERASE): never a rule. Replaying one sets
    /// `factory_reset_requested`; the next boot wipes the owner data (evidence ring, artifact manifest, sealed
    /// snapshot) and LAST this journal — so a power cut mid-wipe leaves the request in place and the wipe re-runs.
    FactoryReset = 8,
    /// G47 (ADR 0058): the owner's name for a device: target = MAC (6) ‖ label (1..=31 bytes, `label_ok`). The latest
    /// set for a MAC wins; remove (target = MAC) returns to the signed DEVICES.TXT label. Cosmetic: never a rule.
    DeviceLabel = 9,
}

impl Kind {
    pub fn from_u8(v: u8) -> Option<Kind> {
        match v {
            1 => Some(Kind::DevicePolicy),
            2 => Some(Kind::ShieldAllow),
            3 => Some(Kind::ShieldBlock),
            4 => Some(Kind::ShieldProfile),
            5 => Some(Kind::Artifact),
            6 => Some(Kind::OwnerKey),
            7 => Some(Kind::AlertHook),
            8 => Some(Kind::FactoryReset),
            9 => Some(Kind::DeviceLabel),
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
            Kind::OwnerKey => "owner_key",
            Kind::AlertHook => "alert_hook",
            Kind::FactoryReset => "factory_reset",
            Kind::DeviceLabel => "device_label",
        }
    }
}

pub const OP_SET: u8 = 1;
pub const OP_REMOVE: u8 = 2;
/// ADR 0055 D7/D8: revoke ALL owner rules (target "*"); the audit trail (artifact records) is kept.
pub const OP_CLEAR: u8 = 3;
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
    /// RPMB (decision record D-RPMB): the journal is OLDER than its anchored high-water mark — an older consistent
    /// copy was restored. Owner rules from it are NOT applied; appends are refused until a factory reset.
    pub rollback: bool,
    /// the anchor this boot: 0 none / inactive, 1 verified, 2 verified + caught up (journal ahead after a power
    /// cut), 3 first anchoring, 4 RPMB faulted (alert; the journal is used as before)
    pub anchor: u8,
}

// ---- RPMB anchor (decision record 2026-11-10 D-RPMB) -------------------------------------------------------------
/// The journal's rollback high-water mark lives outside the user area (RPMB, `crate::rpmb`). `load` = the anchored
/// record (Ok(None) = never anchored; Err = no anchor this boot); `store` = an authenticated write.
pub trait Anchor {
    fn load(&mut self) -> Result<Option<crate::rpmb::Hw>, ()>;
    fn store(&mut self, hw: &crate::rpmb::Hw) -> bool;
    fn active(&self) -> bool;
    /// RPMB answered but did not verify / failed (an alert), as opposed to simply absent (no key on this unit)
    fn faulted(&self) -> bool;
}
static mut ANCHOR: Option<*mut (dyn Anchor + 'static)> = None;
/// Install (or clear) the anchor. The caller keeps `a` alive while it is installed (single core, one owner).
pub unsafe fn set_anchor(a: Option<&mut dyn Anchor>) {
    ANCHOR = a.map(|r| core::mem::transmute::<*mut (dyn Anchor + '_), *mut (dyn Anchor + 'static)>(r as *mut dyn Anchor));
}
fn anchor() -> Option<&'static mut dyn Anchor> {
    unsafe { ANCHOR.map(|p| &mut *p).filter(|a| a.active()) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JErr {
    Full,
    Io,
    Invalid,
    TooManyRules,
    /// a rollback was detected at replay: nothing is appended on top of the old copy (that would launder it into
    /// the anchor); a factory reset (owner token) starts a fresh epoch above the anchor
    RolledBack,
}

/// A valid epoch header: (epoch, base seq, its MAC).
type Hdr = (u32, u64, [u8; 32]);

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
    /// the first epoch a fresh (empty) journal opens: 1, or above the anchor after a factory reset
    epoch_base: u32,
    rolled_back: bool,
    probe_hit: bool,
    /// the anchored record seen at the last replay (the factory reset continues above it)
    anchored: Option<crate::rpmb::Hw>,
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

/// G28: the latest owner-key rotation replayed from the journal (target bytes), if any.
static mut OWNER_ROT: Option<[u8; TARGET_MAX]> = None;

/// The owner-key rotation in force (salt ‖ verifier ‖ OWNER.TXT hash prefix), if the owner ever rotated.
pub fn owner_rotation() -> Option<[u8; TARGET_MAX]> {
    unsafe { *core::ptr::addr_of!(OWNER_ROT) }
}

/// The alert-hook record in force (kept so compaction can carry it).
static mut HOOK_REC: Option<Record> = None;

/// G47: owner device labels (MAC → label), replayed from the journal and carried through compaction.
pub const LABEL_MAX: usize = 31;
pub const LABELS_N: usize = 64;
#[derive(Clone, Copy)]
pub struct Label {
    pub mac: [u8; 6],
    pub label: [u8; LABEL_MAX],
    pub len: u8,
    pub seq: u64,
}
const LB0: Label = Label { mac: [0; 6], label: [0; LABEL_MAX], len: 0, seq: 0 };
static mut LABELS: [Label; LABELS_N] = [LB0; LABELS_N];
static mut NLABELS: usize = 0;

/// The owner label grammar (G47): 1..=31 printable ASCII — letters, digits, space and . _ - ' ( ) , — no leading /
/// trailing space. A superset of DEVICES.TXT's [A-Za-z0-9._-] and always JSON / log safe.
pub fn label_ok(l: &[u8]) -> bool {
    !l.is_empty() && l.len() <= LABEL_MAX && l[0] != b' ' && l[l.len() - 1] != b' '
        && l.iter().all(|&c| c.is_ascii_alphanumeric() || matches!(c, b' ' | b'.' | b'_' | b'-' | b'\'' | b'(' | b')' | b','))
}

/// The owner's label for `mac`, if any.
pub fn owner_label(mac: &[u8; 6], out: &mut [u8; LABEL_MAX]) -> usize {
    let t = unsafe { &(&*core::ptr::addr_of!(LABELS))[..NLABELS] };
    match t.iter().find(|l| l.mac == *mac) {
        Some(l) => {
            *out = l.label;
            l.len as usize
        }
        None => 0,
    }
}

pub fn for_each_label(f: &mut dyn FnMut(&Label)) {
    let t = unsafe { &(&*core::ptr::addr_of!(LABELS))[..NLABELS] };
    for l in t {
        f(l);
    }
}

/// A replayed `FactoryReset` record: the boot path wipes the owner data before serving anything.
static mut RESET_REQ: bool = false;
pub fn factory_reset_requested() -> bool {
    unsafe { RESET_REQ }
}

fn apply(r: &Record) -> Result<(), JErr> {
    if r.kind == Kind::DeviceLabel as u8 {
        let tl = r.tlen as usize;
        if tl < 6 {
            return Ok(());
        }
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&r.target[..6]);
        let t = unsafe { &mut *core::ptr::addr_of_mut!(LABELS) };
        let n = unsafe { NLABELS };
        let pos = t[..n].iter().position(|l| l.mac == mac);
        match (r.op, pos) {
            (OP_SET, _) if !label_ok(&r.target[6..tl]) => {}
            (OP_SET, Some(i)) => {
                t[i].label = [0; LABEL_MAX];
                t[i].label[..tl - 6].copy_from_slice(&r.target[6..tl]);
                t[i].len = (tl - 6) as u8;
                t[i].seq = r.seq;
            }
            (OP_SET, None) => {
                if n >= LABELS_N {
                    return Err(JErr::TooManyRules);
                }
                let mut l = Label { mac, seq: r.seq, ..LB0 };
                l.label[..tl - 6].copy_from_slice(&r.target[6..tl]);
                l.len = (tl - 6) as u8;
                t[n] = l;
                unsafe { NLABELS = n + 1 };
            }
            (OP_REMOVE, Some(i)) => {
                t[i] = t[n - 1];
                unsafe { NLABELS = n - 1 };
            }
            _ => {}
        }
        return Ok(());
    }
    if r.kind == Kind::FactoryReset as u8 {
        if r.op == OP_SET {
            unsafe { RESET_REQ = true };
        }
        return Ok(());
    }
    if r.kind == Kind::AlertHook as u8 {
        let rl = (r.rlen as usize).min(REASON_MAX);
        let h = if r.op == OP_SET { crate::alerthook::Hook::decode(&r.target[..r.tlen as usize], &r.reason[..rl]) } else { None };
        crate::alerthook::set(h);
        unsafe { *core::ptr::addr_of_mut!(HOOK_REC) = h.map(|_| *r) };
        return Ok(());
    }
    if r.kind == Kind::OwnerKey as u8 {
        if r.op == OP_SET && r.tlen as usize == TARGET_MAX {
            unsafe { *core::ptr::addr_of_mut!(OWNER_ROT) = Some(r.target) };
        }
        return Ok(());
    }
    if r.op == OP_CLEAR {
        unsafe { NRULES = 0 };
        return Ok(());
    }
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
        Journal { lo, hi, key, last_mac: [0; 32], next_seq: 1, next_idx: 0, epoch: 0, half: 0, epoch_base: 1, rolled_back: false, probe_hit: false, anchored: None }
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
    fn read_hdr<D: BlockDev + ?Sized>(&self, dev: &D, h: u8) -> Option<Result<Hdr, ()>> {
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
            *core::ptr::addr_of_mut!(OWNER_ROT) = None;
            *core::ptr::addr_of_mut!(HOOK_REC) = None;
            crate::alerthook::set(None);
            RESET_REQ = false;
            NLABELS = 0;
        }
        self.last_mac = [0; 32];
        self.next_seq = 1;
        self.next_idx = 0;
        self.epoch = 0;
        self.half = 0;
        self.rolled_back = false;
        self.anchored = None;
        let mut out = self.replay_chain(dev);
        self.check_anchor(&mut out);
        out
    }

    /// The anchor check after the chain walk (D-RPMB "replay checks the replayed head against the RPMB record").
    fn check_anchor(&mut self, out: &mut Replay) {
        let Some(a) = (unsafe { ANCHOR.map(|p| &mut *p) }) else {
            out.anchor = 0;
            return;
        };
        if !a.active() {
            out.anchor = if a.faulted() { 4 } else { 0 };
            return;
        }
        let hw = match a.load() {
            Ok(h) => h,
            Err(()) => {
                out.anchor = if a.faulted() { 4 } else { 0 };
                return;
            }
        };
        let cur = crate::rpmb::Hw { epoch: self.epoch, seq: self.next_seq - 1, mac: self.last_mac, allow_epoch: 0, wiped: false };
        let Some(h) = hw else {
            // never anchored: anchor what is here (first use on this unit)
            out.anchor = if self.epoch == 0 || a.store(&cur) { 3 } else { 4 };
            return;
        };
        self.anchored = Some(h);
        let ok = if self.epoch == 0 {
            // an empty journal is expected only after an anchored factory reset (or before the first change)
            if h.wiped {
                self.epoch_base = h.allow_epoch.max(1);
            }
            h.wiped || (h.epoch == 0 && h.seq == 0)
        } else if h.wiped {
            self.epoch == h.allow_epoch // the epoch the anchored factory reset opened (an older copy is a rollback)
        } else {
            // the chain passed through the anchored (seq, MAC) — journal equal or ahead; or a compaction whose
            // allowance was anchored but whose final anchor write did not happen (power cut)
            (self.epoch == h.epoch && self.probe_hit) || (h.allow_epoch != 0 && self.epoch == h.allow_epoch)
        };
        if !ok {
            // owner rules from the old copy are not applied — except an owner-requested factory reset, which is the
            // recovery (it erases everything; an attacker replaying an old reset request gains nothing over this)
            let reset = factory_reset_requested();
            clear();
            unsafe { RESET_REQ = reset };
            self.rolled_back = true;
            out.rollback = true;
            out.anchor = 1;
            return;
        }
        let caught_up = cur.epoch != h.epoch || cur.seq != h.seq;
        out.anchor = if caught_up && self.epoch != 0 { if a.store(&cur) { 2 } else { 4 } } else { 1 };
    }

    fn replay_chain<D: BlockDev + ?Sized>(&mut self, dev: &D) -> Replay {
        // the anchored (seq, MAC) to look for on the way (a rollback leaves the chain BEFORE it)
        let probe = anchor().and_then(|a| a.load().ok().flatten()).filter(|h| !h.wiped);
        self.probe_hit = false;
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
        let hit = |e: u32, s: u64, m: &[u8; 32]| probe.is_some_and(|p| p.epoch == e && p.seq == s && p.mac == *m);
        self.probe_hit |= hit(epoch, base - 1, &mac);
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
                self.probe_hit |= hit(epoch, self.next_seq - 1, &want);
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
        let rot = owner_rotation();
        let hook = unsafe { *core::ptr::addr_of!(HOOK_REC) };
        let nl = unsafe { NLABELS };
        if 1 + nr as u64 + na as u64 + rot.is_some() as u64 + hook.is_some() as u64 + nl as u64 + 1 > self.half_cap() || nr + na > 600 {
            return Err(JErr::Full);
        }
        let e2 = self.epoch + 1;
        let other = 1 - self.half;
        static mut CKPT: [[u8; REC_LEN]; 3 + MAX_RULES + ART_N + LABELS_N] = [[0u8; REC_LEN]; 3 + MAX_RULES + ART_N + LABELS_N];
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
        if let Some(t) = rot {
            // the owner-key rotation must survive compaction (else the next boot falls back to OWNER.TXT)
            let mut r = rec(Kind::OwnerKey, OP_SET, &t, 0, b"checkpoint");
            r.seq = seq;
            let (b, m) = self.seal(&prev, &r, e2);
            recs[n] = b;
            prev = m;
            seq += 1;
            n += 1;
        }
        if let Some(mut r) = hook {
            r.seq = seq;
            let (b, m) = self.seal(&prev, &r, e2);
            recs[n] = b;
            prev = m;
            seq += 1;
            n += 1;
        }
        // G47: owner device labels survive compaction
        let labels = unsafe { &(&*core::ptr::addr_of!(LABELS))[..nl] };
        for l in labels {
            let mut t = [0u8; 6 + LABEL_MAX];
            t[..6].copy_from_slice(&l.mac);
            t[6..6 + l.len as usize].copy_from_slice(&l.label[..l.len as usize]);
            let mut r = rec(Kind::DeviceLabel, OP_SET, &t[..6 + l.len as usize], 0, b"checkpoint");
            r.seq = seq;
            let (b, m) = self.seal(&prev, &r, e2);
            recs[n] = b;
            prev = m;
            #[allow(unused_assignments)]
            {
                seq += 1;
            }
            n += 1;
        }
        // D-RPMB two-phase: anchor the allowance for e2 BEFORE the new header can be written (a power cut between
        // the two leaves the old epoch, still anchored-compatible: replay accepts e2 only through this allowance)
        if let Some(a) = anchor() {
            let pre = crate::rpmb::Hw { epoch: self.epoch, seq: self.next_seq - 1, mac: self.last_mac, allow_epoch: e2, wiped: false };
            if !a.store(&pre) {
                return Err(JErr::Io);
            }
        }
        self.write_half(dev, other, &recs[..n])?;
        // the new epoch is live: rebuild the RAM state from exactly what was written (rule seq numbers change)
        let base = self.next_seq;
        unsafe {
            NRULES = 0;
            ART_LEN = 0;
            *core::ptr::addr_of_mut!(OWNER_ROT) = None;
            *core::ptr::addr_of_mut!(HOOK_REC) = None;
            crate::alerthook::set(None);
            RESET_REQ = false;
            NLABELS = 0;
        }
        for b in &recs[1..n] {
            let _ = apply(&Record::decode(b));
        }
        self.half = other;
        self.epoch = e2;
        self.last_mac = prev;
        self.next_idx = n as u64;
        self.next_seq = base + (n as u64 - 1);
        self.anchor_now();
        Ok(())
    }

    /// Factory reset: zero the whole journal region — every record sector of both halves first (the replay
    /// chain breaks at the first zeroed record, so an interrupted wipe already reads as an empty journal),
    /// then the two epoch headers. RAM state is cleared; the next append starts epoch 1 again.
    pub fn wipe<D: BlockDev + ?Sized>(&mut self, dev: &mut D) -> Result<u64, JErr> {
        // D-RPMB: "a factory reset writes a fresh empty-journal record, epoch E+1" — anchored FIRST, so an old copy
        // restored after the reset is a rollback, and the next epoch continues above everything ever anchored
        let top = self.epoch.max(self.epoch_base.saturating_sub(1)).max(self.anchored.map_or(0, |h| h.epoch.max(h.allow_epoch)));
        if let Some(a) = anchor() {
            let w = crate::rpmb::Hw { epoch: top, seq: 0, mac: [0; 32], allow_epoch: top + 1, wiped: true };
            if !a.store(&w) {
                return Err(JErr::Io); // RPMB fault: refuse rather than reset into a permanent false rollback
            }
            self.anchored = Some(w);
        }
        let z = [0u8; 512];
        let mut n = 0u64;
        for h in 0..2u8 {
            for k in 1..self.half_sect() {
                dev.write_block(self.half_lo(h) + k, &z).map_err(|_| JErr::Io)?;
                n += 1;
            }
        }
        for h in 0..2u8 {
            dev.write_block(self.half_lo(h), &z).map_err(|_| JErr::Io)?;
            n += 1;
        }
        clear();
        self.last_mac = [0; 32];
        self.next_seq = 1;
        self.next_idx = 0;
        self.epoch = 0;
        self.half = 0;
        self.rolled_back = false;
        self.epoch_base = if anchor().is_some() { top + 1 } else { 1 };
        Ok(n)
    }

    /// Append one record (seq + MAC are assigned here) and apply it. The device must be armed for the region.
    pub fn append<D: BlockDev + ?Sized>(&mut self, dev: &mut D, mut r: Record) -> Result<u64, JErr> {
        if Kind::from_u8(r.kind).is_none() || !(r.op == OP_SET || r.op == OP_REMOVE || r.op == OP_CLEAR) || r.tlen == 0 {
            return Err(JErr::Invalid);
        }
        // after a detected rollback only the owner's factory reset is accepted (the recovery path); it is not
        // anchored, so the old copy is never laundered into the high-water mark
        if self.rolled_back && r.kind != Kind::FactoryReset as u8 {
            return Err(JErr::RolledBack);
        }
        if self.half_cap() < 4 {
            return Err(JErr::Full);
        }
        if self.epoch == 0 {
            // first write ever: epoch 1 in half 0 (or the epoch an anchored factory reset opened)
            let e = self.epoch_base.max(1);
            let (h, m) = self.seal(&[0u8; 32], &Self::hdr(e, self.next_seq), e);
            self.write_half(dev, 0, &[h])?;
            self.epoch = e;
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
        // D-RPMB: journal first, then the anchor (a power cut between = journal one ahead = accepted + caught up)
        if !self.rolled_back {
            self.anchor_now();
        }
        Ok(r.seq)
    }

    /// Anchor the current head (best effort: a failed write leaves the journal ahead, which replay accepts).
    fn anchor_now(&mut self) {
        if let Some(a) = anchor() {
            let h = crate::rpmb::Hw { epoch: self.epoch, seq: self.next_seq - 1, mac: self.last_mac, allow_epoch: 0, wiped: false };
            if a.store(&h) {
                self.anchored = Some(h);
            }
        }
    }

    /// A rollback was detected at the last replay (the API reports it; appends are refused).
    pub fn rolled_back(&self) -> bool {
        self.rolled_back
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
        *core::ptr::addr_of_mut!(OWNER_ROT) = None;
        *core::ptr::addr_of_mut!(HOOK_REC) = None;
        crate::alerthook::set(None);
        RESET_REQ = false;
        NLABELS = 0;
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

/// `[P-journal-sweep]` (release plan A9): a deterministic corruption sweep over the REAL replay — the owner journal
/// is the device's on-disk rule state, read back at every boot from a medium an attacker with the card can edit. 3000
/// mutated copies of a 5-record journal (random bytes, zeroed / swapped / duplicated sectors, both halves): replay
/// never panics, never yields more records than were written, and whenever it reports the full chain undamaged the
/// rule state is exactly the original (the chained MAC admits no edit).
#[cfg_attr(feature = "cm5", allow(dead_code))]
pub fn sweep_selftest() -> bool {
    let srk = [0x5au8; 32];
    let mut d = MemDisk::new();
    clear();
    let mut j = Journal::new(0, 8, &srk);
    let mut built = true;
    for (i, t) in [&b"a.example"[..], b"b.example", b"c.example", b"d.example", b"e.example"].iter().enumerate() {
        let k = if i % 2 == 0 { Kind::ShieldBlock } else { Kind::ShieldAllow };
        built &= j.append(&mut d, rec(k, OP_SET, t, 1, b"sweep")).is_ok();
    }
    built &= rule_count() == 5;
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut rnd = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let (mut iters, mut bad, mut full, mut refused) = (0u32, 0u32, 0u32, 0u32);
    for _ in 0..3000 {
        let mut t = MemDisk { s: d.s, writes: 0, fail_at: u32::MAX };
        let edits = 1 + (rnd() % 4) as usize;
        for _ in 0..edits {
            let sec = (rnd() % 8) as usize;
            match rnd() % 5 {
                0 => t.s[sec] = [0; 512],
                1 => {
                    let other = (rnd() % 8) as usize;
                    t.s[sec] = t.s[other];
                }
                2 => {
                    let off = (rnd() % 512) as usize;
                    t.s[sec][off] = rnd() as u8;
                }
                3 => {
                    let off = (rnd() % 508) as usize;
                    t.s[sec][off..off + 4].copy_from_slice(&(rnd() as u32).to_le_bytes());
                }
                _ => {
                    let off = (rnd() % 512) as usize;
                    t.s[sec][off] ^= 1 << (rnd() % 8);
                }
            }
        }
        clear();
        let r = Journal::new(0, 8, &srk).replay(&t);
        iters += 1;
        if r.records > 5 || rule_count() > 5 {
            bad += 1;
        }
        if r.records == 5 && !r.damaged {
            full += 1;
            // the chain verified end to end: the state must be exactly the original one
            let same = rule_count() == 5 && shield_blocked(b"a.example") && shield_allowed(b"b.example") && shield_blocked(b"c.example")
                && shield_allowed(b"d.example") && shield_blocked(b"e.example");
            if !same {
                bad += 1;
            }
        } else {
            refused += 1;
        }
    }
    clear();
    let pass = built && iters == 3000 && bad == 0 && refused > 0;
    arch_aarch64::_print(format_args!(
        " [P-journal-sweep] {} — owner-journal replay under {} random corruptions (bytes, zeroed / swapped / duplicated sectors, both halves): no panic, never more records than written, a fully verified chain always equals the original state; violations={} (full chains {} / refused or truncated {})\n",
        if pass { "PASS" } else { "FAIL" }, iters, bad, full, refused
    ));
    pass
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
    // ADR 0055 D7/D8: revoke-all is one sealed record; a replay (reboot) keeps the device rule-free
    let revoke_all = {
        let mut d = MemDisk::new();
        let mut j = Journal::new(0, 8, &srk);
        let _ = j.append(&mut d, rec(Kind::ShieldBlock, OP_SET, b"games.example", 1, b"homework"));
        let _ = j.append(&mut d, rec(Kind::ShieldAllow, OP_SET, b"school.example", 1, b"school"));
        let cleared = j.append(&mut d, rec(Kind::DevicePolicy, OP_CLEAR, b"*", 0, b"start over")).is_ok() && rule_count() == 0;
        clear();
        let mut j2 = Journal::new(0, 8, &srk);
        let r = j2.replay(&d);
        let stays = r.records == 3 && !r.damaged && rule_count() == 0 && !shield_blocked(b"games.example");
        let after = j2.append(&mut d, rec(Kind::ShieldBlock, OP_SET, b"new.example", 1, b"again")).is_ok() && rule_count() == 1;
        clear();
        cleared && stays && after
    };
    // factory reset: the record replays as a request (and is never a rule); wipe zeroes the region, a replay of the
    // wiped journal is empty (no request, no rule, nothing damaged) and the next append starts a fresh epoch 1
    let factory = {
        let mut d = MemDisk::new();
        let mut j = Journal::new(0, 8, &srk);
        let _ = j.append(&mut d, rec(Kind::ShieldBlock, OP_SET, b"games.example", 1, b"homework"));
        let asked = j.append(&mut d, rec(Kind::FactoryReset, OP_SET, b"erase", 0, b"selling the box")).is_ok() && factory_reset_requested() && rule_count() == 1;
        clear();
        let mut j2 = Journal::new(0, 8, &srk);
        let r = j2.replay(&d);
        let replays = r.records == 2 && factory_reset_requested() && rule_count() == 1;
        let wiped = j2.wipe(&mut d).is_ok_and(|n| n == 8) && d.s.iter().all(|x| x.iter().all(|b| *b == 0)) && !factory_reset_requested() && rule_count() == 0;
        let mut j3 = Journal::new(0, 8, &srk);
        let r3 = j3.replay(&d);
        let empty = r3.records == 0 && !r3.damaged && !factory_reset_requested() && j3.epoch() == 0;
        let fresh = j3.append(&mut d, rec(Kind::ShieldAllow, OP_SET, b"school.example", 1, b"new owner")).is_ok() && j3.epoch() == 1 && rule_count() == 1;
        clear();
        asked && replays && wiped && empty && fresh
    };
    // G47 device labels: set, rename (latest wins), replay, remove; bad grammar never applies
    let labels = {
        let mut d = MemDisk::new();
        let mut j = Journal::new(0, 8, &srk);
        let m = [2u8, 0, 0, 0, 0, 0x47];
        let mut t = [0u8; 6 + LABEL_MAX];
        t[..6].copy_from_slice(&m);
        t[6..17].copy_from_slice(b"Mia's iPad ");
        let bad = rec(Kind::DeviceLabel, OP_SET, &t[..17], 0, b"bad: trailing space");
        let _ = j.append(&mut d, bad);
        let mut ob = [0u8; LABEL_MAX];
        let refused = owner_label(&m, &mut ob) == 0;
        t[6..16].copy_from_slice(b"Mia's iPad");
        let _ = j.append(&mut d, rec(Kind::DeviceLabel, OP_SET, &t[..16], 0, b"rename"));
        t[6..18].copy_from_slice(b"Kitchen (TV)");
        let _ = j.append(&mut d, rec(Kind::DeviceLabel, OP_SET, &t[..18], 0, b"rename again"));
        let latest = owner_label(&m, &mut ob) == 12 && &ob[..12] == b"Kitchen (TV)" && rule_count() == 0;
        clear();
        let mut j2 = Journal::new(0, 8, &srk);
        let _ = j2.replay(&d);
        let replayed = owner_label(&m, &mut ob) == 12 && &ob[..12] == b"Kitchen (TV)";
        let _ = j2.append(&mut d, rec(Kind::DeviceLabel, OP_REMOVE, &m, 0, b"back to signed"));
        let removed = owner_label(&m, &mut ob) == 0;
        clear();
        refused && latest && replayed && removed && label_ok(b"a") && !label_ok(b"x\"y") && !label_ok(&[b'a'; 32])
    };
    let pass = labels && factory && revoke_all && appended && replayed && rm && after_rm && keyed && tamper_ok && torn_ok && pinned_holds && unpinned_loosened && tightened && compacted && power_cut && full_ok;
    arch_aarch64::_print(format_args!(
        " [P-ownerjournal] {} — ADR 0055 owner policy journal (stage A + B compaction): append + apply={} replay reproduces the rules (deterministic reconcile)={} removal is a record={} another device key reads nothing={} tampering stops replay at the bad record={} torn tail -> verified prefix={} | precedence: a pinned signed line holds={} an unpinned one is loosened={} an owner rule tightens={} | compaction: 40 changes through a 7-record half, {} epochs, live rules kept, replay identical={} power cut mid-compaction -> the old epoch boots intact={} full only when the live state no longer fits ({} rules)={} | revoke-all record survives a replay (no owner rule after reboot, new rules accepted again)={} | factory reset: request replays, wipe zeroes the region, the wiped journal is empty and starts a fresh epoch={} | G47 device labels: grammar enforced, latest rename wins, replayed, removable, never a rule={}\n",
        if pass { "PASS" } else { "FAIL" }, appended, replayed, rm && after_rm, keyed, tamper_ok, torn_ok, pinned_holds, unpinned_loosened, tightened, epochs, compacted, power_cut, ok_n, full_ok, revoke_all, factory, labels
    ));
    pass
}

// ---- [P-rpmb] journal side (decision record D-RPMB) -------------------------------------------------------------

/// The anchor scenarios on the same 8-sector journal as [P-ownerjournal], each over a fresh RPMB model:
/// (rollback detected + owner rules not applied + appends refused, factory reset continues above the anchor and an
/// older copy after it is a rollback, a power cut between the journal write and the anchor write is accepted and
/// caught up, compactions stay anchored and a pre-compaction copy is a rollback, no key = inactive and unchanged).
pub fn anchor_selftest() -> (bool, bool, bool, bool, bool) {
    use crate::rpmb::{unit_key, RpmbAnchor, SimRpmb};
    let srk = [0x42u8; 32];
    let blk = |d: &[u8]| rec(Kind::ShieldBlock, OP_SET, d, 1, b"rpmb test");
    let unblk = |d: &[u8]| rec(Kind::ShieldBlock, OP_REMOVE, d, 0, b"rpmb test");
    let mut n = 0u8;
    let mut fresh = move || {
        n = n.wrapping_add(1);
        [n; 16]
    };
    // 1 + 2: rollback of an owner's revoke, then the factory reset
    let (rb_ok, reset_ok) = {
        let mut sim: SimRpmb<2> = SimRpmb::new();
        sim.sim_program(unit_key(&srk));
        let mut a = RpmbAnchor::new(&mut sim, unit_key(&srk), &mut fresh);
        unsafe { set_anchor(Some(&mut a)) };
        let mut d = MemDisk::new();
        let mut j = Journal::new(0, 8, &srk);
        let _ = j.replay(&d);
        let first = true;
        let w = j.append(&mut d, blk(b"games.example")).is_ok() && j.append(&mut d, blk(b"chat.example")).is_ok();
        let before_revoke = d.s;
        let revoke = j.append(&mut d, unblk(b"games.example")).is_ok();
        let mut j2 = Journal::new(0, 8, &srk);
        let r2 = j2.replay(&d);
        let normal = !r2.rollback && r2.anchor == 1 && !shield_blocked(b"games.example") && shield_blocked(b"chat.example");
        d.s = before_revoke; // an attacker restores the older, validly MAC'd copy
        let mut j3 = Journal::new(0, 8, &srk);
        let r3 = j3.replay(&d);
        let rb = r3.rollback && rule_count() == 0 && !shield_blocked(b"games.example") && j3.append(&mut d, blk(b"x.example")) == Err(JErr::RolledBack);
        // the recovery: the owner's factory-reset request is still accepted, and survives the next boot's rollback check
        let asked = j3.append(&mut d, rec(Kind::FactoryReset, OP_SET, b"erase", 0, b"recover")).is_ok();
        let mut j3b = Journal::new(0, 8, &srk);
        let r3b = j3b.replay(&d);
        let rb = rb && asked && r3b.rollback && factory_reset_requested() && rule_count() == 0;
        let mut j3 = j3b;
        // factory reset with the owner token: anchored first, then the wipe; the next epoch is above everything
        let wiped = j3.wipe(&mut d).is_ok();
        let fresh_ok = j3.append(&mut d, blk(b"new.example")).is_ok() && j3.epoch() > 1;
        let after_reset = d.s;
        let mut j4 = Journal::new(0, 8, &srk);
        let r4 = j4.replay(&d);
        let clean = !r4.rollback && shield_blocked(b"new.example");
        d.s = before_revoke; // the pre-reset copy again
        let r5 = Journal::new(0, 8, &srk).replay(&d);
        let old_after_reset = r5.rollback && rule_count() == 0;
        d.s = after_reset;
        let _ = Journal::new(0, 8, &srk).replay(&d);
        unsafe { set_anchor(None) };
        (first && w && revoke && normal && rb, wiped && fresh_ok && clean && old_after_reset)
    };
    // 3: power cut between the journal write and the anchor write -> journal one ahead -> accepted, caught up
    let ahead_ok = {
        let mut sim: SimRpmb<2> = SimRpmb::new();
        sim.sim_program(unit_key(&srk));
        let mut a = RpmbAnchor::new(&mut sim, unit_key(&srk), &mut fresh);
        unsafe { set_anchor(Some(&mut a)) };
        let mut d = MemDisk::new();
        let mut j = Journal::new(0, 8, &srk);
        let _ = j.replay(&d);
        let w = j.append(&mut d, blk(b"a.example")).is_ok();
        unsafe { set_anchor(None) };
        let w2 = j.append(&mut d, blk(b"b.example")).is_ok(); // the anchor write "lost"
        unsafe { set_anchor(Some(&mut a)) };
        let r = Journal::new(0, 8, &srk).replay(&d);
        let r2 = Journal::new(0, 8, &srk).replay(&d);
        unsafe { set_anchor(None) };
        w && w2 && !r.rollback && r.anchor == 2 && shield_blocked(b"b.example") && !r2.rollback && r2.anchor == 1
    };
    // 4: compactions (7 records per half) stay anchored; a copy from before a compaction is a rollback
    let compact_ok = {
        let mut sim: SimRpmb<2> = SimRpmb::new();
        sim.sim_program(unit_key(&srk));
        let mut a = RpmbAnchor::new(&mut sim, unit_key(&srk), &mut fresh);
        unsafe { set_anchor(Some(&mut a)) };
        let mut d = MemDisk::new();
        let mut j = Journal::new(0, 8, &srk);
        let _ = j.replay(&d);
        let mut ok = true;
        let mut snap = d.s;
        for i in 0..24u8 {
            let name = [b'h', b'0' + i % 10, b'.', b'e', b'x'];
            ok &= j.append(&mut d, if i % 2 == 0 { blk(&name) } else { unblk(&name) }).is_ok();
            if i == 5 {
                snap = d.s;
            }
        }
        let epochs = j.epoch();
        let r = Journal::new(0, 8, &srk).replay(&d);
        d.s = snap;
        let r_old = Journal::new(0, 8, &srk).replay(&d);
        unsafe { set_anchor(None) };
        ok && epochs > 2 && !r.rollback && r.anchor == 1 && r_old.rollback
    };
    // 5: an unprogrammed unit: RPMB inactive, the journal behaves exactly as before (never a false rollback)
    let inactive_ok = {
        let mut sim: SimRpmb<2> = SimRpmb::new();
        let mut a = RpmbAnchor::new(&mut sim, unit_key(&srk), &mut fresh);
        unsafe { set_anchor(Some(&mut a)) };
        let mut d = MemDisk::new();
        let mut j = Journal::new(0, 8, &srk);
        let r0 = j.replay(&d);
        let w = j.append(&mut d, blk(b"a.example")).is_ok();
        let snap = d.s;
        let w2 = j.append(&mut d, unblk(b"a.example")).is_ok();
        d.s = snap;
        let r = Journal::new(0, 8, &srk).replay(&d);
        unsafe { set_anchor(None) };
        r0.anchor == 0 && w && w2 && !r.rollback && r.anchor == 0 && shield_blocked(b"a.example") && a.writes == 0
    };
    clear();
    (rb_ok, reset_ok, ahead_ok, compact_ok, inactive_ok)
}
