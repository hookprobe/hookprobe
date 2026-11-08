//! Local per-device access policy (parity gap G9 — V1 Fortress `fortress-ctl device set-policy`).
//!
//! `DEVICES.TXT` on the boot partition, operator-signed (`DEVICES.SIG`, magic HQDSIG1 / tag HQDEV1, never
//! interchangeable with the other signed files). One device per line:
//!   `aa:bb:cc:dd:ee:ff  internet_only  kids-tablet`      (label optional, [A-Za-z0-9._-], ≤ 31)
//! Policies (by MAC — a client can change its IP, the AP keys stations by MAC):
//!   full           everything (the default for unlisted devices)
//!   internet_only  the internet, but not this device's management (Mission Control) nor other LAN hosts
//!   lan_only       the LAN and this device, never the internet
//!   quarantine     nothing but DHCP, ARP and DNS to the AP (so it can be told / reach a captive notice)
//! Operator intent, signed — not a suspicion-based drop (ADR 0023 governs detections, not declared policy).
//! V1 lessons: MACs are validated strictly (V1 fed unvalidated MACs into SQL/OVS); a refused file loads
//! nothing (every device stays `full`) and says so.

use crate::policysig::POLICY_PUBKEY;
use hal::BlockDev;

pub const CAP: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Pol {
    Full = 0,
    InternetOnly = 1,
    LanOnly = 2,
    Quarantine = 3,
}

impl Pol {
    pub fn name(self) -> &'static str {
        ["full", "internet_only", "lan_only", "quarantine"][self as usize]
    }
}

/// Where a client frame is going.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dest {
    /// Forwarded to the internet (WAN or management uplink).
    Internet,
    /// Another LAN host (bridged / routed inside).
    Lan,
    /// This device's own services (Mission Control 80/443, other ports).
    DeviceMgmt,
    /// DHCP / DNS / ARP to the AP — always allowed (even in quarantine).
    Infra,
}

/// The decision.
pub fn allows(p: Pol, d: Dest) -> bool {
    match (p, d) {
        (_, Dest::Infra) => true,
        (Pol::Full, _) => true,
        (Pol::InternetOnly, Dest::Internet) => true,
        (Pol::LanOnly, Dest::Lan | Dest::DeviceMgmt) => true,
        _ => false,
    }
}

#[derive(Clone, Copy)]
struct Ent {
    mac: [u8; 6],
    pol: Pol,
    label: [u8; 31],
    llen: u8,
}
const E0: Ent = Ent { mac: [0; 6], pol: Pol::Full, label: [0; 31], llen: 0 };
static mut T: [Ent; CAP] = [E0; CAP];
static mut N: usize = 0;
static mut DENIED: [u64; 4] = [0; 4];

#[derive(Clone, Copy, Debug, Default)]
pub struct Info {
    pub file: u8,
    pub signed: bool,
    pub generation: u64,
    pub skipped: u32,
    pub refused: Option<crate::shield::LoadErr>,
}
static mut INFO: Info = Info { file: 0, signed: false, generation: 0, skipped: 0, refused: None };

pub fn info() -> Info {
    unsafe { INFO }
}
pub fn len() -> usize {
    unsafe { N }
}

/// The policy for `mac` (unlisted → Full).
pub fn policy_of(mac: &[u8; 6]) -> Pol {
    let t = unsafe { &(&*core::ptr::addr_of!(T))[..N] };
    t.binary_search_by(|e| e.mac.cmp(mac)).map_or(Pol::Full, |i| t[i].pol)
}

/// The label for `mac`, if any.
pub fn label_of(mac: &[u8; 6], out: &mut [u8; 31]) -> usize {
    let t = unsafe { &(&*core::ptr::addr_of!(T))[..N] };
    match t.binary_search_by(|e| e.mac.cmp(mac)) {
        Ok(i) => {
            out.copy_from_slice(&t[i].label);
            t[i].llen as usize
        }
        Err(_) => 0,
    }
}

/// Check + count: does `mac`'s policy allow `d`?
pub fn check(mac: &[u8; 6], d: Dest) -> bool {
    // ADR 0053: a session-made, TTL-bound isolation puts the device in quarantine until it expires
    let p = if crate::actions::isolated(mac) { Pol::Quarantine } else { policy_of(mac) };
    let ok = allows(p, d);
    if !ok {
        unsafe { DENIED[p as usize] += 1 };
    }
    ok
}

/// Frames refused per policy (full, internet_only, lan_only, quarantine).
pub fn denied() -> [u64; 4] {
    unsafe { DENIED }
}

fn parse_mac(s: &[u8]) -> Option<[u8; 6]> {
    if s.len() != 17 {
        return None;
    }
    let mut m = [0u8; 6];
    for (i, part) in s.split(|&c| c == b':' || c == b'-').enumerate() {
        if i >= 6 || part.len() != 2 {
            return None;
        }
        let h = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
        m[i] = h(part[0])? << 4 | h(part[1])?;
    }
    if m == [0; 6] || m == [0xff; 6] || m[0] & 1 != 0 {
        return None; // zero / broadcast / multicast are never a station
    }
    Some(m)
}

fn parse_line(line: &[u8]) -> Result<Option<Ent>, ()> {
    let line = match line.iter().position(|&c| c == b'#') {
        Some(p) => &line[..p],
        None => line,
    };
    let mut t = line.split(|c| c.is_ascii_whitespace()).filter(|t| !t.is_empty());
    let Some(m) = t.next() else { return Ok(None) };
    let mac = parse_mac(m).ok_or(())?;
    let pol = match t.next().ok_or(())? {
        b"full" => Pol::Full,
        b"internet_only" => Pol::InternetOnly,
        b"lan_only" => Pol::LanOnly,
        b"quarantine" => Pol::Quarantine,
        _ => return Err(()),
    };
    let mut e = Ent { mac, pol, ..E0 };
    if let Some(l) = t.next() {
        if l.len() > 31 || !l.iter().all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-')) {
            return Err(());
        }
        e.label[..l.len()].copy_from_slice(l);
        e.llen = l.len() as u8;
    }
    if t.next().is_some() {
        return Err(());
    }
    Ok(Some(e))
}

/// Load from text (selftests + the boot loader after verification). Returns lines skipped.
pub fn load_text(text: &[u8]) -> u32 {
    unsafe { N = 0 };
    let mut skipped = 0;
    for line in text.split(|&c| c == b'\n' || c == b'\r') {
        let line = line.split(|&c| c == 0).next().unwrap_or(&[]);
        match parse_line(line) {
            Ok(Some(e)) => unsafe {
                if N < CAP {
                    (*core::ptr::addr_of_mut!(T))[N] = e;
                    N += 1;
                } else {
                    skipped += 1;
                }
            },
            Ok(None) => {}
            Err(()) => skipped += 1,
        }
    }
    unsafe {
        let t = &mut (&mut *core::ptr::addr_of_mut!(T))[..N];
        t.sort_by(|a, b| a.mac.cmp(&b.mac)); // stable: a later duplicate stays after the earlier one
        // duplicates: the LAST line for a MAC wins
        let mut w = 0usize;
        for r in 0..t.len() {
            if w > 0 && t[w - 1].mac == t[r].mac {
                t[w - 1] = t[r];
            } else {
                t[w] = t[r];
                w += 1;
            }
        }
        N = w;
    }
    skipped
}

fn signed_message(gen: u64, len: u64, digest: &[u8; 32]) -> [u8; 54] {
    let mut m = [0u8; 54];
    m[..6].copy_from_slice(b"HQDEV1");
    m[6..14].copy_from_slice(&gen.to_le_bytes());
    m[14..22].copy_from_slice(&len.to_le_bytes());
    m[22..].copy_from_slice(digest);
    m
}

fn check_sig(sig: &[u8], key: &[u8; 32], body: &[u8]) -> Result<u64, crate::shield::LoadErr> {
    use crate::shield::LoadErr;
    if sig.len() < 120 || &sig[..8] != b"HQDSIG1\0" {
        return Err(LoadErr::SigMalformed);
    }
    let gen = u64::from_le_bytes(sig[8..16].try_into().unwrap());
    let len = u64::from_le_bytes(sig[16..24].try_into().unwrap()) as usize;
    if len > body.len() {
        return Err(LoadErr::Io);
    }
    let d = boot_abi::sha256::digest(&body[..len]);
    if d[..] != sig[24..56] {
        return Err(LoadErr::DigestMismatch);
    }
    let pk = ed25519_compact::PublicKey::from_slice(key).map_err(|_| LoadErr::SigMalformed)?;
    let s = ed25519_compact::Signature::from_slice(&sig[56..120]).map_err(|_| LoadErr::SigMalformed)?;
    pk.verify(&signed_message(gen, len as u64, &d)[..], &s).map_err(|_| LoadErr::BadSignature)?;
    Ok(gen)
}

/// Boot: DEVICES.TXT (≤ 16 KiB) + DEVICES.SIG when an operator key is compiled in.
pub fn load<D: BlockDev>(dev: &D) -> Info {
    unsafe { N = 0 };
    let mut info = Info::default();
    let mut sec = [0u8; 512];
    let p1 = if dev.read_block(0, &mut sec).is_ok() { crate::store::parse_mbr(&sec)[0].start } else { 0 };
    let Some((lba, nsec)) = (p1 != 0).then(|| crate::fat::locate_contiguous(dev, p1, b"DEVICES TXT")).flatten() else {
        unsafe { INFO = info };
        return info;
    };
    let mut buf = [0u8; 16384];
    let n = ((nsec as usize) * 512).min(buf.len());
    for k in 0..n / 512 {
        if dev.read_block(lba + k as u64, &mut sec).is_err() {
            info.file = 2;
            info.refused = Some(crate::shield::LoadErr::Io);
            unsafe { INFO = info };
            return info;
        }
        buf[k * 512..k * 512 + 512].copy_from_slice(&sec);
    }
    let body_len = match POLICY_PUBKEY {
        Some(key) => {
            let mut sig = [0u8; 512];
            let r = match crate::fat::locate_contiguous(dev, p1, b"DEVICES SIG").and_then(|(l, _)| dev.read_block(l, &mut sig).ok()) {
                None => Err(crate::shield::LoadErr::SigMissing),
                Some(()) => check_sig(&sig, &key, &buf[..n]),
            };
            match r {
                Ok(g) => {
                    info.signed = true;
                    info.generation = g;
                    u64::from_le_bytes(sig[16..24].try_into().unwrap()) as usize
                }
                Err(e) => {
                    info.file = 2;
                    info.refused = Some(e);
                    unsafe { INFO = info };
                    return info;
                }
            }
        }
        None => n,
    };
    info.skipped = load_text(&buf[..body_len.min(n)]);
    info.file = 1;
    unsafe { INFO = info };
    info
}

/// `[P-devpolicy]`
pub fn selftest() -> bool {
    use ed25519_compact::{KeyPair, Seed};
    let text = b"# devices\n02:00:00:00:00:07 internet_only kids-tablet\n02:00:00:00:00:08 lan_only printer\nAA-BB-CC-00-11-22 quarantine\n02:00:00:00:00:09 full\n02:00:00:00:00:07 quarantine kids-tablet\n01:00:5e:00:00:01 full\nff:ff:ff:ff:ff:ff full\n02:00:00:00:00:0a sometimes\n02:00:00:00:00:0b full bad;label\n0200.0000.000c full\n";
    let skipped = load_text(text);
    let parsed = len() == 4 && skipped == 5;
    let m = |b: u8| [0x02, 0, 0, 0, 0, b];
    let last_wins = policy_of(&m(7)) == Pol::Quarantine;
    let lookups = policy_of(&m(8)) == Pol::LanOnly && policy_of(&[0xaa, 0xbb, 0xcc, 0, 0x11, 0x22]) == Pol::Quarantine
        && policy_of(&m(9)) == Pol::Full && policy_of(&m(0x99)) == Pol::Full;
    let mut lb = [0u8; 31];
    let label = label_of(&m(8), &mut lb) == 7 && &lb[..7] == b"printer";
    use Dest::*;
    let matrix = allows(Pol::Full, Internet) && allows(Pol::Full, DeviceMgmt)
        && allows(Pol::InternetOnly, Internet) && !allows(Pol::InternetOnly, DeviceMgmt) && !allows(Pol::InternetOnly, Lan)
        && allows(Pol::LanOnly, Lan) && allows(Pol::LanOnly, DeviceMgmt) && !allows(Pol::LanOnly, Internet)
        && !allows(Pol::Quarantine, Internet) && !allows(Pol::Quarantine, Lan) && !allows(Pol::Quarantine, DeviceMgmt)
        && [Pol::Full, Pol::InternetOnly, Pol::LanOnly, Pol::Quarantine].iter().all(|&p| allows(p, Infra));
    let d0 = denied()[3];
    let counted = !check(&m(7), Internet) && denied()[3] == d0 + 1 && check(&m(0x99), Internet);
    // signature
    let kp = KeyPair::from_seed(Seed::new([0x81; 32]));
    let pk: [u8; 32] = *kp.pk;
    let body: &[u8] = text;
    let d = boot_abi::sha256::digest(body);
    let mut sig = [0u8; 512];
    sig[..8].copy_from_slice(b"HQDSIG1\0");
    sig[8..16].copy_from_slice(&2u64.to_le_bytes());
    sig[16..24].copy_from_slice(&(body.len() as u64).to_le_bytes());
    sig[24..56].copy_from_slice(&d);
    sig[56..120].copy_from_slice(kp.sk.sign(&signed_message(2, body.len() as u64, &d)[..], None).as_ref());
    let sig_ok = check_sig(&sig, &pk, body) == Ok(2);
    let mut tb = [0u8; 600];
    tb[..body.len()].copy_from_slice(body);
    tb[30] ^= 1;
    let sig_t = check_sig(&sig, &pk, &tb[..body.len()]).is_err();
    let mut x = sig;
    x[..8].copy_from_slice(b"HQBSIG1\0");
    let sig_x = check_sig(&x, &pk, body).is_err();
    let _ = load_text(b"");
    let empty = policy_of(&m(7)) == Pol::Full;
    let pass = parsed && last_wins && lookups && label && matrix && counted && sig_ok && sig_t && sig_x && empty;
    arch_aarch64::_print(format_args!(
        " [P-devpolicy] {} — local per-device policy (parity G9, V1 fortress-ctl set-policy): DEVICES.TXT parse (strict MACs: multicast/broadcast/zero/bad format refused, labels sanitised, unknown policy refused) ok={} last line for a MAC wins={} lookups (unlisted=full)={} labels={} | policy matrix (internet_only: no LAN, no device mgmt; lan_only: no internet; quarantine: only DHCP/DNS/ARP) ={} denials counted={} | DEVICES.SIG ok={} tampered refused={} other-file signature refused={} | empty file = everyone full={}\n",
        if pass { "PASS" } else { "FAIL" }, parsed, last_wins, lookups, label, matrix, counted, sig_ok, sig_t, sig_x, empty
    ));
    pass
}
