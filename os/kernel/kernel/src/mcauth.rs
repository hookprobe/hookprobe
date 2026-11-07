//! Owner authentication for the on-device Mission Control (ADR 0037 D3, ADR 0047 D2).
//!
//! **Physical possession is the only credential; no default password, ever.** The flasher mints
//! a random owner TOKEN at flash time and shows it to the operator once. The device stores only a
//! salted VERIFIER, `sha256(salt ‖ token)`, in `OWNER.TXT` on the boot partition (a fixed-size
//! placeholder the image factory reserves and the flasher patches in place). Reading the eMMC
//! never reveals the token.
//!
//! - `/api/login` with the right token mints a session (128-bit id from the caller's RNG) carried
//!   in an `HttpOnly; SameSite=Strict` cookie — same-origin `fetch` and `EventSource` send it.
//! - An UNCLAIMED device (no verifier) refuses every protected route: there is NO open
//!   "first visitor claims it" window (the race ADR 0037 closes).
//! - Failed logins are throttled (a 128-bit token is not brute-forceable anyway; the throttle
//!   just keeps a flood from costing CPU).
//!
//! Pure + allocation-free; the caller supplies the clock and the random source. `[P-mcauth]`.

use boot_abi::sha256;

/// `OWNER.TXT` is exactly this many bytes (the factory reserves it; the flasher overwrites it in
/// place, so its length must never change).
pub const OWNER_FILE_LEN: usize = 128;
/// 8.3 name of the owner file on the boot partition.
pub const OWNER_8_3: &[u8; 11] = b"OWNER   TXT";

const MAX_SESSIONS: usize = 8;
const SESSION_TTL_MS: u64 = 12 * 3600 * 1000;
const FAIL_WINDOW_MS: u64 = 60_000;
const MAX_FAILS_PER_WINDOW: u32 = 5;
pub const COOKIE: &str = "hq_session";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Owner {
    pub salt: [u8; 16],
    pub verifier: [u8; 32],
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn unhex<const N: usize>(s: &[u8]) -> Option<[u8; N]> {
    if s.len() != 2 * N {
        return None;
    }
    let mut out = [0u8; N];
    for i in 0..N {
        out[i] = (hexval(s[2 * i])? << 4) | hexval(s[2 * i + 1])?;
    }
    Some(out)
}

/// Parse `OWNER.TXT`: `HQOWN1 <salt:32 hex> <verifier:64 hex>` (space-padded to the fixed
/// length). Anything else — including the factory's `HQOWN0 unclaimed` placeholder — is
/// UNCLAIMED (`None`), fail-closed.
pub fn parse_owner(file: &[u8]) -> Option<Owner> {
    let mut it = file.split(|&c| c == b' ' || c == b'\n' || c == b'\r').filter(|t| !t.is_empty());
    if it.next()? != b"HQOWN1" {
        return None;
    }
    let salt = unhex::<16>(it.next()?)?;
    let verifier = unhex::<32>(it.next()?)?;
    Some(Owner { salt, verifier })
}

/// Load the owner verifier from `OWNER.TXT` on the first (boot) partition of `dev` — the same
/// read path on QEMU virtio-blk and the CM5 eMMC. `None` = unclaimed (no file, or a placeholder).
pub fn load_owner<D: hal::BlockDev>(dev: &D) -> Option<Owner> {
    let mut sec = [0u8; 512];
    dev.read_block(0, &mut sec).ok()?;
    let p1 = crate::store::parse_mbr(&sec)[0].start;
    if p1 == 0 {
        return None;
    }
    let (lba, _n) = crate::fat::locate_contiguous(dev, p1, OWNER_8_3)?;
    dev.read_block(lba, &mut sec).ok()?;
    parse_owner(&sec[..OWNER_FILE_LEN])
}

/// `sha256(salt ‖ token)`.
pub fn verifier_for(salt: &[u8; 16], token: &[u8]) -> [u8; 32] {
    let mut h = sha256::Hasher::new();
    h.update(salt);
    h.update(token);
    h.finish()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

#[derive(Debug, PartialEq, Eq)]
pub enum LoginErr {
    Unclaimed,
    BadToken,
    Throttled,
    /// The random source failed: no session can be minted (fail-closed; the sensor keeps running).
    NoEntropy,
}

/// The device's auth state (one instance, owned by the serve loop).
pub struct Auth {
    owner: Option<Owner>,
    sessions: [([u8; 16], u64); MAX_SESSIONS],
    fails: u32,
    fail_window_start: u64,
}

impl Auth {
    pub const fn new(owner: Option<Owner>) -> Self {
        Auth { owner, sessions: [([0; 16], 0); MAX_SESSIONS], fails: 0, fail_window_start: 0 }
    }

    pub fn claimed(&self) -> bool {
        self.owner.is_some()
    }

    /// Exchange the owner token for a session id. `rand16` supplies 16 random bytes (`None` =
/// entropy failure → `NoEntropy`, never a predictable id).
    pub fn login(&mut self, token: &[u8], now_ms: u64, rand16: impl FnOnce() -> Option<[u8; 16]>) -> Result<[u8; 16], LoginErr> {
        let owner = self.owner.ok_or(LoginErr::Unclaimed)?;
        if now_ms.saturating_sub(self.fail_window_start) >= FAIL_WINDOW_MS {
            self.fail_window_start = now_ms;
            self.fails = 0;
        }
        if self.fails >= MAX_FAILS_PER_WINDOW {
            return Err(LoginErr::Throttled);
        }
        if !ct_eq(&verifier_for(&owner.salt, token), &owner.verifier) {
            self.fails += 1;
            return Err(LoginErr::BadToken);
        }
        let id = rand16().ok_or(LoginErr::NoEntropy)?;
        // Reuse an expired slot, else evict the session closest to expiry.
        let slot = (0..MAX_SESSIONS)
            .find(|&i| self.sessions[i].1 <= now_ms)
            .unwrap_or_else(|| (0..MAX_SESSIONS).min_by_key(|&i| self.sessions[i].1).unwrap_or(0));
        self.sessions[slot] = (id, now_ms + SESSION_TTL_MS);
        Ok(id)
    }

    /// Is `cookie_hex` (the `hq_session` cookie value) a live session?
    pub fn check(&self, cookie_hex: Option<&str>, now_ms: u64) -> bool {
        let Some(id) = cookie_hex.and_then(|c| unhex::<16>(c.as_bytes())) else { return false };
        self.sessions.iter().any(|(s, exp)| *exp > now_ms && ct_eq(s, &id))
    }
}

/// Hex-encode a session id for the cookie.
pub fn session_hex(id: &[u8; 16], out: &mut [u8; 32]) {
    const H: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in id.iter().enumerate() {
        out[2 * i] = H[(b >> 4) as usize];
        out[2 * i + 1] = H[(b & 0xf) as usize];
    }
}

/// `[P-mcauth]` — claim/login/session/throttle semantics. Pure; QEMU-provable.
#[cfg(not(feature = "cm5"))]
pub fn mcauth_selftest() -> bool {
    macro_rules! kprint { ($($t:tt)*) => { arch_aarch64::_print(format_args!($($t)*)) }; }
    let salt = [7u8; 16];
    let token = b"hq-test-owner-token-0123456789";
    let v = verifier_for(&salt, token);
    let mut file = [b' '; OWNER_FILE_LEN];
    let line_head = b"HQOWN1 07070707070707070707070707070707 ";
    file[..line_head.len()].copy_from_slice(line_head);
    let mut vh = [0u8; 64];
    {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        let mut lo = [0u8; 16];
        let mut hi = [0u8; 16];
        lo.copy_from_slice(&v[..16]);
        hi.copy_from_slice(&v[16..]);
        session_hex(&lo, &mut a);
        session_hex(&hi, &mut b);
        vh[..32].copy_from_slice(&a);
        vh[32..].copy_from_slice(&b);
    }
    file[line_head.len()..line_head.len() + 64].copy_from_slice(&vh);
    let owner = parse_owner(&file);
    let placeholder_unclaimed = parse_owner(b"HQOWN0 unclaimed").is_none();
    let mut auth = Auth::new(owner);
    let unclaimed_refused = Auth::new(None).login(token, 0, || Some([1; 16])) == Err(LoginErr::Unclaimed);
    let bad = auth.login(b"wrong", 1000, || Some([2; 16])) == Err(LoginErr::BadToken);
    let id = auth.login(token, 2000, || Some([0xAB; 16]));
    let mut hex = [0u8; 32];
    let good = match id {
        Ok(i) => {
            session_hex(&i, &mut hex);
            true
        }
        Err(_) => false,
    };
    let cookie = core::str::from_utf8(&hex).unwrap_or("");
    let session_ok = auth.check(Some(cookie), 3000) && !auth.check(Some("00000000000000000000000000000000"), 3000)
        && !auth.check(None, 3000) && !auth.check(Some(cookie), 2000 + SESSION_TTL_MS + 1);
    for _ in 0..MAX_FAILS_PER_WINDOW {
        let _ = auth.login(b"x", 4000, || Some([3; 16]));
    }
    let throttled = auth.login(token, 4001, || Some([4; 16])) == Err(LoginErr::Throttled)
        && auth.login(token, 4000 + FAIL_WINDOW_MS + 1, || Some([5; 16])).is_ok();
    let pass = owner.is_some() && placeholder_unclaimed && unclaimed_refused && bad && good && session_ok && throttled;
    kprint!(" [P-mcauth] {} — owner auth (ADR 0037 D3): verifier parsed={} placeholder=unclaimed={} unclaimed refuses login={} bad token refused={} token→session={} session cookie valid/forged/absent/expired={} throttle+recovery={}\n",
        if pass { "PASS" } else { "FAIL" }, owner.is_some(), placeholder_unclaimed, unclaimed_refused, bad, good, session_ok, throttled);
    pass
}
