//! M4.4 — the ADR-0004 secure-edge OPERATIONAL ENVELOPE on heqk's native stack.
//!
//! ADR 0004's footer names the "crown jewel" that must be re-implemented on heqk:
//! the **kill-switch**, PBR/fwmark routing, NAT, and the TUN tunnel to the super-PoP
//! (SASE). This module lands the two pieces that are pure, QEMU-provable DECISION
//! logic and rides them on the EXISTING M2 rule plane — the envelope is *policy on
//! top of* `packet::verdict`, never a bypass of it:
//!
//!   1. **WAN-egress kill-switch** (this file's `egress_allowed`, consulted by
//!      `netq::tx_drain`): when an ENROLLED device's secure tunnel is DOWN or
//!      COMPROMISED, WAN-bound egress is CUT (fail-closed — no plaintext leaks
//!      unprotected). It governs **WAN egress ONLY** — never the local SOC, never
//!      LAN, never the PoP-reconnect path — and it NEVER arms for a never-enrolled /
//!      standalone / air-gapped device (that is a valid steady state, not a fault).
//!   2. **msg1-replay DoS guard** (`Msg1DosGuard`): a cheap, stateless-cookie /
//!      rate-limit pre-filter that runs BEFORE the expensive ML-KEM decap / keygen /
//!      encap / Ed25519-verify path (`securechannel::responder_read_msg1`), so a
//!      forged or replayed msg1 flood cannot force asymmetric work.
//!
//! HONESTY (Track-C): the kill-switch DECISION + the msg1 guard are QEMU-provable
//! and proven by `[P19-edge]`. The rest of ADR 0004 — PBR (policy routing), NAT, and
//! the encrypted TUN tunnel to the real super-PoP at line rate — is a LARGER
//! follow-on the size of M2/M3 and needs metal (Gate R). It is SCOPED, not built —
//! see `docs/design/heqk-control-plane.md` §M4.4 / §7.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Local console print (same arch seam as the rest of the kernel).
#[cfg(feature = "securechannel-selftest")]
macro_rules! kprint {
    ($($t:tt)*) => { arch_aarch64::_print(format_args!($($t)*)) };
}

// ===========================================================================
// Kill-switch state (global — the egress gate in netq::tx_drain reads it on the
// datapath; the kernel is single-core so an atomic is the whole synchronization).
// ===========================================================================

/// Armed iff an ENROLLED device's secure tunnel is not UP. Default FALSE, and FALSE
/// forever for a never-enrolled / standalone device — so the gate is a no-op (zero
/// behaviour change) unless enrollment explicitly arms it.
static KS_ARMED: AtomicBool = AtomicBool::new(false);
/// Configured LAN network + mask (host-order); frames to this subnet are LAN/local
/// and are NEVER cut. 0 mask = "not configured" (private-range detection still runs).
static LAN_NET: AtomicU32 = AtomicU32::new(0);
static LAN_MASK: AtomicU32 = AtomicU32::new(0);
/// The super-PoP / control-plane address (host-order). Egress to it is allowed even
/// while the tunnel is down, so the device can RE-ESTABLISH the secure channel — the
/// standard kill-switch carve-out (WireGuard/OpenVPN allow their own endpoint). 0 =
/// unset.
static POP_ADDR: AtomicU32 = AtomicU32::new(0);

/// Enrollment posture, as it bears on the kill-switch. Mirrors `enroll::EnrollStatus`
/// but is the datapath-facing projection (the envelope must not depend on the
/// securechannel feature to make an egress decision).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Posture {
    /// Standalone / air-gapped. A VALID steady state — the kill-switch NEVER arms.
    NeverEnrolled,
    /// Bound to an MSSP / control plane; WAN egress is expected to ride the tunnel.
    Enrolled,
}

/// Secure-tunnel state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tunnel {
    /// The PQ-hybrid Noise tunnel to the PoP is established.
    Up,
    /// The tunnel is down (never came up, dropped, or rekey failed).
    Down,
    /// The tunnel / peer is believed compromised — treated as strictly as Down.
    Compromised,
}

/// The destination scope of an egress frame, as the kill-switch classifies it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    /// Loopback / LAN / link-local / multicast / broadcast / non-IPv4 (ARP, ND).
    /// The local SOC and LAN live here; NEVER cut.
    LocalOrLan,
    /// The configured super-PoP address — the tunnel-reconnect path; allowed even
    /// while the tunnel is down.
    PopReconnect,
    /// A globally-routable (public) destination that is NOT the PoP — the frame that
    /// would leak plaintext onto the internet if the tunnel is down.
    Wan,
}

// ===========================================================================
// State-level decision (the pure core — no globals, exhaustively provable).
// ===========================================================================

/// The pure state-level rule: may WAN egress flow in this `(posture, tunnel)` state?
///
///   * `NeverEnrolled`  -> TRUE. A standalone / air-gapped device routes WAN per its
///     LOCAL policy (default allow). It has no tunnel to protect and must NOT be
///     bricked by the kill-switch — the CLAUDE.md air-gap invariant.
///   * `Enrolled` + `Up`   -> TRUE. WAN egress rides the established secure tunnel.
///   * `Enrolled` + `Down`/`Compromised` -> FALSE. Fail-closed: WAN egress is CUT so
///     no plaintext leaks unprotected while the secure tunnel is not up.
///
/// This governs WAN egress ONLY; LAN / local-SOC / PoP-reconnect frames are decided
/// by `egress_scope`, not by this function.
#[inline]
pub fn wan_egress_permitted(posture: Posture, tunnel: Tunnel) -> bool {
    match posture {
        Posture::NeverEnrolled => true,
        Posture::Enrolled => matches!(tunnel, Tunnel::Up),
    }
}

/// Arm/disarm the datapath kill-switch from the current posture. Armed IFF an
/// ENROLLED device's tunnel is not UP. A `NeverEnrolled` device NEVER arms it
/// (air-gap invariant, enforced here in one place).
pub fn set_state(posture: Posture, tunnel: Tunnel) {
    let armed = matches!(posture, Posture::Enrolled) && !matches!(tunnel, Tunnel::Up);
    KS_ARMED.store(armed, Ordering::Release);
}

/// Provision the LAN subnet + PoP address the classifier uses (from the resolved
/// netcfg + the enrollment binding on metal).
pub fn configure(lan_net: u32, lan_mask: u32, pop_addr: u32) {
    LAN_NET.store(lan_net, Ordering::Release);
    LAN_MASK.store(lan_mask, Ordering::Release);
    POP_ADDR.store(pop_addr, Ordering::Release);
}

/// Whether the datapath kill-switch is currently armed.
#[inline]
pub fn is_armed() -> bool {
    KS_ARMED.load(Ordering::Acquire)
}

/// Is `dst` (host-order IPv4) a LAN/local destination that must NEVER be cut? True
/// for RFC 1918 private ranges, link-local, loopback, multicast, the all-zeros /
/// broadcast sentinels, and the configured LAN subnet.
fn is_local_dst(dst: u32) -> bool {
    if dst == 0 || dst == 0xFFFF_FFFF {
        return true; // this-host / limited broadcast
    }
    let o1 = (dst >> 24) as u8;
    let o2 = (dst >> 16) as u8;
    if o1 == 10 {
        return true; // 10.0.0.0/8
    }
    if o1 == 127 {
        return true; // 127.0.0.0/8 loopback
    }
    if o1 == 172 && (16..=31).contains(&o2) {
        return true; // 172.16.0.0/12
    }
    if o1 == 192 && o2 == 168 {
        return true; // 192.168.0.0/16
    }
    if o1 == 169 && o2 == 254 {
        return true; // 169.254.0.0/16 link-local
    }
    if (224..=239).contains(&o1) {
        return true; // 224.0.0.0/4 multicast
    }
    let net = LAN_NET.load(Ordering::Acquire);
    let mask = LAN_MASK.load(Ordering::Acquire);
    mask != 0 && (dst & mask) == (net & mask)
}

/// Classify a well-formed egress frame's destination scope. A non-IPv4 frame (ARP,
/// IPv6-ND, …) is link-local L2 management and is treated as `LocalOrLan` — never
/// cut. (Malformed IPv4 never reaches here: `packet::verdict` fail-closes it before
/// `netq::tx_drain` consults the kill-switch.)
pub fn egress_scope(frame: &[u8]) -> Scope {
    let dst = match crate::net::eth_ipv4_dst(frame) {
        Some(d) => d,
        None => return Scope::LocalOrLan,
    };
    let pop = POP_ADDR.load(Ordering::Acquire);
    if pop != 0 && dst == pop {
        return Scope::PopReconnect;
    }
    if is_local_dst(dst) {
        return Scope::LocalOrLan;
    }
    Scope::Wan
}

/// THE datapath hook. `netq::tx_drain` calls this on EVERY frame the untrusted EL0
/// IP service tries to send, AFTER the signed rule plane has already PASSed it.
/// Returns whether the frame may leave the box.
///
///   * DISARMED (the default, and ALWAYS for a never-enrolled / standalone /
///     air-gapped device) -> TRUE for every frame. Zero behaviour change; the local
///     SOC and all egress work exactly as before.
///   * ARMED (enrolled + tunnel Down/Compromised) -> LAN/local + PoP-reconnect
///     frames still PASS (the local SOC and LAN stay fully up), and only `Wan`-bound
///     frames are CUT (fail-closed — no plaintext leaks while the tunnel is down).
#[inline]
pub fn egress_allowed(frame: &[u8]) -> bool {
    if !KS_ARMED.load(Ordering::Acquire) {
        return true;
    }
    !matches!(egress_scope(frame), Scope::Wan)
}

// ===========================================================================
// msg1-replay DoS guard (N1) — cheap pre-filter before the expensive asym work.
//
// A forged or replayed msg1 must not be able to force the responder into an ML-KEM
// decap + keygen + encap + Ed25519 verify (the asymmetric work in
// `securechannel::responder_read_msg1`). This is a WireGuard-style, load-triggered
// STATELESS COOKIE (DTLS 1.3 HelloRetryRequest cookie, RFC 9147 §5.1; WireGuard
// cookie-reply): the only work an un-vouched msg1 can force is ONE keyed MAC. A
// peer must echo a cookie bound to it (proving return-routability) before the
// responder spends any asymmetric cycles under load. A token bucket detects "under
// load" so the fast path (no cookie) stays open when the device is not being flooded.
// ===========================================================================

use boot_abi::kdf::{ct_eq, hmac_sha256};

/// Cookie length on the wire (truncated HMAC-SHA256; 128-bit is ample for a
/// short-lived return-routability token).
pub const COOKIE_LEN: usize = 16;

/// The guard's decision for one msg1 attempt.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Msg1Decision {
    /// Cheap checks passed (a valid cookie was echoed, or the device is not under
    /// load) — proceed to the EXPENSIVE `responder_read_msg1` path.
    Process,
    /// Under load and no valid cookie — reply with this stateless cookie and do NO
    /// asymmetric work. The peer must echo it to proceed (return-routability).
    SendCookie([u8; COOKIE_LEN]),
}

/// Load-triggered stateless-cookie DoS guard for the responder's msg1 intake.
pub struct Msg1DosGuard {
    cookie_key: [u8; 32], // per-epoch secret (rotated on metal); never on the wire
    tokens: u32,
    capacity: u32,
    refill_per_tick: u32,
    last_tick: u64,
}

impl Msg1DosGuard {
    /// `capacity` = burst of un-vouched msg1 admitted before the cookie is REQUIRED;
    /// `refill_per_tick` = tokens restored per time tick (0 => a fixed budget for the
    /// burst, which is what the DoS test drains).
    pub const fn new(cookie_key: [u8; 32], capacity: u32, refill_per_tick: u32) -> Self {
        Msg1DosGuard {
            cookie_key,
            tokens: capacity,
            capacity,
            refill_per_tick,
            last_tick: 0,
        }
    }

    /// The stateless cookie bound to `peer` — a single cheap keyed MAC, the ONLY
    /// work a forged/replayed msg1 can force. (On metal `peer` also mixes the source
    /// address + a rotating epoch so a captured cookie neither travels nor lasts.)
    pub fn cookie_for(&self, peer: &[u8]) -> [u8; COOKIE_LEN] {
        let mac = hmac_sha256(&self.cookie_key, peer);
        let mut c = [0u8; COOKIE_LEN];
        c.copy_from_slice(&mac[..COOKIE_LEN]);
        c
    }

    fn refill(&mut self, now: u64) {
        if now > self.last_tick {
            let add = (now - self.last_tick).saturating_mul(self.refill_per_tick as u64);
            let t = (self.tokens as u64).saturating_add(add);
            self.tokens = core::cmp::min(self.capacity as u64, t) as u32;
            self.last_tick = now;
        }
    }

    /// The cheap pre-crypto gate. `presented` is the cookie the peer echoed (if any).
    ///   * a VALID cookie -> `Process` (return-routability proven; always admitted);
    ///   * else, if a token is available (NOT under load) -> `Process` (fast path);
    ///   * else (under load, no valid cookie) -> `SendCookie` — NO asymmetric work
    ///     for an un-vouched / forged / replayed msg1.
    pub fn admit(
        &mut self,
        peer: &[u8],
        presented: Option<&[u8; COOKIE_LEN]>,
        now: u64,
    ) -> Msg1Decision {
        self.refill(now);
        if let Some(c) = presented {
            if ct_eq(c, &self.cookie_for(peer)) {
                return Msg1Decision::Process;
            }
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            Msg1Decision::Process
        } else {
            Msg1Decision::SendCookie(self.cookie_for(peer))
        }
    }
}

// ===========================================================================
// [P19-edge] — the M4.4 self-test (securechannel-selftest). Anti-replay window,
// msg1-DoS pre-crypto rejection, and the kill-switch (both cases + air-gap).
// ===========================================================================

#[cfg(feature = "securechannel-selftest")]
fn yn(b: bool) -> &'static str {
    if b {
        "PASS"
    } else {
        "FAIL"
    }
}

/// Build a minimal Ethernet/IPv4/UDP egress frame to `dst_ip` (host-order) into
/// `buf`, returning its length. dst port 4433 (benign — `packet::verdict` PASSes it,
/// so the kill-switch, not the IPS, is what the test exercises).
#[cfg(feature = "securechannel-selftest")]
fn udp_to(buf: &mut [u8], dst_ip: u32) -> usize {
    const N: usize = 14 + 20 + 8;
    for b in buf.iter_mut().take(N) {
        *b = 0;
    }
    buf[12] = 0x08; // ethertype IPv4
    buf[13] = 0x00;
    buf[14] = 0x45; // IPv4, IHL=5
    let total = 20 + 8;
    buf[16] = (total >> 8) as u8;
    buf[17] = (total & 0xff) as u8;
    buf[23] = 17; // UDP
    // IPv4 dst at offset 30..34.
    buf[30] = (dst_ip >> 24) as u8;
    buf[31] = (dst_ip >> 16) as u8;
    buf[32] = (dst_ip >> 8) as u8;
    buf[33] = dst_ip as u8;
    // UDP src 1234 / dst 4433.
    buf[34] = 0x04;
    buf[35] = 0xd2;
    buf[36] = (4433u16 >> 8) as u8;
    buf[37] = (4433u16 & 0xff) as u8;
    N
}

/// (1) Anti-replay window: in-order + in-window reorder accepted; exact replay +
/// below-window rejected; a forged record never advances the window.
#[cfg(feature = "securechannel-selftest")]
fn anti_replay_check() -> bool {
    use crate::securechannel::{
        initiator_read_msg2, initiator_write_msg1, responder_read_msg1, responder_write_msg2,
        test_vectors, NoiseErr,
    };
    // A real handshake gives matching transport keys: i.send == r.recv, so an
    // AntiReplayRx built from r.recv opens exactly what i.send sealed.
    let tv = test_vectors();
    let (msg1, ipend) =
        match initiator_write_msg1(&tv.dev, &tv.resp.public(), &tv.irand, b"e") {
            Some(x) => x,
            None => return false,
        };
    let rpend = match responder_read_msg1(&tv.resp, &tv.dev.pk, msg1.as_slice()) {
        Ok(x) => x,
        Err(_) => return false,
    };
    let (msg2, rsess) = match responder_write_msg2(rpend, &tv.rrand, b"w") {
        Some(x) => x,
        None => return false,
    };
    let (isess, _p2) = match initiator_read_msg2(ipend, msg2.as_slice()) {
        Ok(x) => x,
        Err(_) => return false,
    };

    let mut sender = isess.send.clone(); // encrypts records for i->r
    let mut rx = rsess.recv.into_anti_replay(); // window over the SAME key (i->r)

    // Precompute the records we need, at their specific sequence numbers. We drive
    // the sender forward and keep only the seqs of interest (avoids a huge array).
    const PT: &[u8] = b"edge-record"; // 11 bytes -> record 27 bytes
    const WANT: [u64; 10] = [0, 1, 2, 3, 5, 6, 7, 8, 10, 500];
    let mut recs = [[0u8; 32]; 10];
    let mut lens = [0usize; 10];
    let mut scratch = [0u8; 64];
    for seq in 0..=500u64 {
        debug_assert_eq!(sender.counter(), seq);
        let n = sender.encrypt_into(b"", PT, &mut scratch).unwrap_or(0);
        if let Some(k) = WANT.iter().position(|&w| w == seq) {
            recs[k][..n].copy_from_slice(&scratch[..n]);
            lens[k] = n;
        }
    }
    let rec = |seq: u64| -> (&[u8], ()) {
        let k = WANT.iter().position(|&w| w == seq).unwrap();
        (&recs[k][..lens[k]], ())
    };
    let mut out = [0u8; 64];
    let ok = |r: Result<usize, NoiseErr>| matches!(r, Ok(n) if n == PT.len());
    let replay = |r: Result<usize, NoiseErr>| r == Err(NoiseErr::Replay);
    let auth = |r: Result<usize, NoiseErr>| r == Err(NoiseErr::AeadAuth);

    // in-order 0,1,2,3
    let inorder = ok(rx.open(0, b"", rec(0).0, &mut out))
        && ok(rx.open(1, b"", rec(1).0, &mut out))
        && ok(rx.open(2, b"", rec(2).0, &mut out))
        && ok(rx.open(3, b"", rec(3).0, &mut out));
    // forward reorder / gap: 6,7 arrive before 5
    let gap = ok(rx.open(6, b"", rec(6).0, &mut out)) && ok(rx.open(7, b"", rec(7).0, &mut out));
    // in-window reorder: the late 5 (never seen) is accepted
    let reorder = ok(rx.open(5, b"", rec(5).0, &mut out));
    // exact replay of 6 -> rejected
    let exact_replay = replay(rx.open(6, b"", rec(6).0, &mut out));
    // forged: a corrupted seq-8 record -> AeadAuth, window NOT advanced...
    let mut bad = recs[WANT.iter().position(|&w| w == 8).unwrap()];
    let blen = lens[WANT.iter().position(|&w| w == 8).unwrap()];
    bad[blen - 1] ^= 0x01;
    let forged_auth = auth(rx.open(8, b"", &bad[..blen], &mut out));
    // ...so the INTACT seq-8 still opens (the forgery didn't burn the slot)
    let intact_after_forge = ok(rx.open(8, b"", rec(8).0, &mut out));
    // big jump forward: 500 accepted, slides the window
    let jump = ok(rx.open(500, b"", rec(500).0, &mut out));
    // below-window: seq 10 (never delivered) is now far below the window -> rejected
    let below_window = replay(rx.open(10, b"", rec(10).0, &mut out));

    let all = inorder && gap && reorder && exact_replay && forged_auth
        && intact_after_forge && jump && below_window;
    kprint!(
        "   anti-replay(RFC 6479): in-order={} gap+reorder={} in-window-reorder={} exact-replay-rejected={} forged→AeadAuth(window-untouched)={} below-window-rejected={}\n",
        yn(inorder), yn(gap), yn(reorder), yn(exact_replay), yn(forged_auth && intact_after_forge), yn(below_window)
    );
    all
}

/// (2) msg1-replay DoS: under load, a forged/replayed msg1 flood is rejected
/// PRE-crypto (0 reach `responder_read_msg1`); a cookie-vouched legit peer reaches
/// (and completes) the expensive path.
#[cfg(feature = "securechannel-selftest")]
fn msg1_dos_check() -> bool {
    use crate::securechannel::{initiator_write_msg1, responder_read_msg1, test_vectors};
    use boot_abi::sha256;

    let key = sha256::digest(b"HEQK-M4.4-cookie-epoch");
    // Small budget, no refill: a burst of 4 un-vouched msg1 is admitted, then the
    // cookie is REQUIRED. The flood happens after the budget is drained.
    let mut guard = Msg1DosGuard::new(key, 4, 0);
    let now = 1u64;

    // Drain the fast-path budget (these WOULD process; count them so the invariant is
    // "bounded work", not "zero" — the bucket caps it at `capacity`).
    let mut warm_process = 0u32;
    for i in 0..4u32 {
        let p = sha256::digest(&i.to_le_bytes());
        if matches!(guard.admit(&p[..], None, now), Msg1Decision::Process) {
            warm_process += 1;
        }
    }

    // FLOOD: 256 forged msg1, each a different (spoofed) peer, NO valid cookie. Under
    // load every one must get SendCookie — ZERO reach the expensive path.
    const FLOOD: u32 = 256;
    let mut expensive = 0u32;
    let mut cookies = 0u32;
    for i in 0..FLOOD {
        let p = sha256::digest(&(0x1000_0000u32 + i).to_le_bytes());
        match guard.admit(&p[..], None, now) {
            Msg1Decision::Process => expensive += 1, // MUST stay 0
            Msg1Decision::SendCookie(_) => cookies += 1,
        }
    }
    let flood_cheap = expensive == 0 && cookies == FLOOD;

    // A REPLAYED msg1 (same forged peer, repeated) is likewise never processed under
    // load without a valid cookie.
    let rp = sha256::digest(b"HEQK-M4.4-replayed-peer");
    let mut replay_expensive = 0u32;
    for _ in 0..32 {
        if matches!(guard.admit(&rp[..], None, now), Msg1Decision::Process) {
            replay_expensive += 1;
        }
    }
    let replay_cheap = replay_expensive == 0;

    // RETURN-ROUTABILITY: a legit peer echoes a cookie bound to it -> Process even
    // under load, AND that admitted msg1 drives the REAL expensive handshake OK. The
    // crypto path is invoked ONLY when the guard admits (the whole point).
    let tv = test_vectors();
    let peer = &tv.dev.pk[..];
    let cookie = guard.cookie_for(peer);
    let admitted = matches!(guard.admit(peer, Some(&cookie), now), Msg1Decision::Process);
    let wrong_cookie_rejected = !matches!(
        guard.admit(peer, Some(&[0u8; COOKIE_LEN]), now),
        Msg1Decision::Process
    );
    let expensive_after_admit = if admitted {
        let (msg1, _ip) =
            initiator_write_msg1(&tv.dev, &tv.resp.public(), &tv.irand, b"m").unwrap();
        responder_read_msg1(&tv.resp, &tv.dev.pk, msg1.as_slice()).is_ok()
    } else {
        false
    };

    let all = warm_process == 4
        && flood_cheap
        && replay_cheap
        && admitted
        && wrong_cookie_rejected
        && expensive_after_admit;
    kprint!(
        "   msg1-DoS(cookie/rate-limit): fast-path-budget={} forged-flood({})→0-crypto+cookie-issued={} replayed-msg1→0-crypto={} wrong-cookie-rejected={} valid-cookie→expensive-path-runs={}\n",
        warm_process, FLOOD, yn(flood_cheap), yn(replay_cheap), yn(wrong_cookie_rejected), yn(expensive_after_admit)
    );
    all
}

/// (3) Kill-switch: enrolled + tunnel-down => WAN egress CUT while LAN + local SOC
/// (+ PoP-reconnect) stay UP; never-enrolled/standalone => local SOC UP (air-gap
/// invariant, never bricked).
#[cfg(feature = "securechannel-selftest")]
fn kill_switch_check() -> bool {
    // LAN 10.0.2.0/24 (the SLIRP net), PoP 203.0.113.10 (public, allowed for reconnect).
    const LAN_NET: u32 = 0x0A00_0200;
    const LAN_MASK: u32 = 0xFFFF_FF00;
    const POP: u32 = 0xCB00_710A; // 203.0.113.10
    configure(LAN_NET, LAN_MASK, POP);

    let mut lan = [0u8; 64];
    let ll = udp_to(&mut lan, 0x0A00_020F); // 10.0.2.15
    let mut wan = [0u8; 64];
    let wl = udp_to(&mut wan, 0x0808_0808); // 8.8.8.8 (the "leak" dst)
    let mut pop = [0u8; 64];
    let pl = udp_to(&mut pop, POP); // 203.0.113.10
    let mut arp = [0u8; 64]; // non-IPv4 (ethertype 0x0806) — link-local mgmt
    arp[12] = 0x08;
    arp[13] = 0x06;
    let al = 42usize;

    // --- state-level pure decision (exhaustive) ---
    let s_never = wan_egress_permitted(Posture::NeverEnrolled, Tunnel::Down); // true
    let s_up = wan_egress_permitted(Posture::Enrolled, Tunnel::Up); // true
    let s_down = !wan_egress_permitted(Posture::Enrolled, Tunnel::Down); // cut
    let s_comp = !wan_egress_permitted(Posture::Enrolled, Tunnel::Compromised); // cut
    let state_ok = s_never && s_up && s_down && s_comp;

    // --- (A) never-enrolled / standalone / air-gap: NEVER arms, local SOC UP ---
    set_state(Posture::NeverEnrolled, Tunnel::Down); // even "down" must not arm
    let standalone_disarmed = !is_armed();
    let standalone_wan = egress_allowed(&wan[..wl]); // WAN per local policy (allow)
    let standalone_lan = egress_allowed(&lan[..ll]); // LAN up
    let airgap_ok = standalone_disarmed && standalone_wan && standalone_lan;

    // --- (B) enrolled + tunnel UP: WAN flows (via the tunnel) ---
    set_state(Posture::Enrolled, Tunnel::Up);
    let up_ok = !is_armed() && egress_allowed(&wan[..wl]) && egress_allowed(&lan[..ll]);

    // --- (C) enrolled + tunnel DOWN: kill-switch — WAN CUT, everything local UP ---
    set_state(Posture::Enrolled, Tunnel::Down);
    let armed = is_armed();
    let wan_cut = !egress_allowed(&wan[..wl]); // the leak is CUT
    let lan_up = egress_allowed(&lan[..ll]); // LAN + local SOC stay up
    let arp_up = egress_allowed(&arp[..al]); // link-local mgmt never cut
    let pop_up = egress_allowed(&pop[..pl]); // reconnect path allowed
    let down_ok = armed && wan_cut && lan_up && arp_up && pop_up;

    // --- (D) enrolled + COMPROMISED: same fail-closed cut ---
    set_state(Posture::Enrolled, Tunnel::Compromised);
    let comp_ok = !egress_allowed(&wan[..wl]) && egress_allowed(&lan[..ll]);

    // --- restore: DISARM so no later datapath test is affected ---
    set_state(Posture::NeverEnrolled, Tunnel::Up);
    configure(0, 0, 0);
    let restored = !is_armed() && egress_allowed(&wan[..wl]);

    let all = state_ok && airgap_ok && up_ok && down_ok && comp_ok && restored;
    kprint!(
        "   kill-switch: state-rule={} standalone/air-gap(never-arms,SOC-up)={} tunnel-up(WAN-flows)={} tunnel-DOWN→WAN-CUT+LAN/PoP/local-UP={} compromised→CUT={} disarm-restored={}\n",
        yn(state_ok), yn(airgap_ok), yn(up_ok), yn(down_ok), yn(comp_ok), yn(restored)
    );
    all
}

/// The [P19-edge] M4.4 secure-edge envelope self-test.
#[cfg(feature = "securechannel-selftest")]
pub fn edge_selftest() {
    kprint!(" [P19-edge] M4.4 secure-edge envelope: anti-replay window + msg1-DoS guard + WAN-egress kill-switch:\n");
    let ar = anti_replay_check();
    let dos = msg1_dos_check();
    let ks = kill_switch_check();
    let pass = ar && dos && ks;
    kprint!(
        " [P19-edge] {} — (1) RFC 6479 anti-replay sliding window on the Noise transport RECEIVER: in-order + in-window reorder ACCEPTED, exact replay + below-window REJECTED, a forged record fails AEAD and NEVER advances the window (RFC 4303 §3.4.3 order); (2) msg1-replay DoS guard (WireGuard/DTLS-1.3-style load-triggered stateless cookie + token-bucket): a 256-deep forged/replayed msg1 flood is rejected PRE-crypto (0 reach the ML-KEM decap/keygen/encap/Ed25519 path) — the only work forced is one keyed MAC — while a cookie-vouched legit peer reaches and COMPLETES the expensive handshake; (3) WAN-egress kill-switch riding the M2 netq egress gate (fail-closed): an ENROLLED device with the secure tunnel DOWN/COMPROMISED has WAN-bound egress CUT (no plaintext leak) while LAN + local SOC + the PoP-reconnect path stay UP, and a NEVER-ENROLLED / standalone / air-gapped device NEVER arms the kill-switch (local SOC + LAN up, WAN per local policy — the air-gap invariant, never bricked). QEMU-provable DECISION logic; the full PBR/NAT/TUN SASE dataplane at line rate + the real super-PoP tunnel = metal (Gate R) — scoped in docs/design/heqk-control-plane.md §M4.4\n",
        if pass { "PASS" } else { "FAIL" }
    );
}
