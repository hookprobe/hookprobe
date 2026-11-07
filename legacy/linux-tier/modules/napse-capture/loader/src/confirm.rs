//! Confirmation gating (2026-07-05 threat-model fix, CRITICAL #1; re-audited 2026-07-05 evening,
//! Q2/Q6 corrections) — the anti-spoof gate a source must pass BEFORE `portscan::PortScanTracker`'s
//! fan-out alert is allowed to carry any enforcement weight. Fed the SAME mirror-sink TCP stream as
//! `portscan.rs` (every direction, every packet — see `dpi::parse_tcp_obs`), this module tracks
//! whether a claimed `(source IP, source MAC)` pair has completed at least one REAL, validated TCP
//! three-way handshake as seen on the wire.
//!
//! ## Why a validated handshake, specifically (not just "any reply")
//! The mirror sees BOTH directions of every NIC (ADR 0005's `render_mirror`: ingress AND egress
//! are both `tc-mirred` to the same sink) — which means this device's OWN auto-generated
//! SYN-ACK/RST reply to an inbound (possibly spoofed) SYN is ALSO on the mirror, indistinguishable
//! from a "real" third-party reply by flags alone. Counting "any bidirectional traffic" as
//! confirmation would therefore confirm EVERY single spoofed SYN this device answers — exactly
//! the DoS the audit found, just moved one step later. The one signal a device auto-reply can
//! NEVER produce on an attacker's behalf is the THIRD packet: a final ACK, arriving FROM the
//! claimed source, whose ack-number correctly acknowledges the SYN-ACK's sequence number. An
//! off-path spoofer (forging `src_ip` = victim/gateway/resolver) never receives that SYN-ACK — it
//! is routed back to the REAL owner of the spoofed address, not to the attacker — so the attacker
//! cannot learn the ISN and cannot forge a validly-acknowledging final ACK. This is the same
//! principle SYN cookies rely on, applied passively at the mirror instead of in the TCP stack.
//!
//! ## Q2 (VERIFY-pass re-audit, CRITICAL) — confirmation must be keyed on (IP, MAC), not IP alone
//! Keying the confirmed set on `Ipv4Addr` alone let a LAN victim `V`'s OWN legitimate traffic
//! (V completing a real handshake as the mirror's connection initiator) silently "vouch" for
//! ANYONE later claiming `src_ip = V` — including an attacker on different hardware sending
//! spoofed SYNs with `src = V`. The attacker never forges a handshake and never needs to; it just
//! borrows a confirmation the REAL V already earned. This is a reflected-DoS: the attacker's
//! fan-out alert renders `confirmed = is_confirmed(V) = true`, `scan_responder::decide` returns
//! `Quarantine{V}`, and the innocent V gets dropped by IP. **Fix:** the confirmed set (and
//! `is_confirmed`) is now keyed on the PAIR `(Ipv4Addr, [u8; 6])` — the claimed IP AND the observed
//! Ethernet source MAC of the packet that completed the handshake. `V`'s real `(V, V_mac)` pair is
//! confirmed; the attacker's `(V, attacker_mac)` pair is NOT — it never completed a handshake as
//! that pair, and (being off-path for the same reason as before) cannot forge one. The emission
//! site (`bin/napse-dpi.rs`) stamps `confirmed` from `is_confirmed(alert.src_ip, alert.src_mac)`,
//! where `src_mac` is the OBSERVED mac of the SCANNING packets themselves — never resolved from the
//! claimed IP.
//!
//! ## Q6 (VERIFY-pass re-audit, MEDIUM) — confirmation must expire
//! Without a TTL, a source that earned confirmation once stays confirmed forever, which is a
//! stale-evidence risk for an active host that later changes hardware/role, and makes the Q2 window
//! (before that fix) effectively permanent. `HandshakeConfig::confirmed_ttl_secs` bounds how old a
//! confirmation may be and still count; `is_confirmed` takes the query time and checks recency.
//! Expiry is enforced lazily (no active timer/sweep needed): a query past the TTL simply reports
//! `false`; the bounded `max_confirmed` FIFO already caps total memory regardless of expiry.
//!
//! ## Honest limitation — this defeats spoofing, not stealth scanning
//! A genuine (non-spoofed) SYN-only "stealth" scanner (e.g. `nmap -sS`) deliberately never
//! completes the handshake (it RSTs after the SYN-ACK), so it will never satisfy this gate either.
//! That is an intentional, documented trade-off (see ADR 0018): such a scan is still DETECTED
//! (the fan-out alert still fires, at LOW severity, unconfirmed) but not auto-enforced. Blocking
//! stealth scans automatically would require a stronger network-layer signal (e.g. per-role
//! SYN-rate limiting, which the SEPARATE in-kernel `napse_detect.bpf.c` fast path already does for
//! the WAN role) — not something this packet-mirror confirmation layer can or should fake.
//!
//! ## 2026-07-06 fix (F4, live Pi pentest) — this tracker is no longer the ONLY confirmation source
//! Before the companion 2026-07-06 F1 fix (`modules/napse-quarantine/bpf/quarantine.bpf.c` /
//! `modules/napse-l2guard/bpf/l2guard.bpf.c`), the tc ingress guards' `TC_ACT_OK` pass-path bug
//! meant the mirror never delivered INBOUND traffic to `napse-dpi` at all on real hardware — this
//! tracker's `is_confirmed` was therefore structurally stuck at `false` for every real attacker,
//! and downstream enforcement (`hookprobe_manifest::scan_responder::decide`) never durably
//! quarantined anything, no matter how real the attack. F1 fixes the root cause, but a mirror
//! remains ONE pipeline that could fail again in a different way. `scan_responder::is_confirmed_any`
//! is the fix for that: it ORs this tracker's (ip, mac)-keyed verdict with an INDEPENDENT signal —
//! this device's own conntrack table showing an ESTABLISHED flow for the claimed ip
//! (`scan_responder::conntrack_established`, reading the same `/var/lib/hookprobe/flows` stream
//! `napse_loader::event::NapseEvent` already renders). That check deliberately lives in
//! `scan_responder.rs`, not here: this module stays a pure, file-I/O-free packet tracker (its
//! whole value is being independently testable against synthetic packet sequences); conntrack
//! evidence is inherently file/kernel-state I/O, which belongs with `scan_responder`'s other
//! enrichment file-reads. [`confirmed_via_either`] below is the pure combinator half of that fix
//! that DOES belong next to `HandshakeTracker` — callers that already have both booleans in hand
//! (this tracker's `is_confirmed` result and a conntrack lookup) can use it directly instead of
//! duplicating the `||`. The anti-spoof invariant is unchanged either way: a source with NEITHER
//! signal true still never confirms.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HandshakeConfig {
    /// Bound on tracked half-open flow attempts (SYN sent, or SYN-ACK seen but not yet ACKed) —
    /// caps memory against an attacker opening unbounded half-open state. FIFO-evicted, oldest
    /// first, same discipline as `portscan::PortScanConfig::max_sources`.
    pub max_flows: usize,
    /// A half-open flow attempt older than this (by its SYN's observed time) is never allowed to
    /// complete a handshake — closes a stale/replayed-SYN-ACK window and bounds how long a slot in
    /// `max_flows` can be pinned by an attempt that will never finish.
    pub half_open_ttl_secs: f64,
    /// Bound on the confirmed-source set (distinct `(ip, mac)` pairs). FIFO-evicted, oldest first
    /// — losing a confirmation just means that pair must re-earn it (fail CLOSED toward "not
    /// confirmed", never permissive).
    pub max_confirmed: usize,
    /// 2026-07-05 Q6 fix: how long a confirmation counts as recent evidence. A `(ip, mac)` pair
    /// whose last validated handshake is older than this is treated as NOT confirmed — recent
    /// evidence, not a permanent vouch. Config-knobbable (`NAPSE_CONFIRM_TTL_SECS` in
    /// `bin/napse-dpi.rs`); minutes-scale by default.
    pub confirmed_ttl_secs: f64,
}

pub const DEFAULT_MAX_FLOWS: usize = 4096;
pub const DEFAULT_HALF_OPEN_TTL_SECS: f64 = 30.0;
pub const DEFAULT_MAX_CONFIRMED: usize = 8192;
/// 10 minutes — long enough that an actively-connecting host stays confirmed across a normal scan
/// burst, short enough that a confirmation earned once cannot silently authorize enforcement on a
/// claimed source indefinitely (Q6).
pub const DEFAULT_CONFIRMED_TTL_SECS: f64 = 600.0;

impl Default for HandshakeConfig {
    fn default() -> Self {
        HandshakeConfig {
            max_flows: DEFAULT_MAX_FLOWS,
            half_open_ttl_secs: DEFAULT_HALF_OPEN_TTL_SECS,
            max_confirmed: DEFAULT_MAX_CONFIRMED,
            confirmed_ttl_secs: DEFAULT_CONFIRMED_TTL_SECS,
        }
    }
}

/// A flow keyed on the CONNECTION-INITIATOR's tuple (`a` = whoever sent the first SYN). Both the
/// forward direction (a→b, the SYN and eventually the final ACK) and the reverse direction (b→a,
/// the SYN-ACK) resolve to the SAME key by construction — see `observe`'s direction handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    a: Ipv4Addr,
    a_port: u16,
    b: Ipv4Addr,
    b_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Stage {
    /// `a`'s opening SYN was observed; `isn_a` is its sequence number.
    SynSent { isn_a: u32, ts: f64 },
    /// A SYN-ACK from `b` was observed AND its ack-number correctly acknowledged `isn_a` — i.e.
    /// this SYN-ACK is bound to THIS specific SYN, not a stray/replayed one. `isn_b` is `b`'s own
    /// chosen sequence number, which the final ACK must in turn acknowledge.
    SynAckSeen { isn_b: u32, ts: f64 },
}

/// The confirmed-set key: a claimed IP is only meaningfully "confirmed" together with the OBSERVED
/// L2 address of the packet that proved it — see this module's Q2 doc section.
type ConfirmedKey = (Ipv4Addr, [u8; 6]);

/// Bounded, pure tracker: feed every TCP packet observed on the mirror (both directions, as
/// `dpi::TcpObs` already reports them); ask `is_confirmed` for the enforcement-gating decision.
pub struct HandshakeTracker {
    cfg: HandshakeConfig,
    flows: HashMap<FlowKey, Stage>,
    order: VecDeque<FlowKey>,
    /// Last-confirmed timestamp per `(ip, mac)` pair. A repeat confirmation of an already-present
    /// pair refreshes the timestamp (extends recency) without disturbing FIFO eviction order —
    /// mirrors `scan_responder::reconcile_quarantine`'s "refresh on re-observe, don't re-add".
    confirmed: HashMap<ConfirmedKey, f64>,
    confirmed_order: VecDeque<ConfirmedKey>,
}

impl HandshakeTracker {
    pub fn new(cfg: HandshakeConfig) -> Self {
        HandshakeTracker {
            cfg,
            flows: HashMap::new(),
            order: VecDeque::new(),
            confirmed: HashMap::new(),
            confirmed_order: VecDeque::new(),
        }
    }

    /// `true` iff the PAIR `(ip, mac)` has completed at least one validated 3-way handshake as
    /// seen on the mirror, that confirmation hasn't expired (`confirmed_ttl_secs`, Q6), and it
    /// hasn't since been evicted from the bounded confirmed set (`HandshakeConfig::max_confirmed`).
    ///
    /// 2026-07-05 Q2 fix: deliberately NOT `is_confirmed(ip)` — a claimed IP alone proves nothing;
    /// the OBSERVED mac of the packet asking to be trusted must match the mac that actually earned
    /// the confirmation. `now` is the caller's current time (the alert-emission timestamp in
    /// `bin/napse-dpi.rs`), not stored state — this function is otherwise a pure lookup.
    pub fn is_confirmed(&self, ip: &Ipv4Addr, mac: &[u8; 6], now: f64) -> bool {
        self.confirmed.get(&(*ip, *mac)).is_some_and(|&ts| now - ts <= self.cfg.confirmed_ttl_secs)
    }

    /// Convenience wrapper: `is_confirmed`'s verdict OR-ed with an independent conntrack-
    /// ESTABLISHED signal the caller already looked up elsewhere (2026-07-06 fix, F4 — see this
    /// module's top doc comment). Equivalent to
    /// `self.is_confirmed(ip, mac, now) || conntrack_established`, spelled out as a named method
    /// so call sites read as "confirmed via either signal" rather than a bare boolean-or. Neither
    /// signal is weakened by this: passing `conntrack_established = false` reduces exactly to
    /// `is_confirmed`'s own behavior.
    pub fn is_confirmed_via_either(&self, ip: &Ipv4Addr, mac: &[u8; 6], now: f64, conntrack_established: bool) -> bool {
        confirmed_via_either(self.is_confirmed(ip, mac, now), conntrack_established)
    }

    fn mark_confirmed(&mut self, ip: Ipv4Addr, mac: [u8; 6], now: f64) {
        let key = (ip, mac);
        let is_new_key = !self.confirmed.contains_key(&key);
        self.confirmed.insert(key, now);
        if is_new_key {
            if self.confirmed.len() > self.cfg.max_confirmed.max(1) {
                if let Some(old) = self.confirmed_order.pop_front() {
                    self.confirmed.remove(&old);
                }
            }
            self.confirmed_order.push_back(key);
        }
    }

    fn evict_flows_if_full(&mut self) {
        let cap = self.cfg.max_flows.max(1);
        while self.flows.len() >= cap {
            match self.order.pop_front() {
                Some(old) => {
                    self.flows.remove(&old);
                }
                None => break,
            }
        }
    }

    fn insert_flow(&mut self, key: FlowKey, stage: Stage) {
        if !self.flows.contains_key(&key) {
            self.evict_flows_if_full();
            self.order.push_back(key);
        }
        self.flows.insert(key, stage);
    }

    /// Feed one TCP packet observation (either direction). `src`/`dst`/`sport`/`dport` are this
    /// packet's OWN header fields (not canonicalized) — `syn`/`ack` are the TCP flag bits, `seq`/
    /// `ack_num` the raw header values, `src_mac` the OBSERVED Ethernet source address of THIS
    /// frame (2026-07-05 Q2 fix — never resolved from `src` afterward; see `dpi::parse_tcp_obs`).
    /// Returns `true` iff THIS call newly confirms `(src, src_mac)` (only meaningful for the
    /// final-ACK case; harmless to ignore otherwise).
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &mut self,
        now: f64,
        src: Ipv4Addr,
        sport: u16,
        dst: Ipv4Addr,
        dport: u16,
        syn: bool,
        ack: bool,
        seq: u32,
        ack_num: u32,
        src_mac: [u8; 6],
    ) -> bool {
        if syn && !ack {
            // Opening SYN: a = src (the initiator), b = dst (the target).
            let key = FlowKey { a: src, a_port: sport, b: dst, b_port: dport };
            self.insert_flow(key, Stage::SynSent { isn_a: seq, ts: now });
            return false;
        }
        if syn && ack {
            // SYN-ACK reply: THIS packet's src is "b", dst is "a" — reconstruct the flow key from
            // the initiator's perspective (a = this packet's dst).
            let key = FlowKey { a: dst, a_port: dport, b: src, b_port: sport };
            if let Some(Stage::SynSent { isn_a, ts }) = self.flows.get(&key).copied() {
                if now - ts <= self.cfg.half_open_ttl_secs && ack_num == isn_a.wrapping_add(1) {
                    self.insert_flow(key, Stage::SynAckSeen { isn_b: seq, ts });
                }
            }
            return false;
        }
        if !syn && ack {
            // Candidate final ACK: a = src (the flow's original initiator), b = dst. Confirmation
            // is stamped on the PAIR (src, src_mac) — the mac observed on THIS packet, i.e. the
            // hardware that actually produced the validly-acknowledging final ACK (Q2).
            let key = FlowKey { a: src, a_port: sport, b: dst, b_port: dport };
            if let Some(Stage::SynAckSeen { isn_b, ts }) = self.flows.get(&key).copied() {
                if now - ts <= self.cfg.half_open_ttl_secs && ack_num == isn_b.wrapping_add(1) {
                    self.flows.remove(&key); // handshake complete — no need to keep half-open state
                    let newly = !self.is_confirmed(&src, &src_mac, now);
                    self.mark_confirmed(src, src_mac, now);
                    return newly;
                }
            }
        }
        false
    }
}

/// Pure combinator (2026-07-06 fix, F4): a source is confirmed if EITHER the mirror-fed
/// handshake tracker saw it (`handshake_confirmed`) OR an independent conntrack-ESTABLISHED
/// lookup names it (`conntrack_established`). See this module's top doc comment for the full
/// rationale — this function intentionally does no I/O and takes no tracker state; it exists so
/// the "OR the two confirmation signals" rule is written once, by name, rather than re-derived
/// ad hoc at each call site (here and in `hookprobe_manifest::scan_responder::is_confirmed_any`,
/// which is the file-I/O-doing counterpart that actually reads `/var/lib/hookprobe/flows`).
pub fn confirmed_via_either(handshake_confirmed: bool, conntrack_established: bool) -> bool {
    handshake_confirmed || conntrack_established
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(o: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, o)
    }

    const MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    const SERVER_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

    // (a) a bare, single spoofed SYN burst (never any reply seen) must NEVER confirm the source —
    // this is the core anti-DoS proof: an off-path spoofer only ever gets to send the FIRST packet.
    #[test]
    fn a_bare_syn_burst_never_confirms() {
        let mut t = HandshakeTracker::new(HandshakeConfig::default());
        let scanner = addr(7);
        for port in 1000..1050u16 {
            t.observe(100.0, scanner, 40000, Ipv4Addr::new(10, 66, 0, 1), port, true, false, 1000, 0, MAC);
        }
        assert!(!t.is_confirmed(&scanner, &MAC, 100.0), "SYN-only fan-out must never confirm on its own");
    }

    // (b) full validated handshake (SYN, SYN-ACK acking the right ISN, final ACK acking the
    // right ISN) confirms the (ip, mac) pair.
    #[test]
    fn a_completed_handshake_confirms_the_source() {
        let mut t = HandshakeTracker::new(HandshakeConfig::default());
        let client = addr(9);
        let server = Ipv4Addr::new(10, 66, 0, 1);
        assert!(!t.observe(100.0, client, 40000, server, 22, true, false, 1000, 0, MAC), "SYN alone: not yet");
        assert!(!t.is_confirmed(&client, &MAC, 100.0));
        assert!(
            !t.observe(100.1, server, 22, client, 40000, true, true, 5000, 1001, SERVER_MAC),
            "SYN-ACK alone: not yet"
        );
        assert!(!t.is_confirmed(&client, &MAC, 100.1));
        let newly = t.observe(100.2, client, 40000, server, 22, false, true, 1001, 5001, MAC);
        assert!(newly, "the final, correctly-acking ACK completes the handshake");
        assert!(t.is_confirmed(&client, &MAC, 100.2));
    }

    // Q2 — THE CORE re-audit proof: the victim's own real (ip, mac) confirmation must never
    // extend to an attacker claiming the same IP from a DIFFERENT mac. Before this fix, the
    // confirmed set was keyed on Ipv4Addr alone, so V's own innocent traffic would silently
    // "vouch" for anyone spoofing V's IP.
    #[test]
    fn confirming_via_one_mac_does_not_confirm_the_same_ip_from_a_different_mac() {
        let mut t = HandshakeTracker::new(HandshakeConfig::default());
        let victim = addr(30);
        let victim_mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let attacker_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        let server = Ipv4Addr::new(10, 66, 0, 1);

        // Victim's OWN legitimate outbound traffic completes a real handshake.
        t.observe(100.0, victim, 40000, server, 443, true, false, 1000, 0, victim_mac);
        t.observe(100.1, server, 443, victim, 40000, true, true, 5000, 1001, SERVER_MAC);
        t.observe(100.2, victim, 40000, server, 443, false, true, 1001, 5001, victim_mac);

        assert!(t.is_confirmed(&victim, &victim_mac, 100.2), "the victim's real (ip, mac) IS confirmed");
        assert!(
            !t.is_confirmed(&victim, &attacker_mac, 100.2),
            "an attacker spoofing the victim's IP from a DIFFERENT mac must NOT inherit the victim's confirmation \
             (this is the reflected-DoS the (ip,mac) keying closes)"
        );
    }

    // An off-path spoofer CANNOT forge the final ACK correctly (it never learns the real ISN the
    // device chose) — a guessed/blind ACK with the wrong ack-number must not confirm.
    #[test]
    fn a_blindly_guessed_final_ack_with_wrong_ack_number_does_not_confirm() {
        let mut t = HandshakeTracker::new(HandshakeConfig::default());
        let spoofed = addr(11);
        let server = Ipv4Addr::new(10, 66, 0, 1);
        t.observe(100.0, spoofed, 40000, server, 22, true, false, 1000, 0, MAC);
        t.observe(100.1, server, 22, spoofed, 40000, true, true, 5000, 1001, SERVER_MAC);
        // attacker blindly guesses ack_num (never actually saw the real SYN-ACK) — wrong value.
        let newly = t.observe(100.2, spoofed, 40000, server, 22, false, true, 1001, 9999, MAC);
        assert!(!newly && !t.is_confirmed(&spoofed, &MAC, 100.2), "a wrong ack-number must never confirm");
    }

    // A SYN-ACK whose own ack-number doesn't match the SYN's ISN (a stray/unrelated reply) must
    // not advance state — only a SYN-ACK genuinely bound to the observed SYN counts.
    #[test]
    fn an_unbound_synack_does_not_advance_state() {
        let mut t = HandshakeTracker::new(HandshakeConfig::default());
        let client = addr(13);
        let server = Ipv4Addr::new(10, 66, 0, 1);
        t.observe(100.0, client, 40000, server, 22, true, false, 1000, 0, MAC);
        // SYN-ACK with the WRONG ack number (not isn_a+1) — must not bind.
        t.observe(100.1, server, 22, client, 40000, true, true, 5000, 42, SERVER_MAC);
        let newly = t.observe(100.2, client, 40000, server, 22, false, true, 1001, 5001, MAC);
        assert!(
            !newly && !t.is_confirmed(&client, &MAC, 100.2),
            "an unbound SYN-ACK must not let the final ACK complete anything"
        );
    }

    // Stale half-open attempts (older than half_open_ttl_secs) must not be completable — closes
    // the window a replayed/delayed SYN-ACK could exploit.
    #[test]
    fn a_stale_half_open_attempt_expires() {
        let cfg = HandshakeConfig { half_open_ttl_secs: 5.0, ..Default::default() };
        let mut t = HandshakeTracker::new(cfg);
        let client = addr(15);
        let server = Ipv4Addr::new(10, 66, 0, 1);
        t.observe(100.0, client, 40000, server, 22, true, false, 1000, 0, MAC);
        // SYN-ACK arrives 10s later — stale, must not bind.
        t.observe(110.0, server, 22, client, 40000, true, true, 5000, 1001, SERVER_MAC);
        let newly = t.observe(110.1, client, 40000, server, 22, false, true, 1001, 5001, MAC);
        assert!(!newly && !t.is_confirmed(&client, &MAC, 110.1));
    }

    #[test]
    fn max_flows_bounds_half_open_state() {
        let cfg = HandshakeConfig { max_flows: 4, ..Default::default() };
        let mut t = HandshakeTracker::new(cfg);
        let server = Ipv4Addr::new(10, 66, 0, 1);
        for i in 0..100u8 {
            t.observe(1000.0 + i as f64, Ipv4Addr::new(192, 168, 1, i), 1, server, 22, true, false, 1, 0, MAC);
        }
        assert!(t.flows.len() <= 4, "half-open flow state must stay bounded");
    }

    #[test]
    fn max_confirmed_bounds_the_confirmed_set() {
        let cfg = HandshakeConfig { max_confirmed: 4, ..Default::default() };
        let mut t = HandshakeTracker::new(cfg);
        let server = Ipv4Addr::new(10, 66, 0, 1);
        for i in 0..20u8 {
            let client = Ipv4Addr::new(192, 168, 1, i);
            t.observe(1000.0, client, 40000, server, 22, true, false, 1000, 0, MAC);
            t.observe(1000.1, server, 22, client, 40000, true, true, 5000, 1001, SERVER_MAC);
            t.observe(1000.2, client, 40000, server, 22, false, true, 1001, 5001, MAC);
        }
        assert!(t.confirmed.len() <= 4, "confirmed set must stay bounded");
    }

    // Multiple independent flows from the SAME (source, mac): confirming via ONE flow is enough —
    // the (ip, mac) pair itself is what gets marked confirmed, not the individual flow.
    #[test]
    fn confirming_one_flow_confirms_the_whole_source() {
        let mut t = HandshakeTracker::new(HandshakeConfig::default());
        let client = addr(21);
        let server = Ipv4Addr::new(10, 66, 0, 1);
        t.observe(100.0, client, 40000, server, 80, true, false, 1000, 0, MAC);
        t.observe(100.1, server, 80, client, 40000, true, true, 5000, 1001, SERVER_MAC);
        t.observe(100.2, client, 40000, server, 80, false, true, 1001, 5001, MAC);
        assert!(t.is_confirmed(&client, &MAC, 100.2));
    }

    // Q6 — THE CORE TTL re-audit proof: a confirmation is recent evidence, not forever.
    #[test]
    fn confirmation_expires_after_its_ttl() {
        let cfg = HandshakeConfig { confirmed_ttl_secs: 60.0, ..Default::default() };
        let mut t = HandshakeTracker::new(cfg);
        let client = addr(40);
        let server = Ipv4Addr::new(10, 66, 0, 1);
        t.observe(1000.0, client, 40000, server, 22, true, false, 1000, 0, MAC);
        t.observe(1000.1, server, 22, client, 40000, true, true, 5000, 1001, SERVER_MAC);
        t.observe(1000.2, client, 40000, server, 22, false, true, 1001, 5001, MAC);

        assert!(t.is_confirmed(&client, &MAC, 1000.2), "just confirmed");
        assert!(t.is_confirmed(&client, &MAC, 1050.0), "still within the 60s ttl");
        assert!(
            !t.is_confirmed(&client, &MAC, 1070.0),
            "expired: confirmation is recent evidence, not a permanent vouch"
        );
    }

    // Q6 — re-observing (refreshing) BEFORE expiry extends the window; a confirmation an attacker
    // cannot forge still has to be re-earned once it goes stale, but an actively-connecting host
    // simply keeps refreshing it, same idempotent-refresh spirit as the quarantine TTL.
    #[test]
    fn confirmation_refreshes_on_repeat_handshake_before_expiry() {
        let cfg = HandshakeConfig { confirmed_ttl_secs: 60.0, ..Default::default() };
        let mut t = HandshakeTracker::new(cfg);
        let client = addr(41);
        let server = Ipv4Addr::new(10, 66, 0, 1);
        t.observe(1000.0, client, 40000, server, 22, true, false, 1000, 0, MAC);
        t.observe(1000.1, server, 22, client, 40000, true, true, 5000, 1001, SERVER_MAC);
        t.observe(1000.2, client, 40000, server, 22, false, true, 1001, 5001, MAC);

        // 50s later (still within ttl): a fresh handshake refreshes last-confirmed time.
        t.observe(1050.0, client, 50000, server, 22, true, false, 2000, 0, MAC);
        t.observe(1050.1, server, 22, client, 50000, true, true, 6000, 2001, SERVER_MAC);
        t.observe(1050.2, client, 50000, server, 22, false, true, 2001, 6001, MAC);

        // Without the refresh this would be 1000.2 + 60 = 1060.2 and already expired; the refresh
        // at 1050.2 pushes the expiry out to 1110.2.
        assert!(t.is_confirmed(&client, &MAC, 1100.0), "refreshed confirmation must still be valid");
    }

    // ---- confirmed_via_either / is_confirmed_via_either — 2026-07-06 fix (F4) ------------------

    #[test]
    fn confirmed_via_either_is_true_if_either_signal_is_true() {
        assert!(confirmed_via_either(true, false));
        assert!(confirmed_via_either(false, true));
        assert!(confirmed_via_either(true, true));
    }

    #[test]
    fn confirmed_via_either_is_false_only_when_both_are_false() {
        assert!(!confirmed_via_either(false, false), "the anti-spoof floor: neither signal confirms => not confirmed");
    }

    // THE CORE F4 PROOF at the tracker level: a source the mirror never saw a handshake for
    // (simulating the pre-F1 dead-ingress-mirror bug — `is_confirmed` alone is false) still
    // confirms once an independent conntrack-ESTABLISHED signal is supplied.
    #[test]
    fn is_confirmed_via_either_confirms_via_conntrack_when_the_tracker_never_saw_a_handshake() {
        let t = HandshakeTracker::new(HandshakeConfig::default());
        let scanner = addr(50);
        assert!(!t.is_confirmed(&scanner, &MAC, 100.0), "tracker alone: never saw any packets for this source");
        assert!(
            t.is_confirmed_via_either(&scanner, &MAC, 100.0, true),
            "conntrack ESTABLISHED must confirm even when the mirror-fed tracker never observed the handshake"
        );
    }

    #[test]
    fn is_confirmed_via_either_stays_false_when_neither_signal_confirms() {
        let t = HandshakeTracker::new(HandshakeConfig::default());
        let scanner = addr(51);
        assert!(!t.is_confirmed_via_either(&scanner, &MAC, 100.0, false), "an unconfirmed, conntrack-absent source must never confirm");
    }
}
