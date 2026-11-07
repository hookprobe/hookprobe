//! WAN health with hysteresis (parity gap G16 — V1 `wan-failover-pbr.sh` did ping + HTTP checks with
//! hysteresis; heqk only had ARP liveness, so a gateway that answers ARP while the internet behind it is
//! dead counted as "up" and the metric-route failover never moved).
//!
//! Pure: the caller sends an ICMP echo per probe slot to `target(i)` (alternating the gateway and an
//! internet anchor, so "local link down" and "upstream down" are told apart) and reports each outcome.
//! States: UP → DEGRADED (loss > 30 % or median-ish RTT > 400 ms over the last 10) → DOWN after 3
//! consecutive internet-probe failures; back UP only after 2 consecutive successes (no flapping).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Unknown,
    Up,
    Degraded,
    Down,
}

impl State {
    pub fn name(self) -> &'static str {
        ["unknown", "up", "degraded", "down"][self as usize]
    }
}

pub const DOWN_AFTER: u8 = 3;
pub const UP_AFTER: u8 = 2;
const WIN: usize = 10;

pub struct WanHealth {
    pub state: State,
    pub gw_ok: bool,
    fails: u8,
    oks: u8,
    ring: [(bool, u16); WIN], // (ok, rtt ms) of internet probes
    rn: usize,
    rpos: usize,
    pub transitions: u32,
    pub probes: u32,
}

/// Internet anchors probed in turn (IP literals; ICMP echo).
pub const ANCHORS: [[u8; 4]; 2] = [[1, 1, 1, 1], [9, 9, 9, 9]];

impl WanHealth {
    pub const fn new() -> Self {
        WanHealth { state: State::Unknown, gw_ok: false, fails: 0, oks: 0, ring: [(false, 0); WIN], rn: 0, rpos: 0, transitions: 0, probes: 0 }
    }

    /// Probe slot `i`: even slots probe the gateway, odd slots an internet anchor.
    pub fn target(i: u32, gw: [u8; 4]) -> ([u8; 4], bool) {
        if i % 2 == 0 { (gw, false) } else { (ANCHORS[(i as usize / 2) % ANCHORS.len()], true) }
    }

    /// Report one probe. `internet` = it was an anchor probe. Returns Some(new state) on a transition.
    pub fn report(&mut self, internet: bool, ok: bool, rtt_ms: u16) -> Option<State> {
        self.probes = self.probes.wrapping_add(1);
        if !internet {
            self.gw_ok = ok; // reported, never by itself an outage (the anchor probes decide)
            return None;
        }
        self.ring[self.rpos] = (ok, rtt_ms);
        self.rpos = (self.rpos + 1) % WIN;
        self.rn = (self.rn + 1).min(WIN);
        if ok {
            self.oks = self.oks.saturating_add(1);
            self.fails = 0;
        } else {
            self.fails = self.fails.saturating_add(1);
            self.oks = 0;
        }
        let new = if self.fails >= DOWN_AFTER {
            State::Down
        } else if matches!(self.state, State::Down | State::Unknown) {
            if self.oks >= UP_AFTER { self.quality() } else { self.state }
        } else if ok || self.fails < DOWN_AFTER {
            self.quality()
        } else {
            self.state
        };
        if new != self.state {
            self.state = new;
            self.transitions += 1;
            return Some(new);
        }
        None
    }

    /// UP or DEGRADED from the window (loss > 30 % over ≥ 5 samples, or the 2nd-highest RTT > 400 ms → degraded).
    fn quality(&self) -> State {
        let w = &self.ring[..self.rn];
        let lost = w.iter().filter(|p| !p.0).count();
        let mut rtts = [0u16; WIN];
        let mut n = 0;
        for p in w.iter().filter(|p| p.0) {
            rtts[n] = p.1;
            n += 1;
        }
        rtts[..n].sort_unstable();
        let high = if n >= 2 { rtts[n - 2] } else if n == 1 { rtts[0] } else { 0 };
        // loss needs ≥ 5 samples to mean anything (1 of 3 is noise, not a degraded link)
        if (self.rn >= 5 && lost * 100 > self.rn * 30) || high > 400 { State::Degraded } else { State::Up }
    }

    /// Usable for routing (failover moves traffic off a DOWN uplink; DEGRADED still carries it).
    pub fn usable(&self) -> bool {
        matches!(self.state, State::Up | State::Degraded | State::Unknown)
    }
}

/// ICMP echo identifier of our probes (replies with it are ours, never NATed to a client).
pub const PROBE_ID: u16 = 0x4851; // "HQ"

/// Build the echo request (Ethernet/IPv4/ICMP) for probe `seq` into `out`; returns its length.
pub fn echo_request(out: &mut [u8], smac: &[u8; 6], dmac: &[u8; 6], sip: [u8; 4], dip: [u8; 4], seq: u16) -> usize {
    let total = 14 + 20 + 8 + 16;
    out[..total].fill(0);
    out[0..6].copy_from_slice(dmac);
    out[6..12].copy_from_slice(smac);
    out[12..14].copy_from_slice(&[0x08, 0x00]);
    out[14..34].copy_from_slice(&[0x45, 0, 0, 44, 0, 0, 0x40, 0, 64, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    out[26..30].copy_from_slice(&sip);
    out[30..34].copy_from_slice(&dip);
    let c = csum(&out[14..34]);
    out[24..26].copy_from_slice(&c.to_be_bytes());
    out[34] = 8; // echo request
    out[38..40].copy_from_slice(&PROBE_ID.to_be_bytes());
    out[40..42].copy_from_slice(&seq.to_be_bytes());
    out[42..58].copy_from_slice(b"hookprobe-health");
    let c = csum(&out[34..total]);
    out[36..38].copy_from_slice(&c.to_be_bytes());
    total
}

/// Is `f` an echo REPLY to one of our probes (to `wan_ip`)? → Some(seq).
pub fn probe_reply(f: &[u8], wan_ip: [u8; 4]) -> Option<u16> {
    if f.len() < 42 || f[12..14] != [0x08, 0x00] || f[14] >> 4 != 4 || f[23] != 1 || f[30..34] != wan_ip {
        return None;
    }
    let i = 14 + ((f[14] & 0x0f) as usize) * 4;
    let h = f.get(i..i + 8)?;
    (h[0] == 0 && u16::from_be_bytes([h[4], h[5]]) == PROBE_ID).then(|| u16::from_be_bytes([h[6], h[7]]))
}

fn csum(b: &[u8]) -> u16 {
    let mut s = 0u32;
    let mut i = 0;
    while i + 1 < b.len() {
        s += u16::from_be_bytes([b[i], b[i + 1]]) as u32;
        i += 2;
    }
    if i < b.len() {
        s += (b[i] as u32) << 8;
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

/// `[P-wanhealth]`
pub fn selftest() -> bool {
    let mut h = WanHealth::new();
    let up = { h.report(true, true, 20); h.report(true, true, 22) == Some(State::Up) };
    let one_fail = { h.report(true, false, 0); h.state == State::Up }; // a single loss is not an outage
    let two_fail = { h.report(true, false, 0); h.state != State::Down };
    let down = h.report(true, false, 0) == Some(State::Down) && !h.usable();
    let no_flap = { h.report(true, true, 20); h.state == State::Down };
    let back = h.report(true, true, 20).is_some() && h.usable();
    let mut d = WanHealth::new();
    for _ in 0..6 {
        d.report(true, true, 600);
    }
    let degraded = d.state == State::Degraded && d.usable();
    let mut g = WanHealth::new();
    g.report(false, false, 0);
    let gw_only = !g.gw_ok && g.state == State::Unknown; // a gateway miss alone never declares an outage
    let slots = WanHealth::target(0, [10, 0, 0, 1]) == ([10, 0, 0, 1], false) && WanHealth::target(1, [10, 0, 0, 1]) == ([1, 1, 1, 1], true) && WanHealth::target(3, [10, 0, 0, 1]) == ([9, 9, 9, 9], true);
    let mut fr = [0u8; 64];
    let n = echo_request(&mut fr, &[2, 0, 0, 0, 0, 2], &[2, 0, 0, 0, 0, 1], [100, 71, 11, 24], [1, 1, 1, 1], 7);
    let req_ok = n == 58 && csum(&fr[14..34]) == 0 && csum(&fr[34..58]) == 0 && fr[34] == 8;
    // turn it into the reply the anchor would send
    let mut rp = fr;
    rp[26..30].copy_from_slice(&[1, 1, 1, 1]);
    rp[30..34].copy_from_slice(&[100, 71, 11, 24]);
    rp[34] = 0;
    let reply_ok = probe_reply(&rp[..n], [100, 71, 11, 24]) == Some(7) && probe_reply(&fr[..n], [100, 71, 11, 24]).is_none()
        && { let mut other = rp; other[39] ^= 1; probe_reply(&other[..n], [100, 71, 11, 24]).is_none() }
        && (0..n).all(|l| probe_reply(&rp[..l], [100, 71, 11, 24]).is_none() || l >= 42);
    let pass = req_ok && reply_ok && up && one_fail && two_fail && down && no_flap && back && degraded && gw_only && slots;
    arch_aarch64::_print(format_args!(
        " [P-wanhealth] {} — WAN health with hysteresis (parity G16): echo probe frame={} only replies with our id={} | 2 OKs -> UP={} one loss stays UP={} two losses not DOWN={} 3 consecutive -> DOWN (failover moves traffic)={} one OK after DOWN does not flap back={} 2 OKs -> back={} high RTT -> DEGRADED (still carries traffic)={} gateway miss alone never an outage={} gateway/anchor probe slots={}\n",
        if pass { "PASS" } else { "FAIL" }, req_ok, reply_ok, up, one_fail, two_fail, down, no_flap, back, degraded, gw_only, slots
    ));
    pass
}
