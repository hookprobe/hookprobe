//! The management ABI (ADR 0059 D9; hsh spec §14): ONE bounded message set every management client uses — the
//! native shell `hsh` (EL0) today, Mission Control's handlers over time. Explicit ids, a version, fixed little-endian
//! records, explicit result codes. Shared by the kernel (`kernel/src/mgmtabi.rs`, the dispatcher, served by the SAME
//! producers as `GET /api/*`) and `el0-hsh` (the formatter), so the two cannot drift.
//!
//! Step 4a carries the READ messages (role `view`). Configuration (4b) and owner (4c) messages map onto cfgd and the
//! /api/anchor backend and are added with their commands.

pub const VERSION: u16 = 1;

// ---- message ids ----
pub const GET_INFO: u16 = 1;
pub const GET_WAN: u16 = 2;
pub const GET_QSECBIT: u16 = 3;
pub const GET_CONFIG: u16 = 4;
pub const GET_ANCHOR: u16 = 5;
pub const GET_PARSERS: u16 = 6;
// step 4b: configuration operations — served by cfgd / the upload path; the kernel journals each (allowed or refused)
pub const CFG_CONFIRM: u16 = 20;
pub const CFG_ROLLBACK: u16 = 21;
/// arg = the caller's VERIFIED upload id (type `config`): activate it -> PENDING -> trial at the next boot
pub const CFG_STAGE: u16 = 22;
// step 4c: owner elevation (hsh spec §6.3). CHALLENGE: a single-use nonce (120 s) bound to this device;
// ELEVATE: payload = Ed25519 by the ENROLLED owner key over "HQCHAL1" || device_id || nonce -> this session holds the
// owner role for ELEVATE_TTL_S. Enrollment / rotation stay in Mission Control (two or three signatures, and there is
// no owner key to elevate with before enrollment).
pub const OWNER_CHALLENGE: u16 = 30;
pub const OWNER_ELEVATE: u16 = 31;
pub const ELEVATE_TTL_S: u64 = 900;
pub const CHALLENGE_TTL_S: u64 = 120;

// ---- result codes ----
pub const R_OK: u8 = 0;
pub const R_UNKNOWN: u8 = 1;
pub const R_DENIED: u8 = 2;
pub const R_UNAVAILABLE: u8 = 3;
pub const R_BAD: u8 = 4;

// ---- roles (ADR 0059 D9) ----
pub const ROLE_VIEW: u8 = 1;
pub const ROLE_OPERATE: u8 = 2;
pub const ROLE_CONFIG: u8 = 3;
pub const ROLE_OWNER: u8 = 4;

/// The role a message needs.
pub fn role_for(msg: u16) -> u8 {
    match msg {
        GET_INFO | GET_WAN | GET_QSECBIT | GET_CONFIG | GET_ANCHOR | GET_PARSERS => ROLE_VIEW,
        CFG_CONFIRM | CFG_ROLLBACK => ROLE_OPERATE,
        CFG_STAGE => ROLE_CONFIG,
        OWNER_CHALLENGE | OWNER_ELEVATE => ROLE_VIEW,
        _ => u8::MAX,
    }
}

/// Reply record length per message (the kernel writes exactly this; the shell refuses anything else).
pub fn reply_len(msg: u16) -> Option<usize> {
    Some(match msg {
        GET_INFO => INFO_LEN,
        GET_WAN => WAN_LEN,
        GET_QSECBIT => QS_LEN,
        GET_CONFIG => CFG_LEN,
        GET_ANCHOR => ANCHOR_LEN,
        GET_PARSERS => PARSERS_LEN,
        CFG_CONFIRM | CFG_ROLLBACK | CFG_STAGE | OWNER_ELEVATE => ACT_LEN,
        OWNER_CHALLENGE => CHAL_LEN,
        _ => return None,
    })
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

/// GET_INFO: build, uptime, the detection engine's counters, configuration + ownership state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Info {
    pub build: [u8; 24],
    pub uptime_s: u64,
    pub rules_active: u32,
    pub seen: u64,
    pub forwarded: u64,
    pub dropped: u64,
    pub detections: u32,
    pub clock_synced: bool,
    pub config_protected: bool,
    pub owner_enrolled: bool,
    pub cfg_state: u8,
    pub cfg_gen: u64,
}
pub const INFO_LEN: usize = 24 + 8 + 4 + 8 + 8 + 8 + 4 + 4 + 8;
impl Info {
    pub fn encode(&self) -> [u8; INFO_LEN] {
        let mut o = [0u8; INFO_LEN];
        o[..24].copy_from_slice(&self.build);
        o[24..32].copy_from_slice(&self.uptime_s.to_le_bytes());
        o[32..36].copy_from_slice(&self.rules_active.to_le_bytes());
        o[36..44].copy_from_slice(&self.seen.to_le_bytes());
        o[44..52].copy_from_slice(&self.forwarded.to_le_bytes());
        o[52..60].copy_from_slice(&self.dropped.to_le_bytes());
        o[60..64].copy_from_slice(&self.detections.to_le_bytes());
        o[64] = self.clock_synced as u8;
        o[65] = self.config_protected as u8;
        o[66] = self.owner_enrolled as u8;
        o[67] = self.cfg_state;
        o[68..76].copy_from_slice(&self.cfg_gen.to_le_bytes());
        o
    }
    pub fn decode(b: &[u8; INFO_LEN]) -> Self {
        let mut build = [0u8; 24];
        build.copy_from_slice(&b[..24]);
        Info {
            build,
            uptime_s: u64_at(b, 24),
            rules_active: u32_at(b, 32),
            seen: u64_at(b, 36),
            forwarded: u64_at(b, 44),
            dropped: u64_at(b, 52),
            detections: u32_at(b, 60),
            clock_synced: b[64] != 0,
            config_protected: b[65] != 0,
            owner_enrolled: b[66] != 0,
            cfg_state: b[67].min(4),
            cfg_gen: u64_at(b, 68),
        }
    }
}

/// GET_WAN: the WAN facts Mission Control's /api/health shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Wan {
    pub present: bool,
    pub up: bool,
    pub mode: u8,
    pub ipv6: bool,
    pub ip: [u8; 4],
    pub clients: u32,
    pub pkts_out: u64,
    pub pkts_in: u64,
    pub dns_inspected: u64,
    pub dns_blocked: u64,
}
pub const WAN_LEN: usize = 4 + 4 + 4 + 8 * 4;
impl Wan {
    pub fn encode(&self) -> [u8; WAN_LEN] {
        let mut o = [0u8; WAN_LEN];
        o[0] = self.present as u8;
        o[1] = self.up as u8;
        o[2] = self.mode;
        o[3] = self.ipv6 as u8;
        o[4..8].copy_from_slice(&self.ip);
        o[8..12].copy_from_slice(&self.clients.to_le_bytes());
        o[12..20].copy_from_slice(&self.pkts_out.to_le_bytes());
        o[20..28].copy_from_slice(&self.pkts_in.to_le_bytes());
        o[28..36].copy_from_slice(&self.dns_inspected.to_le_bytes());
        o[36..44].copy_from_slice(&self.dns_blocked.to_le_bytes());
        o
    }
    pub fn decode(b: &[u8; WAN_LEN]) -> Self {
        Wan {
            present: b[0] != 0,
            up: b[1] != 0,
            mode: b[2].min(2),
            ipv6: b[3] != 0,
            ip: [b[4], b[5], b[6], b[7]],
            clients: u32_at(b, 8),
            pkts_out: u64_at(b, 12),
            pkts_in: u64_at(b, 20),
            dns_inspected: u64_at(b, 28),
            dns_blocked: u64_at(b, 36),
        }
    }
}

/// GET_QSECBIT: the latest risk score (milli-units) and its band, as /api/qsecbit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Qs {
    pub present: bool,
    pub score_milli: u32,
    pub band: [u8; 8],
    pub samples: u32,
}
pub const QS_LEN: usize = 1 + 4 + 8 + 4;
impl Qs {
    pub fn encode(&self) -> [u8; QS_LEN] {
        let mut o = [0u8; QS_LEN];
        o[0] = self.present as u8;
        o[1..5].copy_from_slice(&self.score_milli.to_le_bytes());
        o[5..13].copy_from_slice(&self.band);
        o[13..17].copy_from_slice(&self.samples.to_le_bytes());
        o
    }
    pub fn decode(b: &[u8; QS_LEN]) -> Self {
        let mut band = [0u8; 8];
        band.copy_from_slice(&b[5..13]);
        Qs { present: b[0] != 0, score_milli: u32_at(b, 1), band, samples: u32_at(b, 13) }
    }
}

/// GET_CONFIG: cfgd's lifecycle + the generation floors (as /api/config + /api/anchor floors).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cfg {
    /// 0 none, 1 committed, 2 trial, 3 reverted, 4 refused
    pub state: u8,
    pub on_trial: bool,
    pub needs_confirm: bool,
    pub generation: u64,
    pub floor: u64,
    pub elapsed_s: u64,
    pub window_s: u64,
    pub wan_cur: u64,
    pub wan_floor: u64,
    pub wifi_cur: u64,
    pub wifi_floor: u64,
    pub policy_floor: u64,
}
pub const CFG_LEN: usize = 3 + 8 * 9;
impl Cfg {
    pub fn encode(&self) -> [u8; CFG_LEN] {
        let mut o = [0u8; CFG_LEN];
        o[0] = self.state;
        o[1] = self.on_trial as u8;
        o[2] = self.needs_confirm as u8;
        for (i, v) in [self.generation, self.floor, self.elapsed_s, self.window_s, self.wan_cur, self.wan_floor, self.wifi_cur, self.wifi_floor, self.policy_floor].iter().enumerate() {
            o[3 + 8 * i..11 + 8 * i].copy_from_slice(&v.to_le_bytes());
        }
        o
    }
    pub fn decode(b: &[u8; CFG_LEN]) -> Self {
        let v = |i: usize| u64_at(b, 3 + 8 * i);
        Cfg {
            state: b[0].min(4),
            on_trial: b[1] != 0,
            needs_confirm: b[2] != 0,
            generation: v(0),
            floor: v(1),
            elapsed_s: v(2),
            window_s: v(3),
            wan_cur: v(4),
            wan_floor: v(5),
            wifi_cur: v(6),
            wifi_floor: v(7),
            policy_floor: v(8),
        }
    }
}

/// GET_ANCHOR: which keys verify what (fingerprints only — never key material beyond the public fingerprint).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Anchor {
    pub protected: bool,
    pub vendor: Option<[u8; 8]>,
    pub owner: Option<[u8; 8]>,
    pub owner_gen: u64,
}
pub const ANCHOR_LEN: usize = 1 + 1 + 8 + 1 + 8 + 8;
impl Anchor {
    pub fn encode(&self) -> [u8; ANCHOR_LEN] {
        let mut o = [0u8; ANCHOR_LEN];
        o[0] = self.protected as u8;
        if let Some(v) = self.vendor {
            o[1] = 1;
            o[2..10].copy_from_slice(&v);
        }
        if let Some(w) = self.owner {
            o[10] = 1;
            o[11..19].copy_from_slice(&w);
        }
        o[19..27].copy_from_slice(&self.owner_gen.to_le_bytes());
        o
    }
    pub fn decode(b: &[u8; ANCHOR_LEN]) -> Self {
        let fp = |o: usize| -> [u8; 8] { b[o..o + 8].try_into().unwrap() };
        Anchor {
            protected: b[0] != 0,
            vendor: (b[1] != 0).then(|| fp(2)),
            owner: (b[10] != 0).then(|| fp(11)),
            owner_gen: u64_at(b, 19),
        }
    }
}

/// GET_PARSERS: where the network-facing parsers run (ADR 0050) and their EL0 servers' health.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Parsers {
    pub http_el0: bool,
    pub http_requests: u64,
    pub http_faults: u64,
    pub lan_el0: bool,
    pub lan_calls: u64,
    pub lan_faults: u64,
    pub lan_restarts: u64,
    pub lan_in_kernel: u64,
}
pub const PARSERS_LEN: usize = 2 + 8 * 6;
impl Parsers {
    pub fn encode(&self) -> [u8; PARSERS_LEN] {
        let mut o = [0u8; PARSERS_LEN];
        o[0] = self.http_el0 as u8;
        o[1] = self.lan_el0 as u8;
        for (i, v) in [self.http_requests, self.http_faults, self.lan_calls, self.lan_faults, self.lan_restarts, self.lan_in_kernel].iter().enumerate() {
            o[2 + 8 * i..10 + 8 * i].copy_from_slice(&v.to_le_bytes());
        }
        o
    }
    pub fn decode(b: &[u8; PARSERS_LEN]) -> Self {
        let v = |i: usize| u64_at(b, 2 + 8 * i);
        Parsers { http_el0: b[0] != 0, lan_el0: b[1] != 0, http_requests: v(0), http_faults: v(1), lan_calls: v(2), lan_faults: v(3), lan_restarts: v(4), lan_in_kernel: v(5) }
    }
}

/// A configuration operation's outcome (CFG_*): accepted or refused, the generation now in force / staged, and the
/// reason (ASCII, NUL-padded) — never printed as success before this record says so.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Act {
    pub ok: bool,
    pub generation: u64,
    pub reason: [u8; 56],
}
pub const ACT_LEN: usize = 1 + 8 + 56;
impl Act {
    pub fn new(ok: bool, generation: u64, why: &str) -> Self {
        let mut reason = [0u8; 56];
        let b = why.as_bytes();
        let n = b.len().min(56);
        reason[..n].copy_from_slice(&b[..n]);
        Act { ok, generation, reason }
    }
    pub fn encode(&self) -> [u8; ACT_LEN] {
        let mut o = [0u8; ACT_LEN];
        o[0] = self.ok as u8;
        o[1..9].copy_from_slice(&self.generation.to_le_bytes());
        o[9..].copy_from_slice(&self.reason);
        o
    }
    pub fn decode(b: &[u8; ACT_LEN]) -> Self {
        let mut reason = [0u8; 56];
        for (d, &c) in reason.iter_mut().zip(b[9..].iter()) {
            *d = if (0x20..0x7f).contains(&c) { c } else { 0 };
        }
        Act { ok: b[0] != 0, generation: u64_at(b, 1), reason }
    }
    pub fn reason_str(&self) -> &str {
        let n = self.reason.iter().position(|&c| c == 0).unwrap_or(56);
        core::str::from_utf8(&self.reason[..n]).unwrap_or("")
    }
}

/// OWNER_CHALLENGE reply: what the owner signs, off-device: "HQCHAL1" || device_id || nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub device_id: [u8; 16],
    pub nonce: [u8; 16],
    pub ttl_s: u32,
    /// false = no owner key is enrolled: nothing can be elevated (enroll in Mission Control first).
    pub owner_enrolled: bool,
}
pub const CHAL_LEN: usize = 16 + 16 + 4 + 1;
impl Challenge {
    pub fn encode(&self) -> [u8; CHAL_LEN] {
        let mut o = [0u8; CHAL_LEN];
        o[..16].copy_from_slice(&self.device_id);
        o[16..32].copy_from_slice(&self.nonce);
        o[32..36].copy_from_slice(&self.ttl_s.to_le_bytes());
        o[36] = self.owner_enrolled as u8;
        o
    }
    pub fn decode(b: &[u8; CHAL_LEN]) -> Self {
        Challenge { device_id: b[..16].try_into().unwrap(), nonce: b[16..32].try_into().unwrap(), ttl_s: u32_at(b, 32), owner_enrolled: b[36] != 0 }
    }
}
/// The message the owner signs to elevate.
pub fn challenge_msg(device_id: &[u8; 16], nonce: &[u8; 16]) -> [u8; 39] {
    let mut m = [0u8; 39];
    m[..7].copy_from_slice(b"HQCHAL1");
    m[7..23].copy_from_slice(device_id);
    m[23..].copy_from_slice(nonce);
    m
}
