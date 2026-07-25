//! Wi-Fi role → generated artifact. Reuses the stable-identity role assignment from
//! [`crate::net_roles`] (baked into the manifest as `network.wifi_radios`) and the
//! generated-artifact pattern from [`crate::multi_wan`]: the operator declares intent
//! (the station SSID to join, the AP SSID to broadcast); the reconciler renders the
//! config. Station radios get a `wpa_supplicant` client config; AP radios get a
//! `hostapd` config. Files carry a "do not edit — declare intent" banner and are
//! reproduced from the **signed** manifest every run.
//!
//! Crucially, *which* radio is station vs AP is NOT decided here — it comes from the
//! manifest's `wifi_radios` (assigned by `net_roles` from stable identity, never the
//! `wlanN` name). So a Pi's onboard radio stays the uplink and the USB dongle stays
//! the AP, regardless of boot-order renaming.
//!
//! **Per-device AP SSID.** Two devices flashed from the SAME image must not broadcast the
//! SAME SSID — a phone can't tell them apart and they collide on-air. The shipped default
//! intent therefore does NOT hardcode an SSID: when the operator's `ap:` block omits `ssid`
//! (or leaves it empty), [`default_ssid`] derives a stable, unique-per-device suffix from the
//! signed manifest's `identity.device_id` (itself a hardware-fingerprint hash — see
//! `identity::puf_seed` / `builder::build_manifest`) — same device → same SSID across
//! reboots, different devices → different SSIDs, with NO operator action needed
//! (standalone-by-default, ADR-aligned: capability/identity-derived, never hardware-branched).
//! An explicit operator SSID in the intent always wins — see [`resolve_ap_ssid`].

use crate::multi_wan::GeneratedFile;
use crate::types::WifiRadio;
use sha2::{Digest, Sha256};

/// Operator Wi-Fi intent. Both halves optional — a radio with no matching intent is
/// left idle (no config emitted), never half-configured.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct WifiIntent {
    /// The network the STATION radio (uplink) should join.
    pub station: Option<StationIntent>,
    /// The network the AP radio(s) should broadcast.
    pub ap: Option<ApIntent>,
    /// Regulatory domain (ISO-3166 alpha-2). Default `00` (world / conservative).
    pub country: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct StationIntent {
    pub ssid: String,
    /// Pre-shared key; empty = open network (`key_mgmt=NONE`).
    #[serde(default)]
    pub psk: String,
}

#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ApIntent {
    /// One SSID is broadcast on EVERY AP radio (band steering — clients roam between
    /// 2.4 and 5 GHz). The N100 runs exactly this: both radios, same SSID.
    ///
    /// OPTIONAL — omit it (or leave it empty) to get the per-device DEFAULT derived from
    /// this device's manifest identity (see [`default_ssid`] / [`resolve_ap_ssid`]). An
    /// explicit value here always wins over the derived default (operator intent > default).
    #[serde(default)]
    pub ssid: Option<String>,
    /// Authentication mode: `psk` (default, WPA2-PSK) or `eap` (WPA2-Enterprise /
    /// 802.1X). `eap` is the durable-identity path — it authenticates each client via
    /// RADIUS, which returns the VLAN (`Tunnel-Private-Group-Id`) for dynamic VLAN
    /// assignment. This closes the loop with the `fabric` `.radius` artifact and makes
    /// segmentation survive MAC randomization (see docs/network-segmentation.md).
    #[serde(default)]
    pub auth: Option<String>,
    /// RADIUS server for `auth: eap` (e.g. `127.0.0.1` for a local FreeRADIUS).
    #[serde(default)]
    pub radius_server: Option<String>,
    /// RADIUS shared secret for `auth: eap`.
    #[serde(default)]
    pub radius_secret: Option<String>,
    /// Enable RADIUS-driven dynamic VLAN assignment (default true under `auth: eap`).
    #[serde(default)]
    pub dynamic_vlan: Option<bool>,
    /// WPA2 passphrase; empty = open AP (no encryption — discouraged). Ignored for `eap`.
    #[serde(default)]
    pub passphrase: String,
    /// Channel OVERRIDE. Omit to use the per-band default (2.4→6, 5→36, 6→37) — the
    /// right behaviour for a dual-radio AP where each band needs its own channel.
    #[serde(default)]
    pub channel: Option<u32>,
    /// Band OVERRIDE (rare). Omit to use each radio's DETECTED band — so one intent
    /// configures a 2.4 GHz radio and a 5 GHz radio correctly without per-radio config.
    #[serde(default)]
    pub band: Option<String>,
    #[serde(default)]
    pub hidden: bool,
    /// ADR 0034 D24–D33 — the autonomous survey-based 5 GHz channel optimizer's intent block
    /// (nested under `ap:`). `None` (the block entirely absent from the operator's YAML) resolves
    /// to the full set of shipped defaults via [`crate::wifi_calibrate::optimize_intent`] — see
    /// that function for the precedence/defaults this merely carries as raw operator input.
    #[serde(default)]
    pub optimize: Option<ApOptimizeIntent>,
}

/// Raw operator intent for the ADR 0034 D24–D33 channel optimizer (`wifi.ap.optimize`). Every
/// field is optional; an absent field falls back to the shipped default in
/// [`crate::wifi_calibrate::optimize_intent`], never to a silently-different behaviour here — this
/// struct is deliberately just the parsed YAML shape, with NO defaulting logic of its own.
#[derive(Debug, Clone, Default, PartialEq, serde::Deserialize)]
pub struct ApOptimizeIntent {
    /// Enable the scheduled/on-demand optimizer at all. Default (when absent): `true` when the
    /// resolved band is `5`/`auto` on a 5 GHz-capable radio; the optimizer is a no-op (and disabled)
    /// under a `band: "2.4"` hard pin — nothing to optimize.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Local time-of-day (`"HH:MM"`) the nightly survey runs. Default `"03:00"`.
    #[serde(default)]
    pub at: Option<String>,
    /// May the optimizer switch to a DFS block (52-144) if THIS radio proves (D30) it can hold one?
    /// Default `true` — in every ETSI domain the ONLY non-DFS 80 MHz block is 36-48/ch40, so reaching
    /// a cleaner/higher-power block requires this. The DFS test-and-learn state machine (D30) is what
    /// keeps a non-DFS-capable radio safe (disrupted at most once, ever).
    #[serde(default)]
    pub allow_dfs: Option<bool>,
    /// May the optimizer switch to the 116-128 meteorological sub-band (600 s CAC)? Default `false`
    /// — near-excluded by the CAC penalty (D28) regardless, but this is the explicit opt-in for a
    /// fixed indoor deployment that wants it.
    #[serde(default)]
    pub allow_meteo: Option<bool>,
    /// Required busy-% improvement over the CURRENT channel before switching (hysteresis). Default
    /// `20`. Maps into [`crate::wifi_calibrate::OptimizeWeights::switch_margin`].
    #[serde(default)]
    pub min_improvement: Option<u8>,
}

/// Reduce a (possibly combo) band string to the single band a radio will operate on,
/// preferring the highest available (6 > 5 > 2.4) — a dual-band single radio runs one.
fn effective_band(band: &str) -> &str {
    if band.contains('6') {
        "6"
    } else if band.contains('5') {
        "5"
    } else {
        "2.4"
    }
}

/// hostapd `hw_mode` for a band: 2.4→g, 5/6→a.
fn hw_mode_for(band: &str) -> &'static str {
    match effective_band(band) {
        "2.4" => "g",
        _ => "a",
    }
}

/// A sane default channel per band when the operator gives no override.
fn default_channel_for(band: &str) -> u32 {
    match effective_band(band) {
        "2.4" => 6,
        "6" => 37,
        _ => 36,
    }
}

impl WifiIntent {
    pub fn parse(yaml: &str) -> anyhow::Result<WifiIntent> {
        Ok(serde_yaml::from_str(yaml)?)
    }
    /// The regdomain token to write into hostapd/wpa_supplicant. SANITISED so it is ALWAYS a valid
    /// token — a real 2-letter ISO code (uppercased), or `00` (world). `auto`, blank, or any
    /// non-ISO value collapses to `00`: hostapd rejects `country_code=auto` (it is not a country),
    /// so this is the last-ditch guard that the ADR-0034 detection-and-resolve path never leaks an
    /// unresolved `auto` into a generated config, regardless of the caller. The caller (the
    /// supervisor's reconcile) SHOULD resolve `auto` → the boot-detected CC first (see
    /// `wifi_calibrate::resolved_country_for_render`); this guarantees safety even if it doesn't.
    fn country(&self) -> String {
        sanitize_country(self.country.as_deref().unwrap_or("00"))
    }
}

/// Normalise a country/regdomain string to a valid token: an uppercase 2-letter ISO code, or `00`
/// for world / anything unrecognised (including `auto` and blank). NEVER returns `auto`.
fn sanitize_country(c: &str) -> String {
    let t = c.trim();
    if t == "00" {
        return "00".to_string();
    }
    let up = t.to_ascii_uppercase();
    if up.len() == 2 && up.bytes().all(|b| b.is_ascii_uppercase()) {
        up
    } else {
        "00".to_string()
    }
}

/// Deterministic per-device DEFAULT AP SSID, derived from the signed manifest's stable
/// `identity.device_id` (a hardware-fingerprint hash — see `identity::puf_seed` /
/// `builder::build_manifest`, itself reproducible across reboots but NOT published anywhere
/// secret-sensitive: it is already carried in the plaintext manifest).
///
/// Format: `HookProbe-XXXXXX` — 6 uppercase hex chars (3 bytes) from a domain-separated
/// SHA-256 of the device id, so:
///   - same device_id → same SSID, every boot (stable, not random-per-boot);
///   - different device_id → a different SSID (2^24 space — collision-safe for any real LAN);
///   - the hash is domain-separated so this suffix can never collide with, or be reversed
///     into, the identity signing key material even though both derive from the same root.
///
/// This is ONLY the default. `resolve_ap_ssid` is what actually decides — an explicit
/// operator `ap.ssid` always wins.
pub fn default_ssid(device_id: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"hookprobe-ap-ssid-v1");
    h.update(device_id.as_bytes());
    let digest = h.finalize();
    format!("HookProbe-{}", hex::encode_upper(&digest[..3]))
}

/// Derive a default WPA2 passphrase from device identity, used ONLY when an AP-role radio has
/// no operator-declared passphrase. A security appliance must never come up as an OPEN network,
/// so a fresh standalone device gets a stable, unique-per-device WPA2 key (12 hex chars = 48
/// bits, within hostapd's 8–63 range). Domain-separated from the SSID hash so the SSID never
/// leaks the key. The operator can always override via the `ap:` intent block.
pub fn default_ap_passphrase(device_id: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"hookprobe-ap-psk-v1");
    h.update(device_id.as_bytes());
    let digest = h.finalize();
    hex::encode(&digest[..6])
}

/// ADR 0034 D18 — deterministic non-overlapping 2.4 GHz channel {1, 6, 11} derived from the signed
/// manifest's stable `identity.device_id` (same domain-separated-SHA256 pattern as [`default_ssid`]
/// / [`default_ap_passphrase`]). Replaces the constant `ch6` the 2.4 GHz fail-safe/floor used to
/// hardcode: two boxes flashed from the SAME image and co-located (e.g. a rack of Pi4s) previously
/// both landed on ch6 and collided; deriving the channel from device identity spreads them across
/// 1/6/11 instead — same device → same channel every boot (stable), different device → very likely
/// a different one (2^24 space over 3 buckets). This is ONLY the deterministic, no-survey default;
/// [`crate::wifi_calibrate::pick_24_channel`] still wins with a REAL channel survey when one is
/// available (runtime congestion beats a static per-device guess).
pub fn default_24_channel(device_id: &str) -> u32 {
    const CANDIDATES: [u32; 3] = [1, 6, 11];
    let mut h = Sha256::new();
    h.update(b"hookprobe-24ch-v1");
    h.update(device_id.as_bytes());
    let digest = h.finalize();
    CANDIDATES[(digest[0] as usize) % CANDIDATES.len()]
}

/// Resolve the AP SSID to actually broadcast: the operator's explicit intent SSID wins when
/// present and non-empty; otherwise fall back to this device's derived default. Centralising
/// this precedence here (rather than inlining `.unwrap_or_else` at each call site) keeps the
/// "operator override > derived default" rule enforced in exactly one place.
pub fn resolve_ap_ssid(intent_ssid: Option<&str>, device_id: &str) -> String {
    match intent_ssid {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => default_ssid(device_id),
    }
}

/// One radio's resolved configuration decision.
#[derive(Debug, Clone, PartialEq)]
pub struct WifiAssignment {
    pub iface: String,
    pub role: String,
    /// The SSID this radio was configured for, or `None` if left idle.
    pub ssid: Option<String>,
    /// Human note (idle reason, or the artifact kind).
    pub note: String,
}

/// The Wi-Fi config plan: one assignment per radio (preserving manifest order).
#[derive(Debug, Clone, PartialEq)]
pub struct WifiCfgPlan {
    pub assignments: Vec<WifiAssignment>,
}

impl WifiCfgPlan {
    pub fn summary(&self) -> String {
        if self.assignments.is_empty() {
            return "no Wi-Fi radios".to_string();
        }
        self.assignments
            .iter()
            .map(|a| match &a.ssid {
                Some(s) => format!("{}[{}]→\"{}\"", a.iface, a.role, s),
                None => format!("{}[{}]→idle", a.iface, a.role),
            })
            .collect::<Vec<_>>()
            .join("  ")
    }
}

/// Resolve each radio against the intent (which SSID, or idle). `device_id` is the signed
/// manifest's stable device identity — used ONLY to derive the AP's default SSID when the
/// operator's intent doesn't specify one (see [`resolve_ap_ssid`]); it has no effect on the
/// station side (a station always joins the operator-declared upstream SSID).
pub fn plan(radios: &[WifiRadio], intent: &WifiIntent, device_id: &str) -> WifiCfgPlan {
    let assignments = radios
        .iter()
        .map(|r| match r.role.as_str() {
            "station" => match &intent.station {
                Some(s) => WifiAssignment {
                    iface: r.name.clone(),
                    role: r.role.clone(),
                    ssid: Some(s.ssid.clone()),
                    note: "wpa_supplicant client".to_string(),
                },
                None => idle(r, "no station intent — uplink radio left idle"),
            },
            "ap" => match &intent.ap {
                Some(a) => WifiAssignment {
                    iface: r.name.clone(),
                    role: r.role.clone(),
                    ssid: Some(resolve_ap_ssid(a.ssid.as_deref(), device_id)),
                    note: "hostapd AP".to_string(),
                },
                None => idle(r, "no AP intent — radio left idle"),
            },
            other => idle(r, &format!("unknown role '{other}' — left idle")),
        })
        .collect();
    WifiCfgPlan { assignments }
}

fn idle(r: &WifiRadio, note: &str) -> WifiAssignment {
    WifiAssignment {
        iface: r.name.clone(),
        role: r.role.clone(),
        ssid: None,
        note: note.to_string(),
    }
}

const BANNER: &str = "# GENERATED by hookprobe Wi-Fi reconciler from the signed manifest.\n# Do NOT edit — changes are overwritten. Declare intent instead (wifi-intent.yaml).\n";

/// Render the config artifacts: `wpa_supplicant-<iface>.conf` for station radios,
/// `hostapd-<iface>.conf` for AP radios. Idle radios produce no file. `device_id` feeds the
/// AP's default-SSID derivation (see [`plan`] / [`resolve_ap_ssid`]) — the station side never
/// substitutes a derived SSID (it must join whatever the operator declared).
pub fn render(radios: &[WifiRadio], intent: &WifiIntent, device_id: &str) -> Vec<GeneratedFile> {
    let country = intent.country();
    let country = country.as_str();
    let mut files = Vec::new();
    for r in radios {
        match (r.role.as_str(), &intent.station, &intent.ap) {
            ("station", Some(s), _) => files.push(GeneratedFile {
                path: format!("wpa_supplicant-{}.conf", r.name),
                content: render_station(&r.name, s, country),
            }),
            // AP radio → always emit hostapd. The `ap:` intent block is OPTIONAL: with the
            // per-device-SSID feature the operator normally omits it (SSID derives from
            // device_id), so an AP-role radio MUST render even when `intent.ap` is None —
            // otherwise a standalone-default device broadcasts nothing (fixed 2026-07-09: this
            // was gated on `Some(a)`, so a freshly-flashed Pi/CM5 with no `ap:` block silently
            // produced no hostapd.conf → hostapd's ConditionFileNotEmpty failed → no SSID).
            ("ap", _, ap_opt) => {
                // Derive a default AP when the operator omitted the `ap:` block. A security
                // appliance must NOT come up as an OPEN network, so a default passphrase is
                // derived from device identity (stable, unique-per-device, like the SSID) when
                // none is declared — the operator can always override via intent.
                let mut default_ap = ApIntent::default();
                if default_ap.passphrase.is_empty() {
                    default_ap.passphrase = default_ap_passphrase(device_id);
                }
                let a = ap_opt.as_ref().unwrap_or(&default_ap);
                let ssid = resolve_ap_ssid(a.ssid.as_deref(), device_id);
                files.push(GeneratedFile {
                    path: format!("hostapd-{}.conf", r.name),
                    content: render_ap(&r.name, &ssid, a, country, r.band.as_deref(), None, device_id),
                })
            }
            _ => {} // idle/station-without-intent radio → no artifact
        }
    }
    files
}

fn render_station(iface: &str, s: &StationIntent, country: &str) -> String {
    let net = if s.psk.is_empty() {
        format!("network={{\n    ssid=\"{}\"\n    key_mgmt=NONE\n}}\n", s.ssid)
    } else {
        format!(
            "network={{\n    ssid=\"{}\"\n    psk=\"{}\"\n    key_mgmt=WPA-PSK\n}}\n",
            s.ssid, s.psk
        )
    };
    format!(
        "{BANNER}# station radio {iface} joins \"{}\"\n\
         ctrl_interface=/run/wpa_supplicant\n\
         country={country}\n\
         update_config=1\n\n{net}",
        s.ssid
    )
}

/// VHT80 parameters for a primary 5 GHz channel, if it sits in a clean, NON-DFS 80 MHz block.
/// Returns `(ht40_plus, vht_oper_centr_freq_seg0_idx)`: `ht40_plus` selects `[HT40+]` (the
/// primary is the LOWER channel of its 40 MHz pair) vs `[HT40-]` (the primary is the UPPER
/// channel); `seg0_idx` is the 80 MHz block's center channel (what `vht_oper_centr_freq_seg0_idx`
/// wants).
///
/// DFS blocks (UNII-2 52-64, UNII-2e 100-144) are real 80 MHz-capable blocks on most radios but
/// are deliberately excluded here: turning on VHT80 there requires the AP to run channel
/// availability check (CAC) and in-service radar monitoring correctly on every boot, and a wrong
/// call takes the AP off-air or (worse) interferes with radar — too risky for an unattended
/// default. Only the two NON-DFS blocks get automatic VHT80: UNII-1 (36-48, center 42) and
/// UNII-3 (149-161, center 155). Any other primary (DFS, or a lone channel like 165 that has no
/// clean 80 MHz block) returns `None` and `render_ap` falls back to plain HT20 — the safe,
/// always-valid config this function replaces.
///
/// The `ht40_plus` direction is ALREADY a pure function of the control channel (never hardcoded):
/// `matches!(channel, 36 | 44)` / `matches!(channel, 149 | 157)` picks the LOWER channel of each
/// HT40 pair (36, 44, 149, 157) for `[HT40+]`, the UPPER (40, 48, 153, 161) for `[HT40-]`. This is
/// what the calibration ladder's top rung (2026-07-15,
/// [`crate::wifi_calibrate::candidate_ladder`]) relies on: control ch40 (upper secondary of the
/// 36-48 block) correctly renders `[HT40-]` here — proven on metal to be the ONLY control channel
/// of that block that holds 80 MHz on brcmfmac (BCM43455); ch36 (`[HT40+]`) does not. See
/// `ap_5ghz_ch36_defaults_to_vht80` / `ap_5ghz_ch40_uses_ht40_minus_same_seg0` below.
pub(crate) fn vht80_params(channel: u32) -> Option<(bool, u32)> {
    match channel {
        36 | 40 | 44 | 48 => Some((matches!(channel, 36 | 44), 42)),
        149 | 153 | 157 | 161 => Some((matches!(channel, 149 | 157), 155)),
        _ => None,
    }
}

/// An explicit AP channel width. This is the *forced* selection used by the adaptive
/// calibration ladder (see [`crate::wifi_calibrate`]); the ordinary `render` path never forces a
/// width and instead auto-selects (5 GHz non-DFS → VHT80, else HT20) exactly as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChanWidth {
    /// 20 MHz — the always-safe rung. On brcmfmac FullMAC this is the only STABLE 5 GHz width.
    Ht20,
    /// 40 MHz (HT40) — needs a clean adjacent channel; direction (+/-) derived from the primary.
    Ht40,
    /// 80 MHz (VHT80) — the top rung; only valid on a clean NON-DFS 80 MHz block, and (field-
    /// proven, ADR) frequently REJECTED in AP mode by the BCM43455 FullMAC firmware → collapse.
    Vht80,
}

impl ChanWidth {
    /// The operating bandwidth in MHz — used by the stability verifier to compare the REQUESTED
    /// width against what the radio actually settled on (the brcmfmac collapse detector).
    pub fn mhz(&self) -> u32 {
        match self {
            ChanWidth::Ht20 => 20,
            ChanWidth::Ht40 => 40,
            ChanWidth::Vht80 => 80,
        }
    }
}

/// Is `channel` one of the DFS channels (UNII-2A 52-64, UNII-2C 100-144) — a coarse,
/// WIDTH-INDEPENDENT fact deliberately DUPLICATED here rather than imported from
/// `crate::wifi_calibrate::is_dfs_rung` (which needs a WIDTH too, and lives in the layer ABOVE this
/// one — `wifi_calibrate` depends on `wifi_cfg`, never the reverse; see this module's own doc). DFS
/// applies to the CHANNEL itself, at ANY width, so this is checked independently of `vht80_params`
/// (which stays scoped to non-DFS blocks — see its own doc on why VHT80 is never auto-enabled on a
/// DFS primary).
fn is_dfs_channel(channel: u32) -> bool {
    matches!(channel, 52 | 56 | 60 | 64 | 100 | 104 | 108 | 112 | 116 | 120 | 124 | 128 | 132 | 136 | 140 | 144)
}

/// Compute the hostapd HT/VHT width lines for a given (effective band, primary channel), either
/// auto-selected (`force = None`, the historical default) or FORCED to a specific width (the
/// calibration ladder). Returns the block of `ht_capab`/`ieee80211ac`/`vht_*`/`ieee80211h` lines
/// (each newline-terminated), or an empty string for plain HT20 on a non-DFS channel (hostapd's
/// default — no lines needed).
///
/// The `force = None` behaviour is otherwise byte-identical to the pre-existing inline logic: 5 GHz
/// on a clean NON-DFS 80 MHz block → VHT80; everything else (DFS, lone channel, 2.4/6 GHz) → HT20 —
/// **`vht80_params` deliberately stays scoped to non-DFS blocks, so a DFS primary is NEVER
/// auto-upgraded to VHT80 by this ordinary render path** (that stays the calibration ladder/3AM
/// optimizer's job — see `wifi_calibrate::candidate_ladder`/`optimize_candidates`, which apply their
/// own DFS-aware CAC settle before ever trusting a DFS channel).
///
/// 2026-07-17 (v2 EU channel campaign, PROVEN ON METAL): the brcmfmac BCM43455 FullMAC radio runs
/// DFS/CAC ENTIRELY IN FIRMWARE — hostapd's `ieee80211h=1` (802.11h) is for SoftMAC/mac80211 drivers
/// where the kernel does DFS, and on this FullMAC firmware it is REJECTED: setting it makes hostapd
/// error out and crash-loop. Ground truth: with `ieee80211h=1` present, EVERY DFS channel came up
/// `hostapd=activating` (crash loop). So this function NEVER emits `ieee80211h` on the target
/// hardware — 802.11h is the firmware's job here.
///
/// CORRECTION (2026-07-17, exhaustive-reset EU matrix — supersedes the earlier claim in this very
/// comment that "WITHOUT ieee80211h the SAME DFS blocks ch56/104/120 reached AP-ENABLED at VHT80"):
/// that was a FALSE POSITIVE from a no-radio-reset campaign reading a stale prior channel. With a
/// `rmmod`/reset between every attempt, the brcmfmac BCM43455 FullMAC firmware **cannot bring up ANY
/// DFS channel in AP mode, at any width** — not because of `ieee80211h`, but because the firmware
/// refuses the regulatory-domain handoff (stays `country 99: DFS-UNSET`) and flags DFS channels
/// `NO-IR RADAR`. See `wifi_calibrate.rs`'s RC-DFS section and ADR 0034 Extension RC-DFS for the
/// firmware/CLM forensics + the live proof. Net effect for this function is UNCHANGED (never emit
/// `ieee80211h`), but the *reason* is the firmware limitation, not a "works-without-it" DFS path. If
/// a SoftMAC/mac80211 radio is ever supported (ADR 0042), `ieee80211h` must be re-added GATED on radio
/// type — NEVER unconditionally, and never for brcmfmac.
fn width_lines(eband: &str, channel: u32, force: Option<ChanWidth>) -> String {
    // 2.4/6 GHz: only an explicit HT40 force emits anything; auto + everything else = plain HT20.
    if eband != "5" {
        return match force {
            Some(ChanWidth::Ht40) => {
                // 2.4 GHz HT40: HT40+ pairs upward (ch1-6 have room above), else HT40-.
                let dir = if channel <= 6 { "+" } else { "-" };
                format!("ht_capab=[HT40{dir}][SHORT-GI-20][SHORT-GI-40]\n")
            }
            _ => String::new(),
        };
    }
    // 5 GHz. Resolve the effective width: an explicit force wins; otherwise auto = VHT80 on a
    // clean non-DFS block, else HT20.
    let width = force.unwrap_or(match vht80_params(channel) {
        Some(_) => ChanWidth::Vht80,
        None => ChanWidth::Ht20,
    });
    // NEVER emit ieee80211h — it crash-loops hostapd on the brcmfmac FullMAC firmware (see fn doc).
    // The firmware provides DFS/CAC; `is_dfs_channel` is kept (used by the ladder/optimizer layer).
    let _ = is_dfs_channel(channel);
    let dfs_line = "";
    match width {
        ChanWidth::Ht20 => dfs_line.to_string(),
        ChanWidth::Ht40 => match vht80_params(channel) {
            // Reuse the block table only for the +/- direction; emit HT40 without the VHT lines.
            Some((ht40_plus, _seg0)) => {
                let dir = if ht40_plus { "+" } else { "-" };
                format!("ht_capab=[HT40{dir}][SHORT-GI-20][SHORT-GI-40]\n{dfs_line}")
            }
            // No clean 40 MHz pair (e.g. lone ch165, or a DFS block — see vht80_params's own doc) →
            // safe HT20, still carrying the DFS line if the channel itself is DFS.
            None => dfs_line.to_string(),
        },
        ChanWidth::Vht80 => match vht80_params(channel) {
            Some((ht40_plus, seg0)) => {
                let dir = if ht40_plus { "+" } else { "-" };
                format!(
                    "ht_capab=[HT40{dir}][SHORT-GI-20][SHORT-GI-40]\n\
                     ieee80211ac=1\n\
                     vht_capab=[SHORT-GI-80]\n\
                     vht_oper_chwidth=1\n\
                     vht_oper_centr_freq_seg0_idx={seg0}\n\
                     {dfs_line}"
                )
            }
            // VHT80 forced on a channel with no clean non-DFS 80 MHz block → cannot; safe HT20,
            // still carrying the DFS line if the channel itself is DFS (e.g. a calibration ladder
            // extension that forces Vht80 on a DFS primary before vht80_params supports it).
            None => dfs_line.to_string(),
        },
    }
}

/// Render a hostapd conf for an EXPLICIT calibration rung: the ladder decides the (channel,
/// width); the security block (WPA2-PSK / EAP), SSID, banner and country all come from the same
/// [`render_ap`] used by the ordinary path, so the two renderers can never diverge on the
/// security-critical bits. This is the ONLY seam the adaptive calibrator needs into hostapd
/// rendering. `device_id` feeds the world/unresolved-regdomain 2.4 GHz fail-safe channel pick
/// (ADR 0034 D18, [`default_24_channel`]) — see [`render_ap`].
#[allow(clippy::too_many_arguments)]
pub fn render_ap_rung(
    iface: &str,
    ssid: &str,
    a: &ApIntent,
    country: &str,
    band: &str,
    channel: u32,
    width: ChanWidth,
    device_id: &str,
) -> String {
    render_ap(iface, ssid, a, country, Some(band), Some((channel, width)), device_id)
}

#[allow(clippy::too_many_arguments)]
fn render_ap(
    iface: &str,
    ssid: &str,
    a: &ApIntent,
    country: &str,
    radio_band: Option<&str>,
    force: Option<(u32, ChanWidth)>,
    device_id: &str,
) -> String {
    // Band precedence: explicit intent override > the radio's DETECTED band > 2.4.
    // This is what lets ONE ap intent configure a dual-radio AP correctly: the 2.4 GHz
    // phy renders hw_mode=g/ch6 and the 5 GHz phy renders hw_mode=a/ch36, same SSID.
    //
    // ADR 0034 D15/D22: `band: "auto"` (the new shipped default, and *absent* — every image now
    // ships `auto`) is NOT an override — it means "let the radio's detected capability decide",
    // exactly like `None` always has. This is what makes `auto` actually 5 GHz-FIRST: a dual-band
    // radio's manifest-detected band (`effective_band`, which already prefers 5/6 over 2.4 — see
    // its doc) drives `hw_mode`/width here, so a 5 GHz-capable radio auto-renders VHT80 on a clean
    // block by default (`width_lines`'s existing auto-select) with NO extra wiring. Only a REAL
    // hard pin (`"5"` / `"2.4"`) overrides the radio's own capability — honoring the operator's
    // explicit override, as D15 requires. The runtime calibration loop (`wifi_calibrate`/
    // `wifi-calibrate.sh`) is what actually VERIFIES the width holds and steps down; this render
    // path only decides the safe INITIAL config before that loop converges it.
    let band_override = a.band.as_deref().filter(|b| !b.eq_ignore_ascii_case("auto"));
    let requested_band = band_override.or(radio_band).unwrap_or("2.4");
    // FAIL-SAFE (2026-07-11, Pi4 on-metal gap H2): hostapd REFUSES to start with `country_code=00`
    // on a 5 GHz / VHT config — `Invalid country_code '00'` → the interface fails to initialise →
    // NO SSID AT ALL (not merely slow). When the regdomain is unresolved (world `00` — e.g. a
    // modem-less, air-gapped, or geoIP-off box before ADR-0034 detection resolves a country), pin
    // the AP to 2.4 GHz / HT20 / ch6 — the one band+width the world regulatory domain ALWAYS
    // permits — so the SSID comes up regardless. A resolved country (RO/GB/US/…) uses the intended
    // band/width. "AP up on 2.4 GHz" >> "no AP"; the operator gets connectivity, then the regdomain
    // service (or an operator `country:` override) upgrades it to 5 GHz VHT80 on the next reconcile.
    let failsafe_world = country == "00" && effective_band(requested_band) != "2.4";
    let band = if failsafe_world { "2.4" } else { requested_band };
    let hw_mode = hw_mode_for(band);
    // A forced rung (from the calibration ladder) overrides both channel and width; otherwise the
    // channel comes from intent-override → per-band default, and the width is auto-selected. The
    // world-`00` fail-safe pins the best-match 2.4 GHz channel/HT20 and ignores any 5 GHz force
    // (that force is invalid at `00`). D18 (2026-07-13): the boot-time (no-survey) channel pick is
    // now the per-device DERIVED default (`default_24_channel(device_id)`, {1,6,11}) rather than
    // the constant `6` `pick_24_channel(&[])` used to return — two co-located boxes flashed from
    // the same image no longer collide on ch6 even at this fail-safe. `pick_24_channel` itself is
    // unchanged (still the REAL-survey path the runtime calibration loop uses when it has one).
    let channel = if failsafe_world {
        default_24_channel(device_id)
    } else {
        force.map(|(c, _)| c).or(a.channel).unwrap_or_else(|| default_channel_for(band))
    };
    let force_width = if failsafe_world { None } else { force.map(|(_, w)| w) };
    // Case-insensitive auth so a mistyped "EAP"/"WPA2-EAP" is not silently degraded to PSK.
    let auth_lc = a.auth.as_deref().map(|s| s.to_ascii_lowercase());
    let eap = matches!(auth_lc.as_deref(), Some("eap") | Some("8021x") | Some("wpa2-eap"));
    // 6 GHz needs HE (802.11ax) + an operating class; WPA2-PSK is not permitted there
    // (the band mandates WPA3-SAE). Emit the HE bits + an honest warning rather than a
    // config hostapd will reject.
    let sixghz = if effective_band(band) == "6" {
        "ieee80211ax=1\nop_class=131\n# WARNING: 6 GHz requires WPA3-SAE (not WPA2-PSK) and full HE config — review before use.\n"
    } else {
        ""
    };
    // Channel width: default to the WIDEST block this (band, channel) supports, falling back
    // safely to plain HT20 (no ht_capab/ac line at all — hostapd's default) otherwise. Verified
    // live on a CM5's onboard BCM43455 (1x1, VHT80/no-160): ch36 with no ht_capab/ieee80211ac
    // ran HT20 (~72 Mbps PHY) when the radio supported VHT80 (~433 Mbps PHY) — this closes that
    // gap. 2.4 GHz intentionally stays HT20: it's already the fallback band, and HT40 there
    // eats the only other non-overlapping 20 MHz channel from every neighbour. 6 GHz is
    // untouched (handled entirely by `sixghz` below).
    let width = width_lines(effective_band(band), channel, force_width);
    // 2026-07-16 (BUG-1 defense-in-depth): `{width}wmm_enabled=1\n` below concatenates directly —
    // a non-empty `width` that doesn't already end in `\n` would glue straight onto
    // `wmm_enabled=1` (the exact malformed-conf bug proven on metal in the SHELL mirror,
    // `wifi-calibrate.sh`, whose `read`-based field-splitting used to truncate a multi-line HT/VHT
    // block's trailing newline). `width_lines` itself already guarantees this (every non-empty
    // branch ends in exactly one `\n` — see its doc), but this debug-only assertion locks that
    // invariant at the ONE place a future edit to either function could silently break it, without
    // adding any release-build cost.
    debug_assert!(
        width.is_empty() || width.ends_with('\n'),
        "width_lines() must be empty or end with exactly one \\n — got {width:?}"
    );
    // ADR 0034 D12 (W2, the world/unresolved fail-safe — proven live): hostapd REJECTS
    // `country_code=00` at config-parse on ANY band ("Invalid country_code '00'") — the interface
    // never initialises, so there is NO SSID at all (not merely a degraded one). The sanitised
    // token `00` therefore means UNRESOLVED: OMIT the `country_code` line ENTIRELY (and
    // `ieee80211d`, which only makes sense advertising a REAL country) rather than ever writing
    // `country_code=00`. A real 2-letter code emits both `country_code=<CC>` (hostapd needs it to
    // select the right regulatory ruleset) and `ieee80211d=1` (advertise the Country IE — correct
    // only once the domain is real). This REPLACES the earlier fail-safe that still emitted
    // `country_code=00` (which does not actually start hostapd on any band).
    let country_line =
        if country == "00" { String::new() } else { format!("country_code={country}\nieee80211d=1\n") };
    let sec = if eap {
        // WPA2-Enterprise / 802.1X: authenticate via RADIUS; RADIUS returns the VLAN
        // (Tunnel-Private-Group-Id) → hostapd dynamic_vlan assigns it. Identity, not MAC.
        let server = a.radius_server.as_deref().unwrap_or("");
        let secret = a.radius_secret.as_deref().unwrap_or("");
        let mut b = String::new();
        if server.is_empty() || secret.is_empty() {
            b.push_str("# WARNING: auth: eap needs radius_server + radius_secret — set them in intent\n");
        }
        b.push_str("auth_algs=1\nwpa=2\nwpa_key_mgmt=WPA-EAP\nrsn_pairwise=CCMP\nieee8021x=1\n");
        b.push_str(&format!(
            "auth_server_addr={server}\nauth_server_port=1812\nauth_server_shared_secret={secret}\n"
        ));
        if a.dynamic_vlan.unwrap_or(true) {
            b.push_str("dynamic_vlan=1\nvlan_file=/etc/hostapd/hostapd.vlan\n");
        }
        b
    } else if a.passphrase.is_empty() {
        // Open AP — no WPA block.
        String::new()
    } else {
        // hostapd requires the WPA2 passphrase to be 8–63 chars; out of range = a config
        // hostapd refuses to load. Flag it loudly rather than ship a broken AP.
        let warn = if !(8..=63).contains(&a.passphrase.chars().count()) {
            "# WARNING: wpa_passphrase must be 8–63 characters — hostapd will REJECT this config.\n"
        } else {
            ""
        };
        format!(
            "{warn}auth_algs=1\nwpa=2\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\nwpa_passphrase={}\n",
            a.passphrase
        )
    };
    format!(
        "{BANNER}# AP radio {iface} broadcasts \"{}\" ({} GHz, ch {channel})\n\
         interface={iface}\n\
         driver=nl80211\n\
         {country_line}ssid={}\n\
         hw_mode={hw_mode}\n\
         channel={channel}\n\
         ieee80211n=1\n\
         {width}wmm_enabled=1\n\
         ignore_broadcast_ssid={}\n{sixghz}{sec}",
        ssid, effective_band(band), ssid, if a.hidden { 1 } else { 0 }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed stand-in device id — tests that don't care about SSID derivation use this so
    /// they don't have to think about it (mirrors the `hp-<hex>` shape `builder.rs` produces).
    const DEV: &str = "hp-0000000000000000000000000000000000000000";

    fn radio(name: &str, role: &str) -> WifiRadio {
        WifiRadio { name: name.into(), role: role.into(), band: None }
    }
    fn radio_band(name: &str, role: &str, band: &str) -> WifiRadio {
        WifiRadio { name: name.into(), role: role.into(), band: Some(band.into()) }
    }
    fn ap(ssid: &str, pass: &str) -> ApIntent {
        ApIntent { ssid: Some(ssid.into()), passphrase: pass.into(), ..Default::default() }
    }

    /// 802.1X / WPA2-Enterprise AP: RADIUS auth + dynamic VLAN (the durable-identity
    /// path that survives MAC randomization). Pairs with the fabric `.radius` artifact.
    #[test]
    fn ap_eap_8021x_mode() {
        let radios = vec![radio_band("wlan_5ghz", "ap", "5")];
        let intent = WifiIntent {
            station: None,
            ap: Some(ApIntent {
                ssid: Some("HookProbe-Corp".into()),
                auth: Some("eap".into()),
                radius_server: Some("127.0.0.1".into()),
                radius_secret: Some("radsecret123".into()),
                ..Default::default()
            }),
            country: Some("GB".into()),
        };
        let files = render(&radios, &intent, DEV);
        let c = &files[0].content;
        assert!(c.contains("wpa_key_mgmt=WPA-EAP") && c.contains("ieee8021x=1"), "802.1X enabled");
        assert!(c.contains("auth_server_addr=127.0.0.1") && c.contains("auth_server_shared_secret=radsecret123"));
        assert!(c.contains("dynamic_vlan=1") && c.contains("vlan_file="), "RADIUS-driven dynamic VLAN");
        assert!(!c.contains("wpa_passphrase="), "EAP has no static passphrase");
    }

    /// EAP without a RADIUS server is flagged, not silently broken.
    #[test]
    fn ap_eap_without_radius_warns() {
        let radios = vec![radio_band("wlan0", "ap", "2.4")];
        let intent = WifiIntent {
            station: None,
            ap: Some(ApIntent { ssid: Some("X".into()), auth: Some("eap".into()), ..Default::default() }),
            country: None,
        };
        assert!(render(&radios, &intent, DEV)[0].content.contains("WARNING: auth: eap needs radius_server"));
    }

    /// THE DUAL-RADIO ROUTER (N100): both radios are APs broadcasting the SAME SSID
    /// (band steering). One `ap` intent configures BOTH, each rendered to its DETECTED
    /// band — 2.4 GHz → hw_mode=g/ch6, 5 GHz → hw_mode=a/ch36 — with no per-radio config.
    #[test]
    fn dual_radio_ap_band_steering() {
        let radios = vec![
            radio_band("wlan_24ghz", "ap", "2.4"),
            radio_band("wlan_5ghz", "ap", "5"),
        ];
        let intent = WifiIntent { station: None, ap: Some(ap("hookprobe", "appass1234")), country: Some("GB".into()) };
        let files = render(&radios, &intent, DEV);
        assert_eq!(files.len(), 2, "one hostapd per radio");
        let lo = files.iter().find(|f| f.path == "hostapd-wlan_24ghz.conf").unwrap();
        assert!(lo.content.contains("hw_mode=g") && lo.content.contains("channel=6"), "2.4 GHz → g/ch6");
        let hi = files.iter().find(|f| f.path == "hostapd-wlan_5ghz.conf").unwrap();
        assert!(hi.content.contains("hw_mode=a") && hi.content.contains("channel=36"), "5 GHz → a/ch36");
        // Same SSID on both = band steering.
        assert!(lo.content.contains("ssid=hookprobe") && hi.content.contains("ssid=hookprobe"));
    }

    /// Station + AP each get their artifact; explicit channel override is honoured.
    #[test]
    fn station_and_ap_each_get_their_artifact() {
        let radios = vec![radio_band("wlan_24ghz", "station", "2.4"), radio_band("wlan_5ghz", "ap", "5")];
        let intent = WifiIntent {
            station: Some(StationIntent { ssid: "Up".into(), psk: "secret123".into() }),
            ap: Some(ApIntent { ssid: Some("HP-AP".into()), passphrase: "appass1234".into(), channel: Some(149), ..Default::default() }),
            country: Some("GB".into()),
        };
        let files = render(&radios, &intent, DEV);
        assert_eq!(files.len(), 2);
        let sta = files.iter().find(|f| f.path == "wpa_supplicant-wlan_24ghz.conf").unwrap();
        assert!(sta.content.contains("ssid=\"Up\"") && sta.content.contains("psk=\"secret123\""));
        assert!(sta.content.contains("country=GB"));
        let ap = files.iter().find(|f| f.path == "hostapd-wlan_5ghz.conf").unwrap();
        assert!(ap.content.contains("hw_mode=a"), "5 GHz must use hw_mode=a");
        assert!(ap.content.contains("channel=149"), "explicit channel override honoured");
        assert!(ap.content.contains("wpa_passphrase=appass1234") && ap.content.contains("Do NOT edit"));
    }

    /// 2.4 GHz AP uses hw_mode=g; hidden SSID sets ignore_broadcast_ssid=1; default
    /// world regulatory domain; channel derived from the radio band (no override).
    #[test]
    fn ap_band_24_hidden() {
        let radios = vec![radio_band("wlan0", "ap", "2.4")];
        let intent = WifiIntent {
            station: None,
            ap: Some(ApIntent { ssid: Some("Hidden".into()), passphrase: "p".repeat(10), hidden: true, ..Default::default() }),
            country: None,
        };
        let files = render(&radios, &intent, DEV);
        assert_eq!(files.len(), 1);
        assert!(files[0].content.contains("hw_mode=g") && files[0].content.contains("channel=6"));
        assert!(files[0].content.contains("ignore_broadcast_ssid=1"));
        // ADR 0034 D12 (W2, INVERTED 2026-07-11): hostapd REJECTS `country_code=00` at config-parse
        // on ANY band — "AP up on 2.4 GHz" only actually happens if the line is OMITTED entirely.
        assert!(!files[0].content.contains("country_code="), "world/unresolved regdomain must OMIT country_code, never emit =00: {}", files[0].content);
        assert!(!files[0].content.contains("ieee80211d"), "no Country IE without a real country: {}", files[0].content);
    }

    /// ADR-0034 (c) safety net: an UNRESOLVED `country: auto` (or any junk) must NEVER reach a
    /// generated config as `country_code=auto` — hostapd rejects that. `country()` sanitises it to
    /// the world domain `00`, which D12 (INVERTED 2026-07-11) then renders as NO `country_code=`
    /// line at all (hostapd rejects `=00` too — proven live). (The supervisor SHOULD resolve
    /// `auto`→detected-CC first; this proves the last-ditch guard regardless.)
    #[test]
    fn country_auto_or_junk_is_sanitized_never_emitted() {
        let radios = vec![radio_band("wlan0", "ap", "5")];
        for bad in ["auto", "Auto", "  ", "USA", "g1", ""] {
            let intent = WifiIntent {
                station: None,
                ap: Some(ApIntent { ssid: Some("HP".into()), passphrase: "appass1234".into(), ..Default::default() }),
                country: Some(bad.into()),
            };
            let c = &render(&radios, &intent, DEV)[0].content;
            assert!(!c.contains("country_code=auto"), "must never emit country_code=auto (input {bad:?})");
            assert!(!c.contains("country_code="), "junk/auto country {bad:?} → world/unresolved → NO country_code line: {c}");
        }
        // A real code is preserved, uppercased, and paired with ieee80211d=1.
        let intent = WifiIntent {
            station: None,
            ap: Some(ApIntent { ssid: Some("HP".into()), passphrase: "appass1234".into(), ..Default::default() }),
            country: Some("ro".into()),
        };
        let c = &render(&radios, &intent, DEV)[0].content;
        assert!(c.contains("country_code=RO") && c.contains("ieee80211d=1"), "got: {c}");
    }

    /// A radio with no matching intent is left idle — no half-written config.
    #[test]
    fn radio_without_intent_is_idle() {
        let radios = vec![radio("wlan1", "station"), radio("wlan0", "ap")];
        // Only AP intent given → station radio idle, AP configured (open, no passphrase).
        let intent = WifiIntent { station: None, ap: Some(ap("OnlyAP", "")), country: None };
        let p = plan(&radios, &intent, DEV);
        let sta = p.assignments.iter().find(|a| a.iface == "wlan1").unwrap();
        assert!(sta.ssid.is_none() && sta.note.contains("idle"));
        let files = render(&radios, &intent, DEV);
        assert_eq!(files.len(), 1, "only the AP radio yields a file");
        assert_eq!(files[0].path, "hostapd-wlan0.conf");
        // Open AP (empty passphrase) → no WPA block.
        assert!(!files[0].content.contains("wpa=2"));
    }

    /// Open station network (no psk) → key_mgmt=NONE, no psk line.
    #[test]
    fn open_station_uses_key_mgmt_none() {
        let radios = vec![radio("wlan0", "station")];
        let intent = WifiIntent {
            station: Some(StationIntent { ssid: "OpenWifi".into(), psk: String::new() }),
            ap: None,
            country: None,
        };
        let files = render(&radios, &intent, DEV);
        assert!(files[0].content.contains("key_mgmt=NONE"));
        assert!(!files[0].content.contains("psk="));
    }

    // -----------------------------------------------------------------------------------------
    // Per-device SSID differentiation — the fix for two devices on the SAME image colliding on
    // the same hardcoded "HookProbe" SSID.
    // -----------------------------------------------------------------------------------------

    /// Deterministic: the SAME device_id always derives the SAME SSID (stable across reboots —
    /// `default_ssid` is a pure function of the identity string, no randomness, no clock).
    #[test]
    fn default_ssid_is_deterministic_for_a_fixed_device_id() {
        let a = default_ssid("hp-3c495a31aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let b = default_ssid("hp-3c495a31aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(a, b, "same device_id must derive the identical SSID every time");
        assert!(a.starts_with("HookProbe-"), "human-readable HookProbe-XXXX form: {a}");
        let suffix = a.strip_prefix("HookProbe-").unwrap();
        assert_eq!(suffix.len(), 6, "suffix should be a short, human-readable hex tag: {suffix}");
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()), "suffix must be hex: {suffix}");
    }

    /// Two different devices (e.g. an rpi4 and a CM5, identified by their own manifest
    /// device_id) MUST derive two DIFFERENT SSIDs — this is the actual blocker being fixed:
    /// two devices flashed from the same image must not broadcast the same SSID.
    #[test]
    fn different_device_ids_derive_different_ssids() {
        // Real shapes seen in the field: a CM5's serial-derived id vs an rpi4's.
        let cm5 = default_ssid("hp-3c495a31bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let rpi4 = default_ssid("hp-9f1027acccccccccccccccccccccccccccccccc");
        assert_ne!(cm5, rpi4, "different devices must not collide on the same default SSID");
    }

    /// The explicit operator SSID in intent ALWAYS wins over the derived default, regardless
    /// of device_id — preserves the existing intent path exactly as before this change.
    #[test]
    fn explicit_operator_ssid_overrides_the_derived_default() {
        assert_eq!(resolve_ap_ssid(Some("MyCorpWifi"), "hp-anything"), "MyCorpWifi");
        // Empty string in intent is treated the same as "not set" — not a broken empty SSID.
        assert_eq!(resolve_ap_ssid(Some(""), "hp-anything"), default_ssid("hp-anything"));
        // No intent at all → derived default.
        assert_eq!(resolve_ap_ssid(None, "hp-anything"), default_ssid("hp-anything"));
    }

    /// End-to-end through `render`: an AP intent with NO `ssid` set renders the per-device
    /// derived SSID into the actual hostapd config — this is what makes a freshly-flashed
    /// device come up with its own SSID with zero operator action.
    #[test]
    fn render_uses_derived_ssid_when_intent_omits_it() {
        let radios = vec![radio_band("wlan0", "ap", "2.4")];
        let intent = WifiIntent {
            station: None,
            ap: Some(ApIntent { ssid: None, passphrase: "appass1234".into(), ..Default::default() }),
            country: None,
        };
        let dev_a = "hp-1111111111111111111111111111111111111111";
        let dev_b = "hp-2222222222222222222222222222222222222222";
        let files_a = render(&radios, &intent, dev_a);
        let files_b = render(&radios, &intent, dev_b);
        let expect_a = format!("ssid={}", default_ssid(dev_a));
        let expect_b = format!("ssid={}", default_ssid(dev_b));
        assert!(files_a[0].content.contains(&expect_a), "device A gets its own derived SSID: {}", files_a[0].content);
        assert!(files_b[0].content.contains(&expect_b), "device B gets its own derived SSID: {}", files_b[0].content);
        assert_ne!(expect_a, expect_b, "two devices must render two different SSIDs from the same intent");
        // Same device, re-rendered (simulating a reboot/re-reconcile) → identical SSID again.
        let files_a_again = render(&radios, &intent, dev_a);
        assert_eq!(files_a[0].content, files_a_again[0].content, "stable across re-reconcile/reboot");
    }

    /// THE on-metal bug (fixed 2026-07-09): an AP-role radio with NO `ap:` intent block at all
    /// (`intent.ap == None`) — the standalone-default case a freshly-flashed device boots with —
    /// MUST still render a hostapd.conf (derived SSID + non-open passphrase), or hostapd's
    /// ConditionFileNotEmpty fails and the device broadcasts no SSID. Previously render gated on
    /// `Some(a)` and silently produced nothing.
    #[test]
    fn ap_radio_renders_hostapd_even_when_intent_ap_is_none() {
        let radios = vec![radio_band("wlan0", "ap", "2.4")];
        let intent = WifiIntent { station: None, ap: None, country: None };
        let dev = "hp-1111111111111111111111111111111111111111";
        let files = render(&radios, &intent, dev);
        assert_eq!(files.len(), 1, "AP radio must render exactly one hostapd file with no ap: block");
        assert_eq!(files[0].path, "hostapd-wlan0.conf");
        // derived SSID present
        assert!(files[0].content.contains(&format!("ssid={}", default_ssid(dev))), "derived SSID: {}", files[0].content);
        // NOT an open network — a security appliance must ship WPA2 with a derived key
        assert!(files[0].content.contains("wpa=2") && files[0].content.contains("wpa_passphrase="),
            "default AP must be WPA2-secured, never open: {}", files[0].content);
        assert!(files[0].content.contains(&default_ap_passphrase(dev)), "uses the device-derived passphrase");
        // stable + unique per device
        let dev2 = "hp-2222222222222222222222222222222222222222";
        let files2 = render(&radios, &intent, dev2);
        assert_ne!(files[0].content, files2[0].content, "two devices → different SSID+key");
    }

    // -----------------------------------------------------------------------------------------
    // VHT80-by-default (widest safe channel width) — the fix for the CM5/BCM43455 field finding:
    // a bare `hw_mode=a channel=36 ieee80211n=1` AP ran HT20 (~72 Mbps PHY) on a radio whose
    // `iw phy` caps advertise VHT80 (~433 Mbps PHY 1SS). See `vht80_params`.
    // -----------------------------------------------------------------------------------------

    /// UNII-1 primary ch36 is the LOWER channel of its 40 MHz pair (36,40) → `[HT40+]`, and sits
    /// in the 36-48 80 MHz block whose center channel is 42.
    #[test]
    fn ap_5ghz_ch36_defaults_to_vht80() {
        let radios = vec![radio_band("wlan_5ghz", "ap", "5")];
        let intent = WifiIntent {
            station: None,
            ap: Some(ApIntent { ssid: Some("HP-5G".into()), passphrase: "appass1234".into(), channel: Some(36), ..Default::default() }),
            country: Some("GB".into()),
        };
        let c = &render(&radios, &intent, DEV)[0].content;
        assert!(c.contains("ieee80211ac=1"), "VHT80 enables 802.11ac: {c}");
        assert!(c.contains("ht_capab=[HT40+]"), "ch36 is the lower channel of (36,40): {c}");
        assert!(c.contains("vht_capab=[SHORT-GI-80]"));
        assert!(c.contains("vht_oper_chwidth=1"), "chwidth=1 selects 80 MHz operation: {c}");
        assert!(c.contains("vht_oper_centr_freq_seg0_idx=42"), "80 MHz block 36-48 centers on 42: {c}");
        assert!(c.contains("ieee80211n=1"), "HT still advertised alongside VHT: {c}");
    }

    /// FAIL-SAFE (D12, INVERTED 2026-07-11 — GAP-W2 proven live: hostapd REJECTS `country_code=00`
    /// at config-parse on ANY band, "Invalid country_code '00'" — deleting the line, not emitting
    /// `=00`, is what actually makes hostapd start on the kernel-default domain). With an
    /// UNRESOLVED regdomain, a 5 GHz AP config must OMIT `country_code`/`ieee80211d` entirely and
    /// pin to 2.4 GHz / HT20 / the best-match 1-6-11 channel (`pick_24_channel(&[])` = 6, the one
    /// band+width the world/unresolved domain always permits) so the AP ALWAYS comes up. A
    /// resolved country still gets the intended 5 GHz VHT80.
    #[test]
    fn world_00_5ghz_ap_falls_back_to_24ghz_ht20_so_hostapd_starts() {
        let radios = vec![radio_band("wlan_5ghz", "ap", "5")]; // radio WANTS 5 GHz…
        let intent = WifiIntent {
            station: None,
            ap: Some(ApIntent { ssid: Some("HP".into()), passphrase: "appass1234".into(), channel: Some(36), ..Default::default() }),
            country: None, // …but the regdomain is unresolved → country() = "00"
        };
        let c = &render(&radios, &intent, DEV)[0].content;
        assert!(!c.contains("country_code="), "unresolved must OMIT country_code entirely (never =00 — hostapd rejects it): {c}");
        assert!(!c.contains("ieee80211d"), "no Country IE without a real country: {c}");
        assert!(c.contains("hw_mode=g"), "fail-safe pins 2.4 GHz (hw_mode=g), NOT 5 GHz: {c}");
        // ADR 0034 D18: the no-survey 2.4 GHz fail-safe channel is now the per-device DERIVED
        // {1,6,11} default (`default_24_channel`), not the constant 6 — assert against the same
        // function under test, not a hardcoded literal.
        assert!(
            c.contains(&format!("channel={}", default_24_channel(DEV))),
            "fail-safe pins the per-device-derived 2.4 GHz channel: {c}"
        );
        assert!(!c.contains("ieee80211ac=1"), "NO VHT at an unresolved regdomain (hostapd would reject): {c}");
        assert!(!c.contains("vht_oper_chwidth"), "NO VHT80 when unresolved: {c}");
        assert!(c.contains("ieee80211n=1"), "plain HT20 still fine when unresolved: {c}");
    }

    /// The fail-safe is ONLY for the unresolved `00` case: a resolved country on a 5 GHz radio
    /// still gets 5 GHz VHT80 (no accidental downgrade to 2.4 GHz).
    #[test]
    fn resolved_country_5ghz_ap_keeps_vht80_not_downgraded() {
        let radios = vec![radio_band("wlan_5ghz", "ap", "5")];
        let intent = WifiIntent {
            station: None,
            ap: Some(ApIntent { ssid: Some("HP".into()), passphrase: "appass1234".into(), channel: Some(36), ..Default::default() }),
            country: Some("RO".into()),
        };
        let c = &render(&radios, &intent, DEV)[0].content;
        assert!(c.contains("country_code=RO") && c.contains("hw_mode=a") && c.contains("vht_oper_chwidth=1"),
            "resolved RO keeps 5 GHz VHT80: {c}");
        assert!(c.contains("ieee80211d=1"), "a resolved country advertises the Country IE: {c}");
    }

    /// D12 T1 assertion (Validation Plan): a RESOLVED country renders `country_code=<CC>` +
    /// `ieee80211d=1` together, and NEVER omits them once the regdomain is real.
    #[test]
    fn resolved_country_emits_country_code_and_ieee80211d() {
        let radios = vec![radio_band("wlan0", "ap", "2.4")];
        let intent = WifiIntent {
            station: None,
            ap: Some(ApIntent { ssid: Some("HP".into()), passphrase: "appass1234".into(), ..Default::default() }),
            country: Some("RO".into()),
        };
        let c = &render(&radios, &intent, DEV)[0].content;
        assert!(c.contains("country_code=RO"), "got: {c}");
        assert!(c.contains("ieee80211d=1"), "got: {c}");
    }

    /// ch40 is the UPPER channel of the same (36,40) pair → `[HT40-]`, but the 80 MHz block
    /// (still 36-48) and its center channel (42) are unchanged — same block, different primary.
    #[test]
    fn ap_5ghz_ch40_uses_ht40_minus_same_seg0() {
        let radios = vec![radio_band("wlan_5ghz", "ap", "5")];
        let intent = WifiIntent {
            station: None,
            ap: Some(ApIntent { ssid: Some("HP-5G".into()), passphrase: "appass1234".into(), channel: Some(40), ..Default::default() }),
            country: Some("GB".into()),
        };
        let c = &render(&radios, &intent, DEV)[0].content;
        assert!(c.contains("ht_capab=[HT40-]"), "ch40 is the upper channel of (36,40): {c}");
        assert!(c.contains("vht_oper_centr_freq_seg0_idx=42"), "still the 36-48 block: {c}");
        assert!(c.contains("ieee80211ac=1"));
    }

    /// UNII-3 primaries (149-161) get the same treatment on their own 80 MHz block, center 155.
    #[test]
    fn ap_5ghz_unii3_block_centers_on_155() {
        let radios = vec![radio_band("wlan_5ghz", "ap", "5")];
        let intent = WifiIntent {
            station: None,
            ap: Some(ApIntent { ssid: Some("HP-5G".into()), passphrase: "appass1234".into(), channel: Some(157), ..Default::default() }),
            country: Some("GB".into()),
        };
        let c = &render(&radios, &intent, DEV)[0].content;
        assert!(c.contains("ht_capab=[HT40+]"), "ch157 is the lower channel of (157,161): {c}");
        assert!(c.contains("vht_oper_centr_freq_seg0_idx=155"), "80 MHz block 149-161 centers on 155: {c}");
    }

    /// A DFS primary (e.g. ch52, UNII-2) is NOT auto-upgraded to VHT80 — falls back to the
    /// existing, always-safe plain-HT20 output (no ht_capab/ieee80211ac/vht_* lines at all).
    #[test]
    fn ap_5ghz_dfs_channel_falls_back_to_ht20() {
        let radios = vec![radio_band("wlan_5ghz", "ap", "5")];
        let intent = WifiIntent {
            station: None,
            ap: Some(ApIntent { ssid: Some("HP-5G".into()), passphrase: "appass1234".into(), channel: Some(52), ..Default::default() }),
            country: Some("GB".into()),
        };
        let c = &render(&radios, &intent, DEV)[0].content;
        assert!(!c.contains("ieee80211ac"), "DFS block must not auto-enable VHT80: {c}");
        assert!(!c.contains("ht_capab"), "DFS block keeps the safe plain-HT20 fallback: {c}");
        assert!(c.contains("ieee80211n=1"));
    }

    /// 2026-07-17 (PROVEN ON METAL — v2 EU channel campaign): a DFS channel must NEVER emit
    /// `ieee80211h=1` on the brcmfmac FullMAC radio — that line makes hostapd crash-loop
    /// (`hostapd=activating`, every DFS channel failed with it; without it the same DFS blocks
    /// reached VHT80 after their firmware CAC). DFS/CAC is the FullMAC firmware's job here, not
    /// hostapd's 802.11h. This test locks in "never emit ieee80211h on this hardware" so a future
    /// well-intentioned "add 802.11h for DFS compliance" change can't silently re-brick the AP.
    #[test]
    fn ap_5ghz_dfs_channel_never_emits_ieee80211h_brcmfmac_crashes_on_it() {
        let radios = vec![radio_band("wlan_5ghz", "ap", "5")];
        for dfs_ch in [52u32, 100, 116, 132] {
            let intent = WifiIntent {
                station: None,
                ap: Some(ApIntent {
                    ssid: Some("HP-5G".into()),
                    passphrase: "appass1234".into(),
                    channel: Some(dfs_ch),
                    ..Default::default()
                }),
                country: Some("GB".into()),
            };
            let c = &render(&radios, &intent, DEV)[0].content;
            assert!(!c.contains("ieee80211h"), "ch{dfs_ch} (DFS) must NOT emit ieee80211h (crashes hostapd on brcmfmac): {c}");
            assert!(!c.contains("ieee80211ac"), "ch{dfs_ch} still never auto-enables VHT80: {c}");
        }
    }

    /// A non-DFS 5 GHz channel (the ordinary case) never emits `ieee80211h` — that line is
    /// DFS-specific, not a blanket 5 GHz addition.
    #[test]
    fn ap_5ghz_non_dfs_channel_never_emits_ieee80211h() {
        let radios = vec![radio_band("wlan_5ghz", "ap", "5")];
        let intent = WifiIntent {
            station: None,
            ap: Some(ApIntent { ssid: Some("HP-5G".into()), passphrase: "appass1234".into(), channel: Some(36), ..Default::default() }),
            country: Some("GB".into()),
        };
        let c = &render(&radios, &intent, DEV)[0].content;
        assert!(!c.contains("ieee80211h"), "a non-DFS channel (ch36) must never emit ieee80211h: {c}");
    }

    /// 2.4 GHz stays plain HT20 (the existing, unchanged output) — it's already the fallback
    /// band, and this generator never emits `ieee80211ac`/`vht_*` there.
    #[test]
    fn ap_24ghz_never_emits_vht() {
        let radios = vec![radio_band("wlan0", "ap", "2.4")];
        let intent = WifiIntent {
            station: None,
            ap: Some(ApIntent { ssid: Some("HP-2G".into()), passphrase: "appass1234".into(), ..Default::default() }),
            country: None,
        };
        let c = &render(&radios, &intent, DEV)[0].content;
        assert!(!c.contains("ieee80211ac"), "2.4 GHz must never emit ieee80211ac: {c}");
        assert!(!c.contains("vht_"), "2.4 GHz must never emit vht_* keys: {c}");
        assert!(c.contains("ieee80211n=1"));
    }

    /// `plan()`'s summary also reflects the derived default (not an empty/placeholder SSID) so
    /// the operator-visible plan-as-diff shows exactly what will be broadcast.
    #[test]
    fn plan_summary_shows_the_derived_ssid_when_none_declared() {
        let radios = vec![radio("wlan0", "ap")];
        let intent = WifiIntent { station: None, ap: Some(ApIntent { ssid: None, ..Default::default() }), country: None };
        let p = plan(&radios, &intent, "hp-deadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        let a = p.assignments.iter().find(|a| a.iface == "wlan0").unwrap();
        assert_eq!(a.ssid.as_deref(), Some(default_ssid("hp-deadbeefdeadbeefdeadbeefdeadbeefdeadbeef").as_str()));
    }

    // -----------------------------------------------------------------------------------------
    // ADR 0034 D18 — per-device 2.4 GHz floor channel {1,6,11} (default_24_channel)
    // -----------------------------------------------------------------------------------------

    /// Deterministic + always one of the three non-overlapping candidates.
    #[test]
    fn default_24_channel_is_deterministic_and_in_candidate_set() {
        let ch = default_24_channel("hp-3c495a31aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert!(matches!(ch, 1 | 6 | 11), "must be one of {{1,6,11}}, got {ch}");
        assert_eq!(ch, default_24_channel("hp-3c495a31aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "stable across calls");
    }

    /// Two co-located boxes flashed from the SAME image must not (necessarily) collide on the
    /// same 2.4 GHz floor channel — this is the actual field-observed bug (two Pi4s both on ch6).
    /// A hash-derived pick can't GUARANTEE inequality for every possible pair, but these two real
    /// device_id shapes (an rpi4 and a CM5, mirroring `different_device_ids_derive_different_ssids`)
    /// must differ, proving the derivation is device-sensitive and not a disguised constant.
    #[test]
    fn different_devices_can_land_on_different_24ghz_floor_channels() {
        let cm5 = default_24_channel("hp-3c495a31bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        let rpi4 = default_24_channel("hp-9f1027acccccccccccccccccccccccccccccccc");
        assert_ne!(cm5, rpi4, "these two real-shaped device_ids must land on different 2.4 GHz floor channels");
    }

    /// A handful of short/edge-shaped device_ids all resolve into the valid candidate set — no
    /// panics, no out-of-range picks, regardless of input shape/length.
    #[test]
    fn default_24_channel_always_in_range_for_varied_input_shapes() {
        for id in ["hp-aaaa", "hp-bbbb", "hp-cccc", "hp-dddd", ""] {
            assert!(matches!(default_24_channel(id), 1 | 6 | 11), "out-of-range pick for {id:?}");
        }
    }

    // -----------------------------------------------------------------------------------------
    // ADR 0034 D15/D22 — `band: "auto"` is NOT an override (defers to the radio's detected band,
    // exactly like `band` absent); only a REAL hard pin ("5"/"2.4") overrides it.
    // -----------------------------------------------------------------------------------------

    /// `band: "auto"` on a radio the manifest detected as 5 GHz-capable renders 5 GHz (hw_mode=a),
    /// NOT the old blunt 2.4 GHz default — this is the actual fix for the field bug (the shipped
    /// `band: "2.4"` hard-pin silently overrode a 5 GHz-capable radio; `auto` must not).
    #[test]
    fn band_auto_defers_to_the_radios_detected_5ghz_capability() {
        let radios = vec![radio_band("wlan0", "ap", "5")];
        let intent = WifiIntent {
            station: None,
            ap: Some(ApIntent {
                ssid: Some("HP".into()),
                passphrase: "appass1234".into(),
                band: Some("auto".into()),
                ..Default::default()
            }),
            country: Some("GB".into()),
        };
        let c = &render(&radios, &intent, DEV)[0].content;
        assert!(c.contains("hw_mode=a"), "band:auto on a 5GHz-capable radio must render 5 GHz: {c}");
        assert!(c.contains("ieee80211ac=1"), "band:auto defers to the radio's own VHT80-eligible detected band: {c}");
    }

    /// Case-insensitive + absent `band` behaves identically to `"auto"` (both defer to radio_band)
    /// — `default()`'s `band: None` case, already covered by `dual_radio_ap_band_steering`, plus an
    /// explicit `"Auto"` spelling here.
    #[test]
    fn band_auto_is_case_insensitive_and_matches_absent_band() {
        let radios = vec![radio_band("wlan0", "ap", "2.4")];
        let mk = |band: Option<&str>| WifiIntent {
            station: None,
            ap: Some(ApIntent {
                ssid: Some("HP".into()),
                passphrase: "appass1234".into(),
                band: band.map(String::from),
                ..Default::default()
            }),
            country: None,
        };
        let c_auto = render(&radios, &mk(Some("Auto")), DEV)[0].content.clone();
        let c_absent = render(&radios, &mk(None), DEV)[0].content.clone();
        assert_eq!(c_auto, c_absent, "\"Auto\" (any case) must render identically to band absent");
    }

    /// A REAL hard pin still overrides the radio's detected band — the explicit power-user escape
    /// hatch D15 requires MUST keep working (e.g. pin a 5 GHz-capable radio down to 2.4 GHz).
    #[test]
    fn band_hard_pin_still_overrides_the_radios_detected_band() {
        let radios = vec![radio_band("wlan0", "ap", "5")];
        let intent = WifiIntent {
            station: None,
            ap: Some(ApIntent {
                ssid: Some("HP".into()),
                passphrase: "appass1234".into(),
                band: Some("2.4".into()),
                ..Default::default()
            }),
            country: Some("GB".into()),
        };
        let c = &render(&radios, &intent, DEV)[0].content;
        assert!(c.contains("hw_mode=g"), "an explicit band:2.4 pin must override a 5GHz-capable radio: {c}");
        assert!(!c.contains("ieee80211ac"), "2.4 GHz pin must never emit VHT: {c}");
    }

    // ---- ADR 0034 D24-D33: the `wifi.ap.optimize` block parses through the REAL YAML path ----

    #[test]
    fn ap_optimize_block_deserialises_through_wifiintent_parse() {
        let yaml = r#"
ap:
  ssid: HP
  passphrase: appass1234
  band: auto
  optimize:
    enabled: false
    at: "04:30"
    allow_dfs: false
    allow_meteo: true
    min_improvement: 50
country: RO
"#;
        let intent = WifiIntent::parse(yaml).expect("wifi.ap.optimize must parse");
        let opt = intent.ap.as_ref().unwrap().optimize.as_ref().expect("optimize block must be Some");
        assert_eq!(opt.enabled, Some(false));
        assert_eq!(opt.at.as_deref(), Some("04:30"));
        assert_eq!(opt.allow_dfs, Some(false));
        assert_eq!(opt.allow_meteo, Some(true));
        assert_eq!(opt.min_improvement, Some(50));
    }

    #[test]
    fn ap_optimize_block_absent_parses_to_none_never_a_default_error() {
        let yaml = r#"
ap:
  ssid: HP
  passphrase: appass1234
  band: auto
country: RO
"#;
        let intent = WifiIntent::parse(yaml).expect("must parse without an optimize block");
        assert!(intent.ap.as_ref().unwrap().optimize.is_none(), "absent block must be None, not a default-constructed Some");
    }

    // -----------------------------------------------------------------------------------------
    // 2026-07-16 BUG-1 regression (metal-observed malformed hostapd conf: `ht_capab=[HT40+]
    // [SHORT-GI-20][SHORT-GI-40]wmm_enabled=1` with NO newline between them). `width_lines` itself
    // already terminates every non-empty branch with exactly one `\n` (see its doc + the
    // `debug_assert!` right after its call site above); these tests lock the invariant at the
    // ONLY place that actually matters — the fully rendered conf text — for all three shipped
    // widths, both through the ordinary auto-select path (HT20) and the calibration ladder's
    // explicit forced-width path (HT40/VHT80, exactly what `wifi_calibrate::render_rung_conf`
    // exercises on real hardware).
    // -----------------------------------------------------------------------------------------

    /// HT20 (no width lines at all): `wmm_enabled=1` follows `ieee80211n=1` directly, on its own
    /// line — an EMPTY `width_lines()` output must not introduce a spurious blank line either.
    #[test]
    fn wmm_enabled_on_own_line_ht20() {
        let radios = vec![radio_band("wlan0", "ap", "2.4")];
        let intent = WifiIntent {
            station: None,
            ap: Some(ApIntent { ssid: Some("HP".into()), passphrase: "appass1234".into(), ..Default::default() }),
            country: Some("GB".into()),
        };
        let c = &render(&radios, &intent, DEV)[0].content;
        assert!(
            c.contains("ieee80211n=1\nwmm_enabled=1\n"),
            "HT20: wmm_enabled=1 must directly follow ieee80211n=1, each on its own line: {c}"
        );
        assert!(!c.contains("]wmm_enabled"), "wmm_enabled must never be glued onto a ht_capab line: {c}");
    }

    /// HT40 (ch36, control-channel [HT40+], the forced-width path the calibration ladder's rung 2
    /// uses): `wmm_enabled=1` must land on its own line right after the `ht_capab` line, never
    /// `...[SHORT-GI-40]wmm_enabled=1` glued onto one line (the exact bug seen on metal).
    #[test]
    fn wmm_enabled_on_own_line_ht40() {
        let a = ApIntent { ssid: Some("HP".into()), passphrase: "appass1234".into(), ..Default::default() };
        let c = render_ap_rung("wlan_5ghz", "HP", &a, "GB", "5", 36, ChanWidth::Ht40, DEV);
        assert!(!c.contains("]wmm_enabled"), "HT40: wmm_enabled glued onto the ht_capab line: {c}");
        assert!(
            c.contains("[SHORT-GI-40]\nwmm_enabled=1\n"),
            "HT40: wmm_enabled=1 must be on its own line right after ht_capab: {c}"
        );
    }

    /// VHT80 (ch40, the widest/most line-heavy block — the calibration ladder's top rung):
    /// `wmm_enabled=1` must still land on its own line after the LAST `vht_*` line, not glued onto
    /// `vht_oper_centr_freq_seg0_idx=42`.
    #[test]
    fn wmm_enabled_on_own_line_vht80() {
        let a = ApIntent { ssid: Some("HP".into()), passphrase: "appass1234".into(), ..Default::default() };
        let c = render_ap_rung("wlan_5ghz", "HP", &a, "GB", "5", 40, ChanWidth::Vht80, DEV);
        assert!(!c.contains("]wmm_enabled"), "VHT80: wmm_enabled glued onto a ht_capab/vht_capab line: {c}");
        assert!(
            c.contains("vht_oper_centr_freq_seg0_idx=42\nwmm_enabled=1\n"),
            "VHT80: wmm_enabled=1 must be on its own line right after the last vht_* line: {c}"
        );
    }
}
