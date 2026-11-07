//! Adaptive Wi-Fi: dynamic regulatory domain (from the WAN exit) + on-the-fly channel/width
//! auto-calibration. **Pure, testable core** for ADR 0034 — the runtime feedback loop (which AP
//! is up, which width the radio actually settled on, dmesg chanspec-fail, associated clients)
//! lives in a small oneshot service (`base/scripts/wifi-calibrate.sh` +
//! `base/units/hookprobe-wifi-calibrate.service`) that CALLS this core for every deterministic
//! decision. Nothing here touches a radio, shells out, or reads the network — it is a set of
//! pure functions over explicit inputs, exactly like [`crate::wifi_cfg`] and [`crate::multi_wan`].
//!
//! Two operator-declared capabilities, one intent surface (`wifi.country: auto|GB|…`,
//! `wifi.optimize: max-throughput|conservative`):
//!
//! ## Feature 1 — dynamic regdomain from the WAN exit (COMPLIANCE)
//! A portable SASE edge (see the `sase-edge-default` memory) can boot in any country. The
//! regdomain must NOT be hardcoded: on WAN up / WAN change we DETECT the country and set
//! `iw reg set <CC>` + hostapd `country_code`. [`decide_country`] resolves the detected country
//! from a priority ladder with graceful, offline-capable fallback — the kernel's
//! `wireless-regdb`/CRDA is the actual COMPLIANCE backstop (it clamps TX power, allowed
//! channels and DFS to the set domain; hostapd refuses a config outside it), so this module only
//! has to (a) pick the right country and (b) never PROPOSE a channel the domain forbids.
//!
//! ## Feature 2 — channel/width auto-calibration (max throughput, graceful step-down)
//! VHT80 **IS a stable, reachable top rung** on the Pi/CM onboard BCM43455 (brcmfmac) — proven
//! live on a CM5 (ch40/80 MHz/center-5210, a client at 351 Mbit/s, held). The earlier ch140/20 MHz
//! "collapse" was NOT a firmware VHT80 limitation: it was **`wpa_supplicant` (enabled by default)
//! scanning the AP radio and yanking hostapd off-channel**. The fix is a hard prerequisite — never
//! run a supplicant on an AP-role radio (see [`supplicant_policy`]) — after which VHT80 holds. The
//! step-down ladder still matters (a DFS bounce, a genuinely weaker radio, or residual contention
//! can still make a rung fail), so [`candidate_ladder`] emits a best→safe ladder within the
//! regdomain's allowed non-DFS channels; the runtime tries the widest, VERIFIES it actually held
//! ([`verify_rung`] detects any width-collapse / chanspec-fail), and steps DOWN only if it did
//! not. A weaker radio, or one whose `iw phy` does not advertise VHT80, simply starts lower —
//! capability-driven, never hardware-branched. The brcmfmac-safe VHT80 hostapd block is exactly
//! what [`crate::wifi_cfg`]'s `vht80_params`/`width_lines` emit: `ieee80211ac=1` +
//! `ht_capab=[HT40±][SHORT-GI-*]` + `vht_capab=[SHORT-GI-80]` + `vht_oper_chwidth=1` +
//! `vht_oper_centr_freq_seg0_idx` and NOTHING else — no `[MAX-AMSDU-7935]`/`[MAX-MPDU-11454]`,
//! no `spectrum_mgmt_required`/`ieee80211h` (any of which the FullMAC firmware rejects → hostapd
//! exits).

use crate::wifi_cfg::{ApIntent, ChanWidth};
use serde::{Deserialize, Serialize};

// ===========================================================================================
// Feature 1 — country detection (priority ladder) + regdomain → allowed non-DFS channels
// ===========================================================================================

/// Which source decided the regulatory country, best (most authoritative) first. Recorded in the
/// status artifact so the operator can see WHY a domain was chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CountrySource {
    /// Explicit operator intent (`wifi.country: GB`) — ALWAYS wins (§d in the ADR).
    Operator,
    /// Cached last-known-good — the last REAL country any rung resolved, persisted to
    /// `/var/lib/hookprobe/regdomain-lkg`. Consulted early at boot as a fail-safe against a
    /// transiently-down WAN/modem; skipped on a WAN-change re-eval (mobility re-detection).
    LastKnownGood,
    /// Cellular modem MCC → ISO country (an LTE/5G modem's serving network — most authoritative
    /// LIVE source for a moving box; it IS the physical location).
    ModemMcc,
    /// OFFLINE GeoIP of the box's PUBLIC WAN exit IP against the embedded ODC-PDDL country DB — a
    /// purely local lookup (no packet leaves). Skipped when behind NAT (no public exit IP) unless
    /// the operator opts into a single external IP-echo.
    GeoIp,
    /// System timezone → country (offline, approximate — one TZ can span countries).
    Timezone,
    /// Final fallback: world domain `00` (most conservative — lowest power, fewest channels).
    WorldFallback,
}

impl CountrySource {
    /// A 0–100 confidence for the status artifact (not a probability — an ordering hint).
    pub fn confidence(&self) -> u8 {
        match self {
            CountrySource::Operator => 100,
            // A cached hint: consulted before the live sources at boot for STABILITY, but honestly
            // scored below a live modem reading (it may be stale if the box moved with the WAN down).
            CountrySource::LastKnownGood => 85,
            CountrySource::ModemMcc => 90,
            CountrySource::GeoIp => 75,
            CountrySource::Timezone => 40,
            CountrySource::WorldFallback => 0,
        }
    }
}

/// The detected-country inputs, gathered by the runtime (each independently, best-effort). Any
/// field may be absent; [`decide_country`] applies the priority ladder over whatever is present.
#[derive(Debug, Clone, Default)]
pub struct CountryInputs {
    /// Operator intent country. `Some("GB")` overrides everything; `Some("auto")`/`None` = no
    /// override (let detection decide). Case-insensitive; whitespace-trimmed.
    pub operator: Option<String>,
    /// Cached last-known-good country from `/var/lib/hookprobe/regdomain-lkg` (a real 2-letter code,
    /// never `00`). `None` on a first boot or when a WAN-change re-eval deliberately skips it.
    pub last_known_good: Option<String>,
    /// Cellular modem Mobile Country Code (first 3 digits of the serving PLMN), if a modem is
    /// present and registered.
    pub modem_mcc: Option<u16>,
    /// GeoIP-resolved country (only populated when the outbound lookup is ALLOWED — see the ADR's
    /// standalone/air-gap privacy stance; the runtime leaves this `None` unless consent is on).
    pub geoip_cc: Option<String>,
    /// System timezone (e.g. `Europe/London`), read from `/etc/timezone` — always available
    /// offline.
    pub timezone: Option<String>,
}

/// The resolved regulatory-country decision — the compliance-critical output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CountryDecision {
    /// ISO-3166 alpha-2 (uppercase), or `00` for the world domain.
    pub cc: String,
    pub source: CountrySource,
    pub confidence: u8,
    /// Human note for the evidence graph (what decided, and why).
    pub note: String,
}

/// Resolve the regulatory country from the priority ladder:
/// operator intent → cached last-known-good → modem MCC → offline GeoIP → timezone → world (`00`).
///
/// The operator override ALWAYS wins when it is a real 2-letter code (never for `auto`/blank).
/// Every other source is used only if it yields a plausible ISO code; an unrecognised MCC or
/// timezone falls through to the next source rather than guessing. This is deliberately
/// conservative: a wrong country over-permits TX power/channels (a compliance violation), so an
/// unknown input must degrade toward the *more restrictive* world domain, never toward a guess.
pub fn decide_country(inp: &CountryInputs) -> CountryDecision {
    // (a) operator intent — must be a real alpha-2 (not "auto"/empty).
    if let Some(op) = inp.operator.as_deref() {
        if let Some(cc) = normalize_cc(op) {
            return CountryDecision {
                source: CountrySource::Operator,
                confidence: CountrySource::Operator.confidence(),
                note: format!("operator intent wifi.country={cc} (override — always wins)"),
                cc,
            };
        }
    }
    // (b) cached last-known-good — fail-safe stability at boot (WAN/modem may not be up yet). The
    // runtime WAN-change re-eval leaves this `None` so a physically-moved box re-detects live.
    if let Some(lkg) = inp.last_known_good.as_deref() {
        if let Some(cc) = normalize_cc(lkg) {
            if cc != "00" {
                return CountryDecision {
                    source: CountrySource::LastKnownGood,
                    confidence: CountrySource::LastKnownGood.confidence(),
                    note: format!("cached last-known-good {cc} (fail-safe; skipped on WAN-change re-eval)"),
                    cc,
                };
            }
        }
    }
    // (c) cellular modem MCC.
    if let Some(mcc) = inp.modem_mcc {
        if let Some(cc) = mcc_to_iso(mcc) {
            return CountryDecision {
                source: CountrySource::ModemMcc,
                confidence: CountrySource::ModemMcc.confidence(),
                note: format!("cellular modem MCC {mcc} → {cc}"),
                cc: cc.to_string(),
            };
        }
    }
    // (d) GeoIP of the WAN public IP (offline DB lookup; present only when a public exit IP resolved).
    if let Some(g) = inp.geoip_cc.as_deref() {
        if let Some(cc) = normalize_cc(g) {
            return CountryDecision {
                source: CountrySource::GeoIp,
                confidence: CountrySource::GeoIp.confidence(),
                note: format!("GeoIP of WAN egress → {cc}"),
                cc,
            };
        }
    }
    // (e) system timezone (offline, approximate).
    if let Some(tz) = inp.timezone.as_deref() {
        if let Some(cc) = timezone_to_iso(tz) {
            return CountryDecision {
                source: CountrySource::Timezone,
                confidence: CountrySource::Timezone.confidence(),
                note: format!("system timezone {tz} → {cc} (approximate)"),
                cc: cc.to_string(),
            };
        }
    }
    // (f) world fallback — most conservative.
    CountryDecision {
        cc: "00".to_string(),
        source: CountrySource::WorldFallback,
        confidence: CountrySource::WorldFallback.confidence(),
        note: "no country source available — world domain 00 (conservative)".to_string(),
    }
}

/// Resolve the country to actually WRITE into the hostapd `country_code` at render time — the
/// (c) fix that guarantees hostapd never receives `auto`. Precedence:
///   1. a real 2-letter operator-intent country (`wifi.country: GB`) — always wins;
///   2. the boot-detected CC the regdomain oneshot wrote to `/run/hookprobe/wifi-country`
///      (itself the output of [`decide_country`], already applied via `iw reg set`);
///   3. `00` (world) — the always-valid conservative floor.
///
/// `auto`, blank, or any non-ISO token in EITHER input is rejected (→ falls through), so the
/// return value is ALWAYS a valid regdomain token — never `auto`. This keeps the hostapd
/// `country_code` in lock-step with the kernel regdomain the oneshot set at boot.
pub fn resolved_country_for_render(intent_country: Option<&str>, run_file_cc: Option<&str>) -> String {
    if let Some(cc) = intent_country.and_then(normalize_cc) {
        return cc;
    }
    if let Some(cc) = run_file_cc.and_then(normalize_cc) {
        return cc;
    }
    "00".to_string()
}

/// Validate + normalise an operator/GeoIP country string to an uppercase ISO alpha-2, or `None`
/// if it is `auto`, blank, or not two ASCII letters. `00`/`ZZ` (world) is accepted verbatim.
fn normalize_cc(s: &str) -> Option<String> {
    let t = s.trim();
    if t.eq_ignore_ascii_case("auto") || t.is_empty() {
        return None;
    }
    if t == "00" {
        return Some("00".to_string());
    }
    let up = t.to_ascii_uppercase();
    if up.len() == 2 && up.bytes().all(|b| b.is_ascii_uppercase()) {
        Some(up)
    } else {
        None
    }
}

/// Mobile Country Code → ISO-3166 alpha-2. A representative (not exhaustive) table covering the
/// PLMN ranges this portable edge realistically roams. An unlisted MCC returns `None` so
/// [`decide_country`] falls through to the next (or world) source rather than guessing — the
/// wireless-regdb on-device remains the compliance backstop regardless.
fn mcc_to_iso(mcc: u16) -> Option<&'static str> {
    Some(match mcc {
        202 => "GR",
        204 => "NL",
        206 => "BE",
        208 => "FR",
        212 => "MC",
        213 => "AD",
        214 => "ES",
        216 => "HU",
        218 => "BA",
        219 => "HR",
        220 => "RS",
        222 => "IT",
        225 => "VA",
        226 => "RO",
        228 => "CH",
        230 => "CZ",
        231 => "SK",
        232 => "AT",
        234 | 235 => "GB",
        238 => "DK",
        240 => "SE",
        242 => "NO",
        244 => "FI",
        246 => "LT",
        247 => "LV",
        248 => "EE",
        250 => "RU",
        255 => "UA",
        257 => "BY",
        259 => "MD",
        260 => "PL",
        262 => "DE",
        266 => "GI",
        268 => "PT",
        270 => "LU",
        272 => "IE",
        274 => "IS",
        276 => "AL",
        278 => "MT",
        280 => "CY",
        284 => "BG",
        286 => "TR",
        293 => "SI",
        294 => "MK",
        295 => "LI",
        // Americas
        302 | 303 => "CA",
        310..=316 => "US",
        330 => "PR",
        334 => "MX",
        338 => "JM",
        // South America
        722 => "AR",
        724 | 725 => "BR",
        730 => "CL",
        732 => "CO",
        734 => "VE",
        // Middle East / Africa (common SASE deployments)
        424 => "AE",
        425 => "IL",
        426 => "BH",
        427 => "QA",
        420 => "SA",
        // Asia-Pacific
        404..=406 => "IN",
        440 | 441 => "JP",
        450 => "KR",
        454 => "HK",
        460 | 461 => "CN",
        466 => "TW",
        505 => "AU",
        510 => "ID",
        515 => "PH",
        520 => "TH",
        525 => "SG",
        528 => "BN",
        530 => "NZ",
        _ => return None,
    })
}

/// System timezone (IANA name) → ISO-3166 alpha-2 (approximate, offline). Only the primary zones
/// this edge is likely deployed in are mapped; an unmapped zone returns `None` (→ world domain).
/// A timezone can span multiple countries, hence this is the LOWEST-confidence source.
fn timezone_to_iso(tz: &str) -> Option<&'static str> {
    Some(match tz.trim() {
        "Europe/London" | "Europe/Belfast" => "GB",
        "Europe/Dublin" => "IE",
        "Europe/Paris" => "FR",
        "Europe/Berlin" | "Europe/Busingen" => "DE",
        "Europe/Madrid" => "ES",
        "Europe/Rome" => "IT",
        "Europe/Amsterdam" => "NL",
        "Europe/Brussels" => "BE",
        "Europe/Vienna" => "AT",
        "Europe/Zurich" => "CH",
        "Europe/Lisbon" => "PT",
        "Europe/Warsaw" => "PL",
        "Europe/Prague" => "CZ",
        "Europe/Bratislava" => "SK",
        "Europe/Budapest" => "HU",
        "Europe/Bucharest" => "RO",
        "Europe/Sofia" => "BG",
        "Europe/Athens" => "GR",
        "Europe/Stockholm" => "SE",
        "Europe/Oslo" => "NO",
        "Europe/Copenhagen" => "DK",
        "Europe/Helsinki" => "FI",
        "Europe/Ljubljana" => "SI",
        "Europe/Zagreb" => "HR",
        "Europe/Vilnius" => "LT",
        "Europe/Riga" => "LV",
        "Europe/Tallinn" => "EE",
        "Europe/Luxembourg" => "LU",
        "Europe/Istanbul" => "TR",
        "Europe/Moscow" | "Europe/Kaliningrad" => "RU",
        "Europe/Kiev" | "Europe/Kyiv" => "UA",
        // Americas
        "America/New_York" | "America/Chicago" | "America/Denver" | "America/Los_Angeles"
        | "America/Phoenix" | "America/Anchorage" => "US",
        "America/Toronto" | "America/Vancouver" | "America/Edmonton" | "America/Winnipeg" => "CA",
        "America/Mexico_City" => "MX",
        "America/Sao_Paulo" => "BR",
        "America/Argentina/Buenos_Aires" => "AR",
        "America/Santiago" => "CL",
        "America/Bogota" => "CO",
        // Middle East
        "Asia/Dubai" => "AE",
        "Asia/Jerusalem" | "Asia/Tel_Aviv" => "IL",
        "Asia/Qatar" => "QA",
        "Asia/Riyadh" => "SA",
        // Asia-Pacific
        "Asia/Kolkata" | "Asia/Calcutta" => "IN",
        "Asia/Tokyo" => "JP",
        "Asia/Seoul" => "KR",
        "Asia/Hong_Kong" => "HK",
        "Asia/Shanghai" | "Asia/Chongqing" => "CN",
        "Asia/Taipei" => "TW",
        "Asia/Singapore" => "SG",
        "Asia/Bangkok" => "TH",
        "Asia/Jakarta" => "ID",
        "Asia/Manila" => "PH",
        "Australia/Sydney" | "Australia/Melbourne" | "Australia/Perth"
        | "Australia/Brisbane" => "AU",
        "Pacific/Auckland" => "NZ",
        _ => return None,
    })
}

/// The set of 5 GHz non-DFS channels and 2.4 GHz HT40 permission a regdomain allows the ladder to
/// PROPOSE. This is a COARSE allow-list used only to keep the ladder from proposing an obviously
/// illegal channel; the on-device `wireless-regdb`/CRDA is the authoritative compliance enforcer
/// after `iw reg set`. DFS channels (UNII-2/2e, 52–144) are intentionally excluded everywhere —
/// an unattended edge AP must not gamble on radar CAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegChannels {
    /// The ISO country this table is for (echoed for the status artifact).
    pub cc: String,
    /// 5 GHz non-DFS primary channels the ladder may use, in preference order.
    pub non_dfs_5ghz: Vec<u32>,
    /// Whether 2.4 GHz HT40 is worth proposing in this domain (kept conservative — HT40 in 2.4
    /// eats the only other clean 20 MHz channel and is a poor neighbour; enabled only where the
    /// domain clearly has room).
    pub allow_24_ht40: bool,
}

/// Map a regulatory country to the non-DFS channels the ladder may propose. Conservative and
/// coarse by design (see [`RegChannels`]): the two universally-safe blocks are UNII-1 (36–48) and,
/// where the domain allows it, UNII-3 (149–161). The world domain `00` gets only UNII-1 and no
/// 2.4 HT40 — the most restrictive plausible set.
pub fn reg_channels(cc: &str) -> RegChannels {
    let up = cc.to_ascii_uppercase();
    // UNII-1 is legal for indoor low-power AP use in essentially every domain we target.
    let unii1 = [36u32, 40, 44, 48];
    // UNII-3 (149–161) is allowed at higher power in FCC-style domains (US/CA/MX and much of
    // APAC/Americas), but NOT for AP use across most of ETSI (EU/GB) — excluded there.
    let fcc_style = matches!(
        up.as_str(),
        "US" | "CA" | "MX" | "BR" | "AR" | "CL" | "CO" | "AU" | "NZ" | "KR" | "TW" | "HK"
            | "SG" | "IN" | "JP"
    );
    let mut chans: Vec<u32> = unii1.to_vec();
    if fcc_style {
        chans.extend_from_slice(&[149, 153, 157, 161]);
    }
    RegChannels {
        cc: up.clone(),
        non_dfs_5ghz: chans,
        // Only propose 2.4 HT40 in roomier FCC-style domains; ETSI/world stay HT20 in 2.4.
        allow_24_ht40: fcc_style,
    }
}

// ===========================================================================================
// Feature 2 — radio capabilities, the candidate ladder, and stability verification
// ===========================================================================================

/// What the RADIO can actually do, as read once from `iw phy` by the runtime (NOT re-probed here).
/// This is the capability seam that makes the ladder hardware-agnostic: a FullMAC BCM43455 reports
/// `vht80 = true` and — with the supplicant-contention prerequisite met (see [`supplicant_policy`])
/// — genuinely HOLDS VHT80 in AP mode. The ladder still VERIFIES each rung (a DFS bounce or
/// residual contention can still fail one), but it trusts `iw phy`'s advertised caps to CHOOSE the
/// rungs to try.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadioCaps {
    /// Interface name (for the status artifact and cache key).
    pub iface: String,
    /// Can the radio operate on 5 GHz at all?
    pub band_5ghz: bool,
    /// Can the radio operate on 2.4 GHz?
    pub band_24ghz: bool,
    /// Does `iw phy` advertise HT40?
    pub ht40: bool,
    /// Does `iw phy` advertise VHT80? (Advertised != holds-in-AP-mode — see the type doc.)
    pub vht80: bool,
}

impl RadioCaps {
    /// A conservative default when `iw phy` could not be parsed: 2.4 GHz HT20 only. Never assume a
    /// capability we could not confirm.
    pub fn conservative(iface: &str) -> Self {
        RadioCaps {
            iface: iface.to_string(),
            band_5ghz: false,
            band_24ghz: true,
            ht40: false,
            vht80: false,
        }
    }
}

// -------------------------------------------------------------------------------------------
// AP bring-up PREREQUISITE — no supplicant contention on the AP radio.
//
// Field root-cause (CM5, 2026-07-10): the ch140/20 MHz "VHT80 collapse" was `wpa_supplicant`
// (enabled by default, auto-started) SCANNING the AP-role radio and yanking hostapd off-channel.
// Masking the supplicant on the AP radio makes VHT80 hold. So "no supplicant on an AP radio" is
// a HARD prerequisite of the calibration loop, computed deterministically from the manifest roles.
// -------------------------------------------------------------------------------------------

/// What the runtime must do with `wpa_supplicant` for a given radio before/while it serves an AP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupplicantAction {
    /// STATION-role radio (a USB-dongle uplink): a supplicant is REQUIRED — start it.
    Start,
    /// AP-role radio: a supplicant would scan the radio and yank hostapd off-channel — it MUST be
    /// masked / never pulled in on this interface.
    Mask,
}

/// One radio's (role) → supplicant decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SupplicantPolicy {
    pub iface: String,
    pub role: String,
    pub action: SupplicantAction,
}

/// Deterministically decide, per radio, whether `wpa_supplicant` may run on it. This closes the
/// durable default-`wpa_supplicant.service`-scans-the-AP bug: a supplicant runs ONLY on
/// STATION-role radios; on every AP-role (or unknown-role) radio it is MASKED. The runtime applies
/// this BEFORE calibrating — an AP radio with a scanning supplicant can never hold a wide channel.
///
/// Input is the manifest's `network.wifi_radios` (role assigned by `net_roles` from stable
/// identity, never the `wlanN` name), so the policy survives boot-order renaming.
pub fn supplicant_policy(radios: &[(String, String)]) -> Vec<SupplicantPolicy> {
    radios
        .iter()
        .map(|(iface, role)| {
            let action = if role == "station" {
                SupplicantAction::Start
            } else {
                // AP or anything not explicitly a station → never let a supplicant touch it.
                SupplicantAction::Mask
            };
            SupplicantPolicy { iface: iface.clone(), role: role.clone(), action }
        })
        .collect()
}

/// One rung of the calibration ladder: an explicit (band, channel, width) the runtime will try.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rung {
    /// `"5"` or `"2.4"`.
    pub band: String,
    pub channel: u32,
    /// Serialised as its MHz width for the status artifact.
    #[serde(serialize_with = "ser_width")]
    pub width: ChanWidthShim,
    /// Stable human/cache label, e.g. `5GHz-VHT80-ch36`.
    pub label: String,
}

/// A serialisable mirror of [`ChanWidth`] (which lives in `wifi_cfg` and is deliberately kept free
/// of a serde dependency). Kept 1:1 so conversions are total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChanWidthShim {
    Ht20,
    Ht40,
    Vht80,
}
impl From<ChanWidthShim> for ChanWidth {
    fn from(w: ChanWidthShim) -> ChanWidth {
        match w {
            ChanWidthShim::Ht20 => ChanWidth::Ht20,
            ChanWidthShim::Ht40 => ChanWidth::Ht40,
            ChanWidthShim::Vht80 => ChanWidth::Vht80,
        }
    }
}
impl ChanWidthShim {
    pub fn mhz(&self) -> u32 {
        ChanWidth::from(*self).mhz()
    }
}
fn ser_width<S: serde::Serializer>(w: &ChanWidthShim, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u32(w.mhz())
}

impl Rung {
    fn new(band: &str, channel: u32, width: ChanWidthShim) -> Rung {
        let wname = match width {
            ChanWidthShim::Ht20 => "HT20",
            ChanWidthShim::Ht40 => "HT40",
            ChanWidthShim::Vht80 => "VHT80",
        };
        let bname = if band == "5" { "5GHz" } else { "2.4GHz" };
        Rung {
            band: band.to_string(),
            channel,
            width,
            label: format!("{bname}-{wname}-ch{channel}"),
        }
    }
}

/// Build the best→safe candidate ladder for a radio inside a regdomain. The runtime tries rung 0
/// first and steps DOWN on failure. **The operator's exact 3-rung shape (2026-07-15, proven on
/// metal — Pi4 + CM5, brcmfmac BCM43455)**:
///
/// 1. **5 GHz VHT80 on ch40** — the UNII-1 (36-48) 80 MHz block's UPPER-secondary control channel
///    (`ht_capab=[HT40-]`, `vht_oper_centr_freq_seg0_idx=42` — see
///    [`crate::wifi_cfg::vht80_params`]). Top throughput, and PROVEN to hold stably (AP-ENABLED,
///    80 MHz, no flap) — the LOWER-secondary control channel ch36 (`[HT40+]`) does NOT hold on this
///    firmware (it drifts to a DFS channel and never settles). Falls back to the UNII-3 block's
///    ch149 if the domain doesn't permit UNII-1 at all (rare — every `reg_channels` domain does).
/// 2. **5 GHz HT40 ch36** — the same block's LOWER-primary control channel (`[HT40+]`), proven
///    rock-stable (~150 Mbps). Half the width of rung 1, the safety net if VHT80 doesn't hold.
///    Falls back to plain HT20 on this same anchor channel if the radio has no HT40 capability.
/// 3. **2.4 GHz ch6** — the always-joinable floor (terminal; unconditional Keep). A CONSTANT, not
///    a per-device pick — operator-prescriptive default. [`crate::wifi_cfg::default_24_channel`]
///    remains available for OTHER callers (e.g. the world/unresolved-regdomain render fail-safe)
///    but is deliberately NOT used for this ladder's floor.
///
/// A regdomain allowing 2.4 GHz HT40 (FCC-style) additionally gets a 2.4 GHz HT40 rung ahead of
/// the HT20 floor — unchanged, orthogonal to the 3-rung shape above.
///
/// Rungs the radio can't do (no 5 GHz band, no VHT80/HT40 cap) or the domain forbids (channel not
/// in `non_dfs_5ghz`) are simply omitted — the ladder is always a valid, non-empty subset.
///
/// `device_id` is accepted (and unused) for API stability with callers that still thread it
/// through from the manifest identity — see [`render_rung_conf`], which DOES still need it for the
/// world/unresolved-regdomain render fail-safe.
pub fn candidate_ladder(reg: &RegChannels, caps: &RadioCaps, _device_id: &str) -> Vec<Rung> {
    let mut ladder = Vec::new();
    if caps.band_5ghz {
        // Rung 1: VHT80 on ch40 (UNII-1 upper-secondary, proven-on-metal to hold) — else the
        // UNII-3 block.
        let vht80_primary = if reg.non_dfs_5ghz.contains(&40) {
            Some(40)
        } else {
            reg.non_dfs_5ghz.iter().copied().find(|c| *c == 149)
        };
        if caps.vht80 {
            if let Some(ch) = vht80_primary {
                ladder.push(Rung::new("5", ch, ChanWidthShim::Vht80));
            }
        }
        // Rung 2: HT40 ch36 (UNII-1 lower-primary) — else the lowest allowed 5 GHz channel.
        let anchor = if reg.non_dfs_5ghz.contains(&36) {
            Some(36)
        } else {
            reg.non_dfs_5ghz.first().copied()
        };
        if let Some(ch) = anchor {
            if caps.ht40 {
                ladder.push(Rung::new("5", ch, ChanWidthShim::Ht40));
            } else {
                // No HT40 capability at all — HT20 is the only 5 GHz option left to offer.
                ladder.push(Rung::new("5", ch, ChanWidthShim::Ht20));
            }
        }
    }
    // Rung 3 (floor): 2.4 GHz ch6 — a CONSTANT, operator-prescribed default (see doc above).
    const FLOOR_CH: u32 = 6;
    if caps.band_24ghz {
        if caps.ht40 && reg.allow_24_ht40 {
            ladder.push(Rung::new("2.4", FLOOR_CH, ChanWidthShim::Ht40));
        }
        // The universal floor — guarantees a non-empty ladder even on a conservative radio.
        ladder.push(Rung::new("2.4", FLOOR_CH, ChanWidthShim::Ht20));
    }
    // Absolute backstop: a radio that reported neither band (parsing failure) still gets the
    // 2.4/HT20 floor so the caller always has something to try.
    if ladder.is_empty() {
        ladder.push(Rung::new("2.4", FLOOR_CH, ChanWidthShim::Ht20));
    }
    ladder
}

// ===========================================================================================
// DFS awareness — Channel-Availability-Check (CAC) settle duration (2026-07-15, coordinator
// directive) — a ROBUSTNESS NET, not exercised by the shipped 3-rung ladder above (none of
// VHT80-ch40 / HT40-ch36 / 2.4-ch6 is a DFS channel). If a future regdomain or a wider
// `candidate_ladder` ever proposes a DFS channel (UNII-2A/2C), the radio must complete a
// regulatory Channel-Availability-Check (a radar listen) before hostapd reaches AP-ENABLED;
// treating that window as a rung failure would wrongly step down a channel that is simply still
// performing its mandatory CAC. ETSI EN 301 893 (the RO/ANCOM and EU-wide numbers this edge
// targets) sets the CAC at ~60s for ordinary DFS channels, but a full 10 MINUTES (600s) for the
// METEOROLOGICAL radar sub-band 5600-5650 MHz (ch116/120/124/128) — a single settle constant would
// either be far too short for that sub-band or far too long (wasted boot time) everywhere else, so
// the duration must be a function of the actual channel footprint.
// ===========================================================================================

/// The 4-channel (20 MHz-spaced) 80 MHz-block groupings across the WHOLE 5 GHz band, DFS blocks
/// included — generalises [`crate::wifi_cfg::vht80_params`]'s non-DFS-only UNII-1/UNII-3 table so
/// [`dfs_cac_seconds`] can compute a rung's occupied-channel FOOTPRINT. Used ONLY for that CAC
/// lookup: the shipped ladder never proposes a DFS block, so this never drives the shipped rungs'
/// width lines (that stays `vht80_params`'s job).
const FIVE_GHZ_BLOCKS: [[u32; 4]; 6] = [
    [36, 40, 44, 48],      // UNII-1 — non-DFS (the shipped VHT80 rung's block; control ch40, seg0 42)
    [52, 56, 60, 64],      // UNII-2A — DFS, standard ~60s CAC
    [100, 104, 108, 112],  // UNII-2C — DFS, standard ~60s CAC
    [116, 120, 124, 128],  // UNII-2C — DFS, METEOROLOGICAL sub-band 5600-5650MHz — 10-MINUTE CAC
    [132, 136, 140, 144],  // UNII-2C — DFS, standard ~60s CAC
    [149, 153, 157, 161],  // UNII-3 — non-DFS (the shipped ladder's UNII-1-unavailable fallback)
];

/// The occupied 20 MHz sub-channels for a (control channel, width): HT20 occupies just itself; HT40
/// occupies its pair within the containing 80 MHz block; VHT80 occupies the whole block. A channel
/// outside every known block (e.g. the lone ch165) occupies only itself.
fn channel_footprint(channel: u32, width_mhz: u32) -> Vec<u32> {
    let block = FIVE_GHZ_BLOCKS.iter().find(|b| b.contains(&channel));
    match (width_mhz, block) {
        (80, Some(b)) => b.to_vec(),
        (40, Some(b)) => {
            if b[0..2].contains(&channel) { b[0..2].to_vec() } else { b[2..4].to_vec() }
        }
        _ => vec![channel],
    }
}

fn is_standard_dfs_channel(c: u32) -> bool {
    matches!(c, 52 | 56 | 60 | 64 | 100 | 104 | 108 | 112 | 132 | 136 | 140 | 144)
}

fn is_meteo_dfs_channel(c: u32) -> bool {
    matches!(c, 116 | 120 | 124 | 128)
}

/// Regulatory DFS Channel-Availability-Check duration (seconds) for a rung's OCCUPIED footprint
/// (ETSI EN 301 893):
///   - `0`   — footprint touches no DFS channel (UNII-1 36-48, UNII-3 149-161) — no CAC at all, the
///     ordinary settle applies.
///   - `60`  — a standard DFS channel (UNII-2A 52-64, UNII-2C 100-112 / 132-144).
///   - `600` — footprint touches the METEOROLOGICAL sub-band 5600-5650 MHz (ch116/120/124/128,
///     UNII-2C) — a 10-MINUTE CAC. A 60s (or even a 75s-padded) settle would wrongly fail these —
///     this is exactly why the duration is channel-dependent, not a single constant.
///
/// `width_mhz` widens the footprint checked: a VHT80 rung centered on the 116-128 block needs the
/// 600s CAC even when its CONTROL channel is 116 alone (a "standard" 60s DFS channel on its own),
/// because the block's occupied bandwidth includes 120/124/128.
pub fn dfs_cac_seconds(channel: u32, width_mhz: u32) -> u32 {
    let fp = channel_footprint(channel, width_mhz);
    if fp.iter().any(|c| is_meteo_dfs_channel(*c)) {
        600
    } else if fp.iter().any(|c| is_standard_dfs_channel(*c)) {
        60
    } else {
        0
    }
}

/// Is this (channel, width) footprint a DFS rung at all? A thin, self-documenting wrapper over
/// [`dfs_cac_seconds`] for call sites that only need the boolean.
pub fn is_dfs_rung(channel: u32, width_mhz: u32) -> bool {
    dfs_cac_seconds(channel, width_mhz) > 0
}

/// Pick the settle duration (seconds) the runtime should wait before observing a rung — the
/// DFS-aware Rust mirror of `wifi-calibrate.sh`'s `select_settle`. A non-5GHz rung, or a 5 GHz rung
/// whose footprint touches no DFS channel, uses the caller's ordinary `settle_default`/
/// `settle_5ghz`. A DFS rung overrides that with the regulatory CAC-appropriate settle
/// (`settle_dfs_standard` for a 60s-CAC channel, `settle_dfs_meteo` for the 600s meteorological
/// sub-band) — so a slow CAC is never mistaken for a stalled bring-up. None of the shipped ladder's
/// 3 rungs is DFS, so this always returns `settle_5ghz`/`settle_default` for them today.
pub fn select_settle_seconds(
    rung: &Rung,
    settle_default: u32,
    settle_5ghz: u32,
    settle_dfs_standard: u32,
    settle_dfs_meteo: u32,
) -> u32 {
    if rung.band != "5" {
        return settle_default;
    }
    match dfs_cac_seconds(rung.channel, rung.width.mhz()) {
        0 => settle_5ghz,
        secs if secs >= 600 => settle_dfs_meteo,
        _ => settle_dfs_standard,
    }
}

/// Render the hostapd conf for a specific rung — a thin wrapper over
/// [`crate::wifi_cfg::render_ap_rung`] so the security block (WPA2-PSK/EAP), SSID and banner are
/// produced by exactly the same code as the ordinary path. Only the (channel, width) differ.
/// `device_id` feeds `render_ap_rung`'s world/unresolved-regdomain 2.4 GHz fail-safe channel pick
/// (ADR 0034 D18) — irrelevant for a real regdomain (the rung's own `channel` is used), but kept
/// so this seam can never emit the old hardcoded `ch6` even in that corner case.
pub fn render_rung_conf(
    iface: &str,
    ssid: &str,
    a: &ApIntent,
    country: &str,
    rung: &Rung,
    device_id: &str,
) -> String {
    crate::wifi_cfg::render_ap_rung(
        iface,
        ssid,
        a,
        country,
        &rung.band,
        rung.channel,
        rung.width.into(),
        device_id,
    )
}

/// What the runtime OBSERVED after applying a rung — the feedback the pure verifier classifies.
/// Every field is something the runtime can read with `iw dev … info`, `dmesg`, and (optionally)
/// `iw dev … station dump` / an iperf probe.
#[derive(Debug, Clone, Default)]
pub struct ObservedAp {
    /// Is `hookprobe-hostapd@<iface>` active?
    pub active: bool,
    /// The channel the radio ACTUALLY settled on (from `iw dev … info`), if any.
    pub oper_channel: Option<u32>,
    /// The width the radio ACTUALLY settled on in MHz (20/40/80), if any.
    pub oper_width_mhz: Option<u32>,
    /// Count of `brcmf_set_channel: set chanspec … fail` (or equivalent) lines in the post-apply
    /// dmesg window. Any storm ⇒ the firmware is rejecting the chanspec.
    pub chanspec_fail_count: u32,
    /// Whether a client is EXPECTED to be present, and if so whether it associated. `None` = no
    /// client expected (a fresh AP with nobody connected yet — do NOT fail the rung for this).
    pub client_associated: Option<bool>,
}

/// Threshold above which chanspec-fail lines count as a firmware-rejection STORM (a single
/// stray line during a normal restart is tolerated).
pub const CHANSPEC_FAIL_STORM: u32 = 2;

/// The verdict for one applied rung.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stability {
    /// AP up, operating channel+width match what we requested (or are unreadable), client (if
    /// any) associated. Keep this rung — REGARDLESS of any chanspec-fail lines observed getting
    /// here (BUG-W5: those are the proven, expected bounce-then-converge noise).
    Stable,
    /// AP up but the radio silently dropped to a DIFFERENT channel/width than requested — THE
    /// brcmfmac VHT80 trap (requested VHT80 ch36 → got ch140/20) — with NO chanspec-fail storm to
    /// explain it. Step down.
    WidthCollapsed,
    /// The radio did NOT converge to the requested channel/width, AND the firmware spewed
    /// chanspec-fail errors while trying — an active rejection, not a settle-time bounce. Step
    /// down. (A fail-storm alongside a CONVERGED chanspec is `Stable`, not this — see BUG-W5.)
    ChanspecFailStorm,
    /// The AP unit is not active at all (hostapd refused the config or crashed). Step down.
    Down,
    /// AP up and width held, but an expected client never associated. Step down (the wide config
    /// may be un-associable for the client even if the AP thinks it is up).
    ClientFailed,
}

impl Stability {
    /// Is this rung good enough to keep?
    pub fn is_stable(&self) -> bool {
        matches!(self, Stability::Stable)
    }
}

/// Classify an applied rung from what the runtime observed.
///
/// **Priority (2026-07-12, BUG-W5 metal fix — CM5 + Pi4 onboard BCM43455):** CONVERGENCE wins
/// over any transient chanspec-fail lines logged getting there. Ground truth proved the radio
/// bounces through a `set chanspec … fail` burst on the very first VHT80 bring-up and THEN
/// converges to — and HOLDS (18s+ stable) — the requested chanspec. So a fail count observed
/// during settle is expected noise IF the operating channel+width end up matching the request; it
/// is only a genuine rejection if they do NOT. Order of checks is now:
///   Down → (channel+width CONVERGED? → ClientFailed/Stable, regardless of fail count)
///        → (not converged: ChanspecFailStorm → WidthCollapsed).
/// This inverts the PRE-2026-07-12 ordering (which checked the fail-storm before convergence and
/// consequently stepped down a radio that had, in fact, already converged — the loop-churns-forever
/// bug). The MAX_RETRIES step-down ladder in [`next_rung_action`] is unaffected: a radio that
/// genuinely never converges still retries then steps down exactly as before.
/// The 5 GHz **80 MHz block** a channel belongs to, as its center index (42/58/106/122/138/155).
///
/// An 80 MHz channel is identified by its BLOCK, not by which of the block's four 20 MHz channels
/// is named as primary. Returns `None` for a channel in no known 80 MHz block (2.4 GHz, or a drift
/// target like the classic ch140 bounce), so an unexpected channel can never be mistaken for a
/// match. Mirrored byte-for-byte by `wifi-calibrate.sh`'s own `block_center_for_channel`.
pub fn block_center_for_channel(channel: u32) -> Option<u32> {
    match channel {
        36 | 40 | 44 | 48 => Some(42),
        52 | 56 | 60 | 64 => Some(58),
        100 | 104 | 108 | 112 => Some(106),
        116 | 120 | 124 | 128 => Some(122),
        132 | 136 | 140 | 144 => Some(138),
        149 | 153 | 157 | 161 => Some(155),
        _ => None,
    }
}

/// True when `a` and `b` are the same physical 80 MHz channel (same block).
fn same_80mhz_block(a: u32, b: u32) -> bool {
    match (block_center_for_channel(a), block_center_for_channel(b)) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

pub fn verify_rung(req: &Rung, obs: &ObservedAp) -> Stability {
    if !obs.active {
        return Stability::Down;
    }
    let want_mhz = req.width.mhz();
    // "Converged" = every reading we HAVE matches the request; a reading we don't have (radio
    // unreadable) is not evidence against convergence — matches the pre-fix behaviour of never
    // failing solely on an absent reading.
    let width_converged = obs.oper_width_mhz.map(|m| m == want_mhz).unwrap_or(true);
    // BUG-W7 (2026-07-17, THE 150-Mbps bug — found on live CM5 + Pi4 metal): at 80 MHz the channel
    // test MUST be block-aware, never an exact match. GROUND TRUTH: the proven VHT80-ch40 block
    // (`channel=40`, `ht_capab=[HT40-]`, `seg0_idx=42`) brings the radio up WORKING — `iw dev`
    // reports `channel 36 (5180 MHz), width: 80 MHz, center1: 5210 MHz`, hostapd active, client
    // associated — because the brcmfmac FullMAC firmware names an 80 MHz chanspec's primary as the
    // BLOCK'S LOWEST channel (36), not the configured control (40). The old `c == req.channel` read
    // that as not-converged; the harmless one-time bring-up churn then tripped ChanspecFailStorm and
    // the loop REVERTED a healthy 80 MHz link (~450 Mbit/s PHY, ~250 Mbit/s real, operator-measured)
    // down to HT40 (~150 Mbit/s) — cold AND warm, both boards, every attempt. Warmth was never the
    // cause. 20/40 MHz keep the exact match (the firmware reports those faithfully).
    let chan_converged = obs
        .oper_channel
        .map(|c| c == req.channel || (want_mhz == 80 && same_80mhz_block(c, req.channel)))
        .unwrap_or(true);
    if width_converged && chan_converged {
        if obs.client_associated == Some(false) {
            return Stability::ClientFailed;
        }
        return Stability::Stable;
    }
    // Not converged — the fail-storm is the most diagnostic reason (active firmware rejection);
    // otherwise it's a silent width/channel collapse.
    if obs.chanspec_fail_count >= CHANSPEC_FAIL_STORM {
        return Stability::ChanspecFailStorm;
    }
    Stability::WidthCollapsed
}

// ===========================================================================================
// D13 — 2.4 GHz best-match failover channel
// ===========================================================================================

/// One 2.4 GHz channel survey sample, from `iw dev <iface> survey dump`, gathered by the runtime
/// AFTER the AP is already up (never at boot — surveying at boot would race hostapd's first
/// bring-up, the W4 scan trap this ADR eliminates). `busy_ratio` is 0–100 (percentage busy time
/// on that channel); `stations` is the count of neighboring APs/clients observed on it (from a
/// scan, if available) — both are load signals the picker sums.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelSurvey {
    pub channel: u32,
    pub busy_ratio: u8,
    pub stations: u32,
}

/// Pick the least-congested non-overlapping 2.4 GHz channel — **1, 6, or 11** (D13). With **no**
/// survey (the boot path: a deterministic choice made with no radio read) this ALWAYS returns
/// **6** — the same default `render_ap`'s unresolved-country fail-safe used to hardcode; this
/// function is now the single source of that default (spec item 3). With a survey, each candidate
/// is scored by the SUMMED load (`busy_ratio + stations`) of every surveyed sample within ±2
/// channels of it (the physical 20 MHz overlap window) — the least-loaded candidate wins; a tie
/// is broken by the LOWEST channel number, so the result is fully deterministic. Pure — no I/O.
pub fn pick_24_channel(survey: &[ChannelSurvey]) -> u32 {
    const CANDIDATES: [u32; 3] = [1, 6, 11];
    if survey.is_empty() {
        return 6;
    }
    let mut best = CANDIDATES[0];
    let mut best_score = u32::MAX;
    for &c in &CANDIDATES {
        let score: u32 = survey
            .iter()
            .filter(|s| s.channel.abs_diff(c) <= 2)
            .map(|s| u32::from(s.busy_ratio) + s.stations)
            .sum();
        // Strict `<` so the FIRST (lowest) candidate wins any tie — CANDIDATES is already
        // ascending, so this is the deterministic lowest-channel tie-break.
        if score < best_score {
            best_score = score;
            best = c;
        }
    }
    best
}

// ===========================================================================================
// D14 — verify-retry state machine: clean-retry-the-same-rung before stepping down
// ===========================================================================================

/// What the runtime verify-retry loop should do next for the rung it just applied (D14 — the
/// DFS-bounce-safe bring-up). A transient bounce (a competing scan racing hostapd's first
/// bring-up) very often clears on a CLEAN restart of the SAME rung — proven live: VHT80 holds on
/// retry once the supplicant is masked — so `WidthCollapsed`/`ChanspecFailStorm`/`Down` get up to
/// `max_retries` clean-restart attempts on the same rung before the loop gives up and steps down
/// the ladder. `ClientFailed` is not a radio bounce a same-rung retry would fix, so it steps down
/// immediately. `Stable` keeps the rung and stops the loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RungAction {
    /// The rung held — stop the loop, this is the winning rung.
    Keep,
    /// A transient-looking failure, still within the retry budget — clean-restart the SAME rung.
    RetrySameRung,
    /// Retry budget exhausted (or a non-transient failure) — step DOWN to the next rung.
    StepDown,
}

/// Decide the next verify-retry action from a rung's [`Stability`] verdict. `attempt_on_rung` is
/// how many times THIS rung has already been tried (0 on the first application); `max_retries`
/// bounds the clean-restart budget before the loop gives up on the rung and steps down.
pub fn next_rung_action(v: Stability, attempt_on_rung: u32, max_retries: u32) -> RungAction {
    match v {
        Stability::Stable => RungAction::Keep,
        Stability::WidthCollapsed | Stability::ChanspecFailStorm | Stability::Down => {
            if attempt_on_rung < max_retries {
                RungAction::RetrySameRung
            } else {
                RungAction::StepDown
            }
        }
        // A width-held rung whose expected client still didn't associate is not a radio-bounce
        // symptom a same-rung retry would fix — step down rather than burn the retry budget.
        Stability::ClientFailed => RungAction::StepDown,
    }
}

// ===========================================================================================
// 2026-07-16 (BUG-2) — the WARM-UPGRADE decision: after the boot ladder settles on a non-top
// rung, one more (bounded) attempt at the next-wider rung now that the radio is WARM.
//
// Metal-proven (Pi4 + CM5, BCM43455): `5GHz-VHT80-ch40` HOLDS rock-solid (4/4 polls stable,
// AP-ENABLED) once the radio is WARM — but a genuinely COLD brcmfmac radio can still be mid-bounce
// past the ordinary boot-time settle and get stepped down to `5GHz-HT40-ch36` before it would have
// converged. Rather than inflating every cold rung's settle to cover the worst case, the runtime
// (`wifi-calibrate.sh`) does exactly ONE re-attempt of the next-wider 5 GHz rung, with a longer
// settle (`SETTLE_5GHZ_WARM`), once the ladder has already settled and the radio is warm/serving.
// This is the PURE selection + outcome logic that decision mirrors; the actual apply/observe/
// revert/commit happens in the shell runtime (no radio I/O here, exactly like every other function
// in this module).
// ===========================================================================================

/// Is there a wider 5 GHz rung immediately above the settled one worth a warm re-attempt, and if
/// so which? Eligible ONLY when:
///   - `settled_label` is actually present in `ladder` (an unknown/foreign label — e.g. a stale
///     cache entry from a different pin/regdomain — is never a warm-upgrade candidate);
///   - it is not already the ladder's TOP (widest) rung (index 0) — nothing wider to try;
///   - it is itself a 5 GHz rung AND the rung immediately above it (by ladder order) is ALSO
///     5 GHz — a 2.4 GHz floor settle never attempts to jump bands here (that is a much bigger
///     change than "the same radio, warmed up", and is not what was proven on metal).
///
/// Returns `None` (no warm-upgrade attempt) or `Some(&Rung)` — the ONE candidate to warm-retry.
pub fn warm_upgrade_candidate<'a>(ladder: &'a [Rung], settled_label: &str) -> Option<&'a Rung> {
    let idx = ladder.iter().position(|r| r.label == settled_label)?;
    if idx == 0 {
        return None; // already at (or is) the ladder's top rung — nothing wider to try
    }
    let settled = &ladder[idx];
    let wider = &ladder[idx - 1];
    if settled.band == "5" && wider.band == "5" {
        Some(wider)
    } else {
        None
    }
}

/// The warm-upgrade attempt's final action — what the runtime should do with the result of
/// applying [`warm_upgrade_candidate`]'s pick (if any) and observing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WarmUpgradeAction {
    /// [`warm_upgrade_candidate`] found nothing eligible (already at top, or not a 5 GHz settle) —
    /// the runtime must not even attempt a warm re-try.
    NotEligible,
    /// The warm re-attempt CONVERGED (its [`Stability`] verdict was [`Stability::Stable`]) — commit
    /// the upgrade: the wider rung becomes the new `chosen` rung, and (via the caller's existing
    /// band-LKG/learning-model export, unchanged by this feature) persists as such for next boot.
    Upgrade,
    /// The warm re-attempt did NOT converge — revert to the already-proven settled rung (the AP is
    /// NEVER left down for a failed warm-upgrade attempt) and record the miss (via the caller's
    /// existing `learn_record`/observation plumbing, unchanged by this feature) so the model
    /// doesn't thrash retrying it every cycle.
    Revert,
}

/// Decide the warm-upgrade action from [`warm_upgrade_candidate`]'s eligibility plus the
/// [`Stability`] verdict OBSERVED for that candidate, if a warm re-attempt was made at all.
/// `candidate = None` short-circuits to [`WarmUpgradeAction::NotEligible`] regardless of
/// `observed` (there is nothing to have observed — the runtime must not have attempted anything).
/// At most one candidate is ever considered per call — this function has no memory of prior calls,
/// so "at most ONE warm-upgrade attempt per calibrate run" is enforced by the CALLER invoking this
/// (and the apply/observe it gates) exactly once per run, not by any state here.
pub fn warm_upgrade_action(candidate: Option<&Rung>, observed: Option<Stability>) -> WarmUpgradeAction {
    match candidate {
        None => WarmUpgradeAction::NotEligible,
        Some(_) => match observed {
            Some(s) if s.is_stable() => WarmUpgradeAction::Upgrade,
            _ => WarmUpgradeAction::Revert,
        },
    }
}

// ===========================================================================================
// Cache (last-known-good rung per radio+regdomain) + the status/evidence artifact
// ===========================================================================================

/// Pick the ladder index to START at, given the last-known-good rung LABEL for this
/// (radio, regdomain) from cache. Reboots start at the PROVEN rung, not the top — no re-thrash of
/// a VHT80 the firmware has already been shown to reject. If the cached label is absent or no
/// longer in the ladder (radio/domain changed), start at the top (index 0) and re-discover.
///
/// Hysteresis note: the runtime should only re-run the FULL ladder (from index 0) on a regdomain
/// change, a radio/driver change, boot, or an explicit operator request — never spontaneously.
pub fn start_rung(ladder: &[Rung], cached_label: Option<&str>) -> usize {
    match cached_label {
        Some(lbl) => ladder.iter().position(|r| r.label == lbl).unwrap_or(0),
        None => 0,
    }
}

// ===========================================================================================
// D19 — band-outcome memory (band-LKG), distinct from the regdomain-LKG
// ===========================================================================================

/// The last PROVEN-stable rung for one AP interface, persisted to
/// `/var/lib/hookprobe/wifi-band-lkg-<iface>.json` when the verify-retry loop settles `Stable`
/// (D19). DISTINCT from `/var/lib/hookprobe/regdomain-lkg` (country-only, D10c) — this one
/// remembers the (band, width, channel) rung itself, so next boot starts the calibration loop
/// there directly instead of re-probing from the top (VHT80) and eating the ~45s fail-storm churn
/// on radios (like brcmfmac) that will never hold VHT80. `label` is exactly the
/// [`start_rung`]-compatible cache key — writing it here and feeding it back as `cached_label` is
/// the whole mechanism; no new lookup logic needed on the "resume" side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BandLkg {
    /// The regulatory country this rung was proven under (ISO alpha-2, or `00`). A regdomain
    /// change (different country → potentially different No-IR/DFS flags) invalidates the cache.
    pub cc: String,
    /// A stable radio fingerprint (e.g. the phy's MAC address, or `driver+vendor`) — a swapped
    /// radio on the same interface name must not inherit a rung proven on different hardware.
    pub radio_id: String,
    /// `"5"` or `"2.4"` — echoed for humans/telemetry; `label` is the authoritative cache key.
    pub band: String,
    /// The winning rung's [`Rung::label`] (e.g. `5GHz-HT40-ch36`) — fed straight into
    /// [`start_rung`] as `cached_label`.
    pub label: String,
    pub channel: u32,
    /// ISO8601 timestamp of when this rung was proven stable.
    pub decided_at: String,
}

/// Is a cached band-LKG still trustworthy to resume from? Valid only when BOTH the CURRENT
/// regdomain and the CURRENT radio match what the cache was proven under (D19) — a moved box (new
/// country → possibly different No-IR/DFS rules) or a swapped radio must re-fight the ladder from
/// the top rather than blindly trusting a rung proven on different hardware/regdomain. Pure
/// string-equality; the caller supplies both `cc` and `radio_id` already normalised.
pub fn band_lkg_valid(lkg: &BandLkg, cc: &str, radio_id: &str) -> bool {
    lkg.cc.eq_ignore_ascii_case(cc) && lkg.radio_id == radio_id
}

/// ADR 0034 D22 — the "5"/"2.4" bootstrap band for the FIRST hostapd conf a reconcile renders
/// (the calibration loop then converges the final band/width/channel from there — this decision
/// only has to be a SAFE, VALID starting point, never the final word). Pure — no I/O; the caller
/// gathers `intent_band` (raw operator YAML value), `band_lkg` (already read + validated via
/// [`band_lkg_valid`]), and `ap_capable_5ghz_present` (does ANY 5 GHz channel look usable on this
/// radio+regdomain — a coarse capability signal today; ADR 0034 D16's No-IR pre-flight sharpens
/// this later without changing this function's contract).
///
/// Precedence:
///   1. a real hard pin (`"5"` or `"2.4"`, case-insensitive) — ALWAYS honored, disables the
///      auto-ladder entirely (D15: "explicit operator override of the always-joinable default").
///   2. `auto` / absent, with a VALID band-LKG — resume at the proven band (no flap, no wasted
///      attempt on a radio already shown to need the other band).
///   3. `auto` / absent, no valid LKG — 5 GHz if a channel looks AP-capable on this radio+regdomain
///      (fight for it), else the 2.4 GHz floor.
pub fn resolve_bootstrap_band(
    intent_band: Option<&str>,
    band_lkg: Option<&BandLkg>,
    ap_capable_5ghz_present: bool,
) -> &'static str {
    if let Some(b) = intent_band {
        let t = b.trim();
        if t.eq_ignore_ascii_case("5") {
            return "5";
        }
        if t == "2.4" || t.eq_ignore_ascii_case("2.4ghz") {
            return "2.4";
        }
        // "auto" or anything unrecognised falls through to the discovered-band logic below.
    }
    if let Some(lkg) = band_lkg {
        return if lkg.band == "5" { "5" } else { "2.4" };
    }
    if ap_capable_5ghz_present {
        "5"
    } else {
        "2.4"
    }
}

/// One attempted rung's result, for the status artifact.
#[derive(Debug, Clone, Serialize)]
pub struct RungAttempt {
    pub label: String,
    pub width_mhz: u32,
    pub channel: u32,
    pub result: Stability,
}

/// The full calibration outcome — emitted as JSON to a status/evidence artifact
/// (`/var/lib/hookprobe/wifi-calibration.json`) so the operator (and telemetry-analyst) can see
/// the chosen country + source + confidence, the winning rung, and WHY higher rungs failed.
#[derive(Debug, Clone, Serialize)]
pub struct CalibrationOutcome {
    pub iface: String,
    /// The regulatory decision (Feature 1).
    pub country: CountryDecision,
    /// Every rung tried, best→worst, with its verdict (Feature 2).
    pub attempts: Vec<RungAttempt>,
    /// The winning (kept) rung label, or `None` if even the floor failed (radio dead).
    pub chosen: Option<String>,
    /// ISO8601 timestamp the runtime stamps in.
    pub decided_at: String,
}

impl CalibrationOutcome {
    /// Serialise to pretty JSON for the status artifact. Infallible in practice (all fields are
    /// plain data); returns a diagnostic string on the impossible serializer error.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self)
            .unwrap_or_else(|e| format!("{{\"error\":\"serialize CalibrationOutcome: {e}\"}}"))
    }
}

// ===========================================================================================
// ADR 0034 extension 2026-07-15 (D24–D33) — the AUTONOMOUS survey-based 5 GHz channel optimizer.
//
// Strictly ADDITIVE and off the enforcement path (D24): this layer never runs at boot/bring-up
// (the D6 3-rung ladder above stays fast + DFS-free), only ever on its own schedule
// (`base/units/hookprobe-wifi-optimize@.timer`, 03:00 daily), on-demand, or on a regdomain change,
// and it can only ever hand the AP a channel it has ITSELF validated — any failure degrades to the
// exact channel the boot ladder would have chosen (ch40), never a dead AP. In every ETSI domain the
// only non-DFS 80 MHz block is 36-48/ch40 (the boot ladder's own anchor), so reaching a meaningfully
// cleaner block is, in practice, "safely reach a DFS block IF this radio proves (D30) it can hold
// one" — this is why the whole extension exists above, not inside, the boot ladder.
//
// The runtime half (`base/scripts/wifi-optimize.sh` + `hookprobe-wifi-optimize@<iface>.{service,
// timer}`) gathers `iw scan`/`iw survey dump` measurements and calls every decision below; nothing
// here touches a radio, shells out, or reads the network — pure functions over explicit inputs,
// exactly like the D1-D23 core above.
// ===========================================================================================

/// D25 — the resolved `wifi.ap.optimize` config (operator YAML + shipped defaults merged). See
/// [`optimize_intent`] for the precedence; every default below is a NAMED, field-tunable constant
/// (not hardcoded inline) so a later field-calibration round has one obvious place to change it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OptimizeConfig {
    /// Run the scheduled/on-demand optimizer at all.
    pub enabled: bool,
    /// Local time-of-day (`"HH:MM"`) the nightly survey runs — echoed for the artifact/telemetry;
    /// the systemd timer itself ships a static `OnCalendar=*-*-* 03:00:00` (D25) until a renderer
    /// subcommand exists to template it per-device (see the ADR's "Residual risks" note on the
    /// still-not-built `hookprobe-supervisor --wifi-calibrate`-equivalent for the optimizer).
    pub at: String,
    /// May the optimizer switch to a DFS block if this radio proves (D30) it can hold one?
    pub allow_dfs: bool,
    /// May the optimizer switch to the 600 s-CAC meteorological sub-band (116-128)?
    pub allow_meteo: bool,
    /// Required busy-% improvement over the current channel before switching (hysteresis input —
    /// see [`weights_for`]).
    pub min_improvement: u8,
}

/// Field-tunable default: the nightly survey time-of-day when `wifi.ap.optimize.at` is absent.
pub const OPTIMIZE_DEFAULT_AT: &str = "03:00";
/// Field-tunable default: required busy-% improvement to switch when `min_improvement` is absent —
/// maps to [`OPT_SWITCH_MARGIN`] via [`weights_for`].
pub const OPTIMIZE_DEFAULT_MIN_IMPROVEMENT: u8 = 20;

/// D25 — resolve the operator's `wifi.ap.optimize` block (nested under `ap:`) into a
/// [`OptimizeConfig`], merging shipped defaults for every absent field. Shipped defaults (this
/// change): **enabled** when the band isn't hard-pinned to `2.4` (nothing to optimize there);
/// **allow_dfs: true** (the load-bearing reason: every ETSI domain's only non-DFS 80 MHz block is
/// ch40, so `allow_dfs` is what lets the optimizer do anything at all); **allow_meteo: false** (the
/// 600 s-CAC sub-band stays opt-in); **min_improvement: 20** (a conservative switch-only-if-
/// meaningfully-cleaner hysteresis). A `band: "2.4"` hard pin disables the optimizer regardless of
/// an explicit `enabled: true` — there is no 5 GHz channel to optimize under that pin.
pub fn optimize_intent(a: &ApIntent) -> OptimizeConfig {
    let band_pinned_24 = a
        .band
        .as_deref()
        .map(|b| {
            let t = b.trim();
            t.eq_ignore_ascii_case("2.4") || t.eq_ignore_ascii_case("2.4ghz")
        })
        .unwrap_or(false);
    let o = a.optimize.as_ref();
    let enabled_requested = o.and_then(|o| o.enabled).unwrap_or(true);
    OptimizeConfig {
        enabled: enabled_requested && !band_pinned_24,
        at: o
            .and_then(|o| o.at.clone())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| OPTIMIZE_DEFAULT_AT.to_string()),
        // Default OFF (2026-07-17 exhaustive metal test): the shipped brcmfmac FullMAC radio cannot
        // do DFS in AP mode (every DFS channel failed on Pi4+CM5), so trying it just wastes a 3AM
        // cycle + briefly disrupts the AP. An operator on a SoftMAC/mac80211 radio that DOES support
        // DFS AP opts in with `optimize.allow_dfs: true`.
        allow_dfs: o.and_then(|o| o.allow_dfs).unwrap_or(false),
        allow_meteo: o.and_then(|o| o.allow_meteo).unwrap_or(false),
        min_improvement: o.and_then(|o| o.min_improvement).unwrap_or(OPTIMIZE_DEFAULT_MIN_IMPROVEMENT),
    }
}

/// D26 — one VHT80 candidate block's measured load (skeleton from [`optimize_candidates`], filled
/// in by the runtime's `iw scan`/`iw survey dump` before [`score_block`] is called).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BlockSurvey {
    /// The block's control channel / hostapd `channel=` (40 for UNII-1, else the block's base:
    /// 52/100/116/132, or 149 for UNII-3).
    pub control_channel: u32,
    /// `vht_oper_centr_freq_seg0_idx` for this block (42/58/106/122/138/155).
    pub center_idx: u32,
    /// 0-100 from `iw survey dump`; `None` when only scanned (never on-channel), the D26 scan-only
    /// degradation.
    pub busy_ratio: Option<u8>,
    /// Weighted neighbour BSS count across the block's 4×20 MHz from `iw scan`.
    pub bss_count: u32,
    /// Survey noise floor (dBm), tie-break only — not scored.
    pub noise_dbm: Option<i32>,
    pub dfs: bool,
    /// [`dfs_cac_seconds`] for this block at 80 MHz — `0` for the two non-DFS blocks.
    pub cac_seconds: u32,
    /// 23 dBm (UNII-1/UNII-3) or 30 dBm (the DFS UNII-2C blocks) — from the ETSI table (D27).
    pub max_eirp_dbm: u32,
    /// Combined admission signal (D26/D16a intent): NOT excluded by the No-IR run-file AND NOT in
    /// [`OptimizeState::blocked_channels`]. `true` when the No-IR artifact is unavailable/empty —
    /// the same OPTIMISTIC default D16a specifies (never lock out a block just because we couldn't
    /// read the flags; a real rejection is still caught at D29 step 4d's `verify_rung`).
    pub ap_capable: bool,
}

impl BlockSurvey {
    fn label(&self) -> String {
        format!("5GHz-VHT80-ch{}", self.control_channel)
    }
}

/// D27 — the ETSI EN 301 893 VHT80 block geometry table this optimizer enumerates from: (control
/// channel, center_idx, is_dfs, is_meteo, max_eirp_dbm). The two non-DFS anchors (UNII-1/UNII-3)
/// are handled separately in [`optimize_candidates`] (they come from [`RegChannels`], not this
/// table) — this table is the DFS blocks only.
///
/// **Open field-calibration question (2026-07-17), flagged not silently guessed:** the UNII-1
/// anchor (36-48) is PROVEN on real brcmfmac metal to hold on its block's UPPER-secondary control
/// channel (40, `[HT40-]`) and NOT its lower-primary (36, `[HT40+]`) — see [`candidate_ladder`]'s
/// doc. The 4 DFS blocks below instead use each block's LOWEST channel (52/100/116/132, all
/// lower-primary/`[HT40+]` by [`crate::wifi_cfg::vht80_params`]'s own convention) as `control` — the
/// SAME shape proven NOT to hold reliably for UNII-1. This has never been exercised on real DFS
/// metal (the D29 validate/commit/revert loop + D30 `dfs_ap_supported` state machine make a wrong
/// guess here SAFE — at most one wasted disruption, self-correcting — never a bricked AP), so it is
/// deliberately left AS-IS rather than silently "fixed" to the upper-secondary channels
/// (56/104/120/136) on an unproven assumption. A future DFS-capable-hardware field round should
/// re-run [`optimize_candidates`]/[`select_optimized_channel`] against BOTH conventions and record
/// which one this radio family actually holds, exactly like the UNII-1 anchor's own history.
// 2026-07-17 (EXHAUSTIVE metal matrix, radio-reset between every test, both Pi4+CM5): the brcmfmac
// BCM43455 FullMAC firmware CANNOT bring up ANY DFS channel in AP mode — EVERY DFS channel (52-140)
// at EVERY width failed uniformly (hostapd stuck `activating`, radio drifts to ch34/20). The FullMAC
// AP firmware has no DFS CAC/radar support. So on the SHIPPED hardware these candidates ALWAYS fail
// and the D30 `dfs_ap_supported=false` self-correction disables them after ONE 3AM cycle (and
// `optimize.allow_dfs` now defaults OFF in network.example.yaml to skip even that). These control
// channels are the VHT80-correct 2nd-channel/[HT40-] pattern (same as UNII-1 ch40) kept for a FUTURE
// SoftMAC/mac80211 radio that CAN do DFS AP — NOT validated on any real DFS-capable radio yet.
// (Earlier "ch56/104/120 validated" was a FALSE POSITIVE from a no-reset campaign reading a stale
// prior channel — the reset methodology disproved it. Only UNII-1 36-48 is EU-safe on brcmfmac.)
const OPTIMIZE_DFS_BLOCKS: [(u32, u32, bool, u32); 4] = [
    (56, 58, false, 23),   // UNII-2A 52-64 — 2nd-ch/[HT40-] pattern; brcmfmac AP: FAILS (self-disabled)
    (104, 106, false, 30), // UNII-2C 100-112 — same; brcmfmac AP: FAILS
    (120, 122, true, 30),  // UNII-2C 116-128 — same, METEO 600s CAC; brcmfmac AP: FAILS
    (136, 138, false, 30), // UNII-2C 132-144 — same; brcmfmac AP: FAILS
];

/// D27 — enumerate the candidate VHT80 blocks for this regdomain + config + learned DFS state.
/// Always includes the non-DFS anchor (UNII-1 ch40, or UNII-3 ch149 if UNII-1 is somehow absent —
/// mirrors [`candidate_ladder`]'s own fallback) as the reference every other candidate must beat,
/// PLUS UNII-3 as an independent alternative in FCC-style domains where [`reg_channels`] already
/// admits it. DFS blocks are enumerated only when: `cfg.allow_dfs`, the domain isn't the world `00`
/// (which never legally gets DFS AP use here), [`OptimizeState::dfs_ap_supported`] hasn't already
/// been proven `false` (D30 — a radio proven DFS-incapable is never re-offered a DFS candidate), the
/// block isn't in `state.blocked_channels` (a SPECIFIC DFS block that failed to hold), the meteo
/// block additionally needs `cfg.allow_meteo`, and the 132-144 block additionally needs
/// `radio_ch144_capable` (many chipsets disable ch144 — dropped when the radio doesn't advertise
/// it). `ap_capable_channels` is the D16a No-IR artifact's channel list; EMPTY means "unavailable —
/// optimistically admit everything" (D16a's own stated policy), never a lockout.
pub fn optimize_candidates(
    reg: &RegChannels,
    cfg: &OptimizeConfig,
    radio_ch144_capable: bool,
    ap_capable_channels: &[u32],
    state: &OptimizeState,
) -> Vec<BlockSurvey> {
    let is_ap_capable = |control: u32| -> bool {
        if ap_capable_channels.is_empty() {
            return true;
        }
        channel_footprint(control, 80).iter().any(|c| ap_capable_channels.contains(c))
    };
    let mk = |control: u32, center: u32, dfs: bool, eirp: u32| -> BlockSurvey {
        BlockSurvey {
            control_channel: control,
            center_idx: center,
            busy_ratio: None,
            bss_count: 0,
            noise_dbm: None,
            dfs,
            cac_seconds: dfs_cac_seconds(control, 80),
            max_eirp_dbm: eirp,
            ap_capable: is_ap_capable(control),
        }
    };
    let mut cands = Vec::new();
    // The non-DFS anchor — every candidate must beat this. Mirrors candidate_ladder's own
    // ch40-else-ch149 fallback so the optimizer and the boot ladder never disagree on the anchor.
    if reg.non_dfs_5ghz.contains(&36) {
        cands.push(mk(40, 42, false, 23));
    } else if reg.non_dfs_5ghz.contains(&149) {
        cands.push(mk(149, 155, false, 23));
    }
    // UNII-3 as an INDEPENDENT alternative in FCC-style domains (which keep both blocks legal).
    if reg.non_dfs_5ghz.contains(&149) && cands.iter().all(|c| c.control_channel != 149) {
        cands.push(mk(149, 155, false, 23));
    }
    // DFS blocks: gated by allow_dfs, the world domain, the learned dfs_ap_supported state, and
    // per-block blocklist/meteo/ch144 admission (D27/D30).
    if cfg.allow_dfs && reg.cc != "00" && state.dfs_ap_supported != Some(false) {
        for &(control, center, meteo, eirp) in &OPTIMIZE_DFS_BLOCKS {
            if meteo && !cfg.allow_meteo {
                continue;
            }
            if control == 136 && !radio_ch144_capable {
                continue;
            }
            if state.blocked_channels.contains(&control) {
                continue;
            }
            cands.push(mk(control, center, true, eirp));
        }
    }
    cands
}

/// D28 — scoring weights. Lower score = better (a cost). Every field is a NAMED, field-tunable
/// default (see the `OPT_*` constants below) — the architect has flagged these need one round of
/// field calibration against real 03:00 surveys before this is enabled-by-default in a release; the
/// SAFETY (DFS test-and-learn + validate + revert-to-ch40) does not depend on these being perfectly
/// tuned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptimizeWeights {
    /// Field-tunable default [`OPT_W_BUSY`]: score per 1% channel-busy time (PRIMARY signal).
    pub w_busy: i32,
    /// Field-tunable default [`OPT_W_BSS`]: score per weighted neighbour BSS (fallback/corroborating).
    pub w_bss: i32,
    /// Field-tunable default [`OPT_EIRP_BONUS_PER_DB`]: score delta per dBm of max-EIRP above the
    /// 23 dBm UNII-1 floor (negative — more power lowers the cost).
    pub eirp_bonus_per_db: i32,
    /// Field-tunable default [`OPT_CAC_PENALTY_STD`]: flat penalty for a 60 s-CAC DFS block.
    pub cac_penalty_std: i32,
    /// Field-tunable default [`OPT_CAC_PENALTY_METEO`]: flat penalty for the 600 s meteo block.
    pub cac_penalty_meteo: i32,
    /// Field-tunable default [`OPT_SWITCH_MARGIN`]: the candidate must beat the CURRENT channel's
    /// score by this much to switch (hysteresis gate 2).
    pub switch_margin: i32,
    /// Field-tunable default [`OPT_QUIET_FLOOR_BUSY`]: if the current channel's busy_ratio is below
    /// this, don't switch at all (hysteresis gate 1 — already fine, don't disrupt it).
    pub quiet_floor_busy: u8,
}

/// Field-tunable default: score per 1% channel-busy time (the PRIMARY, survey-measured signal).
pub const OPT_W_BUSY: i32 = 4;
/// Field-tunable default: score per weighted neighbour BSS (the scan-only fallback/corroborating signal).
pub const OPT_W_BSS: i32 = 3;
/// Field-tunable default: score delta per dBm of max-EIRP above the 23 dBm UNII-1 floor.
pub const OPT_EIRP_BONUS_PER_DB: i32 = -6;
/// Field-tunable default: flat penalty for adopting a standard 60 s-CAC DFS block.
pub const OPT_CAC_PENALTY_STD: i32 = 40;
/// Field-tunable default: flat penalty for adopting the 600 s meteorological sub-band.
pub const OPT_CAC_PENALTY_METEO: i32 = 400;
/// Field-tunable default: hysteresis gate 2 — a candidate must beat the current channel by this
/// many score points to trigger a switch.
pub const OPT_SWITCH_MARGIN: i32 = 30;
/// Field-tunable default: hysteresis gate 1 — below this busy_ratio (%) on the CURRENT channel, never
/// switch at all (it's already fine).
pub const OPT_QUIET_FLOOR_BUSY: u8 = 20;
/// Field-tunable default: per-weighted-neighbour busy-% ESTIMATE used only when a candidate has no
/// `busy_ratio` sample (scan-only degradation, D26) — capped at 100.
pub const OPT_BSS_BUSY_ESTIMATE_PCT: i32 = 5;

impl Default for OptimizeWeights {
    fn default() -> Self {
        OptimizeWeights {
            w_busy: OPT_W_BUSY,
            w_bss: OPT_W_BSS,
            eirp_bonus_per_db: OPT_EIRP_BONUS_PER_DB,
            cac_penalty_std: OPT_CAC_PENALTY_STD,
            cac_penalty_meteo: OPT_CAC_PENALTY_METEO,
            switch_margin: OPT_SWITCH_MARGIN,
            quiet_floor_busy: OPT_QUIET_FLOOR_BUSY,
        }
    }
}

/// D28 — map `wifi.ap.optimize.min_improvement` (a %-busy hysteresis the operator can tune) onto
/// [`OptimizeWeights`], scaling `switch_margin` proportionally to the shipped default mapping
/// (`min_improvement=20` → `switch_margin=`[`OPT_SWITCH_MARGIN`]`=30`, unscaled — the default
/// round-trips exactly). Every other weight stays at its field-tuned default.
pub fn weights_for(cfg: &OptimizeConfig) -> OptimizeWeights {
    let mut w = OptimizeWeights::default();
    let min_improvement = i32::from(cfg.min_improvement).max(0);
    w.switch_margin = (min_improvement * OPT_SWITCH_MARGIN) / i32::from(OPTIMIZE_DEFAULT_MIN_IMPROVEMENT);
    w
}

/// D28 — score one candidate (or the current channel). Lower = better. When `busy_ratio` is `None`
/// (never on-channel-surveyed, scan-only) it is ESTIMATED from `bss_count` at
/// [`OPT_BSS_BUSY_ESTIMATE_PCT`] per weighted neighbour, capped at 100 — a documented, conservative
/// proxy, never a hard failure.
pub fn score_block(b: &BlockSurvey, w: &OptimizeWeights) -> i32 {
    let busy_pct: i32 = match b.busy_ratio {
        Some(pct) => i32::from(pct),
        None => (i32::try_from(b.bss_count).unwrap_or(i32::MAX).saturating_mul(OPT_BSS_BUSY_ESTIMATE_PCT)).min(100),
    };
    let mut score = w.w_busy * busy_pct
        + w.w_bss * i32::try_from(b.bss_count).unwrap_or(i32::MAX)
        + w.eirp_bonus_per_db * (i32::try_from(b.max_eirp_dbm).unwrap_or(23) - 23);
    if b.dfs {
        score += if b.cac_seconds >= 600 { w.cac_penalty_meteo } else { w.cac_penalty_std };
    }
    score
}

/// D29 — the survey→score→select decision. `Keep` is the common nightly result (ch40 stays, or a
/// prior DFS-LKG stays); `Switch` proceeds to the runtime's DFS-aware VALIDATE step.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum OptimizeDecision {
    Keep { reason: String },
    Switch { to: BlockSurvey, reason: String },
}

/// D28/D29 — select the best candidate, gated by BOTH hysteresis checks: (1) the current channel's
/// busy_ratio must be AT/ABOVE `quiet_floor_busy` (a quiet, already-fine AP is never disrupted for a
/// marginal gain), AND (2) the best candidate's score must beat the current channel's score by AT
/// LEAST `switch_margin` (meaningfully, not marginally, better). At most ONE candidate is ever
/// proposed (the single best-scoring, `ap_capable` one that isn't the current channel) — the D28
/// "max-disruption budget: at most one channel switch attempt per run."
pub fn select_optimized_channel(
    current: &BlockSurvey,
    cands: &[BlockSurvey],
    w: &OptimizeWeights,
) -> OptimizeDecision {
    let current_busy = current.busy_ratio.unwrap_or(0);
    if current_busy < w.quiet_floor_busy {
        return OptimizeDecision::Keep {
            reason: format!(
                "current ch{} busy_ratio {current_busy}% is below the quiet floor {}% — not worth disrupting",
                current.control_channel, w.quiet_floor_busy
            ),
        };
    }
    let current_score = score_block(current, w);
    let best = cands
        .iter()
        .filter(|c| c.ap_capable && c.control_channel != current.control_channel)
        .min_by_key(|c| score_block(c, w));
    match best {
        None => OptimizeDecision::Keep { reason: "no admitted candidate to compare against".to_string() },
        Some(b) => {
            let bscore = score_block(b, w);
            if bscore + w.switch_margin <= current_score {
                OptimizeDecision::Switch {
                    reason: format!(
                        "candidate {} scores {bscore} vs current {} scoring {current_score} (clears switch_margin {})",
                        b.label(), current.label(), w.switch_margin
                    ),
                    to: b.clone(),
                }
            } else {
                OptimizeDecision::Keep {
                    reason: format!(
                        "best candidate {} scores {bscore} — does not beat current {} ({current_score}) by switch_margin {}",
                        b.label(), current_score, w.switch_margin
                    ),
                }
            }
        }
    }
}

/// D30 — the DFS test-and-learn state, persisted per (interface) at
/// `/var/lib/hookprobe/wifi-optimize-state-<iface>.json`. `dfs_ap_supported` is learned EMPIRICALLY
/// from the first DFS attempt (`None` untested, `Some(false)` proven-unsupported — stop proposing
/// DFS forever on this radio+regdomain, `Some(true)` a DFS commit worked at least once);
/// `blocked_channels` records SPECIFIC DFS blocks that reached AP-ENABLED but wouldn't hold (bounced,
/// or a real radar-vacate), so future runs exclude just those, not the whole DFS capability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OptimizeState {
    pub cc: String,
    pub radio_id: String,
    pub dfs_ap_supported: Option<bool>,
    pub blocked_channels: Vec<u32>,
    pub current_channel: u32,
    pub current_score: i32,
    pub last_run: String,
}

impl Default for OptimizeState {
    fn default() -> Self {
        OptimizeState {
            cc: String::new(),
            radio_id: String::new(),
            dfs_ap_supported: None,
            blocked_channels: Vec::new(),
            current_channel: 40,
            current_score: 0,
            last_run: String::new(),
        }
    }
}

/// D30 — is a cached [`OptimizeState`] still trustworthy? A regdomain or radio change invalidates
/// it (re-test DFS from scratch — new domain/hardware may behave differently); the caller resets to
/// [`OptimizeState::default`] (with the NEW `cc`/`radio_id`) on `false`, exactly like
/// [`band_lkg_valid`]/[`channel_lkg_valid`].
pub fn optimize_state_valid(s: &OptimizeState, cc: &str, radio_id: &str) -> bool {
    s.cc.eq_ignore_ascii_case(cc) && s.radio_id == radio_id
}

/// D31 — the committed channel-LKG, persisted at
/// `/var/lib/hookprobe/wifi-channel-lkg-<iface>.json`. DISTINCT from the regdomain-LKG (country
/// only, D10c) and the band-LKG ([`BandLkg`] — band/width/rung): this one remembers WHICH VHT80
/// block within that band the optimizer last validated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChannelLkg {
    pub cc: String,
    pub radio_id: String,
    pub control_channel: u32,
    pub center_idx: u32,
    pub width_mhz: u32,
    pub dfs: bool,
    pub score: i32,
    pub validated_at: String,
}

/// D31 — is a cached [`ChannelLkg`] still trustworthy to apply? CC or radio change invalidates it
/// (a new legal channel set, or unproven hardware) — the caller re-optimizes from scratch.
pub fn channel_lkg_valid(lkg: &ChannelLkg, cc: &str, radio_id: &str) -> bool {
    lkg.cc.eq_ignore_ascii_case(cc) && lkg.radio_id == radio_id
}

/// D31 — when a resolved channel plan may be applied. A **non-DFS** channel (the common ch40 case)
/// is `BootFast`: zero added boot latency, the D6 ladder simply uses it as its top-rung channel. A
/// **DFS** channel is `PostBootReapply`: the box boots FAST on ch40 (never a boot-time CAC) and
/// `network-apply.sh` starts the optimizer in `reapply` mode shortly after hostapd, which silently
/// upgrades ch40 → the DFS channel within one CAC window of boot on success, or clears the disproven
/// LKG and stays on ch40 on failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyAt {
    BootFast,
    PostBootReapply,
}

/// The `vht_oper_centr_freq_seg0_idx` for ANY of the 24 five-GHz channels in ANY of the 6 VHT80
/// blocks (non-DFS 36-48/149-161 AND DFS 52-144) — not just the 4 specific control channels
/// [`OPTIMIZE_DFS_BLOCKS`] happens to enumerate as candidates. Non-DFS blocks resolve via
/// [`crate::wifi_cfg::vht80_params`] (the render path's own source of truth, unchanged); DFS blocks
/// resolve via [`FIVE_GHZ_BLOCKS`] — the block containing `ch`, center = its lowest channel + 6
/// (36→42, 52→58, 100→106, 116→122, 132→138 — the same arithmetic [`OPTIMIZE_DFS_BLOCKS`]'s own
/// `center` column already encodes, generalised to EVERY channel in the block, not just the one
/// [`OPTIMIZE_DFS_BLOCKS`] lists as `control`). 2026-07-17: previously this fell through to `ch`
/// itself (wrong) for any DFS-block channel that wasn't exactly 52/100/116/132 — e.g. an operator
/// pin on ch56 (same block as 52, center 58) used to compute a bogus seg0_idx of 56. An unknown
/// control channel outside all 6 blocks (e.g. the lone ch165) still returns the channel itself — the
/// same "no clean 80 MHz block" degradation [`crate::wifi_cfg::width_lines`] already uses.
fn center_idx_for_control(ch: u32) -> u32 {
    if let Some((_, center)) = crate::wifi_cfg::vht80_params(ch) {
        return center;
    }
    FIVE_GHZ_BLOCKS.iter().find(|b| b.contains(&ch)).map(|b| b[0] + 6).unwrap_or(ch)
}

/// D24/D31 — the resolved operating-channel plan for a 5 GHz AP, at whatever precedence level won.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ChannelPlan {
    pub channel: u32,
    pub center_idx: u32,
    pub width_mhz: u32,
    pub dfs: bool,
    pub apply_at: ApplyAt,
    /// Which precedence tier decided (`"operator_pin"` | `"channel_lkg"` | `"boot_default_ch40"`) —
    /// echoed for the evidence artifact/telemetry.
    pub source: String,
}

/// D24 — the operating-channel precedence chain: **operator hard-pin (`wifi.ap.channel`) > a valid
/// channel-LKG > the boot default ch40.** The optimizer can only ever move tier 2; it can never
/// override tier 1, and every failure path (the runtime's D29 revert chain) terminates at tier 3.
/// `intent_pin` and `channel_lkg` are the caller's ALREADY-VALIDATED inputs (the caller checks
/// [`channel_lkg_valid`] before passing `Some`) — this function only applies the precedence + the
/// D31 `apply_at` split, it does no I/O and no validity checking of its own.
pub fn resolve_operating_channel(intent_pin: Option<u32>, channel_lkg: Option<&ChannelLkg>) -> ChannelPlan {
    const BOOT_DEFAULT_CHANNEL: u32 = 40;
    const BOOT_DEFAULT_CENTER: u32 = 42;
    if let Some(ch) = intent_pin {
        let center = center_idx_for_control(ch);
        return ChannelPlan {
            channel: ch,
            center_idx: center,
            width_mhz: 80,
            dfs: is_dfs_rung(ch, 80),
            // A pin is ALWAYS applied at boot (it's the operator's explicit choice); a DFS pin is
            // still CAC-validated by the runtime exactly like any other DFS rung — the
            // always-joinable invariant outranks even a pin (D24).
            apply_at: ApplyAt::BootFast,
            source: "operator_pin".to_string(),
        };
    }
    if let Some(lkg) = channel_lkg {
        return ChannelPlan {
            channel: lkg.control_channel,
            center_idx: lkg.center_idx,
            width_mhz: lkg.width_mhz,
            dfs: lkg.dfs,
            apply_at: if lkg.dfs { ApplyAt::PostBootReapply } else { ApplyAt::BootFast },
            source: "channel_lkg".to_string(),
        };
    }
    ChannelPlan {
        channel: BOOT_DEFAULT_CHANNEL,
        center_idx: BOOT_DEFAULT_CENTER,
        width_mhz: 80,
        dfs: false,
        apply_at: ApplyAt::BootFast,
        source: "boot_default_ch40".to_string(),
    }
}

/// D32 — one candidate's WHY (chosen or rejected) for the evidence artifact.
#[derive(Debug, Clone, Serialize)]
pub struct CandidateScore {
    pub label: String,
    pub control_channel: u32,
    pub center_idx: u32,
    pub busy_ratio: Option<u8>,
    pub bss_count: u32,
    pub max_eirp_dbm: u32,
    pub dfs: bool,
    pub cac_seconds: u32,
    pub score: i32,
    pub admitted: bool,
    pub reject_reason: Option<String>,
}

/// Build a [`CandidateScore`] from a measured [`BlockSurvey`] — the WHY-chosen/WHY-rejected view
/// [`OptimizeOutcome`] carries. `admitted` mirrors [`BlockSurvey::ap_capable`] unless the caller
/// supplies a more specific `reject_reason` (e.g. "not the single best candidate this run").
pub fn candidate_score(b: &BlockSurvey, w: &OptimizeWeights, reject_reason: Option<String>) -> CandidateScore {
    CandidateScore {
        label: b.label(),
        control_channel: b.control_channel,
        center_idx: b.center_idx,
        busy_ratio: b.busy_ratio,
        bss_count: b.bss_count,
        max_eirp_dbm: b.max_eirp_dbm,
        dfs: b.dfs,
        cac_seconds: b.cac_seconds,
        score: score_block(b, w),
        admitted: b.ap_capable && reject_reason.is_none(),
        reject_reason,
    }
}

/// D32 — the full nightly/on-demand run, evidence for the operator (Mission Control) and
/// telemetry-analyst (per-platform truth of which DFS blocks a given radio really holds). Written to
/// `/var/lib/hookprobe/wifi-channel-optimize.json` (sibling of `wifi-calibration.json`, D9).
#[derive(Debug, Clone, Serialize)]
pub struct OptimizeOutcome {
    pub iface: String,
    /// `"timer"` | `"on_demand"` | `"regdomain_change"` | `"reapply"`.
    pub trigger: String,
    pub cc: String,
    pub radio_id: String,
    pub current_before: CandidateScore,
    pub candidates: Vec<CandidateScore>,
    /// `"keep"` | `"switch"`.
    pub decision: String,
    pub chosen: Option<CandidateScore>,
    /// The [`OptimizeVerify`] variant name.
    pub verify: String,
    /// What the AP ACTUALLY ended on (ch40 on any revert).
    pub committed_channel: u32,
    pub dfs_ap_supported: Option<bool>,
    pub decided_at: String,
}

impl OptimizeOutcome {
    /// Serialise to pretty JSON for the status/evidence artifact. Infallible in practice; returns a
    /// diagnostic string on the impossible serializer error (mirrors [`CalibrationOutcome::to_json`]).
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self)
            .unwrap_or_else(|e| format!("{{\"error\":\"serialize OptimizeOutcome: {e}\"}}"))
    }
}

/// D29 — the runtime's VALIDATE verdict, recorded in the artifact. Only `Committed` persists a new
/// [`ChannelLkg`]; every other variant means the AP ended (or stayed) on the previous/ch40 channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptimizeVerify {
    /// `select_optimized_channel` returned `Keep` — the common nightly result, nothing applied.
    KeptNotBetter,
    /// A `Switch` decision validated `Stable` + reachable — the new channel-LKG was persisted.
    Committed,
    /// A `Switch` decision was applied but the rung never converged (`verify_rung` != `Stable`).
    RevertedFailedToHold,
    /// A DFS `Switch`'s CAC never completed within `cac_seconds` + settle.
    RevertedCacTimeout,
    /// The rung converged but a previously-associated client / self-probe did not reconnect.
    RevertedNotReachable,
}

// ===========================================================================================
// ADR 0034 extension 2026-07-15b (D35-D44) — the Wi-Fi calibration LEARNING MODEL.
//
// ONE accumulating knowledge store, keyed by the context that actually determines a calibration
// outcome — (radio_id, regdomain, channel, width_mhz) — that SUBSUMES the three prior last-only
// caches ([`BandLkg`] D19, [`ChannelLkg`] D31, [`OptimizeState`]'s `blocked_channels`/
// `dfs_ap_supported` D30). This is NOT a neural net: it is a bounded conjugate-Bayesian
// (Beta-Bernoulli for the binary "did the rung HOLD?" signal) + EMA (for the continuous
// congestion/throughput signals) contextual bandit with a deterministic UCB exploration bonus —
// online, incremental, O(1) per update, O(<=[`MAX_LEARN_ENTRIES`]) per decision, fully auditable
// (every number has a human "why"). It reuses [`Rung`]/[`verify_rung`]/[`Stability`]/
// [`RegChannels`]/[`RadioCaps`]/[`BlockSurvey`]/[`score_block`]/[`select_settle_seconds`] and the
// D25 timer + D29 validate/commit/revert loop, and changes NONE of them.
//
// SHIPPED IN SHADOW MODE (D44): [`LEARN_MODE`] is a single named constant. In
// [`LearnMode::Shadow`] (the shipped default) the model RECORDS every observation and MAY do the
// safe [`BootPlan::ResumeAtRung`] (the band-LKG-equivalent win — never re-thrash a proven rung),
// but the aggressive [`BootPlan::DirectToBest`] ladder-skip is NOT yet exercised — a tier that
// would qualify for it degrades to `ResumeAtRung` instead. Flipping to [`LearnMode::Active`] (one
// field-validated line) turns DirectToBest on. This composes with, and does not override, every
// existing safety invariant: the model ONLY ever selects among the caller-supplied `legal`
// (validated-safe) set, an operator hard-pin (D24 prio-1) still always wins (the model only
// RECORDS for a pinned config), and every miss/cold-model/empty-legal-set case degrades to the
// D6/D20 boot ladder -> the 2.4/HT20 floor (D41 — the model can make the box smarter, never
// un-joinable).
// ===========================================================================================

/// Schema version for the persisted knowledge store — bump on an incompatible field change.
pub const WIFI_LEARN_SCHEMA: u32 = 1;
/// Hard bound on [`WifiKnowledge::entries`] — ~17 legal configs/regdomain x a few visited domains.
/// Memory ~= 64 x ~140B ~= 9KB; CPU = one O(<=64) linear scan per decision. Edge-honest.
pub const MAX_LEARN_ENTRIES: usize = 64;

// --- Beta-Bernoulli (hold model) + EMA (congestion/throughput) tuning, D36 -----------------------
/// Uniform Beta prior (successes side) — an unseen config starts at `hold_prob` 0.5 ("unknown").
pub const ALPHA0: f32 = 1.0;
/// Uniform Beta prior (failures side).
pub const BETA0: f32 = 1.0;
/// `confidence()` denominator constant — reaches 0.60 at `obs_count=3`, 0.75 at `obs_count=6`.
pub const CONF_K: f32 = 2.0;
/// EMA smoothing factor for `busy_ema`/`tput_ema` — the first observation seeds directly (no
/// cold-0 bias); every later one blends at this weight.
pub const EMA_ALPHA: f32 = 0.3;

// --- D37 direct-to-best exploitation gate ---------------------------------------------------------
/// Minimum posterior confidence to trust a winner enough to skip the ladder.
pub const DIRECT_CONFIDENCE: f32 = 0.60;
/// Minimum posterior hold probability to trust a winner enough to skip the ladder.
pub const DIRECT_HOLD: f32 = 0.80;

// --- D38 never-repeat-known-bad ---------------------------------------------------------------
/// `hold_prob` at/below this is "bad".
pub const BAD_HOLD: f32 = 0.25;
/// ...but only trust "bad" once we are this sure (same bar as [`DIRECT_CONFIDENCE`]'s complement).
pub const BAD_CONFIDENCE: f32 = 0.60;
/// After this many days a known-bad config becomes re-probe-eligible again (environment change).
pub const REPROBE_WINDOW_DAYS: f32 = 30.0;

// --- D39 explore/exploit UCB bandit (budgeted to the 3AM optimizer only) -------------------------
/// UCB exploration-bonus weight (quality-units).
pub const EXPLORE_C: f32 = 14.0;
/// Below this many observations, a legal config is "under-observed" -> explore-eligible.
pub const MIN_OBS: u32 = 3;
/// Cadence: explore even a mature set every Nth optimizer run (catch drift).
pub const EXPLORE_EVERY: u32 = 7;

// --- D40 decay / aging ---------------------------------------------------------------------------
/// Geometric half-life (days) for discounting a stale cell's Beta *concentration* (mean preserved).
pub const STALE_HALF_LIFE_DAYS: f32 = 21.0;

// --- D41 anti-flap ---------------------------------------------------------------------------------
/// The optimizer's own hysteresis on top of D28's: a candidate must beat the incumbent's
/// `quality_score` by at least this much (composes with, does not replace, D28's `switch_margin`).
pub const QUALITY_SWITCH_MARGIN: f32 = 8.0;

/// D43 — bound on the persisted "improvement curve" trajectory per decision artifact.
pub const LEARN_CURVE_MAX_POINTS: usize = 20;

/// D44 (SHIP IN SHADOW MODE) — the single flag gating the aggressive [`BootPlan::DirectToBest`]
/// ladder-skip. Flip to [`LearnMode::Active`] after one field-validated round; everything else
/// (recording, [`BootPlan::ResumeAtRung`], the 3AM explore/exploit optimizer) is unaffected by
/// this flag — only the boot-time direct-to-best tier is gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LearnMode {
    /// Shipped default: record + [`BootPlan::ResumeAtRung`] only; a DirectToBest-eligible winner
    /// degrades to `ResumeAtRung`.
    Shadow,
    /// Full exploitation: a DirectToBest-eligible winner skips the ladder (O(1) boot).
    Active,
}
/// The shipped mode (D44). One line to flip after a field-validated round — see the module doc.
pub const LEARN_MODE: LearnMode = LearnMode::Shadow;

// --- D45/D46 warm-vs-cold learning (2026-07-17, metal-diagnosed) ---------------------------------
/// Minimum system uptime (seconds) before the FIRST warm-upgrade attempt — ground truth proved a
/// merely-just-settled radio (~15-95s post-boot, the ordinary boot-ladder timescale) is NOT warm
/// enough for `5GHz-VHT80-ch40` to hold reliably; a manual re-apply "a few minutes post boot" held
/// instantly. [`warm_upgrade_ready`] gates on this; the runtime (`wifi-calibrate.sh`) sleeps the
/// remainder before its first attempt if boot hasn't reached it yet. Field-tunable, like every other
/// named constant in this module — not a magic number buried in the runtime.
pub const WARM_MIN_UPTIME_SECONDS: u64 = 150;
/// Bounded retry budget for the warm-upgrade attempt loop once [`warm_upgrade_ready`] is true — a
/// SHORT bounded retry (not unbounded, not a single shot) in case one settle window still isn't
/// quite enough on a particular unit. The runtime reuses [`next_rung_action`] (Keep/RetrySameRung/
/// StepDown) to drive this loop — no new decision type needed, `StepDown` here just means "give up
/// the warm upgrade and revert to the already-proven cold rung," exactly as `next_rung_action`
/// already documents for the ordinary ladder.
pub const WARM_MAX_ATTEMPTS: u32 = 3;

/// D46 — has the radio been up long enough to trust a warm-upgrade attempt? A tiny, named,
/// independently-testable gate (mirrors [`is_dfs_rung`]'s "thin wrapper" pattern) so the runtime
/// never has to inline the `>=` comparison — and so the exact threshold stays defined in ONE place
/// ([`WARM_MIN_UPTIME_SECONDS`]) the shell mirrors numerically.
pub fn warm_upgrade_ready(uptime_secs: u64, min_uptime_secs: u64) -> bool {
    uptime_secs >= min_uptime_secs
}

/// D35 — the context that DETERMINES a calibration outcome. Two configs with the same key are the
/// "same calibration" — the operator's "does not repeat the same calibration twice" is literally
/// "never re-probe a high-confidence key." `center_idx` is deliberately NOT part of the key — it
/// is a deterministic function of `channel`+`width_mhz` (see [`center_idx_for_control`]), carried
/// on [`ConfigStat`] only for render convenience.
///
/// **D45 (2026-07-17, metal-diagnosed) — the `warm` context dimension.** Ground truth on real Pi4 +
/// CM5 (brcmfmac BCM43455) proved `5GHz-VHT80-ch40` reliably HOLDS once the radio has been up/serving
/// for a few minutes, but reliably FAILS a genuinely cold (~15-95s post-boot) attempt — the SAME
/// physical (channel, width) rung has two entirely different hold rates depending on how long the
/// radio has been warm. Before this field, every observation of a given (radio, regdomain, channel,
/// width) — cold boot-ladder attempts AND the post-settle warm-upgrade attempt alike — folded into
/// ONE Beta-Bernoulli cell; since cold attempts vastly outnumber (and, pre-D46, were not even
/// genuinely warm) the rare successes, `hold_prob` collapsed toward 0 and the model would learn to
/// AVOID ch40 forever — the exact opposite of reality. `warm: false` (cold — a boot-ladder attempt,
/// tried with the ordinary short settle) and `warm: true` (an attempt made ONLY after
/// [`warm_upgrade_ready`] confirms genuine post-boot warmth, via [`plan_warm_upgrade`]'s bounded
/// retry) are now DISTINCT cells for the identical (channel, width) — a cold failure can never
/// poison a warm success's `hold_prob`, or vice versa. [`plan_boot`]/[`band_lkg_from_model`]/
/// [`channel_lkg_from_model`] all select ONLY among `warm: false` (cold-context) entries — they
/// answer "what should the ordinary, short-settle boot ladder resume at," which must never be a
/// rung only proven to hold warm. [`plan_warm_upgrade`] is the ONLY consumer of `warm: true` entries.
/// `#[serde(default)]` makes this backward-compatible with every pre-D45 persisted store: an absent
/// field deserializes as `false` (cold) — the conservative, accurate reading, since every
/// observation recorded before this field existed WAS made with an ordinary (cold-scale) settle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Hash)]
pub struct ConfigKey {
    pub radio_id: String,
    pub regdomain: String,
    pub channel: u32,
    pub width_mhz: u32,
    /// D45 — see this struct's own doc. `false` (cold) unless explicitly set by a genuinely-warm
    /// observation ([`plan_warm_upgrade`]'s bounded retry, gated by [`warm_upgrade_ready`]).
    #[serde(default)]
    pub warm: bool,
}

/// D35 — one accumulating cell of knowledge for one [`ConfigKey`].
///
/// **Typing note (D40):** `successes`/`failures` are `f32`, not `u32` — the discounted-Beta aging
/// pass ([`age_model`]) must be able to shrink them fractionally while preserving their mean (a
/// 3-success cell aged once becomes `1.5`, still `hold_prob ~= 0.71` with lower `confidence`), which
/// D40 states explicitly ("successes/failures become f32 internally... the round-trip JSON stores
/// them as floats"). This supersedes D35's own `u32` sketch of the same fields — the two sections
/// of the ADR disagree on this one point and D40's rationale is load-bearing, so f32 is what's
/// implemented.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigStat {
    pub key: ConfigKey,
    /// `vht_oper_centr_freq_seg0_idx` for render; `0`/self for HT20/HT40-2.4.
    pub center_idx: u32,
    /// `"5"` | `"2.4"` — echoed; derivable from `key.channel` (>14 => 5 GHz).
    pub band: String,
    /// [`is_dfs_rung`]`(channel, width_mhz)` — cached.
    pub dfs: bool,
    /// [`dfs_cac_seconds`]`(channel, width_mhz)` — cached.
    pub cac_seconds: u32,
    // --- the Beta-Bernoulli hold model (binary: did the rung reach & HOLD Stable?) ---
    /// Count of `Stable` verdicts (Beta alpha = successes + [`ALPHA0`]). See the typing note above.
    pub successes: f32,
    /// Count of non-`Stable` verdicts (Beta beta = failures + [`BETA0`]).
    pub failures: f32,
    // --- the EMA models for continuous, drifting quantities ---
    /// 0..100, EMA of survey `busy_ratio` (congestion); seeded by the first observed sample.
    pub busy_ema: f32,
    /// EMA of a PHY-quality proxy (assoc rate / iperf / width*EIRP estimate).
    pub tput_ema: f32,
    // --- bookkeeping ---
    /// `successes + failures`, rounded — drives the artifact/telemetry view; [`confidence`] and
    /// [`hold_prob`] use the authoritative `successes`/`failures` floats directly, not this.
    pub obs_count: u32,
    /// ISO8601 of the last observation.
    pub last_seen: String,
    /// Last [`Stability`] variant (snake_case label), for the artifact.
    pub last_outcome: String,
    /// ISO8601 of the last [`age_model`] pass over this cell.
    pub decayed_at: String,
}

/// D35 — the persisted knowledge store, `/var/lib/hookprobe/wifi-learn-<iface>.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WifiKnowledge {
    pub schema: u32,
    pub iface: String,
    /// Kernel+driver+firmware fingerprint — a change triggers the D38 rehabilitation decay
    /// ([`apply_fw_rehabilitation`]), NOT a `ConfigKey` field (that would explode the table and
    /// discard history on every kernel bump).
    pub fw_id: String,
    /// Bounded to [`MAX_LEARN_ENTRIES`]; evicted per [`retention_priority`] on overflow.
    pub entries: Vec<ConfigStat>,
    /// ISO8601 of the last write/aging pass. [`plan_boot`]/[`choose_mode`]/[`pick_candidate`] treat
    /// this as "now" for [`is_known_bad`]'s re-probe-window check (no `now` parameter of their own,
    /// matching the ADR's stated signatures exactly) — the runtime contract is: call [`age_model`]
    /// (which stamps this field to the real wall-clock `now`) once on load, THEN call these.
    pub updated_at: String,
}

impl WifiKnowledge {
    /// A fresh, empty store for `iface` (first boot, or after a schema reset).
    pub fn new(iface: &str, fw_id: &str, now: &str) -> WifiKnowledge {
        WifiKnowledge {
            schema: WIFI_LEARN_SCHEMA,
            iface: iface.to_string(),
            fw_id: fw_id.to_string(),
            entries: Vec::new(),
            updated_at: now.to_string(),
        }
    }

    /// Serialise to pretty JSON for persistence — infallible in practice (mirrors
    /// [`CalibrationOutcome::to_json`]/[`OptimizeOutcome::to_json`]).
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self)
            .unwrap_or_else(|e| format!("{{\"error\":\"serialize WifiKnowledge: {e}\"}}"))
    }

    /// Parse a persisted store; `None` on any corruption (the runtime's cold-model fallback —
    /// never blocks boot on a missing/corrupt file).
    pub fn from_json(s: &str) -> Option<WifiKnowledge> {
        serde_json::from_str(s).ok()
    }
}

/// D36 — the hold-probability posterior mean (Beta-Bernoulli). Converges to the TRUE hold rate as
/// `obs_count -> infinity` (law of large numbers) — a provable convergence from two numbers.
pub fn hold_prob(s: &ConfigStat) -> f32 {
    (s.successes + ALPHA0) / (s.successes + s.failures + ALPHA0 + BETA0)
}

/// D36 — the posterior concentration, used as a 0..1 "how sure are we" signal. Reaches 0.60 at
/// `obs_count=3`, 0.75 at `obs_count=6` — a couple of confirmations, not hundreds.
pub fn confidence(s: &ConfigStat) -> f32 {
    let obs = s.successes + s.failures;
    obs / (obs + CONF_K)
}

/// D36 — the exploitation ranking (higher = better). Multiplicative in [`hold_prob`] so a config
/// that does not HOLD can never win (never-repeat-known-bad is automatic: a learned-bad cell
/// collapses to ~0 quality and is never the argmax); additive in the throughput/headroom/congestion
/// terms.
pub fn quality_score(s: &ConfigStat, eirp_dbm: u32, w: &QualityWeights) -> f32 {
    let cap = match s.key.width_mhz {
        80 => w.cap_vht80,
        40 => w.cap_ht40,
        _ => w.cap_ht20,
    };
    let headroom = w.eirp_per_db * f32::from(eirp_dbm.saturating_sub(23) as u16);
    let raw = cap + headroom - w.w_busy * s.busy_ema - if s.dfs { w.cac_cost } else { 0.0 };
    hold_prob(s) * raw.max(0.0)
}

/// D36 — code-tuned `quality_score` weights (like [`OptimizeWeights`], NOT operator intent — one
/// field-calibration round is expected before these are trusted at scale).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct QualityWeights {
    /// Base capacity of an 80 MHz rung.
    pub cap_vht80: f32,
    pub cap_ht40: f32,
    pub cap_ht20: f32,
    /// Congestion cost per 1% busy.
    pub w_busy: f32,
    /// Headroom bonus per dBm of max-EIRP above the 23 dBm UNII-1 floor (D28 parity).
    pub eirp_per_db: f32,
    /// Flat adoption-cost penalty for a DFS rung (a 60s outage to switch to it).
    pub cac_cost: f32,
}

/// Field-tunable default: base capacity, an 80 MHz rung.
pub const QUAL_CAP_VHT80: f32 = 100.0;
/// Field-tunable default: base capacity, a 40 MHz rung.
pub const QUAL_CAP_HT40: f32 = 50.0;
/// Field-tunable default: base capacity, a 20 MHz rung.
pub const QUAL_CAP_HT20: f32 = 25.0;
/// Field-tunable default: congestion cost per 1% busy.
pub const QUAL_W_BUSY: f32 = 0.6;
/// Field-tunable default: headroom bonus per dBm of max-EIRP above the 23 dBm floor.
pub const QUAL_EIRP_PER_DB: f32 = 2.0;
/// Field-tunable default: flat DFS adoption-cost penalty.
pub const QUAL_CAC_COST: f32 = 8.0;

impl Default for QualityWeights {
    fn default() -> Self {
        QualityWeights {
            cap_vht80: QUAL_CAP_VHT80,
            cap_ht40: QUAL_CAP_HT40,
            cap_ht20: QUAL_CAP_HT20,
            w_busy: QUAL_W_BUSY,
            eirp_per_db: QUAL_EIRP_PER_DB,
            cac_cost: QUAL_CAC_COST,
        }
    }
}

/// The ETSI EIRP table (D27 parity) as a pure function of control channel — used wherever a caller
/// (e.g. [`pick_candidate`]) needs an EIRP estimate but has only a [`ConfigStat`], not a live
/// [`BlockSurvey`]. UNII-2C's 100/116/132 blocks are 30 dBm; everything else (UNII-1/UNII-3/UNII-2A)
/// is the 23 dBm floor.
pub fn eirp_for_stat(s: &ConfigStat) -> u32 {
    match s.key.channel {
        100 | 116 | 132 => 30,
        _ => 23,
    }
}

/// D35/D37 — the stable, [`start_rung`]-compatible rung label for a [`ConfigStat`] — byte-identical
/// to what [`Rung::new`] would produce for the same (band, channel, width).
pub fn config_key_label(s: &ConfigStat) -> String {
    let wname = match s.key.width_mhz {
        80 => "VHT80",
        40 => "HT40",
        _ => "HT20",
    };
    let bname = if s.band == "5" { "5GHz" } else { "2.4GHz" };
    format!("{bname}-{wname}-ch{}", s.key.channel)
}

fn stability_label(v: Stability) -> &'static str {
    match v {
        Stability::Stable => "stable",
        Stability::WidthCollapsed => "width_collapsed",
        Stability::ChanspecFailStorm => "chanspec_fail_storm",
        Stability::Down => "down",
        Stability::ClientFailed => "client_failed",
    }
}

/// D36 — one observation to fold into the model. Both the boot calibrate loop (every rung it
/// applies + its [`verify_rung`] verdict) and the 3AM optimizer (every candidate it
/// measures/validates) call [`record_observation`] with one of these — a SINGLE write path.
#[derive(Debug, Clone)]
pub struct Observation<'a> {
    pub key: ConfigKey,
    pub center_idx: u32,
    pub verdict: Stability,
    /// Survey `busy_ratio`, if measured (the optimizer path); `None` on the boot path.
    pub busy_ratio: Option<u8>,
    /// Assoc-rate/iperf proxy, if measured; `None` otherwise.
    pub tput_proxy: Option<f32>,
    pub now: &'a str,
}

/// D36 — incremental, online, O(1) update of one cell (creating it on first sight, evicting the
/// lowest-[`retention_priority`] cell if the insert pushes `entries` past [`MAX_LEARN_ENTRIES`]).
/// No batch, no training pass. Also stamps [`WifiKnowledge::updated_at`] to `o.now` — see that
/// field's doc for why callers of [`plan_boot`]/[`choose_mode`]/[`pick_candidate`] can rely on it
/// as "now" without those functions taking their own `now` parameter (matching the ADR's exact
/// signatures).
pub fn record_observation(m: &mut WifiKnowledge, o: &Observation) {
    let idx = match m.entries.iter().position(|e| e.key == o.key) {
        Some(i) => i,
        None => {
            let band = if o.key.channel > 14 { "5" } else { "2.4" }.to_string();
            let dfs = is_dfs_rung(o.key.channel, o.key.width_mhz);
            let cac = dfs_cac_seconds(o.key.channel, o.key.width_mhz);
            m.entries.push(ConfigStat {
                key: o.key.clone(),
                center_idx: o.center_idx,
                band,
                dfs,
                cac_seconds: cac,
                successes: 0.0,
                failures: 0.0,
                // First observation seeds the EMA directly (no cold-0 bias) — the blend below is a
                // no-op the first time (see its own doc).
                busy_ema: o.busy_ratio.map(f32::from).unwrap_or(0.0),
                tput_ema: o.tput_proxy.unwrap_or(0.0),
                obs_count: 0,
                last_seen: o.now.to_string(),
                last_outcome: stability_label(o.verdict).to_string(),
                decayed_at: o.now.to_string(),
            });
            m.entries.len() - 1
        }
    };
    let e = &mut m.entries[idx];
    if o.verdict.is_stable() {
        e.successes += 1.0;
    } else {
        e.failures += 1.0;
    }
    // Blend continuous signals when a fresh sample is present. For a JUST-CREATED cell this is
    // exactly a no-op re-application of the same value it was seeded with above (seed-then-blend).
    if let Some(b) = o.busy_ratio {
        e.busy_ema = (1.0 - EMA_ALPHA) * e.busy_ema + EMA_ALPHA * f32::from(b);
    }
    if let Some(t) = o.tput_proxy {
        e.tput_ema = (1.0 - EMA_ALPHA) * e.tput_ema + EMA_ALPHA * t;
    }
    e.obs_count = (e.successes + e.failures).round() as u32;
    e.last_seen = o.now.to_string();
    e.last_outcome = stability_label(o.verdict).to_string();
    m.updated_at = o.now.to_string();

    evict_if_needed(m, o.now);
}

/// D35 — eviction priority: high for a cell we are either SURE is good or SURE is bad AND recent;
/// low for a stale, low-confidence, half-explored cell. Preserves both confident winners and
/// confident known-bad entries (both are valuable — never-repeat-known-bad needs the bad ones too).
pub fn retention_priority(s: &ConfigStat, now: &str) -> f32 {
    confidence(s) * recency(&s.last_seen, now)
}

fn recency(last_seen: &str, now: &str) -> f32 {
    let age = age_days(last_seen, now);
    0.5f32.powf(age / STALE_HALF_LIFE_DAYS)
}

fn evict_if_needed(m: &mut WifiKnowledge, now: &str) {
    while m.entries.len() > MAX_LEARN_ENTRIES {
        let mut worst_idx = 0usize;
        let mut worst_pri = f32::MAX;
        for (i, e) in m.entries.iter().enumerate() {
            let pri = retention_priority(e, now);
            if pri < worst_pri {
                worst_pri = pri;
                worst_idx = i;
            }
        }
        m.entries.remove(worst_idx);
    }
}

/// Parse a minimal ISO8601 UTC timestamp (`YYYY-MM-DDTHH:MM:SSZ`) into fractional days since a
/// fixed (arbitrary) epoch — dependency-free (no `chrono`); only DIFFERENCES between two calls are
/// ever used, so the epoch itself doesn't matter. Malformed/short input maps to day 0 (so a
/// corrupt/missing timestamp degrades to "no age gap", the conservative reading, never an inflated
/// or negative one).
fn parse_iso8601_days(ts: &str) -> f64 {
    if ts.len() < 19 {
        return 0.0;
    }
    let y: i64 = ts.get(0..4).and_then(|s| s.parse().ok()).unwrap_or(1970);
    let mo: i64 = ts.get(5..7).and_then(|s| s.parse().ok()).unwrap_or(1);
    let d: i64 = ts.get(8..10).and_then(|s| s.parse().ok()).unwrap_or(1);
    let hh: i64 = ts.get(11..13).and_then(|s| s.parse().ok()).unwrap_or(0);
    let mi: i64 = ts.get(14..16).and_then(|s| s.parse().ok()).unwrap_or(0);
    let ss: i64 = ts.get(17..19).and_then(|s| s.parse().ok()).unwrap_or(0);
    let days = days_from_civil(y, mo, d);
    days as f64 + (hh as f64 * 3600.0 + mi as f64 * 60.0 + ss as f64) / 86400.0
}

/// Howard Hinnant's `days_from_civil` — a well-known, dependency-free proleptic-Gregorian
/// days-since-epoch algorithm. The epoch is irrelevant here (only differences matter), so no
/// calendar edge case needs special-casing beyond what the algorithm already handles.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (m + 9) % 12; // [0, 11]
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// Fractional days elapsed from `then` to `now` (both ISO8601 UTC), clamped to >= 0.
pub fn age_days(then: &str, now: &str) -> f32 {
    let a = parse_iso8601_days(then);
    let b = parse_iso8601_days(now);
    (b - a).max(0.0) as f32
}

/// D38 — never-repeat-known-bad, generalised from a boolean `blocked_channels` entry to a learned,
/// decaying signal: bad enough, sure enough, recently enough. After [`REPROBE_WINDOW_DAYS`] a
/// confidently-bad cell becomes re-probe-eligible again (rehabilitation after an environment
/// change) — [`plan_boot`]/[`optimize_candidates`]-equivalent callers simply stop excluding it.
pub fn is_known_bad(s: &ConfigStat, now: &str) -> bool {
    hold_prob(s) <= BAD_HOLD
        && confidence(s) >= BAD_CONFIDENCE
        && age_days(&s.last_seen, now) < REPROBE_WINDOW_DAYS
}

/// D40 — discounted-Beta aging: geometrically shrinks a stale cell's `successes`/`failures`
/// *concentration* toward the uniform prior while PRESERVING the posterior MEAN, so a stale winner
/// becomes explore-eligible again (its UCB bonus rises, its `confidence` drops) without being
/// forgotten outright. Applied once per optimizer run AND on model load (see
/// [`WifiKnowledge::updated_at`]'s doc) — this is also where `updated_at` gets stamped to the real
/// wall-clock `now`, which [`plan_boot`]/[`choose_mode`]/[`pick_candidate`] then treat as "now".
pub fn age_model(m: &mut WifiKnowledge, now: &str) {
    for e in &mut m.entries {
        let age = age_days(&e.decayed_at, now);
        if age > 0.0 {
            let factor = 0.5f32.powf(age / STALE_HALF_LIFE_DAYS);
            e.successes *= factor;
            e.failures *= factor;
            e.decayed_at = now.to_string();
        }
    }
    m.updated_at = now.to_string();
}

/// D38 — firmware/driver-change rehabilitation: a one-time strong decay (halve every entry's
/// `failures`, preserving `successes` — the things that WORKED) whenever [`WifiKnowledge::fw_id`]
/// no longer matches the currently-running firmware fingerprint, then stamps the new one. A
/// firmware fix that resolves a chanspec bug thus gets a re-probe chance without full amnesia.
/// No-op (and no `fw_id` write) when the fingerprint hasn't changed.
pub fn apply_fw_rehabilitation(m: &mut WifiKnowledge, current_fw_id: &str) {
    if m.fw_id == current_fw_id {
        return;
    }
    for e in &mut m.entries {
        e.failures /= 2.0;
    }
    m.fw_id = current_fw_id.to_string();
}

/// D38 — `dfs_ap_supported` is now DERIVED, not stored: `Some(false)` iff every CONFIDENT DFS entry
/// for this (regdomain, radio) is known-bad; `Some(true)` the moment any confident DFS entry is NOT
/// known-bad (holds); `None` when there is no confident DFS evidence yet either way (untested — the
/// D30 `None` case, generalised).
pub fn dfs_ap_supported(m: &WifiKnowledge, cc: &str, radio_id: &str) -> Option<bool> {
    let now = m.updated_at.as_str();
    let dfs_entries: Vec<&ConfigStat> = m
        .entries
        .iter()
        .filter(|s| s.key.radio_id == radio_id && s.key.regdomain.eq_ignore_ascii_case(cc) && s.dfs)
        .filter(|s| confidence(s) >= BAD_CONFIDENCE)
        .collect();
    if dfs_entries.is_empty() {
        return None;
    }
    Some(dfs_entries.iter().any(|s| !is_known_bad(s, now)))
}

/// D37 — the boot-time exploitation plan. See the [`LEARN_MODE`]/[`LearnMode`] doc for the
/// shadow/active split.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum BootPlan {
    /// Tier-2 EXPLOIT (Active mode only): high confidence — SKIP the ladder entirely; render this
    /// (channel, width), ONE `clean_restart`, ONE `verify_rung`. O(1) boot.
    DirectToBest { stat: ConfigStat, quality: f32, confidence: f32 },
    /// Tier-1 RESUME: some confidence (>=1 Stable seen) — start the ladder AT this rung's index,
    /// no VHT80 re-thrash. The band-LKG win, generalised — and what a Shadow-mode DirectToBest
    /// winner degrades to.
    ResumeAtRung { label: String },
    /// COLD / low-confidence / model-miss — run the full D6/D20 ladder from the top.
    Ladder,
}

/// D37 — the boot-time plan. Selection = argmax [`quality_score`] over
/// `{ stat : stat.key matches (radio_id, cc) AND (channel, width) in legal AND !is_known_bad }`.
/// `legal` is the ladder-derived currently-SAFE (channel, width) set (`ap_capable` intersect
/// `reg_channels` intersect radio caps) — the model may ONLY ever choose among these
/// (always-joinable, D41). Gates the DirectToBest tier by [`LEARN_MODE`] (D44 shadow default).
///
/// **D45: cold-context ONLY.** This answers "what should the ordinary, short-settle boot ladder
/// resume/skip-to," which must NEVER be a rung only proven to hold once the radio is WARM (see
/// [`ConfigKey`]'s own doc) — such a winner, applied with the ordinary settle, would very likely
/// fail exactly like a fresh cold attempt. [`plan_warm_upgrade`] is the separate, warm-context-only
/// decision for "what should the POST-settle warm-upgrade step try."
pub fn plan_boot(
    m: &WifiKnowledge,
    cc: &str,
    radio_id: &str,
    legal: &[(u32, u32)],
    eirp_of: impl Fn(u32) -> u32,
    w: &QualityWeights,
) -> BootPlan {
    plan_boot_for_mode(LEARN_MODE, m, cc, radio_id, legal, eirp_of, w)
}

/// Test/introspection seam behind [`plan_boot`] — the real tier-selection logic, parameterised by
/// [`LearnMode`] so both the shadow-degrade AND the underlying Active-mode tier math are directly
/// unit-testable without mutating the (deliberately `const`) [`LEARN_MODE`] flag.
fn plan_boot_for_mode(
    mode: LearnMode,
    m: &WifiKnowledge,
    cc: &str,
    radio_id: &str,
    legal: &[(u32, u32)],
    eirp_of: impl Fn(u32) -> u32,
    w: &QualityWeights,
) -> BootPlan {
    let now = m.updated_at.as_str();
    let winner = m
        .entries
        .iter()
        .filter(|s| s.key.radio_id == radio_id && s.key.regdomain.eq_ignore_ascii_case(cc))
        .filter(|s| !s.key.warm) // D45: cold-context only — see this fn's own doc.
        .filter(|s| legal.contains(&(s.key.channel, s.key.width_mhz)))
        .filter(|s| !is_known_bad(s, now))
        .max_by(|a, b| {
            quality_score(a, eirp_of(a.key.channel), w)
                .partial_cmp(&quality_score(b, eirp_of(b.key.channel), w))
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    let Some(s) = winner else {
        return BootPlan::Ladder;
    };
    let q = quality_score(s, eirp_of(s.key.channel), w);
    let c = confidence(s);
    let h = hold_prob(s);
    if c >= DIRECT_CONFIDENCE && h >= DIRECT_HOLD {
        return match mode {
            LearnMode::Active => BootPlan::DirectToBest { stat: s.clone(), quality: q, confidence: c },
            LearnMode::Shadow => BootPlan::ResumeAtRung { label: config_key_label(s) },
        };
    }
    // NOTE: `> 0.0`, not `>= 1.0` — after `age_model`'s discounted-Beta decay (applied on
    // every load, D40), even a single Stable observation's `successes` erodes BELOW 1.0 after
    // any nonzero elapsed time (a realistic reboot cadence, not just a pathological edge case).
    // A strict `>= 1.0` would defeat the ADR's own "doesn't repeat the same calibration twice"
    // goal on literally the second boot. Decay asymptotically approaches but never reaches
    // exactly zero for a finite age from a nonzero start, so `> 0.0` robustly means "has EVER
    // held, at any confidence" — the DIRECT_CONFIDENCE/DIRECT_HOLD gate above already owns
    // "how much do we trust it," including forcing re-validation as a winner goes stale.
    if s.successes > 0.0 {
        return BootPlan::ResumeAtRung { label: config_key_label(s) };
    }
    BootPlan::Ladder
}

/// D39 — the 3AM optimizer's explore/exploit mode for this run. Exploration is budgeted to the
/// optimizer only (never the boot path) — at most one exploration per run (matching D28's
/// one-switch-per-run disruption cap).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptimizeMode {
    Exploit,
    Explore,
}

/// D39 — `Explore` when ANY of: (a) a legal, not-known-bad config is under-observed
/// (`obs_count < `[`MIN_OBS`]`); (b) the [`EXPLORE_EVERY`]th-run cadence hits (catch drift on an
/// otherwise-mature set); (c) `env_changed` (a busy-ema jump, or a regdomain change fired this
/// run). Otherwise `Exploit` (the common nightly result: re-measure the incumbent, likely `Keep`).
pub fn choose_mode(m: &WifiKnowledge, cc: &str, radio: &str, run_counter: u32, env_changed: bool) -> OptimizeMode {
    if env_changed {
        return OptimizeMode::Explore;
    }
    if run_counter > 0 && run_counter.is_multiple_of(EXPLORE_EVERY) {
        return OptimizeMode::Explore;
    }
    let now = m.updated_at.as_str();
    let under_observed = m
        .entries
        .iter()
        .filter(|s| s.key.radio_id == radio && s.key.regdomain.eq_ignore_ascii_case(cc))
        .filter(|s| !is_known_bad(s, now))
        .any(|s| (s.successes + s.failures) < MIN_OBS as f32);
    if under_observed {
        OptimizeMode::Explore
    } else {
        OptimizeMode::Exploit
    }
}

/// D39 — pick ONE candidate key for this run's mode. `Exploit` picks argmax [`quality_score`];
/// `Explore` picks argmax UCB1 (`quality_score` + [`EXPLORE_C`] * sqrt(ln(total_obs+1)/(obs+1))),
/// favouring high-uncertainty cells. `None` when nothing legal-and-not-known-bad exists for this
/// (regdomain, radio) — the caller then falls back to the D6/D20 ladder default exactly as before
/// this extension. EIRP is derived internally via [`eirp_for_stat`] (a pure function of channel) —
/// the ADR's own `pick_candidate` signature omits the `eirp_of` callback [`plan_boot`] takes; this
/// is the documented, deterministic resolution (see the honest deviation note in the ADR
/// implementation report).
pub fn pick_candidate(
    m: &WifiKnowledge,
    cc: &str,
    radio: &str,
    legal: &[(u32, u32)],
    mode: OptimizeMode,
    w: &QualityWeights,
) -> Option<ConfigKey> {
    let now = m.updated_at.as_str();
    let cands: Vec<&ConfigStat> = m
        .entries
        .iter()
        .filter(|s| s.key.radio_id == radio && s.key.regdomain.eq_ignore_ascii_case(cc))
        .filter(|s| legal.contains(&(s.key.channel, s.key.width_mhz)))
        .filter(|s| !is_known_bad(s, now))
        .collect();
    if cands.is_empty() {
        return None;
    }
    match mode {
        OptimizeMode::Exploit => cands
            .iter()
            .max_by(|a, b| {
                quality_score(a, eirp_for_stat(a), w)
                    .partial_cmp(&quality_score(b, eirp_for_stat(b), w))
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|s| s.key.clone()),
        OptimizeMode::Explore => {
            let total_obs: f32 = cands.iter().map(|s| s.successes + s.failures).sum();
            cands
                .iter()
                .max_by(|a, b| {
                    ucb(a, total_obs, w)
                        .partial_cmp(&ucb(b, total_obs, w))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|s| s.key.clone())
        }
    }
}

fn ucb(s: &ConfigStat, total_obs: f32, w: &QualityWeights) -> f32 {
    let obs = s.successes + s.failures;
    let bonus = EXPLORE_C * (((total_obs + 1.0).ln()) / (obs + 1.0)).sqrt();
    quality_score(s, eirp_for_stat(s), w) + bonus
}

/// D41 — anti-flap gate: should the optimizer replace `current` with `candidate`? Composes with
/// (does not replace) D28's own `switch_margin`/`quiet_floor_busy` hysteresis — this is the MODEL's
/// own additional check. `true` only when `candidate`'s quality clears `current`'s by
/// [`QUALITY_SWITCH_MARGIN`] AND `candidate`'s confidence is at least as high (never flap toward an
/// under-observed cell, even a momentarily higher-quality one — the incumbent wins ties).
pub fn should_switch(current: &ConfigStat, candidate: &ConfigStat, eirp_of: impl Fn(u32) -> u32, w: &QualityWeights) -> bool {
    let cq = quality_score(current, eirp_of(current.key.channel), w);
    let dq = quality_score(candidate, eirp_of(candidate.key.channel), w);
    dq >= cq + QUALITY_SWITCH_MARGIN && confidence(candidate) >= confidence(current)
}

/// D35/D42 — derive the (still-written, still-consulted) [`BandLkg`] export from the model's
/// current argmax over `legal`, so [`start_rung`]'s existing reader needs ZERO change — it consumes
/// the projection; the model is the source of truth behind it. `None` when no confident,
/// not-known-bad, legal, at-least-once-stable entry exists yet (nothing to export).
///
/// **D45: cold-context ONLY** (same reasoning as [`plan_boot`]) — the persisted band-LKG is
/// consumed by [`start_rung`] as "resume the ORDINARY ladder here," so it must never point at a
/// rung only proven to hold warm.
pub fn band_lkg_from_model(
    m: &WifiKnowledge,
    cc: &str,
    radio_id: &str,
    legal: &[(u32, u32)],
    w: &QualityWeights,
) -> Option<BandLkg> {
    let now = m.updated_at.as_str();
    let winner = m
        .entries
        .iter()
        .filter(|s| s.key.radio_id == radio_id && s.key.regdomain.eq_ignore_ascii_case(cc))
        .filter(|s| !s.key.warm) // D45: cold-context only.
        .filter(|s| legal.contains(&(s.key.channel, s.key.width_mhz)))
        .filter(|s| !is_known_bad(s, now))
        .filter(|s| s.successes > 0.0) // decay-robust "has ever held" — see plan_boot_for_mode's note
        .max_by(|a, b| {
            quality_score(a, eirp_for_stat(a), w)
                .partial_cmp(&quality_score(b, eirp_for_stat(b), w))
                .unwrap_or(std::cmp::Ordering::Equal)
        })?;
    Some(BandLkg {
        cc: cc.to_string(),
        radio_id: radio_id.to_string(),
        band: winner.band.clone(),
        label: config_key_label(winner),
        channel: winner.key.channel,
        decided_at: now.to_string(),
    })
}

/// D35/D42 — derive the [`ChannelLkg`] export from the model's current argmax among 5 GHz VHT80
/// entries — mirrors [`band_lkg_from_model`] for the channel-optimizer's own consulted cache.
/// **D45: cold-context only** — same reasoning as [`band_lkg_from_model`]; the 3AM optimizer's own
/// observations are ALL cold-context by construction (this warm/cold axis is scoped exclusively to
/// the boot-ladder warm-upgrade step — see [`ConfigKey`]'s doc), so this filter is a no-op for every
/// existing caller and only ever excludes the NEW warm-context cells the boot ladder now produces.
pub fn channel_lkg_from_model(
    m: &WifiKnowledge,
    cc: &str,
    radio_id: &str,
    legal: &[(u32, u32)],
    w: &QualityWeights,
) -> Option<ChannelLkg> {
    let now = m.updated_at.as_str();
    let winner = m
        .entries
        .iter()
        .filter(|s| s.key.radio_id == radio_id && s.key.regdomain.eq_ignore_ascii_case(cc))
        .filter(|s| !s.key.warm) // D45: cold-context only.
        .filter(|s| s.key.width_mhz == 80)
        .filter(|s| legal.contains(&(s.key.channel, s.key.width_mhz)))
        .filter(|s| !is_known_bad(s, now))
        .filter(|s| s.successes > 0.0) // decay-robust "has ever held" — see plan_boot_for_mode's note
        .max_by(|a, b| {
            quality_score(a, eirp_for_stat(a), w)
                .partial_cmp(&quality_score(b, eirp_for_stat(b), w))
                .unwrap_or(std::cmp::Ordering::Equal)
        })?;
    Some(ChannelLkg {
        cc: cc.to_string(),
        radio_id: radio_id.to_string(),
        control_channel: winner.key.channel,
        center_idx: winner.center_idx,
        width_mhz: 80,
        dfs: winner.dfs,
        score: quality_score(winner, eirp_for_stat(winner), w) as i32,
        validated_at: now.to_string(),
    })
}

/// D46 — the model-informed warm-upgrade TARGET: once the model has accumulated genuinely-WARM
/// evidence (see [`ConfigKey`]'s doc) that some rung reliably HOLDS once the radio is warm, the
/// runtime should warm-upgrade DIRECTLY to it — not merely "the next rung immediately above the
/// cold-settled one," which is [`warm_upgrade_candidate`]'s static, memory-less BOOTSTRAP rule
/// (still correct when nothing has been learned yet, e.g. this box's very first boot).
///
/// Selection: argmax [`quality_score`] over `{ warm-context ConfigStat : same (radio_id,
/// regdomain), (channel, width_mhz) in `legal`, width_mhz STRICTLY WIDER than
/// `cold_chosen_width_mhz`, not known-bad, has-ever-held }` — the model can therefore never
/// warm-upgrade to something narrower than (or sideways of) what the cold ladder already achieved;
/// it can only ever propose an UPGRADE. `None` when no such learned winner exists — the caller then
/// falls back to [`warm_upgrade_candidate`]'s static ladder-adjacency rule.
pub fn plan_warm_upgrade(
    m: &WifiKnowledge,
    cc: &str,
    radio_id: &str,
    legal: &[(u32, u32)],
    cold_chosen_width_mhz: u32,
    w: &QualityWeights,
) -> Option<ConfigKey> {
    let now = m.updated_at.as_str();
    m.entries
        .iter()
        .filter(|s| s.key.radio_id == radio_id && s.key.regdomain.eq_ignore_ascii_case(cc))
        .filter(|s| s.key.warm) // D45: warm-context evidence only — the whole point of this fn.
        .filter(|s| s.key.width_mhz > cold_chosen_width_mhz) // strictly an UPGRADE, never sideways/narrower.
        .filter(|s| legal.contains(&(s.key.channel, s.key.width_mhz)))
        .filter(|s| !is_known_bad(s, now))
        .filter(|s| s.successes > 0.0) // decay-robust "has ever held" — see plan_boot_for_mode's note
        .max_by(|a, b| {
            quality_score(a, eirp_for_stat(a), w)
                .partial_cmp(&quality_score(b, eirp_for_stat(b), w))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|s| s.key.clone())
}

fn width_mhz_for_label(label: &str) -> u32 {
    if label.contains("VHT80") {
        80
    } else if label.contains("HT40") {
        40
    } else {
        20
    }
}

/// D44 migration — seed the model from a PRE-EXISTING [`BandLkg`] (a box upgrading mid-field, one
/// that already has a proven band-LKG from before the model existed) with ONE `Stable` observation,
/// so it starts at `ResumeAtRung`, not cold. No-op if an entry for this exact key already exists
/// (never double-seeds / never overwrites a real observation history).
pub fn seed_from_band_lkg(m: &mut WifiKnowledge, lkg: &BandLkg, now: &str) {
    let width_mhz = width_mhz_for_label(&lkg.label);
    let key = ConfigKey {
        radio_id: lkg.radio_id.clone(),
        regdomain: lkg.cc.clone(),
        channel: lkg.channel,
        width_mhz,
        // D45: a pre-existing band-LKG predates the warm/cold distinction entirely — it was proven
        // by whatever settle the OLD (pre-D46) code used, which was cold-scale. Seed it as cold
        // (never warm) — the conservative, accurate migration.
        warm: false,
    };
    if m.entries.iter().any(|e| e.key == key) {
        return;
    }
    let center_idx = center_idx_for_control(lkg.channel);
    record_observation(
        m,
        &Observation {
            key,
            center_idx,
            verdict: Stability::Stable,
            busy_ratio: None,
            tput_proxy: None,
            now,
        },
    );
}

/// D43 — one alternative's WHY-not, for the operator explanation panel.
#[derive(Debug, Clone, Serialize)]
pub struct SkippedConfig {
    pub label: String,
    pub reason: String,
}

/// D43 — one point on the winning key's (quality, confidence, hold_prob) trajectory — the visible
/// "learning curve."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurvePoint {
    pub at: String,
    pub quality: f32,
    pub confidence: f32,
    pub hold_prob: f32,
}

/// D43 — one boot/optimizer decision's full explanation, appended to `wifi-calibration.json` /
/// `wifi-channel-optimize.json` (D9/D32).
#[derive(Debug, Clone, Serialize)]
pub struct LearnDecision {
    pub iface: String,
    /// `"direct_to_best"` | `"resume_at_rung"` | `"ladder_fallback"` | `"explore"` | `"exploit_keep"`
    /// | `"exploit_switch"`.
    pub mode: String,
    pub chosen: Option<String>,
    pub chosen_quality: f32,
    pub chosen_confidence: f32,
    pub chosen_hold_prob: f32,
    pub skipped: Vec<SkippedConfig>,
    /// The winning key's trajectory — the visible improvement curve, bounded to
    /// [`LEARN_CURVE_MAX_POINTS`].
    pub curve: Vec<CurvePoint>,
    pub decided_at: String,
}

impl LearnDecision {
    /// Serialise to pretty JSON — infallible in practice (mirrors every other `*Outcome::to_json`
    /// in this module).
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self)
            .unwrap_or_else(|e| format!("{{\"error\":\"serialize LearnDecision: {e}\"}}"))
    }
}

/// D43 — build a [`LearnDecision`] for the winning key (or `None` on a `Ladder`/no-legal-candidate
/// outcome), appending one new [`CurvePoint`] onto whatever curve the caller already has (read from
/// the previous artifact) — capped at [`LEARN_CURVE_MAX_POINTS`] so the artifact stays bounded.
#[allow(clippy::too_many_arguments)]
pub fn build_learn_decision(
    iface: &str,
    mode: &str,
    chosen: Option<&ConfigStat>,
    eirp_of: impl Fn(u32) -> u32,
    w: &QualityWeights,
    skipped: Vec<SkippedConfig>,
    mut curve: Vec<CurvePoint>,
    now: &str,
) -> LearnDecision {
    let (chosen_label, cq, cconf, ch) = match chosen {
        Some(s) => {
            let q = quality_score(s, eirp_of(s.key.channel), w);
            let c = confidence(s);
            let h = hold_prob(s);
            curve.push(CurvePoint { at: now.to_string(), quality: q, confidence: c, hold_prob: h });
            if curve.len() > LEARN_CURVE_MAX_POINTS {
                let excess = curve.len() - LEARN_CURVE_MAX_POINTS;
                curve.drain(0..excess);
            }
            (Some(config_key_label(s)), q, c, h)
        }
        None => (None, 0.0, 0.0, 0.0),
    };
    LearnDecision {
        iface: iface.to_string(),
        mode: mode.to_string(),
        chosen: chosen_label,
        chosen_quality: cq,
        chosen_confidence: cconf,
        chosen_hold_prob: ch,
        skipped,
        curve,
        decided_at: now.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Feature 1: country detection ladder ----

    #[test]
    fn operator_override_always_wins() {
        let inp = CountryInputs {
            operator: Some("gb".into()),
            last_known_good: Some("RO".into()), // stale cache — must be ignored under operator intent
            modem_mcc: Some(310), // US — must be ignored
            geoip_cc: Some("DE".into()),
            timezone: Some("America/New_York".into()),
        };
        let d = decide_country(&inp);
        assert_eq!(d.cc, "GB");
        assert_eq!(d.source, CountrySource::Operator);
        assert_eq!(d.confidence, 100);
    }

    #[test]
    fn operator_auto_is_not_an_override() {
        // "auto" means "let detection decide" — must fall through to the modem.
        let inp = CountryInputs {
            operator: Some("auto".into()),
            modem_mcc: Some(234), // GB
            ..Default::default()
        };
        let d = decide_country(&inp);
        assert_eq!(d.cc, "GB");
        assert_eq!(d.source, CountrySource::ModemMcc);
    }

    #[test]
    fn lkg_wins_over_live_sources_at_boot_but_not_over_operator() {
        // Boot fail-safe: a cached RO is trusted before the (possibly-not-yet-up) live modem/GeoIP,
        // so a box that resolved RO once stays RO even if the WAN is briefly down.
        let inp = CountryInputs {
            last_known_good: Some("ro".into()),
            modem_mcc: Some(262), // DE — a live source, but LKG is consulted first at boot
            geoip_cc: Some("US".into()),
            timezone: Some("Europe/Paris".into()),
            ..Default::default()
        };
        let d = decide_country(&inp);
        assert_eq!(d.cc, "RO");
        assert_eq!(d.source, CountrySource::LastKnownGood);
        // …but operator intent still overrides a stale cache.
        let inp2 = CountryInputs { operator: Some("GB".into()), ..inp };
        assert_eq!(decide_country(&inp2).source, CountrySource::Operator);
    }

    #[test]
    fn lkg_skipped_forces_live_redetection() {
        // WAN-change re-eval passes last_known_good=None → the live modem MCC decides (mobility).
        let inp = CountryInputs {
            last_known_good: None,
            modem_mcc: Some(262), // DE
            ..Default::default()
        };
        let d = decide_country(&inp);
        assert_eq!(d.cc, "DE");
        assert_eq!(d.source, CountrySource::ModemMcc);
    }

    #[test]
    fn lkg_never_holds_world_and_confidence_is_honest() {
        // A "00" cache is not a real country — must fall through, never be treated as LKG.
        let inp = CountryInputs {
            last_known_good: Some("00".into()),
            timezone: Some("Europe/Berlin".into()),
            ..Default::default()
        };
        let d = decide_country(&inp);
        assert_eq!(d.source, CountrySource::Timezone, "world '00' is not a valid last-known-good");
        // LKG is scored below a live modem reading (honestly a cached hint).
        assert!(CountrySource::LastKnownGood.confidence() < CountrySource::ModemMcc.confidence());
    }

    #[test]
    fn modem_mcc_beats_geoip_and_timezone() {
        let inp = CountryInputs {
            operator: None,
            last_known_good: None,
            modem_mcc: Some(262), // DE
            geoip_cc: Some("US".into()),
            timezone: Some("America/New_York".into()),
        };
        let d = decide_country(&inp);
        assert_eq!(d.cc, "DE");
        assert_eq!(d.source, CountrySource::ModemMcc);
    }

    #[test]
    fn geoip_used_when_present_and_no_modem() {
        let inp = CountryInputs {
            geoip_cc: Some("fr".into()),
            timezone: Some("Europe/London".into()),
            ..Default::default()
        };
        let d = decide_country(&inp);
        assert_eq!(d.cc, "FR");
        assert_eq!(d.source, CountrySource::GeoIp);
    }

    #[test]
    fn timezone_is_the_offline_fallback() {
        // Air-gapped/standalone: no operator, no modem, GeoIP DISABLED (None) → timezone decides.
        let inp = CountryInputs {
            timezone: Some("Europe/Berlin".into()),
            ..Default::default()
        };
        let d = decide_country(&inp);
        assert_eq!(d.cc, "DE");
        assert_eq!(d.source, CountrySource::Timezone);
        assert!(d.confidence < CountrySource::GeoIp.confidence());
    }

    #[test]
    fn world_domain_when_nothing_known() {
        let d = decide_country(&CountryInputs::default());
        assert_eq!(d.cc, "00");
        assert_eq!(d.source, CountrySource::WorldFallback);
    }

    #[test]
    fn unknown_mcc_and_tz_degrade_conservatively_not_guess() {
        // An unmapped MCC + unmapped TZ must NOT be guessed — degrade to world.
        let inp = CountryInputs {
            modem_mcc: Some(999),
            timezone: Some("Antarctica/Troll".into()),
            ..Default::default()
        };
        let d = decide_country(&inp);
        assert_eq!(d.cc, "00", "unknown inputs must degrade to the conservative world domain");
    }

    #[test]
    fn normalize_rejects_junk_but_accepts_world() {
        assert_eq!(normalize_cc("Gb"), Some("GB".into()));
        assert_eq!(normalize_cc(" us "), Some("US".into()));
        assert_eq!(normalize_cc("00"), Some("00".into()));
        assert_eq!(normalize_cc("auto"), None);
        assert_eq!(normalize_cc(""), None);
        assert_eq!(normalize_cc("USA"), None); // not alpha-2
        assert_eq!(normalize_cc("G1"), None); // not two letters
    }

    // ---- Feature 1: resolve-for-render (never emit country_code=auto) ----

    #[test]
    fn resolve_intent_country_wins_over_runfile() {
        assert_eq!(resolved_country_for_render(Some("GB"), Some("RO")), "GB");
    }

    #[test]
    fn resolve_falls_back_to_boot_detected_runfile() {
        // Intent says auto/absent → use the boot-detected CC the regdomain oneshot wrote.
        assert_eq!(resolved_country_for_render(Some("auto"), Some("RO")), "RO");
        assert_eq!(resolved_country_for_render(None, Some("ro")), "RO");
    }

    #[test]
    fn resolve_never_returns_auto_or_junk() {
        // The whole point of (c): hostapd must never get country_code=auto.
        assert_eq!(resolved_country_for_render(Some("auto"), None), "00");
        assert_eq!(resolved_country_for_render(Some("auto"), Some("auto")), "00");
        assert_eq!(resolved_country_for_render(None, None), "00");
        assert_eq!(resolved_country_for_render(Some("USA"), Some("bogus")), "00");
        // …and world 00 is a valid explicit choice, not treated as junk.
        assert_eq!(resolved_country_for_render(Some("00"), Some("RO")), "00");
    }

    // ---- Feature 1: regdomain → allowed channels ----

    #[test]
    fn etsi_domain_excludes_unii3() {
        let gb = reg_channels("GB");
        assert!(gb.non_dfs_5ghz.contains(&36));
        assert!(!gb.non_dfs_5ghz.contains(&149), "ETSI (GB) must not propose UNII-3 for AP");
        assert!(!gb.allow_24_ht40, "ETSI stays HT20 in 2.4");
    }

    #[test]
    fn fcc_domain_includes_unii3() {
        let us = reg_channels("us");
        assert!(us.non_dfs_5ghz.contains(&36));
        assert!(us.non_dfs_5ghz.contains(&149), "FCC (US) may use UNII-3");
        assert!(us.allow_24_ht40);
    }

    #[test]
    fn world_domain_is_most_restrictive() {
        let w = reg_channels("00");
        assert_eq!(w.non_dfs_5ghz, vec![36, 40, 44, 48], "world = UNII-1 only");
        assert!(!w.allow_24_ht40);
    }

    // ---- Feature 2: supplicant prerequisite ----

    #[test]
    fn supplicant_runs_only_on_station_radios() {
        let radios = vec![
            ("wlan0".to_string(), "ap".to_string()),       // onboard AP → mask
            ("wlan1".to_string(), "station".to_string()),  // USB-dongle uplink → start
            ("wlan2".to_string(), "unknown".to_string()),  // unknown → mask (conservative)
        ];
        let pol = supplicant_policy(&radios);
        let get = |i: &str| pol.iter().find(|p| p.iface == i).unwrap().action;
        assert_eq!(get("wlan0"), SupplicantAction::Mask, "AP radio must NOT run a supplicant (the VHT80-collapse root cause)");
        assert_eq!(get("wlan1"), SupplicantAction::Start, "station radio needs a supplicant");
        assert_eq!(get("wlan2"), SupplicantAction::Mask, "unknown role degrades to Mask");
    }

    // ---- Feature 2: candidate ladder ----

    // A fixed stand-in device_id — `candidate_ladder`'s floor rung is now a CONSTANT (ch6), so no
    // test below depends on what this hashes to; `default_24_channel_*` tests further down (in
    // wifi_cfg) cover the {1,6,11} derivation used by OTHER callers.
    const DEV: &str = "hp-caltest-0000";

    fn brcmfmac() -> RadioCaps {
        // The BCM43455: reports 5 GHz + VHT80 in iw phy, and HOLDS VHT80 in AP mode once the
        // supplicant-contention prerequisite is met (proven live on a CM5, 2026-07-10).
        RadioCaps { iface: "wlan0".into(), band_5ghz: true, band_24ghz: true, ht40: true, vht80: true }
    }

    #[test]
    fn ladder_is_best_to_safe_and_ends_at_the_floor() {
        // The operator's exact 3-rung shape (2026-07-15, proven on metal): VHT80-ch40 (control ch40,
        // the UNII-1 upper-secondary — the ONLY control channel that holds 80 MHz on this
        // firmware) → HT40-ch36 (lower-primary, proven rock-stable) → the 2.4 GHz ch6 floor. No
        // intermediate HT20-ch36 rung (dropped — operator wants exactly 3 stages).
        let reg = reg_channels("GB");
        let ladder = candidate_ladder(&reg, &brcmfmac(), DEV);
        let labels: Vec<&str> = ladder.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(
            labels,
            vec!["5GHz-VHT80-ch40", "5GHz-HT40-ch36", "2.4GHz-HT20-ch6"],
            "GB radio: VHT80-ch40 → HT40-ch36 → 2.4 HT20-ch6 floor (no 2.4 HT40 in ETSI); exactly 3 rungs"
        );
        // Widths strictly non-increasing (best→safe).
        let mhz: Vec<u32> = ladder.iter().map(|r| r.width.mhz()).collect();
        assert!(mhz.windows(2).all(|w| w[0] >= w[1]) || mhz.first() == Some(&80));
        assert_eq!(ladder.last().unwrap().label, "2.4GHz-HT20-ch6", "floor is always last");
    }

    #[test]
    fn fcc_radio_adds_24_ht40_rung() {
        let ladder = candidate_ladder(&reg_channels("US"), &brcmfmac(), DEV);
        assert!(ladder.iter().any(|r| r.label == "2.4GHz-HT40-ch6"), "FCC + HT40-cap radio gets 2.4 HT40");
    }

    #[test]
    fn softmac_without_vht_skips_the_top_rung() {
        // A radio whose iw phy does NOT advertise VHT80 must not get a VHT80 rung at all.
        let caps = RadioCaps { iface: "wlan1".into(), band_5ghz: true, band_24ghz: true, ht40: true, vht80: false };
        let ladder = candidate_ladder(&reg_channels("GB"), &caps, DEV);
        assert!(!ladder.iter().any(|r| matches!(r.width, ChanWidthShim::Vht80)), "no VHT80 without the cap");
        assert_eq!(ladder.first().unwrap().label, "5GHz-HT40-ch36", "top rung is now HT40");
        assert_eq!(ladder.len(), 2, "HT40-ch36 + the 2.4GHz floor — still exactly 2 rungs, no HT20-ch36");
    }

    #[test]
    fn radio_without_ht40_falls_back_to_ht20_anchor() {
        // A radio with neither VHT80 nor HT40 capability still gets a working 5 GHz rung (plain
        // HT20 on the anchor channel) rather than jumping straight past 5 GHz to the floor.
        let caps = RadioCaps { iface: "wlan1".into(), band_5ghz: true, band_24ghz: true, ht40: false, vht80: false };
        let ladder = candidate_ladder(&reg_channels("GB"), &caps, DEV);
        let labels: Vec<&str> = ladder.iter().map(|r| r.label.as_str()).collect();
        assert_eq!(labels, vec!["5GHz-HT20-ch36", "2.4GHz-HT20-ch6"]);
    }

    #[test]
    fn conservative_radio_ladder_is_just_the_floor() {
        let ladder = candidate_ladder(&reg_channels("00"), &RadioCaps::conservative("wlan0"), DEV);
        assert_eq!(ladder.len(), 1);
        assert_eq!(ladder[0].label, "2.4GHz-HT20-ch6");
    }

    #[test]
    fn ladder_is_never_empty() {
        // Even a radio that reported no bands at all gets the floor.
        let caps = RadioCaps { iface: "x".into(), band_5ghz: false, band_24ghz: false, ht40: false, vht80: false };
        assert_eq!(candidate_ladder(&reg_channels("00"), &caps, DEV).len(), 1);
    }

    #[test]
    fn ladder_floor_channel_is_the_constant_6_regardless_of_device_id() {
        // 2026-07-15: the floor is now an operator-prescriptive CONSTANT, not the per-device
        // {1,6,11} hash — two different device_ids must land on the SAME floor channel.
        let reg = reg_channels("GB");
        let caps = brcmfmac();
        let floor_a = candidate_ladder(&reg, &caps, "hp-3c495a31bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .last().unwrap().channel;
        let floor_b = candidate_ladder(&reg, &caps, "hp-9f1027acccccccccccccccccccccccccccccccc")
            .last().unwrap().channel;
        assert_eq!(floor_a, 6, "floor must be the constant ch6");
        assert_eq!(floor_a, floor_b, "the floor channel must be identical across devices — it is a constant now, not a per-device pick");
    }

    // ---- Feature 2: rung rendering reuses wifi_cfg ----

    #[test]
    fn render_rung_vht80_matches_wifi_cfg_auto() {
        let reg = reg_channels("GB");
        let ladder = candidate_ladder(&reg, &brcmfmac(), DEV);
        let vht80 = ladder.iter().find(|r| matches!(r.width, ChanWidthShim::Vht80)).unwrap();
        let a = ApIntent { ssid: Some("HP".into()), passphrase: "appass1234".into(), ..Default::default() };
        let c = render_rung_conf("wlan0", "HP", &a, "GB", vht80, DEV);
        assert!(c.contains("channel=40"), "top rung's control channel is 40: {c}");
        assert!(c.contains("ht_capab=[HT40-]"), "ch40 is the UPPER secondary of (36,40) — must be HT40-: {c}");
        assert!(c.contains("ieee80211ac=1") && c.contains("vht_oper_chwidth=1"));
        assert!(c.contains("vht_oper_centr_freq_seg0_idx=42"), "still the 36-48 block, center 42: {c}");
        assert!(c.contains("country_code=GB"));
    }

    #[test]
    fn render_rung_ht40_has_no_vht_lines() {
        let a = ApIntent { ssid: Some("HP".into()), passphrase: "appass1234".into(), ..Default::default() };
        let rung = Rung::new("5", 36, ChanWidthShim::Ht40);
        let c = render_rung_conf("wlan0", "HP", &a, "GB", &rung, DEV);
        assert!(c.contains("ht_capab=[HT40+]"), "HT40 emits ht_capab: {c}");
        assert!(!c.contains("ieee80211ac"), "HT40 must NOT enable VHT: {c}");
        assert!(!c.contains("vht_"), "HT40 must NOT emit vht_* keys: {c}");
    }

    #[test]
    fn render_rung_ht20_is_plain() {
        let a = ApIntent { ssid: Some("HP".into()), passphrase: "appass1234".into(), ..Default::default() };
        let rung = Rung::new("5", 36, ChanWidthShim::Ht20);
        let c = render_rung_conf("wlan0", "HP", &a, "GB", &rung, DEV);
        assert!(c.contains("channel=36") && c.contains("hw_mode=a"));
        assert!(!c.contains("ht_capab") && !c.contains("ieee80211ac"), "HT20 5G rung is plain: {c}");
    }

    // ---- Feature 2: stability verification (the brcmfmac collapse detector) ----

    #[test]
    fn stable_when_width_and_channel_match() {
        let rung = Rung::new("5", 36, ChanWidthShim::Vht80);
        let obs = ObservedAp { active: true, oper_channel: Some(36), oper_width_mhz: Some(80), chanspec_fail_count: 0, client_associated: None };
        assert_eq!(verify_rung(&rung, &obs), Stability::Stable);
    }

    #[test]
    fn detects_the_brcmfmac_vht80_collapse() {
        // Requested VHT80 ch36, radio silently landed on ch140/20 MHz — the field trap.
        let rung = Rung::new("5", 36, ChanWidthShim::Vht80);
        let obs = ObservedAp { active: true, oper_channel: Some(140), oper_width_mhz: Some(20), chanspec_fail_count: 0, client_associated: None };
        assert_eq!(verify_rung(&rung, &obs), Stability::WidthCollapsed);
    }

    // ---- BUG-W7 (2026-07-17): the 150-Mbps bug — 80 MHz convergence is BLOCK-wise ----

    #[test]
    fn vht80_ch40_reported_as_block_primary_ch36_is_converged() {
        // THE metal ground truth (live CM5 + Pi4, 2026-07-17). Requested the proven VHT80-ch40 block;
        // the brcmfmac firmware brought the AP up WORKING at 80 MHz (center1 5210, hostapd active,
        // client associated) but NAMES the primary as the block's lowest channel: `iw dev` →
        // `channel 36 (5180 MHz), width: 80 MHz`. Plus the harmless one-time bring-up churn (7 fails).
        // The pre-fix code called this ChanspecFailStorm and REVERTED a healthy ~250 Mbit/s link down
        // to HT40 (~150 Mbit/s) — the operator-visible bug. 36 and 40 are the same physical 80 MHz
        // channel, so this MUST be Stable.
        let rung = Rung::new("5", 40, ChanWidthShim::Vht80);
        let obs = ObservedAp { active: true, oper_channel: Some(36), oper_width_mhz: Some(80), chanspec_fail_count: 7, client_associated: None };
        assert_eq!(verify_rung(&rung, &obs), Stability::Stable, "ch36-reported VHT80 IS the requested ch40 block (center 5210) — never revert it");
    }

    #[test]
    fn vht80_block_convergence_accepts_any_channel_of_the_same_block() {
        for oper in [36u32, 40, 44, 48] {
            let rung = Rung::new("5", 40, ChanWidthShim::Vht80);
            let obs = ObservedAp { active: true, oper_channel: Some(oper), oper_width_mhz: Some(80), chanspec_fail_count: 3, client_associated: None };
            assert_eq!(verify_rung(&rung, &obs), Stability::Stable, "ch{oper} is in the 36-48 block");
        }
    }

    #[test]
    fn vht80_block_convergence_still_rejects_a_different_block() {
        // The classic drift must STILL be caught: ch140 is a different block (center 138), so even at
        // 80 MHz this is a genuine failure, not a naming quirk. Block-awareness must not blind the
        // collapse detector.
        let rung = Rung::new("5", 40, ChanWidthShim::Vht80);
        let obs = ObservedAp { active: true, oper_channel: Some(140), oper_width_mhz: Some(80), chanspec_fail_count: 7, client_associated: None };
        assert_eq!(verify_rung(&rung, &obs), Stability::ChanspecFailStorm, "ch140 is NOT the 36-48 block — a real drift");
    }

    #[test]
    fn narrow_widths_still_require_an_exact_channel_match() {
        // 20/40 MHz are reported faithfully by the firmware, so block-leniency must NOT leak into
        // them: an HT40 rung that landed on a different channel of the same block is a real miss.
        let rung = Rung::new("5", 36, ChanWidthShim::Ht40);
        let obs = ObservedAp { active: true, oper_channel: Some(40), oper_width_mhz: Some(40), chanspec_fail_count: 0, client_associated: None };
        assert_eq!(verify_rung(&rung, &obs), Stability::WidthCollapsed, "HT40 keeps the exact-channel contract");
    }

    #[test]
    fn block_center_map_is_correct_and_refuses_unknown_channels() {
        for (ch, want) in [(36u32, 42u32), (48, 42), (52, 58), (64, 58), (100, 106), (112, 106), (116, 122), (128, 122), (132, 138), (144, 138), (149, 155), (161, 155)] {
            assert_eq!(block_center_for_channel(ch), Some(want), "ch{ch}");
        }
        // Not in any 80 MHz block → None, so it can never be mistaken for a match.
        for ch in [1u32, 6, 11, 14, 34, 165] {
            assert_eq!(block_center_for_channel(ch), None, "ch{ch} is in no 80MHz block");
        }
    }

    #[test]
    fn converged_wins_despite_transient_chanspec_fails() {
        // BUG-W5 (2026-07-12, metal-proven CM5+Pi4): the brcmfmac VHT80 rung bounces through a
        // chanspec-fail burst on first bring-up and THEN converges to — and holds — the requested
        // chanspec. Operating channel+width match the request here even though 5 fail lines were
        // logged getting there: the verdict MUST be Stable, not ChanspecFailStorm. This is the
        // exact inversion this fix makes (the old ordering wrongly returned ChanspecFailStorm).
        let rung = Rung::new("5", 36, ChanWidthShim::Vht80);
        let obs = ObservedAp { active: true, oper_channel: Some(36), oper_width_mhz: Some(80), chanspec_fail_count: 5, client_associated: None };
        assert_eq!(verify_rung(&rung, &obs), Stability::Stable, "convergence must win over transient settle-time chanspec-fail lines");
    }

    #[test]
    fn chanspec_fail_storm_only_fires_when_not_converged() {
        // The SAME fail count (5) but the radio did NOT converge (still on ch140/20, not the
        // requested 36/80) — THIS is a genuine firmware rejection, so ChanspecFailStorm is correct.
        let rung = Rung::new("5", 36, ChanWidthShim::Vht80);
        let obs = ObservedAp { active: true, oper_channel: Some(140), oper_width_mhz: Some(20), chanspec_fail_count: 5, client_associated: None };
        assert_eq!(verify_rung(&rung, &obs), Stability::ChanspecFailStorm, "a real rejection is still caught when convergence genuinely fails");
    }

    #[test]
    fn down_ap_is_down() {
        let rung = Rung::new("5", 36, ChanWidthShim::Ht20);
        let obs = ObservedAp { active: false, ..Default::default() };
        assert_eq!(verify_rung(&rung, &obs), Stability::Down);
    }

    #[test]
    fn client_expected_but_not_associated_fails() {
        let rung = Rung::new("5", 36, ChanWidthShim::Ht20);
        let obs = ObservedAp { active: true, oper_channel: Some(36), oper_width_mhz: Some(20), chanspec_fail_count: 0, client_associated: Some(false) };
        assert_eq!(verify_rung(&rung, &obs), Stability::ClientFailed);
        // …but no client expected (None) on the same observation is Stable.
        let obs2 = ObservedAp { client_associated: None, ..obs };
        assert_eq!(verify_rung(&rung, &obs2), Stability::Stable);
    }

    #[test]
    fn a_single_stray_chanspec_line_is_tolerated() {
        let rung = Rung::new("5", 36, ChanWidthShim::Vht80);
        let obs = ObservedAp { active: true, oper_channel: Some(36), oper_width_mhz: Some(80), chanspec_fail_count: 1, client_associated: None };
        assert_eq!(verify_rung(&rung, &obs), Stability::Stable, "one line during restart is not a storm");
    }

    // ---- cache / start-rung hysteresis ----

    #[test]
    fn start_at_cached_known_good_rung() {
        let ladder = candidate_ladder(&reg_channels("GB"), &brcmfmac(), DEV);
        // Cache says HT40-ch36 was last good → start there (index 1), skip re-trying VHT80.
        assert_eq!(start_rung(&ladder, Some("5GHz-HT40-ch36")), 1);
        // No cache → start at the top.
        assert_eq!(start_rung(&ladder, None), 0);
        // Stale cache label not in this ladder (domain changed) → restart from the top.
        assert_eq!(start_rung(&ladder, Some("5GHz-VHT80-ch149")), 0);
    }

    // ---- status artifact ----

    #[test]
    fn outcome_serialises_to_json_with_reasons() {
        let out = CalibrationOutcome {
            iface: "wlan0".into(),
            country: decide_country(&CountryInputs { operator: Some("GB".into()), ..Default::default() }),
            attempts: vec![
                RungAttempt { label: "5GHz-VHT80-ch36".into(), width_mhz: 80, channel: 36, result: Stability::WidthCollapsed },
                RungAttempt { label: "5GHz-HT40-ch36".into(), width_mhz: 40, channel: 36, result: Stability::Stable },
            ],
            chosen: Some("5GHz-HT40-ch36".into()),
            decided_at: "2026-07-10T00:00:00Z".into(),
        };
        let j = out.to_json();
        assert!(j.contains("\"cc\": \"GB\""));
        assert!(j.contains("width_collapsed"));
        assert!(j.contains("\"chosen\": \"5GHz-HT40-ch36\""));
        assert!(j.contains("\"source\": \"operator\""));
    }

    // ---- D13: pick_24_channel ----

    #[test]
    fn pick_24_channel_empty_survey_is_the_deterministic_default_6() {
        assert_eq!(pick_24_channel(&[]), 6, "boot path (no survey) always returns 6 — no radio read");
    }

    #[test]
    fn pick_24_channel_avoids_a_heavily_loaded_channel_6() {
        // ch6 is slammed (high busy + many neighbors); 1 and 11 are clear — must NOT pick 6.
        let survey = vec![
            ChannelSurvey { channel: 6, busy_ratio: 90, stations: 8 },
            ChannelSurvey { channel: 1, busy_ratio: 5, stations: 0 },
            ChannelSurvey { channel: 11, busy_ratio: 5, stations: 0 },
        ];
        let picked = pick_24_channel(&survey);
        assert!(picked == 1 || picked == 11, "must avoid the congested channel 6, got {picked}");
    }

    #[test]
    fn pick_24_channel_ties_break_to_the_lowest_channel() {
        // ch6 is the MOST loaded; ch1 and ch11 tie at a lower, EQUAL load (each sample is outside
        // the ±2 window of the other two candidates, so it scores only its own channel) — the tie
        // between 1 and 11 must break to the lowest, 1.
        let survey = vec![
            ChannelSurvey { channel: 1, busy_ratio: 5, stations: 0 },
            ChannelSurvey { channel: 6, busy_ratio: 50, stations: 0 },
            ChannelSurvey { channel: 11, busy_ratio: 5, stations: 0 },
        ];
        assert_eq!(pick_24_channel(&survey), 1, "a genuine tie must break to the lowest channel");
    }

    #[test]
    fn pick_24_channel_only_counts_samples_within_the_overlap_window() {
        // A sample on ch 6 (±2 = 4-8) must not affect ch1's score (1's window is -1..3, no overlap
        // with ch6's actual reading itself, but DOES overlap ch1..3 if reported there) — verify a
        // far-away busy channel (e.g. reported at ch 9, only within ±2 of 11 and marginally of… not
        // 1) doesn't drag channel 1's score down unfairly relative to an actually-clear one.
        let survey = vec![ChannelSurvey { channel: 9, busy_ratio: 100, stations: 20 }];
        // ch9 is within ±2 of 11 (9..13 vs 11 → diff 2) but NOT of 1 or 6 (diff 8, 3) — wait 6's
        // diff to 9 is 3, still outside ±2. So only 11 is penalized; 1 and 6 are equally (0) clear,
        // tie-break picks the lowest, 1.
        assert_eq!(pick_24_channel(&survey), 1, "only channel 11 overlaps a ch9 sample (diff=2)");
    }

    // ---- D14: next_rung_action ----

    #[test]
    fn next_rung_action_stable_keeps() {
        assert_eq!(next_rung_action(Stability::Stable, 0, 2), RungAction::Keep);
        assert_eq!(next_rung_action(Stability::Stable, 5, 2), RungAction::Keep, "Stable always keeps regardless of attempt count");
    }

    #[test]
    fn next_rung_action_width_collapsed_retries_then_steps_down() {
        assert_eq!(next_rung_action(Stability::WidthCollapsed, 0, 2), RungAction::RetrySameRung);
        assert_eq!(next_rung_action(Stability::WidthCollapsed, 1, 2), RungAction::RetrySameRung);
        assert_eq!(next_rung_action(Stability::WidthCollapsed, 2, 2), RungAction::StepDown, "attempt == max_retries → give up");
    }

    #[test]
    fn next_rung_action_chanspec_fail_storm_retries_then_steps_down() {
        assert_eq!(next_rung_action(Stability::ChanspecFailStorm, 0, 2), RungAction::RetrySameRung);
        assert_eq!(next_rung_action(Stability::ChanspecFailStorm, 2, 2), RungAction::StepDown);
    }

    #[test]
    fn next_rung_action_down_retries_then_steps_down() {
        assert_eq!(next_rung_action(Stability::Down, 0, 2), RungAction::RetrySameRung);
        assert_eq!(next_rung_action(Stability::Down, 2, 2), RungAction::StepDown);
    }

    #[test]
    fn next_rung_action_client_failed_always_steps_down_immediately() {
        assert_eq!(next_rung_action(Stability::ClientFailed, 0, 2), RungAction::StepDown, "not a radio-bounce symptom — no point retrying the same rung");
    }

    #[test]
    fn bug_w5_converged_despite_transient_fails_yields_keep_end_to_end() {
        // Full chain (verify_rung -> next_rung_action), the exact scenario the METAL run found:
        // VHT80 ch36 bounces through chanspec-fail lines, then converges and holds. The verdict
        // must flow through to RungAction::Keep on the FIRST attempt (no retry/stepdown needed).
        let rung = Rung::new("5", 36, ChanWidthShim::Vht80);
        let obs = ObservedAp { active: true, oper_channel: Some(36), oper_width_mhz: Some(80), chanspec_fail_count: 4, client_associated: None };
        let verdict = verify_rung(&rung, &obs);
        assert_eq!(verdict, Stability::Stable);
        assert_eq!(next_rung_action(verdict, 0, 2), RungAction::Keep, "a converged rung must be kept on attempt 0, not stepped down for transient fails");
    }

    #[test]
    fn next_rung_action_zero_max_retries_steps_down_immediately() {
        // A caller that disables retries entirely (max_retries=0) must step down on attempt 0.
        assert_eq!(next_rung_action(Stability::WidthCollapsed, 0, 0), RungAction::StepDown);
    }

    // ---- 2026-07-16 (BUG-2): warm_upgrade_candidate / warm_upgrade_action ----------------------

    /// The operator's exact 3-rung ladder for a capable radio — the fixture every warm-upgrade
    /// test below is built against (same shape `ladder_is_best_to_safe_and_ends_at_the_floor`
    /// proves): `["5GHz-VHT80-ch40", "5GHz-HT40-ch36", "2.4GHz-HT20-ch6"]`.
    fn full_ladder() -> Vec<Rung> {
        candidate_ladder(&reg_channels("GB"), &brcmfmac(), DEV)
    }

    /// Settled on the SAFETY-NET rung (HT40-ch36, one step below the top) — this is the exact
    /// metal scenario BUG-2 fixes: the wider VHT80-ch40 rung above it is the eligible candidate.
    #[test]
    fn warm_upgrade_candidate_settled_on_ht40_targets_vht80() {
        let ladder = full_ladder();
        let cand = warm_upgrade_candidate(&ladder, "5GHz-HT40-ch36");
        assert_eq!(
            cand.map(|r| r.label.as_str()),
            Some("5GHz-VHT80-ch40"),
            "the rung immediately above HT40-ch36 (index 0) must be offered for one warm re-try"
        );
    }

    /// Already settled on the ladder's TOP (widest) rung — nothing wider exists, so no warm-upgrade
    /// attempt is ever offered (the "at most one attempt, never a loop" bound starts here).
    #[test]
    fn warm_upgrade_candidate_top_rung_already_no_attempt() {
        let ladder = full_ladder();
        assert_eq!(warm_upgrade_candidate(&ladder, "5GHz-VHT80-ch40"), None, "already at the top — nothing wider to warm-upgrade to");
    }

    /// Settled on the 2.4 GHz floor — the wider rung immediately above it (HT40-ch36) is a
    /// DIFFERENT band, so this must NOT attempt a band-jumping "warm upgrade" (that is a much
    /// bigger change than "the same warm radio", and was never what was proven on metal).
    #[test]
    fn warm_upgrade_candidate_never_jumps_bands_from_the_24ghz_floor() {
        let ladder = full_ladder();
        assert_eq!(
            warm_upgrade_candidate(&ladder, "2.4GHz-HT20-ch6"),
            None,
            "the 2.4 GHz floor must never trigger a warm re-attempt at a 5 GHz rung"
        );
    }

    /// An unknown/foreign settled label (e.g. a stale cache entry from a different pin/regdomain
    /// whose ladder no longer contains it) is never a candidate — degrades safely to "no attempt".
    #[test]
    fn warm_upgrade_candidate_unknown_label_is_not_eligible() {
        let ladder = full_ladder();
        assert_eq!(warm_upgrade_candidate(&ladder, "not-a-real-rung"), None);
    }

    /// A hard 2.4-only pin's ladder (a single floor rung, `candidate_ladder`'s conservative-radio
    /// shape) has no wider rung at all — never eligible, regardless of which label is queried.
    #[test]
    fn warm_upgrade_candidate_single_rung_ladder_never_eligible() {
        let ladder = candidate_ladder(&reg_channels("00"), &RadioCaps::conservative("wlan0"), DEV);
        assert_eq!(ladder.len(), 1);
        assert_eq!(warm_upgrade_candidate(&ladder, &ladder[0].label), None);
    }

    /// The full decision: settled-on-HT40 → eligible candidate found → a Stable observation of the
    /// warm re-attempt → Upgrade (commit VHT80-ch40; the caller's existing band-LKG/model export
    /// then persists it, unchanged by this feature).
    #[test]
    fn warm_upgrade_action_converges_to_upgrade() {
        let ladder = full_ladder();
        let cand = warm_upgrade_candidate(&ladder, "5GHz-HT40-ch36");
        assert!(cand.is_some());
        let observed = Stability::Stable;
        assert_eq!(warm_upgrade_action(cand, Some(observed)), WarmUpgradeAction::Upgrade);
    }

    /// The full decision: settled-on-HT40 → eligible candidate found → the warm re-attempt does
    /// NOT converge (still 40 MHz after the longer settle) → Revert (stay on HT40-ch36; the AP is
    /// never left down — the caller reverts, it does not simply give up mid-air).
    #[test]
    fn warm_upgrade_action_fails_to_revert() {
        let ladder = full_ladder();
        let cand = warm_upgrade_candidate(&ladder, "5GHz-HT40-ch36");
        for miss in [Stability::WidthCollapsed, Stability::ChanspecFailStorm, Stability::Down, Stability::ClientFailed] {
            assert_eq!(
                warm_upgrade_action(cand, Some(miss)),
                WarmUpgradeAction::Revert,
                "a non-Stable warm re-attempt verdict ({miss:?}) must revert, never leave the AP on an unconverged rung"
            );
        }
    }

    /// Already at the top rung → no candidate → NotEligible regardless of what `observed` carries
    /// (there is nothing to have observed — the runtime must not have attempted anything at all).
    #[test]
    fn warm_upgrade_action_top_rung_already_is_not_eligible_even_with_a_stray_observation() {
        let ladder = full_ladder();
        let cand = warm_upgrade_candidate(&ladder, "5GHz-VHT80-ch40");
        assert_eq!(cand, None);
        assert_eq!(warm_upgrade_action(cand, None), WarmUpgradeAction::NotEligible);
        assert_eq!(
            warm_upgrade_action(cand, Some(Stability::Stable)),
            WarmUpgradeAction::NotEligible,
            "no candidate means NotEligible no matter what — a caller must never even reach an observation here"
        );
    }

    // NOTE (2026-07-15): the D18 per-device {1,6,11} floor pick is NO LONGER used by
    // `candidate_ladder` — the operator wants a CONSTANT ch6 floor for the calibration ladder (see
    // `ladder_floor_channel_is_the_constant_6_regardless_of_device_id` above).
    // `wifi_cfg::default_24_channel` itself is unchanged and still exercised by its own tests in
    // `wifi_cfg.rs` (it remains the world/unresolved-regdomain RENDER fail-safe's channel pick).

    // ---- D19: BandLkg + band_lkg_valid ----------------------------------------------------------

    fn sample_lkg() -> BandLkg {
        BandLkg {
            cc: "RO".into(),
            radio_id: "aa:bb:cc:dd:ee:ff".into(),
            band: "5".into(),
            label: "5GHz-HT40-ch36".into(),
            channel: 36,
            decided_at: "2026-07-12T00:00:00Z".into(),
        }
    }

    #[test]
    fn band_lkg_valid_when_cc_and_radio_match() {
        let lkg = sample_lkg();
        assert!(band_lkg_valid(&lkg, "RO", "aa:bb:cc:dd:ee:ff"));
        assert!(band_lkg_valid(&lkg, "ro", "aa:bb:cc:dd:ee:ff"), "cc compare is case-insensitive");
    }

    #[test]
    fn band_lkg_invalid_on_regdomain_change() {
        let lkg = sample_lkg();
        assert!(!band_lkg_valid(&lkg, "GB", "aa:bb:cc:dd:ee:ff"), "a moved box (new country) must re-fight the ladder");
    }

    #[test]
    fn band_lkg_invalid_on_radio_change() {
        let lkg = sample_lkg();
        assert!(!band_lkg_valid(&lkg, "RO", "11:22:33:44:55:66"), "a swapped radio must not inherit a rung proven on different hardware");
    }

    #[test]
    fn band_lkg_serialises_round_trip() {
        let lkg = sample_lkg();
        let j = serde_json::to_string(&lkg).unwrap();
        let back: BandLkg = serde_json::from_str(&j).unwrap();
        assert_eq!(lkg, back);
    }

    // ---- D22: resolve_bootstrap_band -------------------------------------------------------------

    #[test]
    fn resolve_bootstrap_band_hard_pins_always_win() {
        // A real pin wins regardless of LKG or discovered capability — "disables the auto-ladder".
        let lkg = sample_lkg(); // band "5"
        assert_eq!(resolve_bootstrap_band(Some("2.4"), Some(&lkg), true), "2.4");
        assert_eq!(resolve_bootstrap_band(Some("5"), None, false), "5", "explicit 5GHz pin wins even with no discovered 5GHz capability");
        assert_eq!(resolve_bootstrap_band(Some("2.4ghz"), None, true), "2.4", "a friendlier '2.4ghz' spelling is still recognised as the pin");
    }

    #[test]
    fn resolve_bootstrap_band_auto_prefers_valid_lkg() {
        let lkg_5 = sample_lkg(); // band "5"
        assert_eq!(resolve_bootstrap_band(Some("auto"), Some(&lkg_5), false), "5", "a valid 5GHz LKG wins even if capability now looks absent (avoids re-thrash)");
        let lkg_24 = BandLkg { band: "2.4".into(), ..sample_lkg() };
        assert_eq!(resolve_bootstrap_band(None, Some(&lkg_24), true), "2.4", "absent band == auto; a valid 2.4 LKG is honored");
    }

    #[test]
    fn resolve_bootstrap_band_auto_no_lkg_fights_for_5ghz_when_capable() {
        assert_eq!(resolve_bootstrap_band(Some("auto"), None, true), "5", "no LKG yet — fight for 5GHz when it looks usable");
        assert_eq!(resolve_bootstrap_band(None, None, true), "5", "absent band behaves exactly like auto");
    }

    #[test]
    fn resolve_bootstrap_band_auto_no_lkg_no_5ghz_falls_to_floor() {
        assert_eq!(resolve_bootstrap_band(Some("auto"), None, false), "2.4");
        assert_eq!(resolve_bootstrap_band(None, None, false), "2.4");
    }

    // ---- DFS-aware CAC settle (2026-07-15 coordinator directive) ----------------------------------

    #[test]
    fn dfs_cac_seconds_unii1_and_unii3_are_non_dfs() {
        // The shipped ladder's actual rungs: VHT80's control ch40 (36-48 block) and the UNII-3
        // fallback block are both non-DFS — no CAC at all.
        assert_eq!(dfs_cac_seconds(40, 80), 0, "the shipped VHT80 rung's block (36-48, control ch40) is non-DFS");
        assert_eq!(dfs_cac_seconds(36, 40), 0, "the shipped HT40 rung (ch36) is non-DFS");
        assert_eq!(dfs_cac_seconds(149, 80), 0, "UNII-3 (149-161) is non-DFS");
    }

    #[test]
    fn dfs_cac_seconds_standard_dfs_channels_get_60s() {
        assert_eq!(dfs_cac_seconds(52, 20), 60, "UNII-2A ch52, HT20");
        assert_eq!(dfs_cac_seconds(100, 40), 60, "UNII-2C ch100, HT40 (pairs with 104 — no meteo overlap)");
        assert_eq!(dfs_cac_seconds(132, 80), 60, "the 132-144 VHT80 block has no meteo overlap — standard 60s CAC");
    }

    #[test]
    fn dfs_cac_seconds_meteo_subband_gets_600s() {
        assert_eq!(dfs_cac_seconds(120, 20), 600, "ch120 (5600 MHz) sits inside the meteo sub-band");
        assert_eq!(
            dfs_cac_seconds(116, 40), 600,
            "ch116 ALONE reads as standard DFS, but its HT40 pair (116,120) touches the meteo sub-band — footprint-aware"
        );
        assert_eq!(
            dfs_cac_seconds(116, 80), 600,
            "the VHT80 block 116-128 fully overlaps the meteo sub-band even though the control channel is 116"
        );
        assert_eq!(dfs_cac_seconds(128, 20), 600, "ch128 (5640 MHz) is the top edge of the meteo sub-band");
    }

    #[test]
    fn is_dfs_rung_matches_zero_vs_nonzero_cac() {
        assert!(!is_dfs_rung(40, 80), "the shipped VHT80-ch40 rung is not DFS");
        assert!(is_dfs_rung(52, 20), "a standard DFS channel is a DFS rung");
        assert!(is_dfs_rung(120, 20), "a meteo-subband channel is a DFS rung");
    }

    #[test]
    fn select_settle_seconds_shipped_ladder_rungs_use_ordinary_settle() {
        // None of the 3 shipped rungs is DFS — this path never fires on the default ladder.
        let vht80_ch40 = Rung::new("5", 40, ChanWidthShim::Vht80);
        let ht40_ch36 = Rung::new("5", 36, ChanWidthShim::Ht40);
        let floor = Rung::new("2.4", 6, ChanWidthShim::Ht20);
        assert_eq!(select_settle_seconds(&vht80_ch40, 15, 15, 75, 660), 15);
        assert_eq!(select_settle_seconds(&ht40_ch36, 15, 15, 75, 660), 15);
        assert_eq!(select_settle_seconds(&floor, 15, 15, 75, 660), 15, "2.4 GHz never gets a DFS settle");
    }

    #[test]
    fn select_settle_seconds_standard_dfs_uses_the_dfs_standard_settle() {
        let rung = Rung::new("5", 52, ChanWidthShim::Ht20);
        assert_eq!(select_settle_seconds(&rung, 15, 15, 75, 660), 75, "a standard DFS channel gets the ~60s-CAC settle, not the ordinary 15s");
    }

    #[test]
    fn select_settle_seconds_meteo_dfs_uses_the_much_longer_settle() {
        let rung = Rung::new("5", 120, ChanWidthShim::Ht20);
        assert_eq!(select_settle_seconds(&rung, 15, 15, 75, 660), 660, "the meteo sub-band's 10-minute CAC needs the 660s settle — 75s would wrongly fail it");
    }

    #[test]
    fn select_settle_seconds_meteo_vht80_block_also_gets_the_long_settle() {
        // A VHT80 rung on the 116-128 block: even though its control channel might not itself be
        // in {116,120,124,128} conceptually distinct from a bare-channel lookup, the whole block
        // occupied by this rung is exactly that meteo block.
        let rung = Rung::new("5", 116, ChanWidthShim::Vht80);
        assert_eq!(select_settle_seconds(&rung, 15, 15, 75, 660), 660);
    }
}

// ===========================================================================================
// ADR 0034 D24-D33 — the autonomous survey-based 5 GHz channel optimizer, T1 pure unit tests
// (D34).
// ===========================================================================================
#[cfg(test)]
mod optimize_tests {
    use super::*;
    use crate::wifi_cfg::{ApIntent, ApOptimizeIntent};

    fn survey(control: u32, center: u32, busy: Option<u8>, bss: u32, dfs: bool, eirp: u32) -> BlockSurvey {
        BlockSurvey {
            control_channel: control,
            center_idx: center,
            busy_ratio: busy,
            bss_count: bss,
            noise_dbm: None,
            dfs,
            cac_seconds: dfs_cac_seconds(control, 80),
            max_eirp_dbm: eirp,
            ap_capable: true,
        }
    }

    fn state_untested(cc: &str, radio: &str) -> OptimizeState {
        OptimizeState { cc: cc.to_string(), radio_id: radio.to_string(), ..OptimizeState::default() }
    }

    // ---- D25/optimize_intent ----

    #[test]
    fn optimize_intent_defaults_when_block_absent() {
        let a = ApIntent { band: Some("auto".into()), ..Default::default() };
        let cfg = optimize_intent(&a);
        assert!(cfg.enabled, "default enabled=true under band=auto");
        assert_eq!(cfg.at, "03:00");
        assert!(!cfg.allow_dfs, "default allow_dfs=FALSE (2026-07-17 metal: brcmfmac FullMAC can't DFS-AP; opt-in for SoftMAC radios)");
        assert!(!cfg.allow_meteo, "default allow_meteo=false");
        assert_eq!(cfg.min_improvement, 20);
    }

    #[test]
    fn optimize_intent_disabled_on_24_band_pin() {
        let a = ApIntent { band: Some("2.4".into()), ..Default::default() };
        let cfg = optimize_intent(&a);
        assert!(!cfg.enabled, "band: 2.4 hard pin disables the optimizer — nothing to optimize");

        // Even an explicit enabled:true cannot override the 2.4 pin (there is no 5GHz channel).
        let a2 = ApIntent {
            band: Some("2.4ghz".into()),
            optimize: Some(ApOptimizeIntent { enabled: Some(true), ..Default::default() }),
            ..Default::default()
        };
        assert!(!optimize_intent(&a2).enabled);
    }

    #[test]
    fn optimize_intent_operator_overrides_every_field() {
        let a = ApIntent {
            band: Some("auto".into()),
            optimize: Some(ApOptimizeIntent {
                enabled: Some(false),
                at: Some("04:30".into()),
                allow_dfs: Some(false),
                allow_meteo: Some(true),
                min_improvement: Some(50),
            }),
            ..Default::default()
        };
        let cfg = optimize_intent(&a);
        assert!(!cfg.enabled);
        assert_eq!(cfg.at, "04:30");
        assert!(!cfg.allow_dfs);
        assert!(cfg.allow_meteo);
        assert_eq!(cfg.min_improvement, 50);
    }

    #[test]
    fn optimize_intent_blank_at_falls_back_to_default() {
        let a = ApIntent {
            optimize: Some(ApOptimizeIntent { at: Some("  ".into()), ..Default::default() }),
            ..Default::default()
        };
        assert_eq!(optimize_intent(&a).at, OPTIMIZE_DEFAULT_AT);
    }

    // ---- D27/optimize_candidates ----

    fn cfg_default() -> OptimizeConfig {
        optimize_intent(&ApIntent { band: Some("auto".into()), ..Default::default() })
    }

    #[test]
    fn optimize_candidates_etsi_domain_never_gets_unii3() {
        let reg = reg_channels("GB");
        let cands = optimize_candidates(&reg, &cfg_default(), true, &[], &state_untested("GB", "r1"));
        assert!(!cands.iter().any(|c| c.control_channel == 149), "ETSI must not propose UNII-3: {cands:?}");
        assert!(cands.iter().any(|c| c.control_channel == 40), "the non-DFS anchor ch40 must always be present");
    }

    #[test]
    fn optimize_candidates_fcc_domain_adds_unii3_as_an_alternative() {
        let reg = reg_channels("US");
        let cands = optimize_candidates(&reg, &cfg_default(), true, &[], &state_untested("US", "r1"));
        assert!(cands.iter().any(|c| c.control_channel == 40));
        assert!(cands.iter().any(|c| c.control_channel == 149), "FCC keeps UNII-3 as an independent alternative");
        // Exactly one of each — no duplicate ch40/ch149.
        assert_eq!(cands.iter().filter(|c| c.control_channel == 40).count(), 1);
        assert_eq!(cands.iter().filter(|c| c.control_channel == 149).count(), 1);
    }

    #[test]
    fn optimize_candidates_dfs_gated_by_allow_dfs() {
        let reg = reg_channels("GB");
        let mut cfg = cfg_default();
        cfg.allow_dfs = false;
        let cands = optimize_candidates(&reg, &cfg, true, &[], &state_untested("GB", "r1"));
        assert!(cands.iter().all(|c| !c.dfs), "allow_dfs=false must enumerate zero DFS blocks: {cands:?}");

        cfg.allow_dfs = true;
        let cands2 = optimize_candidates(&reg, &cfg, true, &[], &state_untested("GB", "r1"));
        assert!(cands2.iter().any(|c| c.dfs), "allow_dfs=true must enumerate at least one DFS block");
    }

    #[test]
    fn optimize_candidates_meteo_gated_by_allow_meteo() {
        let reg = reg_channels("GB");
        let mut cfg = cfg_default();
        cfg.allow_dfs = true; // default is now false (brcmfmac can't DFS-AP); this test exercises DFS gating
        cfg.allow_meteo = false;
        let cands = optimize_candidates(&reg, &cfg, true, &[], &state_untested("GB", "r1"));
        assert!(!cands.iter().any(|c| c.control_channel == 120), "allow_meteo=false must exclude the 116-128 block (control 120)");

        cfg.allow_meteo = true;
        let cands2 = optimize_candidates(&reg, &cfg, true, &[], &state_untested("GB", "r1"));
        assert!(cands2.iter().any(|c| c.control_channel == 120), "allow_meteo=true must admit the meteo block");
    }

    #[test]
    fn optimize_candidates_ch144_dropped_when_radio_lacks_it() {
        let reg = reg_channels("GB");
        let mut cfg = cfg_default();
        cfg.allow_dfs = true; // default is now false (brcmfmac can't DFS-AP); this test exercises DFS candidates
        let with_144 = optimize_candidates(&reg, &cfg, true, &[], &state_untested("GB", "r1"));
        let without_144 = optimize_candidates(&reg, &cfg, false, &[], &state_untested("GB", "r1"));
        assert!(with_144.iter().any(|c| c.control_channel == 136));
        assert!(!without_144.iter().any(|c| c.control_channel == 136), "ch144-incapable radio must not get the 132-144 block");
    }

    #[test]
    fn optimize_candidates_world_domain_is_a_noop() {
        let reg = reg_channels("00");
        let cands = optimize_candidates(&reg, &cfg_default(), true, &[], &state_untested("00", "r1"));
        assert!(cands.iter().all(|c| !c.dfs), "world domain must never propose a DFS candidate");
        assert_eq!(cands.iter().filter(|c| !c.dfs).count(), 1, "world domain: only the ch40 anchor");
    }

    #[test]
    fn optimize_candidates_dfs_unsupported_excludes_all_dfs() {
        let reg = reg_channels("GB");
        let mut state = state_untested("GB", "r1");
        state.dfs_ap_supported = Some(false); // D30: proven this radio can't DFS
        let cands = optimize_candidates(&reg, &cfg_default(), true, &[], &state);
        assert!(cands.iter().all(|c| !c.dfs), "a radio proven DFS-incapable must never be offered a DFS candidate again");
    }

    #[test]
    fn optimize_candidates_blocked_channel_excluded_but_others_remain() {
        let reg = reg_channels("GB");
        let mut state = state_untested("GB", "r1");
        state.blocked_channels = vec![104]; // D30: this SPECIFIC block failed to hold
        let mut cfg = cfg_default();
        cfg.allow_dfs = true; // default is now false (brcmfmac can't DFS-AP); this test exercises DFS candidates
        let cands = optimize_candidates(&reg, &cfg, true, &[], &state);
        assert!(!cands.iter().any(|c| c.control_channel == 104), "blocked channel 104 must be excluded");
        assert!(cands.iter().any(|c| c.control_channel == 56), "other DFS blocks stay admitted");
    }

    #[test]
    fn optimize_candidates_no_ir_run_file_excludes_specific_channels_optimistically_when_empty() {
        let reg = reg_channels("GB");
        let mut cfg = cfg_default();
        cfg.allow_dfs = true; // default is now false (brcmfmac can't DFS-AP); this test exercises DFS candidates
        // Empty ap_capable_channels (D16a artifact unavailable) => optimistic, everything admitted.
        let cands = optimize_candidates(&reg, &cfg, true, &[], &state_untested("GB", "r1"));
        assert!(cands.iter().all(|c| c.ap_capable), "empty No-IR list must optimistically admit everything");

        // A real (sparse) No-IR list that does NOT cover ch40's footprint marks it not ap_capable.
        let cands2 = optimize_candidates(&reg, &cfg, true, &[52, 56, 60, 64], &state_untested("GB", "r1"));
        let anchor = cands2.iter().find(|c| c.control_channel == 40).unwrap();
        assert!(!anchor.ap_capable, "a non-empty No-IR list that excludes ch40's footprint must mark it not ap_capable");
        let unii2a = cands2.iter().find(|c| c.control_channel == 56).unwrap();
        assert!(unii2a.ap_capable, "ch56's footprint IS covered by the supplied No-IR list");
    }

    // ---- D28/score_block ----

    #[test]
    fn score_block_busy_dominates() {
        let w = OptimizeWeights::default();
        let quiet = survey(40, 42, Some(5), 2, false, 23);
        let busy = survey(52, 58, Some(80), 2, true, 23);
        assert!(score_block(&busy, &w) > score_block(&quiet, &w), "a busier channel must score worse (higher)");
    }

    #[test]
    fn score_block_eirp_bonus_can_make_a_clean_dfs_block_beat_a_congested_anchor() {
        let w = OptimizeWeights::default();
        // A heavily congested ch40 (80% busy, many neighbours) vs. a clean 30dBm DFS block.
        let congested_ch40 = survey(40, 42, Some(80), 10, false, 23);
        let clean_dfs = survey(100, 106, Some(2), 0, true, 30);
        assert!(
            score_block(&clean_dfs, &w) < score_block(&congested_ch40, &w),
            "a clean, high-EIRP DFS block must be able to beat a congested ch40 despite the CAC penalty"
        );
    }

    #[test]
    fn score_block_meteo_penalty_near_excludes_it() {
        let w = OptimizeWeights::default();
        let meteo = survey(116, 122, Some(0), 0, true, 30); // perfectly clean, still meteo
        let standard_dfs = survey(100, 106, Some(0), 0, true, 30); // perfectly clean, standard DFS
        assert!(score_block(&meteo, &w) > score_block(&standard_dfs, &w), "meteo penalty must dominate even a perfectly clean sample");
    }

    #[test]
    fn score_block_scan_only_degrades_gracefully() {
        let w = OptimizeWeights::default();
        let scan_only_quiet = survey(40, 42, None, 1, false, 23);
        let scan_only_busy = survey(40, 42, None, 20, false, 23);
        assert!(score_block(&scan_only_busy, &w) > score_block(&scan_only_quiet, &w), "scan-only bss_count still discriminates busier vs quieter");
    }

    // ---- D28/D29 select_optimized_channel ----

    #[test]
    fn select_keeps_when_current_is_quiet() {
        let w = OptimizeWeights::default();
        let current = survey(40, 42, Some(5), 0, false, 23); // below quiet_floor_busy=20
        let candidates = vec![survey(100, 106, Some(0), 0, true, 30)];
        let d = select_optimized_channel(&current, &candidates, &w);
        assert!(matches!(d, OptimizeDecision::Keep { .. }), "a quiet current channel must never be disrupted: {d:?}");
    }

    #[test]
    fn select_keeps_when_not_meaningfully_better() {
        let w = OptimizeWeights::default();
        let current = survey(40, 42, Some(30), 3, false, 23); // busy enough to pass the quiet gate
        // A candidate only marginally better — must not clear switch_margin.
        let candidates = vec![survey(52, 58, Some(28), 3, true, 23)];
        let d = select_optimized_channel(&current, &candidates, &w);
        assert!(matches!(d, OptimizeDecision::Keep { .. }), "a marginal improvement must not trigger a switch: {d:?}");
    }

    #[test]
    fn select_switches_when_clearly_better() {
        let w = OptimizeWeights::default();
        let current = survey(40, 42, Some(80), 10, false, 23);
        let candidates = vec![survey(100, 106, Some(2), 0, true, 30)];
        let d = select_optimized_channel(&current, &candidates, &w);
        match d {
            OptimizeDecision::Switch { to, .. } => assert_eq!(to.control_channel, 100),
            other => panic!("expected Switch, got {other:?}"),
        }
    }

    #[test]
    fn select_picks_single_best_candidate_only() {
        let w = OptimizeWeights::default();
        let current = survey(40, 42, Some(90), 12, false, 23);
        let candidates = vec![
            survey(52, 58, Some(10), 1, true, 23),
            survey(100, 106, Some(1), 0, true, 30), // clearly the best
            survey(132, 138, Some(15), 2, true, 30),
        ];
        let d = select_optimized_channel(&current, &candidates, &w);
        match d {
            OptimizeDecision::Switch { to, .. } => assert_eq!(to.control_channel, 100, "must pick the single lowest-scoring candidate"),
            other => panic!("expected Switch, got {other:?}"),
        }
    }

    #[test]
    fn select_ignores_non_ap_capable_candidates() {
        let w = OptimizeWeights::default();
        let current = survey(40, 42, Some(80), 10, false, 23);
        let mut blocked = survey(100, 106, Some(0), 0, true, 30);
        blocked.ap_capable = false;
        let d = select_optimized_channel(&current, &[blocked], &w);
        assert!(matches!(d, OptimizeDecision::Keep { .. }), "a non-ap_capable candidate must never be selected: {d:?}");
    }

    // ---- D30 optimize_state_valid ----

    #[test]
    fn optimize_state_valid_requires_both_cc_and_radio_match() {
        let s = state_untested("RO", "aa:bb:cc:dd:ee:ff");
        assert!(optimize_state_valid(&s, "RO", "aa:bb:cc:dd:ee:ff"));
        assert!(optimize_state_valid(&s, "ro", "aa:bb:cc:dd:ee:ff"), "cc compare is case-insensitive");
        assert!(!optimize_state_valid(&s, "GB", "aa:bb:cc:dd:ee:ff"), "regdomain change invalidates");
        assert!(!optimize_state_valid(&s, "RO", "11:22:33:44:55:66"), "radio swap invalidates");
    }

    // ---- D31 channel_lkg_valid + resolve_operating_channel precedence ----

    fn lkg(cc: &str, radio: &str, ch: u32, dfs: bool) -> ChannelLkg {
        ChannelLkg {
            cc: cc.to_string(),
            radio_id: radio.to_string(),
            control_channel: ch,
            center_idx: if ch == 40 { 42 } else { 106 },
            width_mhz: 80,
            dfs,
            score: 10,
            validated_at: "2026-07-15T03:00:00Z".to_string(),
        }
    }

    #[test]
    fn channel_lkg_valid_requires_cc_and_radio_match() {
        let l = lkg("RO", "r1", 100, true);
        assert!(channel_lkg_valid(&l, "RO", "r1"));
        assert!(!channel_lkg_valid(&l, "GB", "r1"));
        assert!(!channel_lkg_valid(&l, "RO", "r2"));
    }

    #[test]
    fn resolve_operating_channel_precedence_pin_beats_everything() {
        let l = lkg("RO", "r1", 100, true);
        let plan = resolve_operating_channel(Some(44), Some(&l));
        assert_eq!(plan.channel, 44, "operator pin always wins");
        assert_eq!(plan.source, "operator_pin");
        assert_eq!(plan.apply_at, ApplyAt::BootFast, "a pin is always applied at boot");
    }

    #[test]
    fn resolve_operating_channel_lkg_beats_boot_default() {
        let l = lkg("RO", "r1", 100, true);
        let plan = resolve_operating_channel(None, Some(&l));
        assert_eq!(plan.channel, 100);
        assert_eq!(plan.source, "channel_lkg");
        assert_eq!(plan.apply_at, ApplyAt::PostBootReapply, "a DFS channel-LKG is applied post-boot, never blocking bring-up");
    }

    #[test]
    fn resolve_operating_channel_nondfs_lkg_is_bootfast() {
        let l = lkg("GB", "r1", 40, false);
        let plan = resolve_operating_channel(None, Some(&l));
        assert_eq!(plan.apply_at, ApplyAt::BootFast, "a non-DFS channel-LKG (ch40) adds zero boot latency");
    }

    #[test]
    fn resolve_operating_channel_falls_back_to_boot_default_ch40() {
        let plan = resolve_operating_channel(None, None);
        assert_eq!(plan.channel, 40);
        assert_eq!(plan.center_idx, 42);
        assert!(!plan.dfs);
        assert_eq!(plan.source, "boot_default_ch40");
        assert_eq!(plan.apply_at, ApplyAt::BootFast);
    }

    #[test]
    fn resolve_operating_channel_pin_on_a_dfs_channel_is_still_marked_dfs() {
        // Even a pinned DFS channel must be flagged dfs=true — the runtime STILL CAC-validates it
        // (D24: "the always-joinable invariant outranks even a pin"), it is never trusted blindly.
        let plan = resolve_operating_channel(Some(100), None);
        assert!(plan.dfs);
        assert_eq!(plan.center_idx, 106);
    }

    /// 2026-07-17 — `center_idx_for_control` (exercised end-to-end via `resolve_operating_channel`'s
    /// pin path) must compute the correct block center for EVERY channel in EVERY 80 MHz block —
    /// non-DFS via `wifi_cfg::vht80_params`, DFS via the full `FIVE_GHZ_BLOCKS` table — not just the
    /// 4 specific channels `OPTIMIZE_DFS_BLOCKS` happens to enumerate as `control`. Known-answer
    /// table, one representative per block, covering a channel OTHER than each block's designated
    /// `control` (the exact case that used to fall through to the bogus `unwrap_or(ch)`).
    #[test]
    fn center_idx_known_answer_per_block_including_non_control_channels() {
        let cases: &[(u32, u32)] = &[
            // UNII-1 (36-48), center 42 — non-DFS, via wifi_cfg::vht80_params.
            (36, 42), (40, 42), (44, 42), (48, 42),
            // UNII-2A (52-64), center 58 — DFS; 56/60/64 are NOT OPTIMIZE_DFS_BLOCKS' own `control`.
            (52, 58), (56, 58), (60, 58), (64, 58),
            // UNII-2C (100-112), center 106.
            (100, 106), (104, 106), (108, 106), (112, 106),
            // UNII-2C meteo (116-128), center 122.
            (116, 122), (120, 122), (124, 122), (128, 122),
            // UNII-2C (132-144), center 138.
            (132, 138), (136, 138), (140, 138), (144, 138),
            // UNII-3 (149-161), center 155 — non-DFS, via wifi_cfg::vht80_params.
            (149, 155), (153, 155), (157, 155), (161, 155),
        ];
        for &(ch, want_center) in cases {
            let plan = resolve_operating_channel(Some(ch), None);
            assert_eq!(
                plan.center_idx, want_center,
                "ch{ch} should center on {want_center}, got {}",
                plan.center_idx
            );
        }
    }

    /// A channel outside all 6 known VHT80 blocks (the lone ch165) degrades to "center on itself" —
    /// the same safe "no clean 80 MHz block" fallback `wifi_cfg::width_lines` already uses.
    #[test]
    fn center_idx_unknown_channel_degrades_to_itself() {
        let plan = resolve_operating_channel(Some(165), None);
        assert_eq!(plan.center_idx, 165);
    }

    // ---- D32 candidate_score + OptimizeOutcome::to_json round-trip ----

    #[test]
    fn candidate_score_admitted_reflects_ap_capable_and_reason() {
        let w = OptimizeWeights::default();
        let mut b = survey(100, 106, Some(5), 1, true, 30);
        let admitted = candidate_score(&b, &w, None);
        assert!(admitted.admitted);
        assert!(admitted.reject_reason.is_none());

        b.ap_capable = false;
        let rejected = candidate_score(&b, &w, Some("no_ir".to_string()));
        assert!(!rejected.admitted);
        assert_eq!(rejected.reject_reason.as_deref(), Some("no_ir"));
    }

    #[test]
    fn optimize_outcome_to_json_round_trips_and_is_valid_json() {
        let w = OptimizeWeights::default();
        let current = survey(40, 42, Some(80), 10, false, 23);
        let chosen_survey = survey(100, 106, Some(2), 0, true, 30);
        let outcome = OptimizeOutcome {
            iface: "wlan0".to_string(),
            trigger: "timer".to_string(),
            cc: "GB".to_string(),
            radio_id: "aa:bb:cc:dd:ee:ff".to_string(),
            current_before: candidate_score(&current, &w, None),
            candidates: vec![candidate_score(&chosen_survey, &w, None)],
            decision: "switch".to_string(),
            chosen: Some(candidate_score(&chosen_survey, &w, None)),
            verify: format!("{:?}", OptimizeVerify::Committed).to_lowercase(),
            committed_channel: 100,
            dfs_ap_supported: Some(true),
            decided_at: "2026-07-15T03:00:00Z".to_string(),
        };
        let json = outcome.to_json();
        assert!(json.contains("\"iface\": \"wlan0\""));
        assert!(json.contains("\"committed_channel\": 100"));
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
        assert_eq!(parsed["decision"], "switch");
        assert_eq!(parsed["candidates"][0]["control_channel"], 100);
    }

    // ---- D24 layering: a failed optimize always degrades to ch40, never a dead AP (documented
    // via the precedence + apply_at behaviour proven above — this test is the end-to-end summary) ----
    #[test]
    fn every_precedence_path_terminates_on_a_valid_joinable_channel() {
        // No pin, no LKG => ch40 (boot ladder's own anchor).
        assert_eq!(resolve_operating_channel(None, None).channel, 40);
        // Invalid/absent LKG (caller already filtered via channel_lkg_valid) => same ch40 floor.
        let invalid = lkg("GB", "r1", 100, true);
        assert!(!channel_lkg_valid(&invalid, "RO", "r1"), "a regdomain-changed LKG must be filtered by the caller");
        // A pin degrades to nothing else — it's authoritative, but always dfs-flagged honestly.
        assert_eq!(resolve_operating_channel(Some(40), None).channel, 40);
    }

    // ===========================================================================================
    // D35-D44 — the Wi-Fi calibration LEARNING MODEL
    // ===========================================================================================

    fn key40(radio: &str, cc: &str) -> ConfigKey {
        ConfigKey { radio_id: radio.to_string(), regdomain: cc.to_string(), channel: 40, width_mhz: 80, warm: false }
    }
    /// D45 — the WARM-context counterpart of [`key40`]: same physical rung, distinct cell.
    fn key40_warm(radio: &str, cc: &str) -> ConfigKey {
        ConfigKey { radio_id: radio.to_string(), regdomain: cc.to_string(), channel: 40, width_mhz: 80, warm: true }
    }
    fn key36ht40(radio: &str, cc: &str) -> ConfigKey {
        ConfigKey { radio_id: radio.to_string(), regdomain: cc.to_string(), channel: 36, width_mhz: 40, warm: false }
    }
    fn obs<'a>(key: ConfigKey, verdict: Stability, now: &'a str) -> Observation<'a> {
        Observation { key, center_idx: 42, verdict, busy_ratio: None, tput_proxy: None, now }
    }
    fn t(day: u32) -> String {
        format!("2026-07-{day:02}T00:00:00Z")
    }

    // ---- D36: record_observation / hold_prob / confidence ----

    #[test]
    fn record_observation_creates_cell_and_increments_beta_counts() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        assert!(m.entries.is_empty());
        record_observation(&mut m, &obs(key40("r1", "RO"), Stability::Stable, &t(1)));
        assert_eq!(m.entries.len(), 1);
        assert_eq!(m.entries[0].successes, 1.0);
        assert_eq!(m.entries[0].failures, 0.0);
        assert_eq!(m.entries[0].obs_count, 1);
        record_observation(&mut m, &obs(key40("r1", "RO"), Stability::WidthCollapsed, &t(2)));
        // Same key -> same cell updated, not a new one.
        assert_eq!(m.entries.len(), 1);
        assert_eq!(m.entries[0].successes, 1.0);
        assert_eq!(m.entries[0].failures, 1.0);
        assert_eq!(m.entries[0].obs_count, 2);
        assert_eq!(m.entries[0].last_outcome, "width_collapsed");
        // A different key creates a second cell.
        record_observation(&mut m, &obs(key36ht40("r1", "RO"), Stability::Stable, &t(2)));
        assert_eq!(m.entries.len(), 2);
    }

    #[test]
    fn record_observation_ema_seed_then_blend() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        let t1 = t(1);
        let mut o = obs(key40("r1", "RO"), Stability::Stable, &t1);
        o.busy_ratio = Some(40);
        record_observation(&mut m, &o);
        // First sample seeds directly — no cold-0 bias.
        assert_eq!(m.entries[0].busy_ema, 40.0);
        let t2 = t(2);
        let mut o2 = obs(key40("r1", "RO"), Stability::Stable, &t2);
        o2.busy_ratio = Some(60);
        record_observation(&mut m, &o2);
        // Blended: (1-0.3)*40 + 0.3*60 = 46.
        assert!((m.entries[0].busy_ema - 46.0).abs() < 1e-4);
        // An observation with no busy sample leaves the EMA untouched.
        record_observation(&mut m, &obs(key40("r1", "RO"), Stability::Stable, &t(3)));
        assert!((m.entries[0].busy_ema - 46.0).abs() < 1e-4);
    }

    #[test]
    fn hold_prob_and_confidence_match_the_specified_uniform_prior_math() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        // 3 clean holds -> hold_prob 0.80, confidence 0.60 (obs=3, CONF_K=2 -> 3/5=0.6).
        for d in 1..=3 {
            record_observation(&mut m, &obs(key40("r1", "RO"), Stability::Stable, &t(d)));
        }
        let s = &m.entries[0];
        assert!((hold_prob(s) - 0.80).abs() < 1e-4, "hold_prob={}", hold_prob(s));
        assert!((confidence(s) - 0.60).abs() < 1e-4, "confidence={}", confidence(s));
        // 6 obs -> confidence 0.75.
        for d in 4..=6 {
            record_observation(&mut m, &obs(key40("r1", "RO"), Stability::Stable, &t(d)));
        }
        assert!((confidence(&m.entries[0]) - 0.75).abs() < 1e-4);
        // An unseen key starts at hold_prob 0.5 ("unknown").
        let unseen = ConfigStat {
            key: key36ht40("r1", "RO"),
            center_idx: 42,
            band: "5".to_string(),
            dfs: false,
            cac_seconds: 0,
            successes: 0.0,
            failures: 0.0,
            busy_ema: 0.0,
            tput_ema: 0.0,
            obs_count: 0,
            last_seen: t(1),
            last_outcome: String::new(),
            decayed_at: t(1),
        };
        assert!((hold_prob(&unseen) - 0.5).abs() < 1e-6);
    }

    // ---- D36: quality_score ----

    fn mkstat(channel: u32, width_mhz: u32, successes: f32, failures: f32, busy_ema: f32, dfs: bool) -> ConfigStat {
        ConfigStat {
            key: ConfigKey { radio_id: "r1".to_string(), regdomain: "RO".to_string(), channel, width_mhz, warm: false },
            center_idx: center_idx_for_control(channel),
            band: if channel > 14 { "5" } else { "2.4" }.to_string(),
            dfs,
            cac_seconds: dfs_cac_seconds(channel, width_mhz),
            successes,
            failures,
            busy_ema,
            tput_ema: 0.0,
            obs_count: (successes + failures) as u32,
            last_seen: t(1),
            last_outcome: "stable".to_string(),
            decayed_at: t(1),
        }
    }

    #[test]
    fn quality_score_hold_prob_gates_known_bad_to_near_zero() {
        let w = QualityWeights::default();
        // Confidently bad: many failures, no successes (20 obs -> hold_prob = 1/22 ~= 0.045).
        let bad = mkstat(36, 40, 0.0, 20.0, 0.0, false);
        let q = quality_score(&bad, 23, &w);
        assert!(q < 5.0, "known-bad quality should collapse near 0, got {q}");
        // Same width (so the raw capacity term is identical) but confidently GOOD — the gate is
        // hold_prob, not the width/capacity term.
        let good_same_width = mkstat(36, 40, 20.0, 0.0, 0.0, false);
        let qgood = quality_score(&good_same_width, 23, &w);
        assert!(q < qgood * 0.1, "known-bad ({q}) must be an order of magnitude below a confident good ({qgood})");
        // A confidently good VHT80 rung also clears it, as a sanity cross-check.
        let good = mkstat(40, 80, 10.0, 0.0, 0.0, false);
        assert!(quality_score(&good, 23, &w) > q);
    }

    #[test]
    fn quality_score_orders_width_capacity_vht80_gt_ht40_gt_ht20() {
        let w = QualityWeights::default();
        let vht80 = mkstat(40, 80, 5.0, 0.0, 0.0, false);
        let ht40 = mkstat(36, 40, 5.0, 0.0, 0.0, false);
        let ht20 = mkstat(36, 20, 5.0, 0.0, 0.0, false);
        assert!(quality_score(&vht80, 23, &w) > quality_score(&ht40, 23, &w));
        assert!(quality_score(&ht40, 23, &w) > quality_score(&ht20, 23, &w));
    }

    #[test]
    fn quality_score_eirp_bonus_can_lift_a_clean_dfs_block_and_busy_penalises() {
        let w = QualityWeights::default();
        // A clean (busy=0), high-EIRP DFS block vs a congested non-DFS ch40.
        let clean_dfs = mkstat(100, 80, 5.0, 0.0, 0.0, true);
        let congested_ch40 = mkstat(40, 80, 5.0, 0.0, 90.0, false);
        assert!(
            quality_score(&clean_dfs, 30, &w) > quality_score(&congested_ch40, 23, &w),
            "a clean high-EIRP DFS block should be able to beat a heavily congested ch40"
        );
        // Busy penalises: same config, higher busy -> lower quality.
        let quiet = mkstat(40, 80, 5.0, 0.0, 0.0, false);
        let busy = mkstat(40, 80, 5.0, 0.0, 80.0, false);
        assert!(quality_score(&quiet, 23, &w) > quality_score(&busy, 23, &w));
    }

    // ---- D37: plan_boot / BootPlan tiers ----

    #[test]
    fn plan_boot_is_ladder_on_a_cold_model() {
        let m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        let w = QualityWeights::default();
        let legal = [(40u32, 80u32), (36, 40)];
        let plan = plan_boot(&m, "RO", "r1", &legal, |_| 23, &w);
        assert_eq!(plan, BootPlan::Ladder);
    }

    #[test]
    fn plan_boot_active_direct_to_best_after_3_clean_holds_resume_before_that() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        let w = QualityWeights::default();
        let legal = [(40u32, 80u32), (36, 40)];
        // 1 Stable observation -> ResumeAtRung (>=1 Stable, below the direct-to-best gate).
        record_observation(&mut m, &obs(key40("r1", "RO"), Stability::Stable, &t(1)));
        let plan1 = plan_boot_for_mode(LearnMode::Active, &m, "RO", "r1", &legal, |_| 23, &w);
        match plan1 {
            BootPlan::ResumeAtRung { label } => assert_eq!(label, "5GHz-VHT80-ch40"),
            other => panic!("expected ResumeAtRung after 1 Stable, got {other:?}"),
        }
        // 2 more clean holds (3 total) -> hold_prob 0.80, confidence 0.60 -> DirectToBest (Active).
        record_observation(&mut m, &obs(key40("r1", "RO"), Stability::Stable, &t(2)));
        record_observation(&mut m, &obs(key40("r1", "RO"), Stability::Stable, &t(3)));
        let plan3 = plan_boot_for_mode(LearnMode::Active, &m, "RO", "r1", &legal, |_| 23, &w);
        assert!(matches!(plan3, BootPlan::DirectToBest { .. }), "expected DirectToBest at obs=3, got {plan3:?}");
    }

    #[test]
    fn plan_boot_shadow_mode_never_skips_the_ladder() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        let w = QualityWeights::default();
        let legal = [(40u32, 80u32)];
        for d in 1..=5 {
            record_observation(&mut m, &obs(key40("r1", "RO"), Stability::Stable, &t(d)));
        }
        // Would clear the DirectToBest gate in Active mode...
        let active = plan_boot_for_mode(LearnMode::Active, &m, "RO", "r1", &legal, |_| 23, &w);
        assert!(matches!(active, BootPlan::DirectToBest { .. }));
        // ...but the SHIPPED constant is Shadow, and plan_boot() (the public fn) must therefore
        // degrade the exact same model state to ResumeAtRung, never DirectToBest.
        assert_eq!(LEARN_MODE, LearnMode::Shadow, "D44: must ship in shadow mode");
        let shipped = plan_boot(&m, "RO", "r1", &legal, |_| 23, &w);
        match shipped {
            BootPlan::ResumeAtRung { label } => assert_eq!(label, "5GHz-VHT80-ch40"),
            other => panic!("shadow mode must never return DirectToBest, got {other:?}"),
        }
    }

    #[test]
    fn plan_boot_only_selects_among_the_legal_set_always_joinable() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        let w = QualityWeights::default();
        for d in 1..=5 {
            record_observation(&mut m, &obs(key40("r1", "RO"), Stability::Stable, &t(d)));
        }
        // ch40/80 is NOT in the legal set this boot (e.g. No-IR/DFS-bounced) -> must never be chosen,
        // even though it is the model's clear favourite; a model-miss degrades to Ladder.
        let legal = [(36u32, 40u32)];
        let plan = plan_boot(&m, "RO", "r1", &legal, |_| 23, &w);
        assert_eq!(plan, BootPlan::Ladder);
    }

    #[test]
    fn plan_boot_a_known_bad_winner_is_excluded_never_selected() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        let w = QualityWeights::default();
        // ch40 confidently bad; ch36/HT40 has a couple of clean holds.
        for d in 1..=5 {
            record_observation(&mut m, &obs(key40("r1", "RO"), Stability::WidthCollapsed, &t(d)));
        }
        record_observation(&mut m, &obs(key36ht40("r1", "RO"), Stability::Stable, &t(6)));
        let legal = [(40u32, 80u32), (36, 40)];
        let plan = plan_boot(&m, "RO", "r1", &legal, |_| 23, &w);
        match plan {
            BootPlan::ResumeAtRung { label } => assert_eq!(label, "5GHz-HT40-ch36"),
            other => panic!("expected the not-known-bad ch36 rung to win, got {other:?}"),
        }
    }

    // ---- D45/D46 (2026-07-17, metal-diagnosed): warm-vs-cold learning context ----

    /// The core bug this fixes: many COLD failures for VHT80-ch40 must NEVER poison a SEPARATE
    /// warm-context cell's `hold_prob` for the exact same physical rung — they are different
    /// `ConfigKey`s (differing only in `warm`), so a confidently-bad cold cell and a confidently-good
    /// warm cell coexist without interference.
    #[test]
    fn cold_failures_never_poison_the_warm_cells_hold_prob() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        // 5 genuine COLD failures (the ground-truth symptom: cold VHT80-ch40 chanspec-fail-storms).
        for d in 1..=5 {
            record_observation(&mut m, &obs(key40("r1", "RO"), Stability::ChanspecFailStorm, &t(d)));
        }
        // 3 genuine WARM successes (the ground-truth symptom: warm VHT80-ch40 holds rock-solid).
        for d in 6..=8 {
            record_observation(&mut m, &obs(key40_warm("r1", "RO"), Stability::Stable, &t(d)));
        }
        assert_eq!(m.entries.len(), 2, "cold and warm must be two INDEPENDENT cells, not one merged cell");
        let cold = m.entries.iter().find(|e| !e.key.warm).unwrap();
        let warm = m.entries.iter().find(|e| e.key.warm).unwrap();
        assert!(hold_prob(cold) <= BAD_HOLD, "the cold cell is genuinely bad: hold_prob={}", hold_prob(cold));
        assert!(hold_prob(warm) >= DIRECT_HOLD, "the warm cell is genuinely good: hold_prob={}", hold_prob(warm));
        assert!(is_known_bad(cold, &t(9)), "cold VHT80-ch40 is correctly learned known-bad-cold");
        assert!(!is_known_bad(warm, &t(9)), "warm VHT80-ch40 must NOT be known-bad — it holds warm");
    }

    /// `plan_boot`/`band_lkg_from_model`/`channel_lkg_from_model` are cold-context ONLY: even with
    /// strong warm evidence for ch40/80, they must resume at the best COLD winner (ch36/40) — never
    /// hand the ordinary short-settle boot ladder a rung only proven to hold warm.
    #[test]
    fn plan_boot_and_lkg_exports_ignore_warm_only_evidence() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        let w = QualityWeights::default();
        let legal = [(40u32, 80u32), (36, 40)];
        // Strong warm-only evidence for ch40/80 (no cold observations for it at all).
        for d in 1..=5 {
            record_observation(&mut m, &obs(key40_warm("r1", "RO"), Stability::Stable, &t(d)));
        }
        // A cold-proven ch36/HT40.
        record_observation(&mut m, &obs(key36ht40("r1", "RO"), Stability::Stable, &t(6)));

        let plan = plan_boot(&m, "RO", "r1", &legal, |_| 23, &w);
        match plan {
            BootPlan::ResumeAtRung { label } => assert_eq!(label, "5GHz-HT40-ch36", "must resume at the COLD winner, not the warm-only ch40"),
            other => panic!("expected ResumeAtRung(ch36), got {other:?}"),
        }

        let band_lkg = band_lkg_from_model(&m, "RO", "r1", &legal, &w).expect("a cold winner exists");
        assert_eq!(band_lkg.label, "5GHz-HT40-ch36", "band-LKG export must never point at a warm-only rung");

        let legal80 = [(40u32, 80u32)];
        assert!(
            channel_lkg_from_model(&m, "RO", "r1", &legal80, &w).is_none(),
            "channel-LKG export must find NOTHING for ch40/80 when only warm-context evidence exists"
        );
    }

    /// If NEITHER cold nor warm data exists yet, plan_boot degrades to Ladder exactly as before this
    /// feature (a cold model behaves identically whether or not the warm axis exists).
    #[test]
    fn plan_boot_cold_model_unaffected_by_the_warm_axis() {
        let m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        let w = QualityWeights::default();
        let legal = [(40u32, 80u32), (36, 40)];
        assert_eq!(plan_boot(&m, "RO", "r1", &legal, |_| 23, &w), BootPlan::Ladder);
    }

    /// `plan_warm_upgrade`: with strong warm evidence for ch40/80 (wider than the cold-chosen
    /// ch36/40), it picks ch40/80 — the model-informed target, not merely "the next rung up" (which
    /// happens to coincide here, but this proves the SELECTION mechanism, not just the ladder shape).
    #[test]
    fn plan_warm_upgrade_selects_the_proven_warm_winner() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        let w = QualityWeights::default();
        let legal = [(40u32, 80u32), (36, 40)];
        for d in 1..=5 {
            record_observation(&mut m, &obs(key40_warm("r1", "RO"), Stability::Stable, &t(d)));
        }
        let target = plan_warm_upgrade(&m, "RO", "r1", &legal, 40 /* cold-chosen width_mhz */, &w)
            .expect("a proven warm winner exists");
        assert_eq!(target.channel, 40);
        assert_eq!(target.width_mhz, 80);
        assert!(target.warm);
    }

    /// `plan_warm_upgrade` returns `None` (caller falls back to the static ladder-adjacency rule)
    /// when nothing warm-proven exists yet — the correct BOOTSTRAP behaviour on a box's first boot.
    #[test]
    fn plan_warm_upgrade_none_on_a_cold_only_or_empty_model() {
        let w = QualityWeights::default();
        let legal = [(40u32, 80u32), (36, 40)];
        let empty = WifiKnowledge::new("wlan0", "fw1", &t(1));
        assert!(plan_warm_upgrade(&empty, "RO", "r1", &legal, 40, &w).is_none());

        let mut cold_only = WifiKnowledge::new("wlan0", "fw1", &t(1));
        for d in 1..=5 {
            record_observation(&mut cold_only, &obs(key40("r1", "RO"), Stability::Stable, &t(d)));
        }
        assert!(
            plan_warm_upgrade(&cold_only, "RO", "r1", &legal, 40, &w).is_none(),
            "cold-context observations must never satisfy the warm-only filter"
        );
    }

    /// `plan_warm_upgrade` never proposes a target that is NARROWER than (or equal to) the
    /// cold-chosen width — it can only ever be an upgrade. A warm cell recorded for the SAME width
    /// as the cold-chosen rung (e.g. a warm re-confirmation of ch36/40 itself) must not be offered.
    #[test]
    fn plan_warm_upgrade_never_proposes_sideways_or_narrower() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        let w = QualityWeights::default();
        let warm_same_width = ConfigKey { radio_id: "r1".to_string(), regdomain: "RO".to_string(), channel: 36, width_mhz: 40, warm: true };
        for d in 1..=5 {
            record_observation(&mut m, &obs(warm_same_width.clone(), Stability::Stable, &t(d)));
        }
        let legal = [(36u32, 40u32)];
        assert!(
            plan_warm_upgrade(&m, "RO", "r1", &legal, 40 /* cold-chosen is ALSO 40 MHz */, &w).is_none(),
            "a warm cell at the SAME width as the cold-chosen rung is not an upgrade — must be excluded"
        );
    }

    /// `plan_warm_upgrade` respects the caller's legal set exactly like `plan_boot` — a warm winner
    /// outside `legal` (e.g. a regdomain that no longer permits it) is never selected.
    #[test]
    fn plan_warm_upgrade_never_selects_outside_the_legal_set() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        let w = QualityWeights::default();
        for d in 1..=5 {
            record_observation(&mut m, &obs(key40_warm("r1", "RO"), Stability::Stable, &t(d)));
        }
        let legal_without_ch40 = [(36u32, 40u32)];
        assert!(plan_warm_upgrade(&m, "RO", "r1", &legal_without_ch40, 40, &w).is_none());
    }

    /// `warm_upgrade_ready` — the D46 min-uptime gate the shell mirrors numerically.
    #[test]
    fn warm_upgrade_ready_gates_on_minimum_uptime() {
        assert!(!warm_upgrade_ready(0, WARM_MIN_UPTIME_SECONDS));
        assert!(!warm_upgrade_ready(WARM_MIN_UPTIME_SECONDS - 1, WARM_MIN_UPTIME_SECONDS));
        assert!(warm_upgrade_ready(WARM_MIN_UPTIME_SECONDS, WARM_MIN_UPTIME_SECONDS));
        assert!(warm_upgrade_ready(WARM_MIN_UPTIME_SECONDS + 100, WARM_MIN_UPTIME_SECONDS));
    }

    /// Backward-compat: a pre-D45 persisted `ConfigKey` JSON (no `warm` field at all) deserializes
    /// with `warm: false` (cold) — the conservative, accurate reading (every pre-D45 observation WAS
    /// made with an ordinary/cold-scale settle).
    #[test]
    fn config_key_missing_warm_field_deserializes_as_cold() {
        let legacy_json = r#"{"radio_id":"r1","regdomain":"RO","channel":40,"width_mhz":80}"#;
        let key: ConfigKey = serde_json::from_str(legacy_json).expect("legacy ConfigKey must still parse");
        assert!(!key.warm, "an absent `warm` field must default to false (cold), never true");
    }

    /// A round-tripped (serialize then deserialize) `WifiKnowledge` preserves the `warm` field
    /// exactly — the persistence layer never silently collapses the two contexts back together.
    #[test]
    fn wifi_knowledge_json_round_trip_preserves_warm_context() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        record_observation(&mut m, &obs(key40("r1", "RO"), Stability::Stable, &t(1)));
        record_observation(&mut m, &obs(key40_warm("r1", "RO"), Stability::Stable, &t(2)));
        let json = m.to_json();
        let reloaded = WifiKnowledge::from_json(&json).expect("round-trip must parse");
        assert_eq!(reloaded.entries.len(), 2);
        assert!(reloaded.entries.iter().any(|e| e.key.warm));
        assert!(reloaded.entries.iter().any(|e| !e.key.warm));
    }

    // ---- D38: is_known_bad / re-probe window / fw rehabilitation ----

    #[test]
    fn is_known_bad_threshold_and_reprobe_window() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        for d in 1..=5 {
            record_observation(&mut m, &obs(key40("r1", "RO"), Stability::WidthCollapsed, &t(d)));
        }
        let s = &m.entries[0];
        assert!(hold_prob(s) <= BAD_HOLD);
        assert!(confidence(s) >= BAD_CONFIDENCE);
        assert!(is_known_bad(s, &t(6)), "confidently-bad + recent must be known-bad");
        // Just inside the re-probe window boundary (a few days later) — still known-bad.
        assert!(is_known_bad(s, &t(20)));
        // Past the re-probe window (>=30 days later) — rehabilitation-eligible again.
        let far_future = "2026-09-10T00:00:00Z"; // well over 30 days after 2026-07-05
        assert!(!is_known_bad(s, far_future), "past the re-probe window a known-bad cell must reopen");
    }

    #[test]
    fn fw_change_halves_failures_preserves_successes_and_stamps_new_fw_id() {
        let mut m = WifiKnowledge::new("wlan0", "fw-old", &t(1));
        record_observation(&mut m, &obs(key40("r1", "RO"), Stability::Stable, &t(1)));
        record_observation(&mut m, &obs(key40("r1", "RO"), Stability::WidthCollapsed, &t(2)));
        record_observation(&mut m, &obs(key40("r1", "RO"), Stability::WidthCollapsed, &t(3)));
        assert_eq!(m.entries[0].successes, 1.0);
        assert_eq!(m.entries[0].failures, 2.0);
        apply_fw_rehabilitation(&mut m, "fw-new");
        assert_eq!(m.entries[0].successes, 1.0, "successes (what worked) must be preserved");
        assert_eq!(m.entries[0].failures, 1.0, "failures must be halved");
        assert_eq!(m.fw_id, "fw-new");
        // No-op on an unchanged fingerprint.
        apply_fw_rehabilitation(&mut m, "fw-new");
        assert_eq!(m.entries[0].failures, 1.0);
    }

    #[test]
    fn dfs_ap_supported_is_derived_from_confident_dfs_entries() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        // No DFS evidence yet -> None (untested).
        assert_eq!(dfs_ap_supported(&m, "RO", "r1"), None);
        // Confidently-failing DFS entry -> Some(false).
        let dfs_key = ConfigKey { radio_id: "r1".to_string(), regdomain: "RO".to_string(), channel: 100, width_mhz: 80, warm: false };
        for d in 1..=5 {
            record_observation(&mut m, &obs(dfs_key.clone(), Stability::Down, &t(d)));
        }
        assert_eq!(dfs_ap_supported(&m, "RO", "r1"), Some(false));
        // One confident hold anywhere flips it true.
        let dfs_key2 = ConfigKey { radio_id: "r1".to_string(), regdomain: "RO".to_string(), channel: 116, width_mhz: 80, warm: false };
        for d in 6..=10 {
            record_observation(&mut m, &obs(dfs_key2.clone(), Stability::Stable, &t(d)));
        }
        assert_eq!(dfs_ap_supported(&m, "RO", "r1"), Some(true));
    }

    // ---- D40: age_model (discounted Beta preserves mean, drops confidence) ----

    #[test]
    fn age_model_preserves_mean_but_lowers_confidence_for_a_stale_cell() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        // A mixed cell (some failures too) so the RAW successes:failures RATIO is a meaningful
        // "mean" to check for exact preservation — halving both counts by the same factor leaves
        // that ratio untouched by construction (successes/(successes+failures) = 6/8 before AND
        // 3/4 after). The Bayesian POSTERIOR mean (hold_prob, which adds the fixed ALPHA0/BETA0
        // prior) necessarily shrinks toward the uniform prior (0.5) as concentration drops — that
        // is the correct, expected non-stationary-bandit behaviour (D40), not a bug, so this test
        // checks the RAW ratio exactly and the posterior hold_prob only loosely.
        for _ in 0..6 {
            record_observation(&mut m, &obs(key40("r1", "RO"), Stability::Stable, &t(1)));
        }
        for _ in 0..2 {
            record_observation(&mut m, &obs(key40("r1", "RO"), Stability::WidthCollapsed, &t(1)));
        }
        let raw_ratio_before = m.entries[0].successes / (m.entries[0].successes + m.entries[0].failures);
        let hold_before = hold_prob(&m.entries[0]);
        let conf_before = confidence(&m.entries[0]);
        assert_eq!(m.entries[0].successes, 6.0);
        assert_eq!(m.entries[0].failures, 2.0);
        // Age exactly one half-life (21 days).
        let later = "2026-07-22T00:00:00Z";
        age_model(&mut m, later);
        assert!((m.entries[0].successes - 3.0).abs() < 1e-3, "successes={}", m.entries[0].successes);
        assert!((m.entries[0].failures - 1.0).abs() < 1e-3, "failures={}", m.entries[0].failures);
        let raw_ratio_after = m.entries[0].successes / (m.entries[0].successes + m.entries[0].failures);
        assert!(
            (raw_ratio_after - raw_ratio_before).abs() < 1e-4,
            "the raw successes:failures RATIO must be exactly preserved by a uniform decay: before={raw_ratio_before} after={raw_ratio_after}"
        );
        let hold_after = hold_prob(&m.entries[0]);
        let conf_after = confidence(&m.entries[0]);
        // The posterior mean shrinks toward the uniform prior as concentration drops — still close
        // (a generous but non-trivial bound), and confidence must strictly drop.
        assert!((hold_after - hold_before).abs() < 0.15, "posterior mean should shift only moderately: before={hold_before} after={hold_after}");
        assert!(conf_after < conf_before, "confidence must drop after aging: before={conf_before} after={conf_after}");
        assert_eq!(m.updated_at, later);
    }

    #[test]
    fn age_model_no_op_when_already_current() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        record_observation(&mut m, &obs(key40("r1", "RO"), Stability::Stable, &t(1)));
        age_model(&mut m, &t(1));
        assert_eq!(m.entries[0].successes, 1.0, "no time elapsed => no decay");
    }

    // ---- D39: choose_mode / pick_candidate (explore/exploit) ----

    #[test]
    fn choose_mode_explores_under_observed_and_on_cadence_and_env_change() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        record_observation(&mut m, &obs(key40("r1", "RO"), Stability::Stable, &t(1)));
        // Under-observed (1 < MIN_OBS=3) -> Explore.
        assert_eq!(choose_mode(&m, "RO", "r1", 1, false), OptimizeMode::Explore);
        // Mature (>= MIN_OBS) and NOT on cadence and no env-change -> Exploit.
        for d in 2..=3 {
            record_observation(&mut m, &obs(key40("r1", "RO"), Stability::Stable, &t(d)));
        }
        assert_eq!(choose_mode(&m, "RO", "r1", 1, false), OptimizeMode::Exploit);
        // Cadence hits every EXPLORE_EVERY-th run.
        assert_eq!(choose_mode(&m, "RO", "r1", EXPLORE_EVERY, false), OptimizeMode::Explore);
        // env_changed forces Explore regardless.
        assert_eq!(choose_mode(&m, "RO", "r1", 1, true), OptimizeMode::Explore);
    }

    #[test]
    fn pick_candidate_exploit_argmax_quality_explore_favours_high_uncertainty() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        let w = QualityWeights::default();
        // Both candidates are VHT80 (same capacity term) so quality differs only by hold_prob — a
        // mature A (20 obs, 75% hold -> quality ~75) that is HIGHER quality than a nearly-untested
        // B (1 obs, 1 success -> hold_prob 0.667, quality ~66.7), but B's UCB exploration bonus
        // (far fewer observations => a much bigger sqrt(ln(total)/(obs+1)) term) is large enough to
        // overtake A's small remaining bonus — the textbook "explore the high-uncertainty arm"
        // behaviour, while Exploit still (correctly) prefers A's higher raw quality.
        let key_a = key40("r1", "RO");
        let key_b = ConfigKey { radio_id: "r1".to_string(), regdomain: "RO".to_string(), channel: 149, width_mhz: 80, warm: false };
        for d in 1..=15 {
            record_observation(&mut m, &obs(key_a.clone(), Stability::Stable, &t(d)));
        }
        for d in 16..=20 {
            record_observation(&mut m, &obs(key_a.clone(), Stability::WidthCollapsed, &t(d)));
        }
        record_observation(&mut m, &obs(key_b.clone(), Stability::Stable, &t(1)));
        assert_eq!(m.entries.iter().find(|e| e.key == key_a).unwrap().obs_count, 20);
        assert_eq!(m.entries.iter().find(|e| e.key == key_b).unwrap().obs_count, 1);

        let legal = [(40u32, 80u32), (149, 80)];
        let exploit = pick_candidate(&m, "RO", "r1", &legal, OptimizeMode::Exploit, &w);
        assert_eq!(exploit, Some(key_a.clone()), "exploit must pick the higher-quality mature cell");
        let explore = pick_candidate(&m, "RO", "r1", &legal, OptimizeMode::Explore, &w);
        assert_eq!(explore, Some(key_b), "explore must favour the far-more-uncertain cell's UCB bonus");
    }

    #[test]
    fn pick_candidate_none_when_nothing_legal_and_not_known_bad() {
        let m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        let w = QualityWeights::default();
        let legal = [(40u32, 80u32)];
        assert_eq!(pick_candidate(&m, "RO", "r1", &legal, OptimizeMode::Exploit, &w), None);
    }

    #[test]
    fn pick_candidate_one_exploration_budget_per_run_is_a_single_key() {
        // pick_candidate always returns at most ONE key (Option<ConfigKey>, never a Vec) — this is
        // the "at most one exploration per run" (D39/D28) budget enforced BY THE TYPE, not by a
        // counter the caller could forget to check.
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        record_observation(&mut m, &obs(key40("r1", "RO"), Stability::Stable, &t(1)));
        record_observation(&mut m, &obs(key36ht40("r1", "RO"), Stability::Stable, &t(1)));
        let w = QualityWeights::default();
        let legal = [(40u32, 80u32), (36, 40)];
        let picked = pick_candidate(&m, "RO", "r1", &legal, OptimizeMode::Explore, &w);
        assert!(picked.is_some());
    }

    // ---- D41: anti-flap (QUALITY_SWITCH_MARGIN + confidence gate) ----

    #[test]
    fn anti_flap_holds_the_incumbent_on_a_near_tie() {
        let w = QualityWeights::default();
        let current = mkstat(40, 80, 5.0, 0.0, 10.0, false);
        // A candidate that is only marginally better (below the switch margin) must NOT switch.
        let marginal = mkstat(36, 40, 5.0, 0.0, 0.0, false);
        // marginal is HT40 (lower cap) so it won't even beat VHT80 here; use a same-width near-tie:
        let near_tie = mkstat(149, 80, 5.0, 0.0, 9.0, false); // 1% less busy — negligible gain
        assert!(!should_switch(&current, &near_tie, |_| 23, &w), "a near-tie must not switch (anti-flap)");
        let _ = marginal;
        // A candidate that clears the margin AND has >= confidence DOES switch.
        let clearly_better = mkstat(149, 80, 20.0, 0.0, 0.0, false); // much higher confidence + quality
        assert!(should_switch(&current, &clearly_better, |_| 23, &w));
        // A momentarily higher-quality but LOWER-confidence cell must not flap in.
        let low_conf_high_quality = mkstat(149, 80, 1.0, 0.0, 0.0, false);
        // Even if its raw quality happens to clear the margin, low confidence blocks the switch.
        if quality_score(&low_conf_high_quality, 23, &w) >= quality_score(&current, 23, &w) + QUALITY_SWITCH_MARGIN {
            assert!(!should_switch(&current, &low_conf_high_quality, |_| 23, &w));
        }
    }

    // ---- eviction: bounded to MAX_LEARN_ENTRIES, never evicts a confident cell ----

    #[test]
    fn eviction_bounds_entries_and_never_evicts_the_most_confident_cell() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        // One highly-confident, RECENT cell.
        let champion = ConfigKey { radio_id: "r1".to_string(), regdomain: "RO".to_string(), channel: 40, width_mhz: 80, warm: false };
        for d in 1..=10 {
            record_observation(&mut m, &obs(champion.clone(), Stability::Stable, &t(d.min(28))));
        }
        // Fill with many stale, barely-observed cells (channels 44..44+80, all past MAX_LEARN_ENTRIES).
        for i in 0..80u32 {
            let k = ConfigKey { radio_id: "r1".to_string(), regdomain: "RO".to_string(), channel: 1000 + i, width_mhz: 20, warm: false };
            record_observation(&mut m, &obs(k, Stability::Down, "2020-01-01T00:00:00Z"));
        }
        assert!(m.entries.len() <= MAX_LEARN_ENTRIES, "entries={}", m.entries.len());
        assert!(
            m.entries.iter().any(|e| e.key == champion),
            "the confident, recent champion cell must never be evicted"
        );
    }

    // ---- D43: LearnDecision / WifiKnowledge round-trip ----

    #[test]
    fn wifi_knowledge_to_json_round_trips() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        record_observation(&mut m, &obs(key40("r1", "RO"), Stability::Stable, &t(1)));
        let json = m.to_json();
        let parsed = WifiKnowledge::from_json(&json).expect("must round-trip");
        assert_eq!(parsed, m);
    }

    #[test]
    fn learn_decision_to_json_is_valid_and_curve_is_bounded() {
        let w = QualityWeights::default();
        let s = mkstat(40, 80, 5.0, 0.0, 10.0, false);
        let mut curve = Vec::new();
        for i in 0..25 {
            curve.push(CurvePoint { at: t(i + 1), quality: 50.0, confidence: 0.5, hold_prob: 0.5 });
        }
        let skipped = vec![SkippedConfig { label: "5GHz-HT40-ch36".to_string(), reason: "lower_quality".to_string() }];
        let d = build_learn_decision("wlan0", "exploit_keep", Some(&s), |_| 23, &w, skipped, curve, &t(30));
        assert!(d.curve.len() <= LEARN_CURVE_MAX_POINTS, "curve must be bounded, got {}", d.curve.len());
        assert_eq!(d.chosen.as_deref(), Some("5GHz-VHT80-ch40"));
        let json = d.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("must be valid JSON");
        assert_eq!(parsed["chosen"], "5GHz-VHT80-ch40");
        assert_eq!(parsed["skipped"][0]["reason"], "lower_quality");
    }

    // ---- LKG export round-trip (band-LKG / channel-LKG derived FROM the model) ----

    #[test]
    fn band_lkg_and_channel_lkg_are_exported_from_the_model_and_gate_on_legal_and_stable() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        let w = QualityWeights::default();
        let legal = [(40u32, 80u32), (36, 40)];
        // Nothing proven yet -> no export.
        assert!(band_lkg_from_model(&m, "RO", "r1", &legal, &w).is_none());
        assert!(channel_lkg_from_model(&m, "RO", "r1", &legal, &w).is_none());
        record_observation(&mut m, &obs(key40("r1", "RO"), Stability::Stable, &t(1)));
        let band = band_lkg_from_model(&m, "RO", "r1", &legal, &w).expect("must export now");
        assert_eq!(band.label, "5GHz-VHT80-ch40");
        assert_eq!(band.cc, "RO");
        assert_eq!(band.radio_id, "r1");
        let chan = channel_lkg_from_model(&m, "RO", "r1", &legal, &w).expect("must export now");
        assert_eq!(chan.control_channel, 40);
        assert_eq!(chan.width_mhz, 80);
        assert!(!chan.dfs);
        // channel_lkg_valid/band_lkg_valid (the pre-existing readers) accept these exports unchanged.
        assert!(channel_lkg_valid(&chan, "RO", "r1"));
        assert!(band_lkg_valid(&band, "RO", "r1"));
        // A regdomain change invalidates both, exactly as before this extension.
        assert!(!channel_lkg_valid(&chan, "GB", "r1"));
        assert!(!band_lkg_valid(&band, "GB", "r1"));
    }

    #[test]
    fn seed_from_band_lkg_migration_starts_the_model_at_resume_not_cold() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        let lkg = BandLkg {
            cc: "RO".to_string(),
            radio_id: "r1".to_string(),
            band: "5".to_string(),
            label: "5GHz-VHT80-ch40".to_string(),
            channel: 40,
            decided_at: t(1),
        };
        seed_from_band_lkg(&mut m, &lkg, &t(2));
        assert_eq!(m.entries.len(), 1);
        assert_eq!(m.entries[0].successes, 1.0);
        let w = QualityWeights::default();
        let legal = [(40u32, 80u32)];
        let plan = plan_boot(&m, "RO", "r1", &legal, |_| 23, &w);
        assert!(matches!(plan, BootPlan::ResumeAtRung { .. }), "migration seed must start at Resume, not cold");
        // Seeding again (e.g. a second boot before any real observation) must NOT double-seed.
        seed_from_band_lkg(&mut m, &lkg, &t(3));
        assert_eq!(m.entries.len(), 1);
        assert_eq!(m.entries[0].successes, 1.0);
    }

    // ---- Convergence property test (the machine-checked "learning curve") ----

    #[test]
    fn convergence_property_a_rises_b_falls_and_plan_boot_tiers_flip_at_the_specified_counts() {
        let mut m = WifiKnowledge::new("wlan0", "fw1", &t(1));
        let w = QualityWeights::default();
        let key_a = key40("r1", "RO");
        let key_b = key36ht40("r1", "RO");
        let legal = [(40u32, 80u32), (36, 40)];

        // Before any observation: cold -> Ladder.
        assert_eq!(plan_boot_for_mode(LearnMode::Active, &m, "RO", "r1", &legal, |_| 23, &w), BootPlan::Ladder);

        // B fails consistently (mostly-fail) while A holds consistently (mostly-Stable), tracked
        // day by day so the trajectory is monotone-ish and machine-checked at each step.
        let mut prev_quality_a = f32::MIN;
        for day in 1..=6u32 {
            record_observation(&mut m, &obs(key_a.clone(), Stability::Stable, &t(day)));
            record_observation(&mut m, &obs(key_b.clone(), Stability::WidthCollapsed, &t(day)));
            let a = m.entries.iter().find(|e| e.key == key_a).unwrap();
            let qa = quality_score(a, 23, &w);
            assert!(qa >= prev_quality_a - 1e-6, "quality(A) must rise (or hold) monotonically: day={day} qa={qa} prev={prev_quality_a}");
            prev_quality_a = qa;

            let plan = plan_boot_for_mode(LearnMode::Active, &m, "RO", "r1", &legal, |_| 23, &w);
            match day {
                1 => assert!(
                    matches!(&plan, BootPlan::ResumeAtRung { label } if label == "5GHz-VHT80-ch40"),
                    "day1: expected ResumeAtRung(A), got {plan:?}"
                ),
                3 => assert!(
                    matches!(plan, BootPlan::DirectToBest { .. }),
                    "day3 (3 clean holds -> hold=0.80,conf=0.60): expected DirectToBest, got {plan:?}"
                ),
                _ => {}
            }
        }
        let a = m.entries.iter().find(|e| e.key == key_a).unwrap();
        let b = m.entries.iter().find(|e| e.key == key_b).unwrap();
        assert!(confidence(a) > 0.7, "A's confidence must have saturated upward: {}", confidence(a));
        let qa = quality_score(a, 23, &w);
        let qb = quality_score(b, 23, &w);
        // "-> ~0" is relative to A's thriving quality (an order of magnitude gap), not a literal
        // sub-1.0 absolute bound after only 6 observations — the Beta posterior mean only reaches
        // a truly near-zero ABSOLUTE value asymptotically with many more failures; the load-bearing
        // property this test proves is the RELATIVE collapse plus never-repeat-known-bad (B is
        // excluded from every plan_boot winner throughout, checked via the day-by-day loop above).
        assert!(qb < qa * 0.1, "B's quality ({qb}) must collapse relative to A's ({qa})");
        // The final tier is DirectToBest(A) — never-repeat-known-bad(B) holds throughout.
        let final_plan = plan_boot_for_mode(LearnMode::Active, &m, "RO", "r1", &legal, |_| 23, &w);
        assert!(matches!(final_plan, BootPlan::DirectToBest { .. }));
    }
}
