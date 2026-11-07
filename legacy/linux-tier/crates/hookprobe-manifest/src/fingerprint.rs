//! Behavioural device fingerprinting — MAC-INDEPENDENT identity ("who has what").
//!
//! The segmentation thesis (`docs/architecture/network-segmentation.md`): a MAC is not an identity,
//! and on a real LAN many clients randomize it. The N100's live LAN is the proof — the
//! iPhone (`c2:…`) and the Mac (`9e:…`) both use locally-administered (randomized) MACs
//! with no OUI, yet their DHCP hostname, vendor class, DHCP option-55 fingerprint and
//! mDNS advertisements identify them precisely. This module turns those *observed
//! signals* into a device class + a suggested segment, layered strongest-signal-first:
//!
//!   mDNS service  >  DHCP vendor class (opt60)  >  hostname  >  DHCP opt-55 sig  >  OUI
//!
//! Output feeds AEGIS as a *recommendation* (the operator/policy still decides); the
//! `fabric` reconciler then renders the chosen segment. Identity is observed, not asserted.

use crate::fabric::{mac_class, MacClass};

/// Observed signals for one device (from Senzorium / dnsmasq leases / DHCP / mDNS).
/// Everything optional — classification uses whatever is present.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(default)]
pub struct DeviceObservation {
    pub mac: String,
    pub ip: Option<String>,
    /// DHCP hostname (option 12).
    pub hostname: Option<String>,
    /// DHCP vendor class identifier (option 60), e.g. "android-dhcp-13", "MSFT 5.0".
    pub vendor_class: Option<String>,
    /// DHCP parameter-request list (option 55) as the raw comma list, Fingerbank-style.
    pub dhcp_opt55: Option<String>,
    /// Advertised mDNS/Bonjour service types, e.g. "_airplay._tcp", "_ipp._tcp".
    pub mdns_services: Vec<String>,
    /// Model strings harvested from mDNS TXT records (`md=`/`model=`/`am=`), e.g.
    /// "HomePod", "Mac17,9", "AudioAccessory5,1" — the most definitive signal there is.
    #[serde(default)]
    pub models: Vec<String>,
}

/// Device class — coarse enough to drive a segment, fine enough to be useful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceClass {
    Phone,
    Tablet,
    Computer,
    Wearable,
    IoTCamera,
    IoTSensor,
    VoiceAssistant,
    Printer,
    MediaStreamer,
    GameConsole,
    SingleBoardComputer,
    Router,
    Unknown,
}

impl DeviceClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceClass::Phone => "phone",
            DeviceClass::Tablet => "tablet",
            DeviceClass::Computer => "computer",
            DeviceClass::Wearable => "wearable",
            DeviceClass::IoTCamera => "iot-camera",
            DeviceClass::IoTSensor => "iot-sensor",
            DeviceClass::VoiceAssistant => "voice-assistant",
            DeviceClass::Printer => "printer",
            DeviceClass::MediaStreamer => "media-streamer",
            DeviceClass::GameConsole => "game-console",
            DeviceClass::SingleBoardComputer => "sbc",
            DeviceClass::Router => "router",
            DeviceClass::Unknown => "unknown",
        }
    }
    /// Default segment for this class (operator policy can override). Personal devices →
    /// `byod`; cameras isolated; other IoT → `iot`; infra on its own; unknown onboards.
    pub fn suggested_segment(&self) -> &'static str {
        match self {
            DeviceClass::Phone | DeviceClass::Tablet | DeviceClass::Computer | DeviceClass::Wearable => "byod",
            DeviceClass::IoTCamera => "cameras",
            DeviceClass::IoTSensor | DeviceClass::VoiceAssistant => "iot",
            DeviceClass::Printer => "printers",
            DeviceClass::MediaStreamer | DeviceClass::GameConsole => "media",
            DeviceClass::SingleBoardComputer | DeviceClass::Router => "infra",
            DeviceClass::Unknown => "onboarding",
        }
    }
}

/// Confidence in the classification — driven by signal strength.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}
impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

/// The classification result.
#[derive(Debug, Clone)]
pub struct DeviceProfile {
    pub mac: String,
    pub class: DeviceClass,
    pub confidence: Confidence,
    pub suggested_segment: String,
    /// True if the MAC is randomized — i.e. it must NOT be used as durable identity.
    pub mac_randomized: bool,
    /// Human-readable signals that drove the decision (the "why").
    pub signals: Vec<String>,
}

/// One classification rule's verdict.
struct Hit {
    class: DeviceClass,
    confidence: Confidence,
    signal: String,
}

/// Classify a device from its observed signals (MAC-independent). The strongest signal
/// wins; ties keep the first (the layering order below is the priority).
pub fn classify(obs: &DeviceObservation) -> DeviceProfile {
    let randomized = !obs.mac.is_empty() && mac_class(&obs.mac) == MacClass::LocallyAdministered;
    let mut hits: Vec<Hit> = Vec::new();

    // Layer 0 — mDNS model strings (md=/model=/am=). The most definitive signal: a TXT
    // record saying `md=HomePod` is ground truth. High confidence.
    for m in &obs.models {
        if let Some(h) = from_model(m) {
            hits.push(h);
        }
    }
    // Layer 1 — mDNS services (a device advertising _ipp IS a printer). High confidence.
    for svc in &obs.mdns_services {
        if let Some(h) = from_mdns(svc) {
            hits.push(h);
        }
    }
    // Layer 2 — DHCP vendor class (opt 60). High/medium.
    if let Some(vc) = obs.vendor_class.as_deref() {
        if let Some(h) = from_vendor_class(vc) {
            hits.push(h);
        }
    }
    // Layer 3 — hostname. Medium (user-settable but in practice very telling: "iPhone").
    if let Some(hn) = obs.hostname.as_deref() {
        if let Some(h) = from_hostname(hn) {
            hits.push(h);
        }
    }
    // Layer 4 — DHCP parameter-request list (option 55), Fingerbank-style. Low/medium.
    if let Some(sig) = obs.dhcp_opt55.as_deref() {
        if let Some(h) = from_dhcp_opt55(sig) {
            hits.push(h);
        }
    }
    // Layer 5 — OUI, ONLY for a universal (non-randomized) MAC. Low/medium.
    if !randomized {
        if let Some(h) = from_oui(&obs.mac) {
            hits.push(h);
        }
    }

    // Pick the highest-confidence hit (sort_by_key is stable too: first among equals by layering order).
    hits.sort_by_key(|h| std::cmp::Reverse(h.confidence));
    let (class, confidence, mut signals) = match hits.first() {
        Some(top) => {
            let sigs: Vec<String> = hits.iter().map(|h| h.signal.clone()).collect();
            (top.class, top.confidence, sigs)
        }
        None => (
            DeviceClass::Unknown,
            Confidence::Low,
            vec!["no identifying signal (hostname/vendor/mDNS/OUI all absent or generic)".to_string()],
        ),
    };
    if randomized {
        signals.push("MAC is randomized (locally-administered) — identity is the fingerprint, not the MAC".to_string());
    }
    DeviceProfile {
        mac: obs.mac.clone(),
        class,
        confidence,
        suggested_segment: class.suggested_segment().to_string(),
        mac_randomized: randomized,
        signals,
    }
}

fn from_mdns(svc: &str) -> Option<Hit> {
    let s = svc.to_ascii_lowercase();
    let (class, label) = if s.contains("_ipp") || s.contains("_printer") || s.contains("_pdl") {
        (DeviceClass::Printer, "printer")
    } else if s.contains("_googlecast") {
        (DeviceClass::MediaStreamer, "Chromecast")
    } else if s.contains("_airplay") || s.contains("_raop") {
        (DeviceClass::MediaStreamer, "AirPlay")
    } else if s.contains("_hap") {
        (DeviceClass::IoTSensor, "HomeKit accessory")
    } else if s.contains("_amzn") || s.contains("_alexa") {
        (DeviceClass::VoiceAssistant, "Amazon device")
    } else {
        return None;
    };
    Some(Hit { class, confidence: Confidence::High, signal: format!("mDNS {svc} → {label}") })
}

fn from_model(m: &str) -> Option<Hit> {
    let s = m.to_ascii_lowercase();
    let (class, label) = if s.contains("homepod") || s.contains("audioaccessory") {
        (DeviceClass::VoiceAssistant, "HomePod")
    } else if s.contains("appletv") {
        (DeviceClass::MediaStreamer, "Apple TV")
    } else if s.starts_with("mac") || s.contains("macbook") || s.contains("imac") {
        (DeviceClass::Computer, "Mac")
    } else if s.contains("iphone") {
        (DeviceClass::Phone, "iPhone")
    } else if s.contains("ipad") {
        (DeviceClass::Tablet, "iPad")
    } else if s.contains("watch") {
        (DeviceClass::Wearable, "Apple Watch")
    } else {
        return None;
    };
    Some(Hit { class, confidence: Confidence::High, signal: format!("model \"{m}\" → {label}") })
}

fn from_dhcp_opt55(sig: &str) -> Option<Hit> {
    // Fingerbank-style: the option-55 parameter-request list is a stable per-OS signature.
    // A small set of well-known prefixes (kept conservative — low/medium confidence).
    let s: String = sig.split_whitespace().collect();
    let (class, conf, label) = if s.starts_with("1,3,6,15,119,252") {
        (DeviceClass::Computer, Confidence::Medium, "Apple/macOS-iOS opt55")
    } else if s.starts_with("1,33,3,6,15,28,51,58,59") || s.contains("1,33,3,6,12,15,28,42") {
        (DeviceClass::Phone, Confidence::Medium, "Android opt55")
    } else if s.starts_with("1,15,3,6,44,46,47,31,33,121") || s.contains("1,3,6,15,31,33,43,44,46,47,121,249,252") {
        (DeviceClass::Computer, Confidence::Medium, "Windows opt55")
    } else {
        return None;
    };
    Some(Hit { class, confidence: conf, signal: format!("DHCP opt55 [{sig}] → {label}") })
}

fn from_vendor_class(vc: &str) -> Option<Hit> {
    let s = vc.to_ascii_lowercase();
    let (class, conf, label) = if s.contains("android-dhcp") {
        (DeviceClass::Phone, Confidence::High, "Android")
    } else if s.starts_with("msft") {
        (DeviceClass::Computer, Confidence::Medium, "Windows")
    } else if s.contains("dhcpcd") {
        (DeviceClass::SingleBoardComputer, Confidence::Low, "Linux/dhcpcd")
    } else if s.contains("udhcp") {
        (DeviceClass::IoTSensor, Confidence::Low, "embedded/udhcp")
    } else {
        return None;
    };
    Some(Hit { class, confidence: conf, signal: format!("vendor-class \"{vc}\" → {label}") })
}

fn from_hostname(hn: &str) -> Option<Hit> {
    let s = hn.to_ascii_lowercase();
    // (substring, class) — order matters; first match wins within hostname layer.
    let table: &[(&str, DeviceClass)] = &[
        ("iphone", DeviceClass::Phone),
        ("ipad", DeviceClass::Tablet),
        ("watch", DeviceClass::Wearable),
        ("fitbit", DeviceClass::Wearable),
        ("garmin", DeviceClass::Wearable),
        ("macbook", DeviceClass::Computer),
        ("imac", DeviceClass::Computer),
        ("-mac", DeviceClass::Computer),
        ("pixel", DeviceClass::Phone),
        ("galaxy", DeviceClass::Phone),
        ("oneplus", DeviceClass::Phone),
        ("redmi", DeviceClass::Phone),
        ("xiaomi", DeviceClass::Phone),
        ("android", DeviceClass::Phone),
        ("echo", DeviceClass::VoiceAssistant),
        ("alexa", DeviceClass::VoiceAssistant),
        ("nest-mini", DeviceClass::VoiceAssistant),
        ("nesthub", DeviceClass::VoiceAssistant),
        ("googlehome", DeviceClass::VoiceAssistant),
        ("homepod", DeviceClass::VoiceAssistant),
        ("roku", DeviceClass::MediaStreamer),
        ("chromecast", DeviceClass::MediaStreamer),
        ("firetv", DeviceClass::MediaStreamer),
        ("appletv", DeviceClass::MediaStreamer),
        ("shield", DeviceClass::MediaStreamer),
        ("reolink", DeviceClass::IoTCamera),
        ("amcrest", DeviceClass::IoTCamera),
        ("wyze", DeviceClass::IoTCamera),
        ("hikvision", DeviceClass::IoTCamera),
        ("dahua", DeviceClass::IoTCamera),
        ("ipcam", DeviceClass::IoTCamera),
        ("camera", DeviceClass::IoTCamera),
        ("ecobee", DeviceClass::IoTSensor),
        ("thermostat", DeviceClass::IoTSensor),
        ("hue", DeviceClass::IoTSensor),
        ("lifx", DeviceClass::IoTSensor),
        ("sensor", DeviceClass::IoTSensor),
        ("playstation", DeviceClass::GameConsole),
        ("xbox", DeviceClass::GameConsole),
        ("nintendo", DeviceClass::GameConsole),
        ("printer", DeviceClass::Printer),
        ("epson", DeviceClass::Printer),
        ("raspberrypi", DeviceClass::SingleBoardComputer),
        ("guardian", DeviceClass::SingleBoardComputer),
        ("hooksound", DeviceClass::SingleBoardComputer),
        ("hookprobe", DeviceClass::SingleBoardComputer),
    ];
    for (needle, class) in table {
        if s.contains(needle) {
            return Some(Hit {
                class: *class,
                confidence: Confidence::Medium,
                signal: format!("hostname \"{hn}\" → {}", class.as_str()),
            });
        }
    }
    // A bare "mac" hostname (Apple default) — common, treat as a computer at low conf.
    if s == "mac" {
        return Some(Hit { class: DeviceClass::Computer, confidence: Confidence::Medium, signal: format!("hostname \"{hn}\" → computer (Apple)") });
    }
    None
}

/// OUI (first 3 octets, colon-lowercase) → (class, vendor label) — universal MACs only. Shared
/// by `from_oui` (a classification `Hit`) and `oui_vendor` (a plain label lookup for callers,
/// e.g. the scan-responder's host-intel enrichment, that just want the vendor string without
/// running the full multi-signal classifier). One table, no duplication.
fn oui_table(oui: &str) -> Option<(DeviceClass, &'static str)> {
    match oui {
        "dc:a6:32" | "b8:27:eb" | "e4:5f:01" | "28:cd:c1" | "d8:3a:dd" => Some((DeviceClass::SingleBoardComputer, "Raspberry Pi")),
        "9c:8e:cd" => Some((DeviceClass::IoTCamera, "Amcrest")),
        "00:1a:11" => Some((DeviceClass::VoiceAssistant, "Google")),
        "44:65:0d" | "fc:65:de" => Some((DeviceClass::VoiceAssistant, "Amazon")),
        _ => None,
    }
}

fn from_oui(mac: &str) -> Option<Hit> {
    let oui = mac.to_ascii_lowercase().replace('-', ":");
    let oui = oui.get(..8)?;
    // Small representative table — universal OUIs only (randomized MACs never reach here).
    let (class, vendor) = oui_table(oui)?;
    Some(Hit { class, confidence: Confidence::Medium, signal: format!("OUI {oui} → {vendor}") })
}

/// Plain OUI vendor lookup for a UNIVERSAL (non-randomized) MAC — `None` for an empty/randomized
/// MAC or an unrecognized OUI. Public so enrichment callers outside the classifier (the
/// scan-responder's host-intel record) can get the vendor label directly without running the
/// full multi-signal classifier, and so a randomized MAC is honestly reported as having no
/// universal-OUI vendor rather than guessed.
pub fn oui_vendor(mac: &str) -> Option<&'static str> {
    if mac.is_empty() || mac_class(mac) == MacClass::LocallyAdministered {
        return None;
    }
    let oui = mac.to_ascii_lowercase().replace('-', ":");
    let oui = oui.get(..8)?;
    oui_table(oui).map(|(_, vendor)| vendor)
}

/// Classify a batch and return the AEGIS-style segment recommendations.
pub fn classify_all(obs: &[DeviceObservation]) -> Vec<DeviceProfile> {
    obs.iter().map(classify).collect()
}

// ---------------------------------------------------------------------------
// AEGIS bridge — identity → segment + ENFORCEMENT MECHANISM (the plan-as-diff).
// ---------------------------------------------------------------------------

/// How a device's segment membership should be ENFORCED. The crucial decision: a
/// randomized MAC must NOT be pinned by a `dl_src` flow (it churns), so an identified
/// randomizing client is steered to 802.1X; only stable-OUI devices get a MAC flow.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Mechanism {
    /// Stable OVS `dl_src` → VLAN flow. Only for a universal (non-randomized) MAC.
    MacFlow,
    /// 802.1X identity → RADIUS VLAN. For an identified device on a randomized MAC.
    Dot1x,
    /// Onboard + observe — no durable identity yet; classify further before binding.
    Observe,
}
impl Mechanism {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mechanism::MacFlow => "mac-flow",
            Mechanism::Dot1x => "dot1x",
            Mechanism::Observe => "observe",
        }
    }
}

/// One AEGIS segmentation decision for a device: which segment, enforced how, and why.
#[derive(Debug, Clone)]
pub struct SegmentDecision {
    pub mac: String,
    pub class: DeviceClass,
    pub segment: String,
    pub mechanism: Mechanism,
    pub reason: String,
}

/// Decide segment + enforcement for one classified device. This is the AEGIS rule that
/// makes segmentation survive MAC randomization (docs/architecture/network-segmentation.md §2).
pub fn recommend(p: &DeviceProfile) -> SegmentDecision {
    let (segment, mechanism, reason) = if p.class == DeviceClass::Unknown {
        (
            "onboarding".to_string(),
            Mechanism::Observe,
            "no durable identity yet → onboard + observe (DHCP opt-55/mDNS/TLS) to classify".to_string(),
        )
    } else if p.mac_randomized {
        (
            p.suggested_segment.clone(),
            Mechanism::Dot1x,
            format!("identified as {} but MAC is randomized → enforce by 802.1X (a dl_src flow would churn)", p.class.as_str()),
        )
    } else {
        (
            p.suggested_segment.clone(),
            Mechanism::MacFlow,
            format!("identified as {} on a stable MAC → OVS dl_src flow is safe", p.class.as_str()),
        )
    };
    SegmentDecision { mac: p.mac.clone(), class: p.class, segment, mechanism, reason }
}

pub fn recommend_all(profiles: &[DeviceProfile]) -> Vec<SegmentDecision> {
    profiles.iter().map(recommend).collect()
}

// ---------------------------------------------------------------------------
// Live signal enrichment — pull richer signals from the edge and merge by IP/host.
// ---------------------------------------------------------------------------

/// One host's mDNS footprint (services advertised + model strings from TXT records).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MdnsHost {
    pub ip: String,
    pub services: Vec<String>,
    pub models: Vec<String>,
}

/// Parse `avahi-browse -p -r` output (`=;iface;proto;name;service;domain;host;ip;port;"txt"…`)
/// into per-IP mDNS footprints. Harvests `md=`/`model=`/`am=` TXT values as model hints.
pub fn parse_avahi_browse(text: &str) -> Vec<MdnsHost> {
    use std::collections::BTreeMap;
    let mut by_ip: BTreeMap<String, MdnsHost> = BTreeMap::new();
    for line in text.lines() {
        if !line.starts_with('=') {
            continue;
        }
        let f: Vec<&str> = line.split(';').collect();
        if f.len() < 8 {
            continue;
        }
        let service = f[4].trim().to_string();
        let ip = f[7].trim().to_string();
        if ip.is_empty() {
            continue;
        }
        let host = by_ip.entry(ip.clone()).or_insert_with(|| MdnsHost { ip: ip.clone(), ..Default::default() });
        if !service.is_empty() && !host.services.contains(&service) {
            host.services.push(service);
        }
        // Harvest model hints from TXT tokens: "md=…", "model=…", "am=…".
        for tok in line.split('"') {
            if let Some((k, v)) = tok.split_once('=') {
                let k = k.trim().to_ascii_lowercase();
                if (k == "md" || k == "model" || k == "am") && !v.is_empty() {
                    let v = v.trim().to_string();
                    if !host.models.contains(&v) {
                        host.models.push(v);
                    }
                }
            }
        }
    }
    by_ip.into_values().collect()
}

/// Parse a dnsmasq DHCP log (`log-dhcp`) for `vendor class:` (opt 60) and `client
/// provides name:` lines, pairing them by dnsmasq's per-request id → `(hostname,
/// vendor_class)`. This is how the live N100 reveals that `E1680422` is `MSFT 5.0`.
pub fn parse_dnsmasq_dhcp_log(text: &str) -> Vec<(String, String)> {
    use std::collections::BTreeMap;
    let (mut names, mut vendors): (BTreeMap<String, String>, BTreeMap<String, String>) = Default::default();
    let id_before = |line: &str, marker: &str| -> Option<String> {
        let idx = line.find(marker)?;
        line[..idx].split_whitespace().last().map(|s| s.to_string())
    };
    for line in text.lines() {
        if let Some(idx) = line.find("client provides name:") {
            if let Some(id) = id_before(line, "client provides name:") {
                let name = line[idx + "client provides name:".len()..].trim();
                // Strip any domain suffix (E1680422.internal.vodafone.com → E1680422).
                let name = name.split('.').next().unwrap_or(name).to_string();
                names.entry(id).or_insert(name);
            }
        } else if let Some(idx) = line.find("vendor class:") {
            if let Some(id) = id_before(line, "vendor class:") {
                vendors.insert(id, line[idx + "vendor class:".len()..].trim().to_string());
            }
        }
    }
    names
        .into_iter()
        .filter_map(|(id, name)| vendors.get(&id).map(|v| (name, v.clone())))
        .collect()
}

/// Merge enrichment signals into observations: mDNS by IP, DHCP vendor-class by hostname.
pub fn enrich(obs: &mut [DeviceObservation], mdns: &[MdnsHost], dhcp_vendor: &[(String, String)]) {
    for o in obs.iter_mut() {
        if let Some(ip) = &o.ip {
            if let Some(h) = mdns.iter().find(|h| &h.ip == ip) {
                for s in &h.services {
                    if !o.mdns_services.contains(s) {
                        o.mdns_services.push(s.clone());
                    }
                }
                for m in &h.models {
                    if !o.models.contains(m) {
                        o.models.push(m.clone());
                    }
                }
            }
        }
        if o.vendor_class.is_none() {
            if let Some(hn) = o.hostname.as_deref() {
                if let Some((_, vc)) = dhcp_vendor.iter().find(|(name, _)| name.eq_ignore_ascii_case(hn)) {
                    o.vendor_class = Some(vc.clone());
                }
            }
        }
    }
}

/// Parse dnsmasq leases (`<expiry> <mac> <ip> <hostname> <clientid>`) into observations.
/// `*` hostnames become `None`. This is the live edge feed (the N100 LAN).
pub fn observations_from_dnsmasq_leases(text: &str) -> Vec<DeviceObservation> {
    text.lines()
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 3 {
                return None;
            }
            let hostname = f.get(3).filter(|h| **h != "*").map(|h| h.to_string());
            Some(DeviceObservation {
                mac: f[1].to_string(),
                ip: Some(f[2].to_string()),
                hostname,
                ..Default::default()
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(mac: &str, host: &str) -> DeviceObservation {
        DeviceObservation { mac: mac.into(), hostname: Some(host.into()), ..Default::default() }
    }

    /// THE PROOF (N100 live LAN): an iPhone with a RANDOMIZED MAC and no OUI is still
    /// classified as a phone → byod, purely from its hostname. MAC-independent identity.
    #[test]
    fn randomized_iphone_identified_by_hostname() {
        let p = classify(&obs("c2:01:b1:72:4d:dc", "iPhone"));
        assert_eq!(p.class, DeviceClass::Phone);
        assert_eq!(p.suggested_segment, "byod");
        assert!(p.mac_randomized, "c2:.. is locally-administered");
        assert!(p.signals.iter().any(|s| s.contains("randomized")));
    }

    /// A randomized-MAC Mac → computer/byod from hostname.
    #[test]
    fn randomized_mac_identified_by_hostname() {
        let p = classify(&obs("9e:a3:53:c7:fe:ec", "Mac"));
        assert_eq!(p.class, DeviceClass::Computer);
        assert!(p.mac_randomized);
    }

    /// A universal Raspberry Pi OUI → SBC even with a generic hostname; OUI layer fires.
    #[test]
    fn raspberry_pi_by_oui() {
        let p = classify(&DeviceObservation { mac: "dc:a6:32:a4:b6:87".into(), ..Default::default() });
        assert_eq!(p.class, DeviceClass::SingleBoardComputer);
        assert!(!p.mac_randomized);
        assert_eq!(p.suggested_segment, "infra");
    }

    /// Strongest signal wins: mDNS _ipp (printer, high) beats a misleading hostname.
    #[test]
    fn mdns_beats_hostname() {
        let o = DeviceObservation {
            mac: "11:22:33:44:55:66".into(),
            hostname: Some("livingroom".into()),
            mdns_services: vec!["_ipp._tcp".into()],
            ..Default::default()
        };
        let p = classify(&o);
        assert_eq!(p.class, DeviceClass::Printer);
        assert_eq!(p.confidence, Confidence::High);
    }

    /// Android vendor-class (opt60) classifies a phone even with no hostname.
    #[test]
    fn android_by_vendor_class() {
        let o = DeviceObservation { mac: "02:aa:bb:cc:dd:ee".into(), vendor_class: Some("android-dhcp-13".into()), ..Default::default() };
        let p = classify(&o);
        assert_eq!(p.class, DeviceClass::Phone);
        assert!(p.mac_randomized);
    }

    /// No signal at all → Unknown → onboarding (low confidence), never misclassified.
    #[test]
    fn no_signal_is_unknown_onboarding() {
        let p = classify(&DeviceObservation { mac: "02:00:00:00:00:01".into(), ..Default::default() });
        assert_eq!(p.class, DeviceClass::Unknown);
        assert_eq!(p.suggested_segment, "onboarding");
        assert_eq!(p.confidence, Confidence::Low);
    }

    /// AEGIS rule: identified randomizing client → 802.1X (NOT a churning MAC flow);
    /// identified stable device → MAC flow; unidentified → observe/onboard.
    #[test]
    fn aegis_mechanism_respects_mac_stability() {
        // Randomized iPhone → dot1x.
        let iphone = recommend(&classify(&obs("c2:01:b1:72:4d:dc", "iPhone")));
        assert_eq!(iphone.mechanism, Mechanism::Dot1x);
        assert_eq!(iphone.segment, "byod");
        // Stable Raspberry Pi (universal OUI) → MAC flow.
        let pi = recommend(&classify(&DeviceObservation { mac: "dc:a6:32:a4:b6:87".into(), hostname: Some("guardian".into()), ..Default::default() }));
        assert_eq!(pi.mechanism, Mechanism::MacFlow);
        // Unidentified → observe in onboarding.
        let unk = recommend(&classify(&obs("e4:1f:d5:f3:2e:42", "E1680422")));
        assert_eq!(unk.mechanism, Mechanism::Observe);
        assert_eq!(unk.segment, "onboarding");
    }

    /// Enrichment resolves the `unknown`s — the live N100 cases. A Windows box that was
    /// `unknown` by hostname becomes `computer` via DHCP vendor class; a HomePod that
    /// hostname-guessed `sbc` becomes `voice-assistant` via mDNS model string.
    #[test]
    fn enrichment_resolves_unknowns() {
        // Vendor class (opt 60) from the DHCP log resolves the Windows device.
        let win = classify(&DeviceObservation {
            mac: "e4:1f:d5:f3:2e:42".into(),
            hostname: Some("E1680422".into()),
            vendor_class: Some("MSFT 5.0".into()),
            ..Default::default()
        });
        assert_eq!(win.class, DeviceClass::Computer, "MSFT 5.0 → Windows computer");

        // mDNS model string beats the misleading 'hooksound'→sbc hostname guess.
        let homepod = classify(&DeviceObservation {
            mac: "40:ed:cf:82:62:6b".into(),
            hostname: Some("hooksound".into()),
            models: vec!["AudioAccessory5,1".into()],
            mdns_services: vec!["_hap._tcp".into()],
            ..Default::default()
        });
        assert_eq!(homepod.class, DeviceClass::VoiceAssistant, "HomePod model → voice assistant");
        assert_eq!(homepod.confidence, Confidence::High);
    }

    /// avahi-browse output parses to per-IP services + model hints (md=/model=/am=).
    #[test]
    fn parses_avahi_browse() {
        let text = "=;FTS;IPv4;HomePodSensor;_hap._tcp;local;hooksound.local;10.200.0.12;55235;\"md=HomePod\" \"c#=2\"\n\
                    =;FTS;IPv4;name;AirTunes;local;hooksound.local;10.200.0.12;7000;\"am=AudioAccessory5,1\"\n";
        let hosts = parse_avahi_browse(text);
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ip, "10.200.0.12");
        assert!(hosts[0].services.contains(&"_hap._tcp".to_string()));
        assert!(hosts[0].models.iter().any(|m| m == "HomePod"));
        assert!(hosts[0].models.iter().any(|m| m == "AudioAccessory5,1"));
    }

    /// The dnsmasq DHCP log pairs hostname↔vendor-class by request id, strips domains.
    #[test]
    fn parses_dnsmasq_dhcp_log() {
        let text = "Jun 30 09:07:21 h dnsmasq-dhcp[2548]: 1102032030 client provides name: E1680422\n\
                    Jun 30 09:07:25 h dnsmasq-dhcp[2548]: 1102032030 vendor class: MSFT 5.0\n\
                    Jun 30 09:07:25 h dnsmasq-dhcp[2548]: 1102032030 client provides name: E1680422.internal.vodafone.com\n";
        let pairs = parse_dnsmasq_dhcp_log(text);
        assert!(pairs.iter().any(|(n, v)| n == "E1680422" && v == "MSFT 5.0"));
    }

    /// `enrich` merges mDNS (by IP) and vendor-class (by hostname) into observations.
    #[test]
    fn enrich_merges_by_ip_and_hostname() {
        let mut obs = vec![DeviceObservation {
            mac: "40:ed:cf:82:62:6b".into(), ip: Some("10.200.0.12".into()),
            hostname: Some("hooksound".into()), ..Default::default()
        }];
        let mdns = vec![MdnsHost { ip: "10.200.0.12".into(), services: vec!["_hap._tcp".into()], models: vec!["HomePod".into()] }];
        let dhcp = vec![("hooksound".to_string(), "udhcp 1.0".to_string())];
        enrich(&mut obs, &mdns, &dhcp);
        assert!(obs[0].models.contains(&"HomePod".to_string()));
        assert_eq!(obs[0].vendor_class.as_deref(), Some("udhcp 1.0"));
        assert_eq!(classify(&obs[0]).class, DeviceClass::VoiceAssistant);
    }

    /// `oui_vendor` — the plain-label lookup the scan-responder's enrichment uses directly.
    #[test]
    fn oui_vendor_recognizes_universal_mac() {
        assert_eq!(oui_vendor("dc:a6:32:a4:b6:87"), Some("Raspberry Pi"));
        assert_eq!(oui_vendor("9c:8e:cd:11:22:33"), Some("Amcrest"));
    }

    /// A randomized (locally-administered) MAC must NEVER get a guessed OUI vendor, even if its
    /// low 3 octets happen to collide with a table entry — the flag matters more than a guess.
    #[test]
    fn oui_vendor_none_for_randomized_mac() {
        assert_eq!(oui_vendor("c2:01:b1:72:4d:dc"), None, "c2:.. is locally-administered");
    }

    /// Unrecognized universal OUI / empty MAC → None, not a panic.
    #[test]
    fn oui_vendor_none_for_unknown_or_empty() {
        assert_eq!(oui_vendor("00:11:22:33:44:55"), None);
        assert_eq!(oui_vendor(""), None);
    }

    /// The live N100 lease format parses into observations (mac + hostname).
    #[test]
    fn parses_dnsmasq_leases() {
        let text = "1782839711 c2:01:b1:72:4d:dc 10.200.0.10 iPhone 01:c2:01:b1:72:4d:dc\n\
                    1782842845 e4:1f:d5:f3:2e:42 10.200.0.11 * 01:e4:1f:d5:f3:2e:42\n";
        let obs = observations_from_dnsmasq_leases(text);
        assert_eq!(obs.len(), 2);
        assert_eq!(obs[0].mac, "c2:01:b1:72:4d:dc");
        assert_eq!(obs[0].hostname.as_deref(), Some("iPhone"));
        assert_eq!(obs[1].hostname, None, "'*' hostname → None");
    }
}
