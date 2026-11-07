//! WiFi station/AP role assignment by STABLE identity (driver/bus/onboard), NEVER
//! by the kernel-assigned `wlanN` name — which reorders across reboots (USB vs SDIO
//! enumeration timing).
//!
//! **Role policy (operator rule, 2026-06-30):**
//!   - The **INTERNAL** radio — Pi 4 / CM5 onboard (`brcmfmac`/SDIO) and any PCIe card on a
//!     fixed router (e.g. the N100's `ath12k`) → **ALWAYS AP**. It serves the local trusted
//!     bubble; it is NEVER a station uplink.
//!   - An **EXTERNAL USB dongle** (`bus == usb`, e.g. `rtl88XXau`) → **STATION** — the uplink
//!     to external / untrusted ("rogue") networks (coffee shop / hotel / airplane). This is the
//!     portable-SASE-edge pattern: onboard = the bubble, the dongle = the way out.
//!   - A device with only internal radios + no wired/cellular/dongle has an AP bubble but **no
//!     Wi-Fi uplink** — the uplink must be a wired port, a cellular modem, or a USB dongle.
//!   - (future, capability-gated) a concurrent-AP+STA-capable onboard radio (some dual-radio
//!     CM5) MAY additionally run a station on a second band ("2.4 GHz AP + 5 GHz STA").
//!
//! The signal is the BUS, not `onboard`: a PCIe router radio is `onboard=false` yet must stay an
//! AP, so keying station-role on `bus == usb` (an external dongle) is what's correct.
//! Pin the interface NAMES too (see `base/network/`) so hostapd/wpa_supplicant bind to a stable
//! name regardless of boot order.

use crate::scan::ScanInterface;
use crate::types::InterfaceType;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WifiRole {
    Station,
    Ap,
}
impl WifiRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            WifiRole::Station => "station",
            WifiRole::Ap => "ap",
        }
    }
}

/// True if the device has any non-Wi-Fi uplink (a wired port or a cellular modem).
/// When it does, Wi-Fi radios serve as **APs**; only a device with no other way
/// online turns a radio into the station uplink.
pub fn has_nonwifi_uplink(interfaces: &[ScanInterface], lte_present: bool) -> bool {
    lte_present
        || interfaces.iter().any(|i| {
            i.iface_type == InterfaceType::Ethernet || i.iface_type == InterfaceType::Lte
        })
}

/// True if a radio is an EXTERNAL USB dongle — the station-uplink role. Keyed on the bus
/// (a USB dongle), not `onboard`: a PCIe router radio is `onboard=false` but must stay an AP.
fn is_external_dongle(i: &ScanInterface) -> bool {
    !i.onboard && i.bus.as_deref() == Some("usb")
}

/// Assign a role to each Wi-Fi radio from STABLE identity, ignoring `wlanN`.
///
/// Per the operator role policy (see module docs):
/// - INTERNAL radios (onboard SDIO `brcmfmac`, or any PCIe card) → **AP** — always. The N100's
///   2.4 + 5 GHz PCIe radios run as a band-steered dual-band AP; the Pi/CM5 onboard is an AP.
/// - EXTERNAL USB dongles (`bus == usb`) → **STATION** — the uplink to external/rogue networks.
///
/// `has_nonwifi_uplink` is accepted for call-site compatibility but no longer changes the role:
/// the internal radio is an AP whether or not a wired/cellular uplink exists, and the USB dongle
/// is the station regardless (it's a failover uplink alongside wired/cellular — see
/// `enumerate_uplinks`).
pub fn assign_wifi_roles(
    interfaces: &[ScanInterface],
    _has_nonwifi_uplink: bool,
) -> Vec<(String, WifiRole)> {
    let mut wifis: Vec<&ScanInterface> = interfaces
        .iter()
        .filter(|i| i.iface_type == InterfaceType::Wifi)
        .collect();
    wifis.sort_by(|a, b| a.name.cmp(&b.name)); // deterministic ordering

    wifis
        .iter()
        .map(|i| {
            // External USB dongle = STATION uplink; internal (onboard/PCIe) = AP.
            let role = if is_external_dongle(i) { WifiRole::Station } else { WifiRole::Ap };
            (i.name.clone(), role)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Unified uplink model — the "Get Online" view (one list of every WAN candidate).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UplinkKind {
    Wired,
    WifiStation,
    Cellular,
}
impl UplinkKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            UplinkKind::Wired => "wired",
            UplinkKind::WifiStation => "wifi-station",
            UplinkKind::Cellular => "cellular",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Uplink {
    pub name: String,
    pub kind: UplinkKind,
    /// Failover priority — lower = preferred.
    pub priority: u32,
}

/// Hardware class of a wired NIC for default-WAN selection — lower = the enclosure's more
/// "primary" port. The systemd predictable interface NAME encodes the hardware topology, so
/// classing by name prefix is hardware-topology-based and matches the enclosure labels
/// deterministically. On RPi5/CM5 the labelled MAIN port (the RP1 ONBOARD Gigabit, the documented
/// `eth0` rename) is `end0`; a PCIe-attached NIC is `enP1p1s0`/`enp*` (the 2nd+ ports); USB is
/// `enx*`. This is the fix for the 2026-07-09 CM5 bug where a raw name sort made `enP1p1s0` (the
/// 2nd port) beat `end0` (the labelled 1st/main port) and bound the WAN to the wrong socket.
fn nic_hw_class(name: &str) -> u8 {
    if name.starts_with("end") || name.starts_with("eth") || name.starts_with("eno") {
        0 // onboard / platform NIC — the labelled main port (eth0)
    } else if name.starts_with("enp") || name.starts_with("enP") {
        1 // PCIe-attached NIC — the 2nd+ ports (eth1…)
    } else if name.starts_with("enx") {
        2 // USB NIC (`enx<mac>`)
    } else {
        3 // anything else last
    }
}

/// Link penalty for the WAN sort: a carrier-UP port sorts before a carrier-DOWN one, but only as a
/// tiebreaker WITHIN a hardware class (class dominates, so the labelled main port stays the default
/// WAN even if probed before link-up — the CM5 first-boot timing case).
fn link_penalty(i: &ScanInterface) -> u8 {
    if i.state.eq_ignore_ascii_case("up") {
        0
    } else {
        1
    }
}

/// Enumerate WAN uplink candidates (the "Get Online" / single-pane view): every
/// wired port, the onboard Wi-Fi in station mode, and the cellular modem — in
/// default failover priority (wired > Wi-Fi-station > cellular). `multi_wan` picks
/// and fails over between them; the operator can override the priority.
pub fn enumerate_uplinks(interfaces: &[ScanInterface], lte_present: bool) -> Vec<Uplink> {
    use crate::types::InterfaceRole;
    // A WAN candidate must be a normal forwarding port — never an interface already
    // committed to a non-WAN role: an out-of-band IDS tap or an inline IDS element must
    // not also be advertised as a route to the internet (it would make one NIC both the
    // WAN route AND a LAN/mirror port). This keeps the WAN set and the fabric LAN set disjoint.
    let is_wan_eligible = |i: &ScanInterface| {
        !matches!(i.role, InterfaceRole::OutOfBand | InterfaceRole::Inline | InterfaceRole::Mgmt)
    };
    let mut out = Vec::new();
    // ROUTER PORT POLICY (operator instruction 2026-07-09): "1st port WAN, LAN others; if only one
    // port, WAN only." The FIRST wired port is the WAN uplink; EVERY OTHER wired port is a LAN
    // switch port (a fabric bridge member — `fabric::plan` leaves the WAN uplink OFF the bridge and
    // makes the rest members), NOT a failover WAN uplink. "First" = the labelled MAIN port by
    // HARDWARE CLASS (onboard `end0`/`eth0` before PCIe `enP1p1s0`/`enp*` before USB `enx*`),
    // carrier-up preferred WITHIN a class — see the `wired.sort_by` below. This is the 2026-07-09
    // CM5 fix: a raw name sort put `enP1p1s0` (the 2nd port, `P`<`d`) before `end0` (the labelled
    // 1st/main port) and bound the WAN to the wrong socket. Connect WAN to the enclosure's 1st
    // (onboard) port and it is always the WAN. (Wi-Fi-STATION dongle + cellular remain genuine
    // FAILOVER uplinks below — those are never LAN switch ports; only extra WIRED ports become LAN.)
    let mut wired: Vec<&ScanInterface> = interfaces
        .iter()
        .filter(|i| i.iface_type == InterfaceType::Ethernet && is_wan_eligible(i))
        .collect();
    wired.sort_by(|a, b| {
        // Order by HARDWARE CLASS (dominant), then link, then name — NOT the raw name string. The
        // physical port the enclosure labels `eth0` follows the hardware topology; the kernel
        // interface NAMES do not sort in that order. On RPi5/CM5 the RP1 ONBOARD Gigabit (the
        // documented rename of `eth0`, the MAIN port) is **`end0`**, while a PCIe-attached NIC gets
        // a PCI-path name like **`enP1p1s0`** (the 2nd port) and USB NICs get `enx<mac>`. Sorting by
        // name put `enP1p1s0` before `end0` (`P` < `d` in ASCII) and wrongly made the 2nd port the
        // WAN — the 2026-07-09 CM5 bug (operator's cable on eth0=`end0`, WAN bound to eth1=
        // `enP1p1s0`). Hardware class DOMINATES so the onboard main port is always the default WAN;
        // carrier-up and name only break ties WITHIN a class.
        nic_hw_class(&a.name)
            .cmp(&nic_hw_class(&b.name))
            .then_with(|| link_penalty(a).cmp(&link_penalty(b)))
            .then_with(|| a.name.cmp(&b.name))
    });
    if let Some(primary) = wired.first() {
        out.push(Uplink { name: primary.name.clone(), kind: UplinkKind::Wired, priority: 10 });
    }
    // The Wi-Fi STATION uplink is the EXTERNAL USB dongle (internal radios are APs, never WAN
    // candidates). Per the role policy the dongle is a station regardless of a wired/cellular
    // path — it's a first-class FAILOVER uplink (the portable edge's way out on a rogue net),
    // so include it always; multi_wan orders wired > Wi-Fi-station > cellular (operator-overridable).
    let has_nonwifi = has_nonwifi_uplink(interfaces, lte_present);
    for (sta, _) in assign_wifi_roles(interfaces, has_nonwifi)
        .into_iter()
        .filter(|(_, r)| *r == WifiRole::Station)
    {
        out.push(Uplink { name: sta, kind: UplinkKind::WifiStation, priority: 20 });
    }
    if lte_present || interfaces.iter().any(|i| i.iface_type == InterfaceType::Lte) {
        let name = interfaces
            .iter()
            .find(|i| i.iface_type == InterfaceType::Lte)
            .map(|i| i.name.clone())
            .unwrap_or_else(|| "cellular".to_string());
        out.push(Uplink { name, kind: UplinkKind::Cellular, priority: 30 });
    }
    // Order: (1) uplink class + link-state via `priority` (carrier-up wired 8 > carrier-down wired
    // 12 > Wi-Fi-station 20 > cellular 30), then (2) a DETERMINISTIC name tiebreaker so the default
    // WAN is always the "first port" (eth0 before eth1, enP1p1s0/port-1 before enP1p2s0/port-2) and
    // never left to nondeterministic sysfs scan order. multi_wan takes the head of this list as the
    // primary WAN. (Operator intent 2026-07-09: the WAN default is the 1st, connected port.)
    out.sort_by(|a, b| a.priority.cmp(&b.priority).then_with(|| a.name.cmp(&b.name)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::InterfaceRole;

    fn wifi(name: &str, driver: &str, bus: &str, onboard: bool) -> ScanInterface {
        wifi_band(name, driver, bus, onboard, None)
    }
    fn wifi_band(name: &str, driver: &str, bus: &str, onboard: bool, band: Option<&str>) -> ScanInterface {
        ScanInterface {
            name: name.into(),
            mac: None,
            iface_type: InterfaceType::Wifi,
            driver: Some(driver.into()),
            supported_modes: vec![],
            role: InterfaceRole::Unassigned,
            fail_mode: None,
            state: "up".into(),
            bus: Some(bus.into()),
            onboard,
            band: band.map(|b| b.into()),
            hw_timestamping: false,
        }
    }

    /// Operator rule: the USB dongle (`wlan0`, bus=usb) is the STATION uplink; the onboard
    /// `brcmfmac` (`wlan1`) is an AP — regardless of `wlanN` ordering or any wired/cellular path.
    #[test]
    fn usb_dongle_is_station_onboard_is_ap() {
        let ifaces = vec![
            wifi("wlan0", "rtl88XXau", "usb", false), // USB dongle → STATION
            wifi("wlan1", "brcmfmac", "sdio", true),  // onboard → AP
        ];
        // role is independent of has_nonwifi_uplink now — assert both ways
        for hn in [false, true] {
            let roles = assign_wifi_roles(&ifaces, hn);
            let role_of = |n: &str| roles.iter().find(|(x, _)| x == n).map(|(_, r)| *r);
            assert_eq!(role_of("wlan0"), Some(WifiRole::Station), "USB dongle must be STATION");
            assert_eq!(role_of("wlan1"), Some(WifiRole::Ap), "onboard must be AP");
        }
    }

    /// Dual-radio ROUTER (the N100): a wired/cellular uplink exists, so BOTH radios are
    /// APs (band-steered 2.4 + 5 GHz). Neither becomes a station.
    #[test]
    fn both_radios_ap_when_nonwifi_uplink_exists() {
        let ifaces = vec![
            wifi_band("wlan_24ghz", "ath12k_pci", "pci", false, Some("2.4")),
            wifi_band("wlan_5ghz", "ath12k_pci", "pci", false, Some("5")),
        ];
        let roles = assign_wifi_roles(&ifaces, /* has_nonwifi_uplink */ true);
        assert!(roles.iter().all(|(_, r)| *r == WifiRole::Ap), "every radio must be AP: {roles:?}");
    }

    /// A device with ONLY an internal radio (no dongle/wired/cellular): the onboard radio is an
    /// AP bubble with NO Wi-Fi uplink (the uplink must be external — wired/cellular/USB dongle).
    #[test]
    fn single_onboard_is_ap_no_wifi_uplink() {
        let ifaces = vec![wifi("wlan0", "brcmfmac", "sdio", true)];
        assert_eq!(
            assign_wifi_roles(&ifaces, false),
            vec![("wlan0".to_string(), WifiRole::Ap)]
        );
        assert!(
            enumerate_uplinks(&ifaces, false).is_empty(),
            "an onboard AP is a bubble, not a WAN candidate"
        );
    }

    fn eth(name: &str) -> ScanInterface {
        ScanInterface {
            name: name.into(), mac: None, iface_type: InterfaceType::Ethernet,
            driver: Some("igc".into()), supported_modes: vec![],
            role: InterfaceRole::Unassigned, fail_mode: None, state: "up".into(),
            bus: Some("pci".into()), onboard: false, band: None,
            hw_timestamping: false,
        }
    }
    fn lte(name: &str) -> ScanInterface {
        ScanInterface {
            name: name.into(), mac: None, iface_type: InterfaceType::Lte,
            driver: Some("cdc_mbim".into()), supported_modes: vec![],
            role: InterfaceRole::Unassigned, fail_mode: None, state: "unknown".into(),
            bus: Some("usb".into()), onboard: false, band: None,
            hw_timestamping: false,
        }
    }

    /// CM5-IO board port-mapping regression (2026-07-09, corrected by the operator): the CM5 has
    /// TWO ethernet ports and the RPi kernel names them by HARDWARE topology — `end0` is the RP1
    /// ONBOARD Gigabit = the enclosure-labelled MAIN port (eth0, where the WAN cable goes), and
    /// `enP1p1s0` is the PCIe-path 2nd port (eth1). A raw name sort put `enP1p1s0` before `end0`
    /// (`P`<`d` in ASCII) and bound the WAN to the WRONG socket → the "phone connected but no
    /// internet" bug (WAN on the free eth1 while the cable was on eth0). The WAN MUST be the onboard
    /// main port `end0`. Scan order lists `enP1p1s0` FIRST (as on metal) to prove HARDWARE CLASS —
    /// not name, not scan order — decides. Carrier state is deliberately the WORST case for the fix
    /// (onboard `end0` probed DOWN, PCIe `enP1p1s0` UP): class still dominates, because the operator
    /// contract is "WAN on the 1st/onboard port" and boot-probe link timing must not flip the socket.
    #[test]
    fn cm5_onboard_end0_is_wan_not_pcie_second_port() {
        let mut end0 = eth("end0"); end0.state = "down".into(); end0.onboard = true;
        let enp = eth("enP1p1s0"); // eth() defaults state = "up"
        // Scan order lists the PCIe 2nd port first, exactly as the CM5 kernel enumerates it.
        let ups = enumerate_uplinks(&[enp, end0], false);
        let wired: Vec<&str> = ups.iter()
            .filter(|u| u.kind == UplinkKind::Wired)
            .map(|u| u.name.as_str())
            .collect();
        // Router policy: EXACTLY ONE wired WAN — the onboard main port. The PCIe 2nd port is a LAN
        // switch port (a fabric bridge member), NOT a WAN uplink.
        assert_eq!(wired, vec!["end0"],
            "onboard main port end0 is WAN; the PCIe 2nd port enP1p1s0 is LAN, got {wired:?}");
    }

    /// "1st port WAN, LAN others": with two BOTH-connected wired ports, the lowest-named is WAN and
    /// the other is LAN (not a second WAN uplink).
    #[test]
    fn two_up_wired_ports_first_is_wan_rest_lan() {
        let ups = enumerate_uplinks(&[eth("eth1"), eth("eth0")], false);
        let wired: Vec<&str> = ups.iter().filter(|u| u.kind == UplinkKind::Wired).map(|u| u.name.as_str()).collect();
        assert_eq!(wired, vec!["eth0"], "1st port (eth0) is the sole WAN; eth1 is LAN, got {wired:?}");
    }

    /// "if only 1 port, WAN only": a single wired NIC is the WAN.
    #[test]
    fn single_wired_port_is_wan() {
        let ups = enumerate_uplinks(&[eth("end0")], false);
        let wired: Vec<&str> = ups.iter().filter(|u| u.kind == UplinkKind::Wired).map(|u| u.name.as_str()).collect();
        assert_eq!(wired, vec!["end0"]);
    }

    /// Router (N100 shape) WITH a USB dongle: the 1st wired port (`eth0`) is the WAN; the USB dongle
    /// (STATION) + cellular are FAILOVER uplinks; the onboard SDIO radio is an AP (never a WAN
    /// candidate). Router policy: the SECOND wired port (`eth1`) is a LAN switch port, NOT a second
    /// WAN uplink — so exactly ONE Wired kind appears (wired > Wi-Fi-station > cellular).
    #[test]
    fn uplinks_one_wired_wan_plus_dongle_and_cellular_failover() {
        let ifaces = vec![
            wifi("wlan0", "rtl88XXau", "usb", false), // USB dongle → STATION failover uplink
            wifi("wlan1", "brcmfmac", "sdio", true),  // onboard → AP (not an uplink)
            eth("eth0"),                               // 1st wired → WAN
            eth("eth1"),                               // 2nd wired → LAN (not a WAN uplink)
            lte("wwan0"),
        ];
        let ups = enumerate_uplinks(&ifaces, true);
        let kinds: Vec<UplinkKind> = ups.iter().map(|u| u.kind).collect();
        assert_eq!(
            kinds,
            vec![UplinkKind::Wired, UplinkKind::WifiStation, UplinkKind::Cellular]
        );
        assert_eq!(ups[0].name, "eth0", "the 1st wired port is the WAN");
        assert!(!ups.iter().any(|u| u.name == "eth1"), "eth1 is a LAN switch port, never a WAN uplink");
    }

    /// Wi-Fi-uplink-only device: the USB dongle (`wlan0`) is the station uplink; the onboard
    /// `brcmfmac` (`wlan1`) is the AP bubble.
    #[test]
    fn wifi_only_device_station_is_usb_dongle() {
        let ifaces = vec![
            wifi("wlan0", "rtl88XXau", "usb", false), // STATION uplink
            wifi("wlan1", "brcmfmac", "sdio", true),  // AP
        ];
        let ups = enumerate_uplinks(&ifaces, false);
        let wifi_up = ups.iter().find(|u| u.kind == UplinkKind::WifiStation).unwrap();
        assert_eq!(wifi_up.name, "wlan0", "the uplink is the USB dongle station, not the onboard AP");
    }
}
