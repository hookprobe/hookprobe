//! `GET /api/capabilities` — what this device can do, so Mission Control greys out (with the reason) or hides what
//! it cannot (UI contract from the Mission Control session, 2026-11-10):
//!   {"source":"manifest","schema":2,"granted":[ids],"denied":{id: one-line operator-facing reason}}
//! Every entry is a FACT of this build / this hardware, not a guess: runtime facts (the Wi-Fi AP actually came up,
//! WPA3 is configured) are set by the bring-up code; the denials carry the measured reason (metal evidence).

use crate::mcstate::JsonBuf;
use core::sync::atomic::{AtomicBool, Ordering::Relaxed};

static WIFI_AP: AtomicBool = AtomicBool::new(false);
static WPA3: AtomicBool = AtomicBool::new(false);

/// The Wi-Fi AP is beaconing (set by the AP bring-up).
pub fn set_wifi_ap(up: bool) {
    WIFI_AP.store(up, Relaxed);
}
/// The AP runs a WPA3 mode (SAE + PMF).
pub fn set_wpa3(on: bool) {
    WPA3.store(on, Relaxed);
}

/// Always granted on heqk: the detection plane, Shield, the WAN uplink, DHCP + the DNS forwarder, per-device trust
/// and segmentation (in-kernel), IPv6, owner alerts, signed OS updates.
const ALWAYS: &[&str] = &["ids", "dns_filtering", "wan", "dhcp", "dns", "segmentation", "device_trust", "ipv6", "alerts", "os_update"];

/// Not available on this hardware / firmware — with the reason the owner sees.
const DENIED: &[(&str, &str)] = &[
    ("openvswitch", "Not used: heqk enforces segmentation in its own kernel, no Open vSwitch"),
    ("multi_wan", "One WAN port on this hardware"),
    ("guest_ssid", "This Wi-Fi firmware cannot run a second network; use an internet-only device policy instead"),
    ("lte_wan", "No cellular modem support yet"),
    ("planner", "No AI planner is configured on this device"),
];

/// The granted ids, in order, through `f`.
pub fn for_each_granted(f: &mut dyn FnMut(&str)) {
    for id in ALWAYS {
        f(id);
    }
    if WIFI_AP.load(Relaxed) {
        f("wifi_ap");
    }
    if WPA3.load(Relaxed) {
        f("wpa3");
    }
}

/// `["ids",...]`
pub fn render_granted(w: &mut JsonBuf) {
    w.raw("[");
    let mut first = true;
    for_each_granted(&mut |id| {
        if !first {
            w.raw(",");
        }
        first = false;
        w.string(id);
    });
    w.raw("]");
}

/// The whole manifest document.
pub fn render(w: &mut JsonBuf) {
    w.raw("{\"source\":\"manifest\",\"schema\":2,\"granted\":");
    render_granted(w);
    w.raw(",\"denied\":{");
    let mut first = true;
    for (id, why) in DENIED {
        if *id == "wifi_ap" && WIFI_AP.load(Relaxed) {
            continue;
        }
        if !first {
            w.raw(",");
        }
        first = false;
        w.string(id);
        w.raw(":");
        w.string(why);
    }
    if !WIFI_AP.load(Relaxed) {
        if !first {
            w.raw(",");
        }
        w.raw("\"wifi_ap\":\"No Wi-Fi access point on this device or build\"");
    }
    w.raw("}}");
}

/// [P-caps]
pub fn selftest() -> bool {
    let mut b = [0u8; 1024];
    let mut w = JsonBuf::new(&mut b[..]);
    set_wifi_ap(false);
    render(&mut w);
    let n = w.len;
    let s = core::str::from_utf8(&b[..n]).unwrap_or("");
    let off = s.starts_with("{\"source\":\"manifest\",\"schema\":2,\"granted\":[\"ids\",") && s.contains("\"wifi_ap\":\"No Wi-Fi") && !s.contains("\"wifi_ap\",") && s.ends_with("}}");
    let mut b2 = [0u8; 1024];
    let mut w2 = JsonBuf::new(&mut b2[..]);
    set_wifi_ap(true);
    set_wpa3(true);
    render(&mut w2);
    let n2 = w2.len;
    let s2 = core::str::from_utf8(&b2[..n2]).unwrap_or("");
    let on = s2.contains("\"wifi_ap\",\"wpa3\"]") && !s2.contains("\"wifi_ap\":") && s2.contains("\"guest_ssid\":\"This Wi-Fi firmware");
    set_wifi_ap(false);
    set_wpa3(false);
    let pass = off && on;
    arch_aarch64::_print(format_args!(
        " [P-caps] {} — GET /api/capabilities (UI contract: source manifest, schema 2, granted ids, denied id -> reason): no AP -> wifi_ap denied with a reason={} | AP + WPA3 up -> granted, guest_ssid denied with the measured firmware reason={}\n",
        if pass { "PASS" } else { "FAIL" }, off, on
    ));
    pass
}
