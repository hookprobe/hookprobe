//! T2 gate-ladder harness (verification-engineer, ADR 0034 validation, 2026-07-11).
//! Renders REAL hostapd confs via the exact same `wifi_cfg::render` production path, for the
//! two shapes the W2 (D12) regression gate must prove:
//!   1. UNRESOLVED regdomain (country: None -> sanitizes to "00") -> country_code line OMITTED.
//!   2. RESOLVED regdomain (country: Some("RO")) -> country_code=RO + ieee80211d=1 present.
//! Writes both confs to the given output directory (default: /tmp/hp-wifi-gate) so an external
//! `hostapd -dd -t <conf>` dry-parse can run against them (this binary does not itself invoke
//! hostapd — kept dependency-free / no shell-out from Rust).
use hookprobe_manifest::types::WifiRadio;
use hookprobe_manifest::wifi_cfg::{render, ApIntent, WifiIntent};

const DEV: &str = "hp-0000000000000000000000000000000000000000";

fn main() {
    let outdir = std::env::args().nth(1).unwrap_or_else(|| "/tmp/hp-wifi-gate".to_string());
    std::fs::create_dir_all(&outdir).expect("mkdir outdir");

    let radios = vec![WifiRadio { name: "wlan0".into(), role: "ap".into(), band: Some("5".into()) }];

    // 1. Unresolved (no country set -> sanitizes to "00" -> D12 omits country_code/ieee80211d).
    let intent_unresolved = WifiIntent {
        station: None,
        ap: Some(ApIntent {
            ssid: Some("HP-Gate-Unresolved".into()),
            passphrase: "gatepass1234".into(),
            channel: Some(36),
            ..Default::default()
        }),
        country: None,
    };
    let files = render(&radios, &intent_unresolved, DEV);
    let unresolved_path = format!("{outdir}/hostapd-unresolved.conf");
    std::fs::write(&unresolved_path, &files[0].content).expect("write unresolved conf");
    println!("wrote {unresolved_path}");

    // 2. Resolved (country: RO -> D12 emits country_code=RO + ieee80211d=1 + intended VHT80 band).
    let intent_resolved = WifiIntent {
        station: None,
        ap: Some(ApIntent {
            ssid: Some("HP-Gate-Resolved".into()),
            passphrase: "gatepass1234".into(),
            channel: Some(36),
            ..Default::default()
        }),
        country: Some("RO".into()),
    };
    let files = render(&radios, &intent_resolved, DEV);
    let resolved_path = format!("{outdir}/hostapd-resolved.conf");
    std::fs::write(&resolved_path, &files[0].content).expect("write resolved conf");
    println!("wrote {resolved_path}");

    // 3. NEGATIVE CONTROL: hand-craft a conf that explicitly emits the forbidden `country_code=00`
    //    (what the OLD, pre-D12 behaviour used to produce) — this MUST fail hostapd's dry-parse,
    //    proving the T2 gate can actually detect a regression back to the old behaviour.
    let negative = files[0]
        .content
        .replace("country_code=RO\nieee80211d=1\n", "country_code=00\nieee80211d=1\n");
    let negative_path = format!("{outdir}/hostapd-negative-control-00.conf");
    std::fs::write(&negative_path, &negative).expect("write negative-control conf");
    println!("wrote {negative_path}");
}
