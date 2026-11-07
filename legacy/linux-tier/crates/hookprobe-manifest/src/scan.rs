//! Scanner / probert-style raw hardware scan types.
//!
//! These are the INPUT to the bootstrap generator (read from
//! `manifest/fixtures/*.profile.json`). They differ from the manifest types:
//! - `ScanInterface` carries a `driver` field (stripped in the manifest output).
//! - Wifi/Lte are shared with the manifest output (passed through as-is).
//!
//! The real hardware probe is a future impl; see the `Scanner` trait in
//! `bootstrap/src/main.rs`.  // TODO: real probe (lshw/DT/DMI/ethtool/iw/TPM)

use serde::{Deserialize, Serialize};

use crate::types::{Arch, InterfaceRole, InterfaceType, Lte, Npu, SecureBoot, StorageDevice, Tpm, Wifi};

/// Wrapper that mirrors the `{ "scan": { ... } }` fixture file layout.
#[derive(Debug, Deserialize)]
pub struct ScanProfile {
    pub scan: HardwareScan,
}

/// Raw hardware facts as emitted by the scanner (probert-style).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareScan {
    #[serde(default)]
    pub device_tree_compatible: Vec<String>,
    pub dmi: Option<DmiInfo>,
    pub arch: Arch,
    pub cpu: ScanCpu,
    pub memory_mb: u64,
    /// Kernel release (uname `-r`, e.g. "6.1.0-49-arm64"). Probed once; drives `bpf_stateful`
    /// (the eBPF conntrack fast-path needs ≥ 5.19). Absent ⇒ conservative (software floor).
    #[serde(default)]
    pub kernel_release: Option<String>,
    pub storage: Vec<StorageDevice>,
    pub tpm: Tpm,
    pub secure_boot: SecureBoot,
    pub npu: Npu,
    pub virt: String,
    pub interfaces: Vec<ScanInterface>,
    pub wifi: Wifi,
    pub lte: Lte,
    /// PCI/USB network-class devices that are PRESENT but have NO driver bound —
    /// hardware this image can't drive (missing kernel module / firmware). An
    /// immutable signed image can't ship every driver, so these are surfaced as a
    /// deploy PREREQUISITE ("bake the driver for X"), never silently ignored.
    #[serde(default)]
    pub unbound: Vec<UnboundDevice>,
}

/// A present-but-undriven network device (the kernel sees it; no driver is bound,
/// so it never becomes a usable interface).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnboundDevice {
    pub bus: String,   // "pci" | "usb"
    pub id: String,    // "vvvv:pppp"
    pub class: String, // ethernet | network-other | comm/modem | wireless
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCpu {
    pub model: String,
    pub cores: u32,
}

/// Raw DMI fields (may contain blank/"Default string" values).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmiInfo {
    pub sys_vendor: Option<String>,
    pub product_name: Option<String>,
    pub board_name: Option<String>,
}

/// Scanner interface — includes `driver` which is stripped from manifest output.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ScanInterface {
    pub name: String,
    pub mac: Option<String>,
    #[serde(rename = "type")]
    pub iface_type: InterfaceType,
    /// NIC driver name (e.g. "igc", "stmmac"). Used for known-good NIC checks.
    #[serde(default)]
    pub driver: Option<String>,
    #[serde(default)]
    pub supported_modes: Vec<String>,
    #[serde(default = "default_role")]
    pub role: InterfaceRole,
    /// Explicit fail_mode from scanner; if absent for inline, bootstrap defaults to "fail-open".
    pub fail_mode: Option<String>,
    #[serde(default = "default_state")]
    pub state: String,
    /// Bus the NIC sits on: `sdio`/`mmc` (Pi onboard radio), `usb`, `pci`, `platform`.
    /// Stable across reboots — used to tell the onboard radio from add-on radios.
    #[serde(default)]
    pub bus: Option<String>,
    /// True for the SoC's built-in radio (Pi `brcmfmac` on SDIO / a Pi MAC OUI).
    /// The onboard radio defaults to STATION, add-on radios to AP — decided by THIS
    /// flag, never by the unstable `wlanN` name (which reorders across reboots).
    #[serde(default)]
    pub onboard: bool,
    /// Wi-Fi band(s) the radio supports, by STABLE phy capability (not the `wlanN`
    /// name): "2.4", "5", "6", or a combo like "2.4+5" for a dual-band single radio.
    /// `None` for non-Wi-Fi NICs or when `iw` is unavailable at probe time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub band: Option<String>,
    /// Real per-board hardware-PTP fact (base-tier-build-ticket.md Phase 0 §5 / Phase 3,
    /// ADR 0031 §B): does THIS interface report **hardware** rx/tx timestamping
    /// (`SOF_TIMESTAMPING_TX_HARDWARE`/`SOF_TIMESTAMPING_RX_HARDWARE`) **and** a bound PTP
    /// Hardware Clock (PHC) index via `ethtool -T <iface>`? Read-only, best-effort — a
    /// missing `ethtool`, a missing interface, or a command failure all degrade to `false`,
    /// NEVER `true` (no-fabricated-capabilities discipline, same as `npu.driver_ready`).
    /// Feeds the `ptp_hw` capability token (`capabilities::compute_one`); default `false`
    /// so pre-Phase-3 fixtures without this field still parse safely.
    #[serde(default)]
    pub hw_timestamping: bool,
}

fn default_role() -> InterfaceRole {
    InterfaceRole::Unassigned
}

fn default_state() -> String {
    "unknown".to_string()
}
