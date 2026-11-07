//! LiveScanner — the REAL, read-only hardware probe.
//!
//! Reads `/proc`, `/sys`, the device-tree, DMI, and net interfaces directly.
//! **Strictly read-only:** opens files for reading only (or shells out to a read-only
//! query tool) and writes nothing and touches no services, so it is safe to run on live
//! production devices. It is almost entirely sysfs/procfs-based and works on a *bare*
//! machine. Two narrow exceptions shell out to read-only query tools when present:
//! Wi-Fi band detection (`iw phy <phy> info`) and per-interface hardware-PTP-timestamping
//! detection (`ethtool -T <iface>`, base-tier-build-ticket.md Phase 3, ADR 0031 §B) — both
//! pure queries, neither mutates any state. If the tool is absent the corresponding fact is
//! simply left unknown/`false` — no other external tool is ever run (no lshw/dmidecode).
//!
//! Ports the detection intelligence proven in V1 `~/hookprobe/install.sh`
//! (detect_architecture / detect_cpu / detect_ram / detect_platform /
//! detect_network_interfaces …) into the V2 manifest pipeline's `scan` profile.
//!
//! Every field degrades gracefully: a missing kernel interface yields a safe
//! default (absent/none/empty), never a panic — so a minimal initramfs probe
//! still produces a valid scan.

use std::fs;
use std::path::Path;

use anyhow::Result;
use hookprobe_manifest::scan::{DmiInfo, HardwareScan, ScanCpu, ScanInterface, UnboundDevice};
use hookprobe_manifest::types::{
    Arch, InterfaceRole, InterfaceType, Lte, Npu, SecureBoot, StorageDevice, Tpm, TpmKind, Wifi,
};

/// Run the full read-only probe and assemble a `HardwareScan`.
pub fn probe() -> Result<HardwareScan> {
    Ok(HardwareScan {
        device_tree_compatible: dt_compatible(),
        dmi: dmi(),
        arch: arch(),
        cpu: cpu(),
        memory_mb: mem_mb(),
        kernel_release: kernel_release(),
        storage: storage(),
        tpm: tpm(),
        secure_boot: secure_boot(),
        npu: npu(),
        virt: virt(),
        interfaces: interfaces(),
        wifi: wifi(),
        lte: lte(),
        unbound: unbound_devices(),
    })
}

/// Kernel release (uname `-r`), from `/proc/sys/kernel/osrelease`. Drives the inspect ladder's
/// `bpf_stateful` gate (eBPF conntrack fast-path needs ≥ 5.19). Read-only; None if unavailable.
fn kernel_release() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Hardware PRESENT on the bus but with NO driver bound — a network/wireless/modem
/// OR AI-accelerator device the running image can't drive (the deploy prerequisite).
/// Read-only.
fn unbound_devices() -> Vec<UnboundDevice> {
    let mut out = Vec::new();

    // PCI: class 0x02xxxx = network controller. No `driver` symlink ⇒ unbound.
    if let Ok(entries) = fs::read_dir("/sys/bus/pci/devices") {
        for e in entries.flatten() {
            let dev = e.path();
            let class = read_hex(dev.join("class")).unwrap_or(0);
            let top = class >> 16;
            if top != 0x02 && top != 0x12 {
                continue; // not a network controller (0x02) or AI accelerator (0x12)
            }
            if dev.join("driver").exists() {
                continue; // already driven
            }
            let vendor = read_trim(dev.join("vendor")).unwrap_or_default();
            let device = read_trim(dev.join("device")).unwrap_or_default();
            out.push(UnboundDevice {
                bus: "pci".to_string(),
                id: format!(
                    "{}:{}",
                    vendor.trim_start_matches("0x"),
                    device.trim_start_matches("0x")
                ),
                class: if top == 0x12 {
                    "ai-accelerator".to_string()
                } else {
                    match (class >> 8) & 0xff {
                        0x00 => "ethernet",
                        0x80 => "network-other",
                        _ => "network",
                    }
                    .to_string()
                },
                path: e.file_name().to_string_lossy().to_string(),
            });
        }
    }

    // USB: an interface whose class is Communications (0x02 = modems/CDC) or Wireless
    // Controller (0xe0), with no driver bound. (0xff vendor-specific is skipped — too
    // broad to flag reliably as network.)
    let mut seen = std::collections::HashSet::new();
    if let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !name.contains(':') {
                continue; // only interface entries (dev:cfg.intf)
            }
            let intf = e.path();
            let cls = read_hex(intf.join("bInterfaceClass")).unwrap_or(0xffff);
            if !matches!(cls, 0x02 | 0xe0) {
                continue;
            }
            if intf.join("driver").exists() {
                continue;
            }
            let parent = name.split(':').next().unwrap_or("").to_string();
            let pdir = Path::new("/sys/bus/usb/devices").join(&parent);
            let id = format!(
                "{}:{}",
                read_trim(pdir.join("idVendor")).unwrap_or_default(),
                read_trim(pdir.join("idProduct")).unwrap_or_default()
            );
            if !seen.insert(id.clone()) {
                continue;
            }
            out.push(UnboundDevice {
                bus: "usb".to_string(),
                id,
                class: if cls == 0x02 { "comm/modem" } else { "wireless" }.to_string(),
                path: parent,
            });
        }
    }
    out
}

/// Read a hex sysfs value (e.g. `0x020000`) as u32.
fn read_hex<P: AsRef<Path>>(p: P) -> Option<u32> {
    let s = read_trim(p)?;
    u32::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

// --- small helpers -----------------------------------------------------------

fn read_trim<P: AsRef<Path>>(p: P) -> Option<String> {
    fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Read a NUL-list device-tree property into trimmed UTF-8 strings.
fn dt_strings<P: AsRef<Path>>(p: P) -> Vec<String> {
    fs::read(p)
        .ok()
        .map(|b| {
            b.split(|&c| c == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

// --- arch --------------------------------------------------------------------

fn arch() -> Arch {
    // The binary runs natively on the device, so its target arch IS the device arch.
    match std::env::consts::ARCH {
        "x86_64" => Arch::Amd64,
        "aarch64" => Arch::Arm64,
        "riscv64" => Arch::Riscv64,
        other => {
            eprintln!("probe: warn: unmapped arch '{other}', defaulting amd64");
            Arch::Amd64
        }
    }
}

// --- cpu ---------------------------------------------------------------------

fn cpu() -> ScanCpu {
    let info = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let mut model = String::new();
    let mut cores: u32 = 0;
    for line in info.lines() {
        if let Some((k, v)) = line.split_once(':') {
            let (k, v) = (k.trim(), v.trim());
            if k == "processor" {
                cores += 1;
            }
            if model.is_empty()
                && matches!(k, "model name" | "Model" | "Hardware" | "cpu model" | "CPU part")
            {
                model = v.to_string();
            }
        }
    }
    if cores == 0 {
        cores = 1;
    }
    if model.is_empty() {
        // ARM boards often omit "model name"; fall back to the device-tree model.
        model = dt_model().unwrap_or_else(|| "Unknown CPU".to_string());
    }
    ScanCpu { model, cores }
}

// --- memory ------------------------------------------------------------------

fn mem_mb() -> u64 {
    let info = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    for line in info.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            return kb / 1024;
        }
    }
    0
}

// --- storage -----------------------------------------------------------------

fn storage() -> Vec<StorageDevice> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/block") else {
        return out;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        // Skip virtual/loopback/zram/device-mapper/raid block devices.
        if ["loop", "ram", "zram", "dm-", "md", "sr", "fd"]
            .iter()
            .any(|p| name.starts_with(p))
        {
            continue;
        }
        let base = e.path();
        // size is in 512-byte sectors.
        let sectors: u64 = read_trim(base.join("size"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if sectors == 0 {
            continue;
        }
        let size_gb = (sectors as f64 * 512.0) / 1e9;
        let rotational = read_trim(base.join("queue/rotational"))
            .map(|s| s == "1")
            .unwrap_or(false);
        let kind = if name.starts_with("nvme") {
            "nvme"
        } else if name.starts_with("mmcblk") {
            "emmc-sd"
        } else if rotational {
            "hdd"
        } else {
            "ssd"
        };
        let serial = read_trim(base.join("device/serial"))
            .or_else(|| read_trim(base.join("device/wwid")))
            .or_else(|| read_trim(base.join("wwid")));
        let removable = read_trim(base.join("removable"))
            .map(|s| s == "1")
            .unwrap_or(false);
        out.push(StorageDevice {
            dev: name,
            size_gb: (size_gb * 10.0).round() / 10.0,
            kind: kind.to_string(),
            serial,
            removable,
        });
    }
    out.sort_by(|a, b| a.dev.cmp(&b.dev));
    out
}

// --- device-tree (ARM) -------------------------------------------------------

fn dt_compatible() -> Vec<String> {
    dt_strings("/proc/device-tree/compatible")
}

fn dt_model() -> Option<String> {
    dt_strings("/proc/device-tree/model").into_iter().next()
}

// --- DMI (x86) ---------------------------------------------------------------

fn dmi() -> Option<DmiInfo> {
    let f = |k: &str| read_trim(format!("/sys/class/dmi/id/{k}"));
    let sys_vendor = f("sys_vendor");
    let product_name = f("product_name");
    let board_name = f("board_name");
    if sys_vendor.is_none() && product_name.is_none() && board_name.is_none() {
        None
    } else {
        Some(DmiInfo {
            sys_vendor,
            product_name,
            board_name,
        })
    }
}

// --- TPM ---------------------------------------------------------------------

fn tpm() -> Tpm {
    let present = Path::new("/sys/class/tpm/tpm0").exists() || Path::new("/dev/tpm0").exists();
    if !present {
        return Tpm {
            present: false,
            version: None,
            kind: TpmKind::None,
        };
    }
    let version = match read_trim("/sys/class/tpm/tpm0/tpm_version_major").as_deref() {
        Some("2") => Some("2.0".to_string()),
        Some("1") => Some("1.2".to_string()),
        _ => None,
    };
    // Discrete vs firmware is not reliably exposed; default firmware (fTPM is
    // the common case on the boards we target). Manifest only needs present+sealed.
    Tpm {
        present: true,
        version,
        kind: TpmKind::Firmware,
    }
}

// --- Secure Boot -------------------------------------------------------------

fn secure_boot() -> SecureBoot {
    let efi = Path::new("/sys/firmware/efi").exists();
    if !efi {
        // Non-UEFI boot (e.g. Raspberry Pi firmware) — Secure Boot N/A.
        return SecureBoot {
            supported: false,
            enabled: false,
        };
    }
    SecureBoot {
        supported: true,
        enabled: efivar_last_byte_is_one("SecureBoot"),
    }
}

fn efivar_last_byte_is_one(name: &str) -> bool {
    let Ok(entries) = fs::read_dir("/sys/firmware/efi/efivars") else {
        return false;
    };
    let prefix = format!("{name}-");
    for e in entries.flatten() {
        if e.file_name().to_string_lossy().starts_with(&prefix) {
            if let Ok(bytes) = fs::read(e.path()) {
                // Layout: 4-byte attributes + data; the SecureBoot value is the last byte.
                return bytes.last().map(|&b| b == 1).unwrap_or(false);
            }
        }
    }
    false
}

// --- NPU / AI accelerator (best-effort, conservative) ------------------------

fn npu() -> Npu {
    // Rockchip RKNPU (e.g. RK3588 — 6 TOPS).
    if Path::new("/proc/device-tree").exists() {
        let has_rknpu = fs::read_dir("/proc/device-tree")
            .map(|d| {
                d.flatten()
                    .any(|e| e.file_name().to_string_lossy().starts_with("npu"))
            })
            .unwrap_or(false)
            || dt_compatible().iter().any(|s| s.contains("rknpu"));
        if has_rknpu {
            let driver_ready =
                Path::new("/dev/rknpu").exists() || Path::new("/sys/kernel/debug/rknpu").exists();
            return Npu {
                present: true,
                driver_ready,
                vendor: Some("rockchip".to_string()),
                model: Some("rknpu".to_string()),
            };
        }
    }
    // PCIe AI accelerator (Hailo / Coral Edge-TPU / MediaTek, or PCI class 0x12
    // "Processing accelerators"). driver_ready = a bound driver; else it's a deploy
    // prerequisite (also flagged in `unbound`). This is how a CM5 + PCIe AI chip is
    // absorbed by the SAME capability model — `edge_ai` grants once it's driver-ready.
    if let Some(acc) = pci_accelerator() {
        return acc;
    }

    // Conservative default: no accelerator detected (correct for Pi/N100).
    Npu {
        present: false,
        driver_ready: false,
        vendor: None,
        model: None,
    }
}

/// Detect a PCIe AI accelerator (NPU). PCI class 0x12xxxx = Processing accelerators,
/// plus known AI-accelerator vendor IDs. Reported even when UNDRIVEN (then
/// `driver_ready=false` and it also appears in `unbound` as a prerequisite).
fn pci_accelerator() -> Option<Npu> {
    for e in fs::read_dir("/sys/bus/pci/devices").ok()?.flatten() {
        let dev = e.path();
        let class = read_hex(dev.join("class")).unwrap_or(0);
        let vendor = read_trim(dev.join("vendor")).unwrap_or_default().to_lowercase();
        let is_accel = (class >> 16) == 0x12
            || matches!(vendor.as_str(), "0x1e60" | "0x1ac1" | "0x1f9f");
        if !is_accel {
            continue;
        }
        let device = read_trim(dev.join("device")).unwrap_or_default();
        let name = match vendor.as_str() {
            "0x1e60" => "hailo",
            "0x1ac1" => "coral-edgetpu",
            "0x1f9f" => "mediatek-npu",
            _ => "pci-accelerator",
        };
        return Some(Npu {
            present: true,
            driver_ready: dev.join("driver").exists(),
            vendor: Some(name.to_string()),
            model: Some(format!(
                "{}:{}",
                vendor.trim_start_matches("0x"),
                device.trim_start_matches("0x")
            )),
        });
    }
    None
}

// --- virtualization ----------------------------------------------------------

fn virt() -> String {
    if let Some(d) = dmi() {
        let hay = format!(
            "{} {} {}",
            d.sys_vendor.unwrap_or_default(),
            d.product_name.unwrap_or_default(),
            d.board_name.unwrap_or_default()
        )
        .to_lowercase();
        for (needle, name) in [
            ("kvm", "kvm"),
            ("qemu", "qemu"),
            ("vmware", "vmware"),
            ("virtualbox", "oracle"),
            ("microsoft corporation", "microsoft"),
            ("xen", "xen"),
            ("bochs", "qemu"),
            ("openstack", "kvm"),
            ("amazon ec2", "aws"),
            ("google", "gce"),
        ] {
            if hay.contains(needle) {
                return name.to_string();
            }
        }
    }
    if Path::new("/.dockerenv").exists() {
        return "docker".to_string();
    }
    if fs::read_to_string("/proc/1/cgroup")
        .map(|s| s.contains("lxc"))
        .unwrap_or(false)
    {
        return "lxc".to_string();
    }
    // Generic hypervisor flag (x86 CPUID hypervisor bit surfaces in cpuinfo flags).
    if fs::read_to_string("/proc/cpuinfo")
        .map(|s| s.lines().any(|l| l.starts_with("flags") && l.contains(" hypervisor")))
        .unwrap_or(false)
    {
        return "vm".to_string();
    }
    "none".to_string()
}

// --- network interfaces ------------------------------------------------------

fn interfaces() -> Vec<ScanInterface> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return out;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if name == "lo" {
            continue;
        }
        let base = e.path();
        let is_wifi = base.join("wireless").exists() || base.join("phy80211").exists();
        let is_wwan = name.starts_with("wwan") || name.starts_with("wwp");
        // A PHYSICAL nic has a `device` symlink; virtual ifaces (veth, bridges,
        // vxlan, tap, docker/podman) do not — this is how we avoid the "25 NICs"
        // over-count seen on the N100 (podman/veth virtuals).
        let has_device = base.join("device").exists();
        if !has_device && !is_wifi && !is_wwan {
            continue;
        }
        // Defensive name-prefix filter for known virtual interfaces.
        if [
            "veth", "docker", "br-", "virbr", "vxlan", "tap", "cni", "podman", "dummy", "bond",
            "ovs", "gre", "sit", "ip6tnl",
        ]
        .iter()
        .any(|p| name.starts_with(p))
        {
            continue;
        }

        let mac = read_trim(base.join("address")).filter(|m| m != "00:00:00:00:00:00");
        let state = read_trim(base.join("operstate")).unwrap_or_else(|| "unknown".to_string());
        let driver = fs::read_link(base.join("device/driver"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()));
        let bus = fs::read_link(base.join("device/subsystem"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()));
        let iface_type = if is_wifi {
            InterfaceType::Wifi
        } else if is_wwan {
            InterfaceType::Lte
        } else {
            InterfaceType::Ethernet
        };
        // Onboard radio (Pi brcmfmac on SDIO / a Pi MAC OUI) — the STABLE discriminator
        // for "default to station". NEVER trust the wlanN name (reorders across reboots).
        let onboard = is_wifi
            && (driver.as_deref() == Some("brcmfmac")
                || matches!(bus.as_deref(), Some("sdio") | Some("mmc"))
                || mac.as_deref().map(is_pi_oui).unwrap_or(false));
        // Band(s) the radio supports — stable phy capability, NOT the wlanN name.
        // Read the phy via /sys, then (gracefully) `iw phy <phy> info`. None if iw absent.
        let band = if is_wifi {
            read_trim(base.join("phy80211/name")).and_then(|phy| wifi_band(&phy))
        } else {
            None
        };
        // Hardware-PTP fact (base-tier-build-ticket.md Phase 0 §5 / Phase 3, ADR 0031 §B):
        // only wired ethernet carries the macb/GEM (or equivalent) TSU this token targets —
        // skip wifi/lte to avoid a meaningless/noisy `ethtool -T` call on radios.
        let hw_timestamping = if matches!(iface_type, InterfaceType::Ethernet) {
            ethtool_hw_timestamping(&name)
        } else {
            false
        };

        out.push(ScanInterface {
            name,
            mac,
            iface_type,
            driver,
            // Link modes require ethtool ioctls; left empty in the read-only probe.
            // The capability mapper's known-good NIC check uses `driver`, not modes.
            supported_modes: Vec::new(),
            // IDS roles (inline/out-of-band/mgmt) are assigned by policy at reconcile
            // time; wifi station/AP roles are assigned from `onboard` (see net_roles).
            role: InterfaceRole::Unassigned,
            fail_mode: None,
            state,
            bus,
            onboard,
            band,
            hw_timestamping,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Detect the band(s) a Wi-Fi radio supports from its phy capability via `iw phy
/// <phy> info` (read-only). Returns "2.4", "5", "6", or a combo like "2.4+5" for a
/// dual-band single radio. Returns None if `iw` is unavailable or parsing fails —
/// the band is then supplied by operator intent at config time.
fn wifi_band(phy: &str) -> Option<String> {
    let out = std::process::Command::new("iw")
        .args(["phy", phy, "info"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let (mut has24, mut has5, mut has6) = (false, false, false);
    for line in text.lines() {
        // Frequency lines look like: "* 2412 MHz [1] (20.0 dBm)".
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("* ") {
            // The number is a float, e.g. "5180.0 MHz [36]" — take the integer part.
            if let Some(mhz) = rest
                .split_whitespace()
                .next()
                .and_then(|n| n.split('.').next())
                .and_then(|n| n.parse::<u32>().ok())
            {
                match mhz {
                    2400..=2500 => has24 = true,
                    5000..=5895 => has5 = true,
                    5925..=7125 => has6 = true,
                    _ => {}
                }
            }
        }
    }
    let mut bands = Vec::new();
    if has24 { bands.push("2.4"); }
    if has5 { bands.push("5"); }
    if has6 { bands.push("6"); }
    if bands.is_empty() { None } else { Some(bands.join("+")) }
}

/// Real per-board hardware-PTP-timestamping fact for one interface
/// (base-tier-build-ticket.md Phase 0 §5 / Phase 3, ADR 0031 §B): does `ethtool -T <iface>`
/// report BOTH a hardware transmit AND hardware receive timestamp capability AND a bound
/// PTP Hardware Clock (PHC) index (not `none`)? All three must hold — this is the exact
/// metal gate Phase-0 §5 specifies ("`ethtool -T <macb-if>` reports **hardware** rx/tx
/// timestamping + a PHC index"). Read-only query; degrades to `false` on ANY failure
/// (missing `ethtool` binary, missing interface, non-zero exit, unparsable output) —
/// never fabricates `true` (no-fabricated-capabilities discipline, mirrors `npu()` above).
fn ethtool_hw_timestamping(iface: &str) -> bool {
    let out = match std::process::Command::new("ethtool").args(["-T", iface]).output() {
        Ok(o) if o.status.success() => o,
        _ => return false,
    };
    let text = String::from_utf8_lossy(&out.stdout);

    // Capabilities block lists tokens like "hardware-transmit (SOF_TIMESTAMPING_TX_HARDWARE)"
    // and "hardware-receive (SOF_TIMESTAMPING_RX_HARDWARE)" — match on the leading token so a
    // trailing "hardware-receive-filter" style variant (none exists today) can't false-match.
    let has_hw_tx = text
        .lines()
        .any(|l| l.split_whitespace().next() == Some("hardware-transmit"));
    let has_hw_rx = text
        .lines()
        .any(|l| l.split_whitespace().next() == Some("hardware-receive"));
    // "PTP Hardware Clock: 0" (bound, real PHC) vs "PTP Hardware Clock: none" (no PHC).
    let has_phc = text.lines().any(|l| {
        l.trim_start()
            .strip_prefix("PTP Hardware Clock:")
            .map(|v| v.trim())
            .map(|v| v != "none" && v.parse::<i64>().is_ok())
            .unwrap_or(false)
    });
    has_hw_tx && has_hw_rx && has_phc
}

// --- wifi / lte presence -----------------------------------------------------

fn wifi() -> Wifi {
    let present = fs::read_dir("/sys/class/ieee80211")
        .map(|mut d| d.next().is_some())
        .unwrap_or(false);
    Wifi {
        present,
        max_standard: None, // needs `iw`; left None in the read-only probe.
    }
}

fn lte() -> Lte {
    let present = fs::read_dir("/sys/class/net")
        .map(|d| {
            d.flatten().any(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.starts_with("wwan") || n.starts_with("wwp")
            })
        })
        .unwrap_or(false);
    Lte {
        present,
        model: None,
    }
}

/// Raspberry Pi (Trading/Foundation) MAC OUIs — identify the onboard radio/NIC even
/// when the driver/bus is ambiguous. Lower-cased prefix match.
fn is_pi_oui(mac: &str) -> bool {
    const PI_OUIS: &[&str] = &[
        "dc:a6:32", "b8:27:eb", "e4:5f:01", "28:cd:c1", "d8:3a:dd", "2c:cf:67",
    ];
    let m = mac.to_lowercase();
    PI_OUIS.iter().any(|o| m.starts_with(o))
}
