//! Data-partition target selection — decides WHERE the persistent `hookprobe-data`
//! partition is provisioned, from the manifest's storage list. This is the canonical,
//! testable policy behind `base/scripts/firstboot-provision-data.sh`.
//!
//! The trap this closes: a `hookprobe-data` partition placed on a **removable**
//! non-boot disk (a USB stick a user plugged in once) would vanish on the next boot
//! and break the by-label mount. So removable non-boot media is NEVER a data home.
//!
//! Policy (stable):
//!   1. NEVER select a removable non-boot disk (transient USB/SD) — exclude it.
//!   2. The safe automatic action is to grow free space on the **boot disk** (the
//!      single-disk / SBC SD-card norm). The OS already lives there.
//!   3. A fixed, non-boot spare disk is *recommended* for dedication but NEVER
//!      auto-claimed — it may already hold data; dedicating it is an operator action.
//!   4. If the boot medium itself is removable (Pi SD card), still grow it (that's
//!      where the OS is) but warn and point at attaching a fixed disk.

use crate::types::StorageDevice;

/// Where firstboot will (safely, automatically) place the data partition.
#[derive(Debug, Clone, PartialEq)]
pub enum DataTarget {
    /// Grow free space on the boot disk — the safe automatic firstboot action.
    GrowBootDisk { dev: String, removable: bool },
    /// No safe target (the boot disk was not found in the storage list).
    None { reason: String },
}

/// The full data-placement decision: the automatic target, what was deliberately
/// not chosen (with reasons), an advisory dedicate recommendation, and any caveat.
#[derive(Debug, Clone, PartialEq)]
pub struct DataPlan {
    pub target: DataTarget,
    /// `(dev, reason)` for every disk deliberately NOT chosen.
    pub excluded: Vec<(String, String)>,
    /// A fixed, non-boot spare disk the operator MAY dedicate to data (advisory —
    /// never auto-claimed here, since it could already hold data).
    pub recommend_dedicated: Option<String>,
    /// Non-fatal caveat (e.g. the boot medium is removable).
    pub warning: Option<String>,
}

impl DataPlan {
    pub fn summary(&self) -> String {
        match &self.target {
            DataTarget::GrowBootDisk { dev, removable } => format!(
                "grow data partition on boot disk {dev}{}",
                if *removable { " (REMOVABLE boot medium)" } else { "" }
            ),
            DataTarget::None { reason } => format!("NO data target — {reason}"),
        }
    }
}

/// Decide where the `hookprobe-data` partition goes. `boot_dev` is the boot disk's
/// bare name (e.g. `nvme0n1`); `boot_serial` matches it stably across `/dev` reorders.
pub fn select_data_target(
    storage: &[StorageDevice],
    boot_dev: &str,
    boot_serial: Option<&str>,
) -> DataPlan {
    let is_boot = |d: &StorageDevice| {
        d.dev == boot_dev
            || (boot_serial.is_some()
                && boot_serial != Some("")
                && d.serial.as_deref() == boot_serial)
    };

    let mut excluded = Vec::new();

    // A fixed, non-boot spare → advisory dedicate recommendation (largest first).
    let mut spares: Vec<&StorageDevice> = storage
        .iter()
        .filter(|d| !is_boot(d) && !d.removable)
        .collect();
    spares.sort_by(|a, b| {
        b.size_gb
            .partial_cmp(&a.size_gb)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let recommend_dedicated = spares.first().map(|d| d.dev.clone());

    // Removable non-boot disks are transient — never a data home.
    for d in storage.iter().filter(|d| !is_boot(d) && d.removable) {
        excluded.push((
            d.dev.clone(),
            "removable non-boot media (transient USB/SD) — would vanish on reboot and break the by-label mount".to_string(),
        ));
    }
    // Fixed non-boot spares: surfaced as a recommendation, not auto-claimed.
    for d in storage.iter().filter(|d| !is_boot(d) && !d.removable) {
        excluded.push((
            d.dev.clone(),
            "fixed spare — not auto-claimed (may already hold data); dedicate via the console".to_string(),
        ));
    }

    match storage.iter().find(|d| is_boot(d)) {
        Some(b) => {
            let warning = if b.removable {
                Some(format!(
                    "boot medium {} is removable (SD/USB) — data lives on it; attach a fixed disk and dedicate it for durable storage",
                    b.dev
                ))
            } else {
                None
            };
            DataPlan {
                target: DataTarget::GrowBootDisk { dev: b.dev.clone(), removable: b.removable },
                excluded,
                recommend_dedicated,
                warning,
            }
        }
        None => DataPlan {
            target: DataTarget::None {
                reason: format!("boot disk '{boot_dev}' not present in the storage list"),
            },
            excluded,
            recommend_dedicated,
            warning: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn disk(dev: &str, size_gb: f64, kind: &str, serial: Option<&str>, removable: bool) -> StorageDevice {
        StorageDevice {
            dev: dev.into(),
            size_gb,
            kind: kind.into(),
            serial: serial.map(|s| s.into()),
            removable,
        }
    }

    /// A USB stick plugged into an N100 must NOT become the data home — the fixed
    /// NVMe boot disk is grown, the stick is excluded with a reason.
    #[test]
    fn usb_stick_excluded_boot_disk_grown() {
        let storage = vec![
            disk("nvme0n1", 512.0, "nvme", Some("NVME-SER"), false),
            disk("sda", 30.0, "usb", Some("USB-SER"), true),
        ];
        let plan = select_data_target(&storage, "nvme0n1", Some("NVME-SER"));
        assert_eq!(plan.target, DataTarget::GrowBootDisk { dev: "nvme0n1".into(), removable: false });
        assert!(plan.warning.is_none());
        assert!(
            plan.excluded.iter().any(|(d, r)| d == "sda" && r.contains("transient")),
            "the USB stick must be excluded as transient: {:?}", plan.excluded
        );
    }

    /// SBC reality (Pi on an SD card, no other disk): grow the boot medium but warn
    /// that it is removable and recommend attaching a fixed disk.
    #[test]
    fn removable_boot_medium_grown_with_warning() {
        let storage = vec![disk("mmcblk0", 64.0, "mmc", Some("SD-SER"), true)];
        let plan = select_data_target(&storage, "mmcblk0", Some("SD-SER"));
        assert_eq!(plan.target, DataTarget::GrowBootDisk { dev: "mmcblk0".into(), removable: true });
        assert!(plan.warning.as_deref().unwrap().contains("removable"));
    }

    /// A fixed spare disk is RECOMMENDED for dedication but NOT auto-claimed (it may
    /// already hold data) — the safe automatic action stays "grow the boot disk".
    #[test]
    fn fixed_spare_recommended_not_claimed() {
        let storage = vec![
            disk("nvme0n1", 256.0, "nvme", Some("BOOT"), false),
            disk("sda", 2000.0, "ssd", Some("SPARE"), false),
        ];
        let plan = select_data_target(&storage, "nvme0n1", Some("BOOT"));
        assert_eq!(plan.target, DataTarget::GrowBootDisk { dev: "nvme0n1".into(), removable: false });
        assert_eq!(plan.recommend_dedicated.as_deref(), Some("sda"), "largest fixed spare is recommended");
        assert!(plan.excluded.iter().any(|(d, r)| d == "sda" && r.contains("not auto-claimed")));
    }

    /// Boot disk matched by SERIAL even when the `/dev` name reordered (sda↔nvme).
    #[test]
    fn boot_matched_by_serial_across_dev_reorder() {
        let storage = vec![disk("sdb", 512.0, "ssd", Some("STABLE-SER"), false)];
        // boot_dev name is stale ("nvme0n1") but the serial still identifies it.
        let plan = select_data_target(&storage, "nvme0n1", Some("STABLE-SER"));
        assert_eq!(plan.target, DataTarget::GrowBootDisk { dev: "sdb".into(), removable: false });
    }

    /// Unknown boot disk → explicit None, never a silent wrong pick.
    #[test]
    fn unknown_boot_disk_is_none() {
        let storage = vec![disk("sda", 30.0, "usb", None, true)];
        let plan = select_data_target(&storage, "nvme0n1", None);
        assert!(matches!(plan.target, DataTarget::None { .. }));
        // ...and the only disk present (a removable) is excluded, not chosen.
        assert!(plan.excluded.iter().any(|(d, _)| d == "sda"));
    }
}
