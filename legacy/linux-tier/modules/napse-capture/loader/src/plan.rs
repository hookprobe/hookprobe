//! Manifest → concrete attach plan: for each NIC, which hook to attach the detection object to
//! (native XDP vs TC-bpf @ clsact vs software-only), its kernel `ifindex`, and its WAN/LAN role byte
//! (fed into the BPF `role_by_ifindex` map). Pure logic reusing [`inspect::plan`]; `ifindex_for` is
//! injected so it unit-tests without touching `/sys`.

use hookprobe_manifest::inspect::{self, CaptureMode, IfaceInspect, InspectIntent, InspectRole, XdpCaps};
use hookprobe_manifest::types::Manifest;

/// Where the detection object attaches on a NIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachKind {
    /// SEC("xdp") on the driver hook (native XDP).
    Xdp,
    /// SEC("tc") at the clsact ingress+egress hook (universal; the Wi-Fi path).
    Tc,
    /// No BPF (pre-5.19 / no-BTF kernel) — the userspace senzorium-flow floor covers it.
    SoftwareOnly,
}

/// One resolved attach target the loader acts on.
#[derive(Debug, Clone, PartialEq)]
pub struct AttachTarget {
    pub iface: String,
    pub ifindex: u32,
    pub attach: AttachKind,
    /// role byte for the BPF `role_by_ifindex` map: 0 = LAN, 1 = WAN.
    pub role: u8,
}

fn kind_of(mode: CaptureMode) -> AttachKind {
    match mode {
        CaptureMode::XdpNative => AttachKind::Xdp,
        CaptureMode::TcBpf => AttachKind::Tc,
        CaptureMode::Software => AttachKind::SoftwareOnly,
    }
}

fn role_byte(role: InspectRole) -> u8 {
    match role {
        InspectRole::Wan => 1,
        InspectRole::Lan => 0,
    }
}

/// Turn a resolved inspect plan into concrete attach targets, dropping NICs whose ifindex can't be
/// resolved (down/removed) — they'll be picked up on the next reconcile.
pub fn from_inspect(ifaces: &[IfaceInspect], ifindex_for: impl Fn(&str) -> Option<u32>) -> Vec<AttachTarget> {
    ifaces
        .iter()
        .filter_map(|f| {
            let ifindex = ifindex_for(&f.iface)?;
            Some(AttachTarget { iface: f.iface.clone(), ifindex, attach: kind_of(f.mode), role: role_byte(f.role) })
        })
        .collect()
}

/// Full path from a signed manifest + intent to attach targets (self-selecting ladder, ADR 0005).
pub fn build(
    manifest: &Manifest,
    intent: &InspectIntent,
    wan_uplinks: &[&str],
    ifindex_for: impl Fn(&str) -> Option<u32>,
) -> Vec<AttachTarget> {
    let ifaces = &manifest.network.interfaces;
    let plan = inspect::plan(
        ifaces,
        wan_uplinks,
        intent,
        |name| XdpCaps { native: ifaces.iter().find(|i| i.name == name).map(|i| i.xdp_native).unwrap_or(false) },
        manifest.network.bpf_stateful,
    );
    from_inspect(&plan.ifaces, ifindex_for)
}

/// Resolve a NIC's ifindex from sysfs (`/sys/class/net/<name>/ifindex`). The real `ifindex_for`.
pub fn sysfs_ifindex(name: &str) -> Option<u32> {
    std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ii(iface: &str, mode: CaptureMode, role: InspectRole) -> IfaceInspect {
        IfaceInspect { iface: iface.into(), mode, role, mirrored: true }
    }

    #[test]
    fn maps_modes_and_roles_and_resolves_ifindex() {
        let ifaces = vec![
            ii("end0", CaptureMode::TcBpf, InspectRole::Wan),
            ii("wlan0", CaptureMode::TcBpf, InspectRole::Lan),
            ii("enp1s0", CaptureMode::XdpNative, InspectRole::Lan),
            ii("gone0", CaptureMode::TcBpf, InspectRole::Lan), // no ifindex → dropped
        ];
        let idx = |n: &str| match n {
            "end0" => Some(2),
            "wlan0" => Some(3),
            "enp1s0" => Some(4),
            _ => None,
        };
        let t = from_inspect(&ifaces, idx);
        assert_eq!(t.len(), 3); // gone0 dropped
        assert_eq!(t[0], AttachTarget { iface: "end0".into(), ifindex: 2, attach: AttachKind::Tc, role: 1 });
        assert_eq!(t[1].attach, AttachKind::Tc);
        assert_eq!(t[1].role, 0); // LAN
        assert_eq!(t[2].attach, AttachKind::Xdp); // native-XDP NIC
    }

    #[test]
    fn software_floor_maps_through() {
        let ifaces = vec![ii("eth0", CaptureMode::Software, InspectRole::Wan)];
        let t = from_inspect(&ifaces, |_| Some(2));
        assert_eq!(t[0].attach, AttachKind::SoftwareOnly);
    }
}
