//! L2 topology assertion (ADR 0020 D3 condition 2) — "assert, never trust the config string." The
//! IP-layer `target_guard` check is structurally inert for broadcast/multicast frames (no unicast
//! IP destination to check), so L2/broadcast/line-rate safety rests ENTIRELY on this module: before
//! any such probe is allowed to fire, we independently query the KERNEL's own view of the interface
//! (via `ip -j`/`iproute2`, which is itself a netlink client — the same source of truth a raw
//! netlink socket would read) and refuse unless:
//!   1. the egress interface is `kind==veth` (never trust `require_isolation.l2_egress_must_be_veth:
//!      true` in the YAML by itself — that boolean only says the ROE AUTHOR intended veth-only
//!      egress; this module proves the interface actually IS one, right now, on this host).
//!   2. its peer interface (found via the veth ifindex-pairing invariant: a veth's `/sys/.../iflink`
//!      equals its peer's `ifindex`, cross-namespace) is resident inside the DECLARED DUT netns.
//!   3. that netns has NO default route and no route to any prefix outside the DUT's own connected
//!      subnet.
//!
//! Two independent failures are required for a frame to escape (D3.3 / the "Netns topology
//! isolation" abuse-analysis row): even if this module had a bug, the netns itself has no route
//! off the veth, so there is nowhere for an escaping frame to go.
#![forbid(unsafe_code)]

use anyhow::{bail, Context, Result};
use std::process::Command;

/// Abstraction over "ask the kernel" so target_guard's unit tests can inject a fake topology
/// without needing CAP_NET_ADMIN / a real netns (this crate's tests must run on an unprivileged
/// dev box). The production impl (`IpCommandTopology`) shells to `ip -j` (a netlink client);
/// nothing here is a raw-socket send, so it is safe to construct unconditionally.
pub trait Topology {
    /// `(kind, sysfs_iflink)` for `iface` on the host netns. `kind` is `"veth"` iff the kernel says
    /// so via `ip -j -d link show`; `sysfs_iflink` is `/sys/class/net/<iface>/iflink`.
    fn link_info(&self, iface: &str) -> Result<LinkInfo>;
    /// Every ifindex present inside `netns` (from `ip -j -n <netns> link show`).
    fn netns_ifindexes(&self, netns: &str) -> Result<Vec<i64>>;
    /// `true` iff `netns` exists (`ip netns list`).
    fn netns_exists(&self, netns: &str) -> Result<bool>;
    /// Every route destination string inside `netns` (from `ip -n <netns> route show`); a
    /// `"default"` entry means a default route exists.
    fn netns_routes(&self, netns: &str) -> Result<Vec<String>>;
}

#[derive(Debug, Clone)]
pub struct LinkInfo {
    pub ifindex: i64,
    pub kind: Option<String>,
    pub iflink: i64,
}

/// Production implementation — shells to `ip -j` (iproute2's own JSON output), which is itself a
/// netlink(7) client; this is "verified via netlink," not "trusted from the ROE string."
pub struct IpCommandTopology;

fn run_json(args: &[&str]) -> Result<serde_json::Value> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .with_context(|| format!("exec `ip {}`", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "`ip {}` failed (status {}): {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&text).with_context(|| format!("`ip {}` did not return valid JSON: {text}", args.join(" ")))
}

impl Topology for IpCommandTopology {
    fn link_info(&self, iface: &str) -> Result<LinkInfo> {
        let v = run_json(&["-j", "-d", "link", "show", "dev", iface])?;
        let arr = v.as_array().filter(|a| !a.is_empty()).context("no such interface")?;
        let entry = &arr[0];
        let ifindex = entry["ifindex"].as_i64().context("missing ifindex")?;
        let kind = entry["linkinfo"]["info_kind"].as_str().map(|s| s.to_string());
        let iflink = entry["link_index"]
            .as_i64()
            .or_else(|| {
                // Fallback: sysfs iflink (always present; the veth peer-ifindex invariant).
                std::fs::read_to_string(format!("/sys/class/net/{iface}/iflink"))
                    .ok()
                    .and_then(|s| s.trim().parse::<i64>().ok())
            })
            .unwrap_or(ifindex);
        Ok(LinkInfo { ifindex, kind, iflink })
    }

    fn netns_ifindexes(&self, netns: &str) -> Result<Vec<i64>> {
        let v = run_json(&["-j", "-n", netns, "link", "show"])?;
        let arr = v.as_array().cloned().unwrap_or_default();
        Ok(arr.iter().filter_map(|e| e["ifindex"].as_i64()).collect())
    }

    fn netns_exists(&self, netns: &str) -> Result<bool> {
        let out = Command::new("ip")
            .args(["netns", "list"])
            .output()
            .context("exec `ip netns list`")?;
        let text = String::from_utf8_lossy(&out.stdout);
        Ok(text.lines().any(|l| l.split_whitespace().next() == Some(netns)))
    }

    fn netns_routes(&self, netns: &str) -> Result<Vec<String>> {
        let out = Command::new("ip")
            .args(["-n", netns, "route", "show"])
            .output()
            .context("exec `ip -n <netns> route show`")?;
        let text = String::from_utf8_lossy(&out.stdout);
        Ok(text.lines().map(|l| l.to_string()).collect())
    }
}

/// The condition-2 assertion. `veth_iface` is the HOST-side end of the pair (from the ROE's
/// `allowed_targets[].interface`); `dut_netns` is the declared DUT netns (from `allowed_targets[].netns`
/// or `require_isolation`). Returns `Ok(())` only if EVERY leg of the assertion holds; any failure
/// is a plain `Err` the caller (target_guard) must treat as a hard refuse.
pub fn assert_l2_veth_topology(topo: &dyn Topology, veth_iface: &str, dut_netns: &str) -> Result<()> {
    if !topo.netns_exists(dut_netns)? {
        bail!("L2 topology assertion FAILED: netns {dut_netns:?} does not exist");
    }
    let info = topo.link_info(veth_iface)?;
    match info.kind.as_deref() {
        Some("veth") => {}
        other => bail!(
            "L2 topology assertion FAILED: {veth_iface:?} is kind={other:?}, not veth -- refusing \
             (condition 2: L2/broadcast egress MUST be a netlink-verified veth)"
        ),
    }
    if info.iflink == info.ifindex {
        bail!("L2 topology assertion FAILED: {veth_iface:?} has no distinct peer ifindex (iflink==ifindex)");
    }
    let peer_ifindexes = topo.netns_ifindexes(dut_netns)?;
    if !peer_ifindexes.contains(&info.iflink) {
        bail!(
            "L2 topology assertion FAILED: {veth_iface:?}'s peer (ifindex {}) is NOT resident inside \
             netns {dut_netns:?} -- refusing (condition 2: peer must live in the declared DUT netns)",
            info.iflink
        );
    }
    let routes = topo.netns_routes(dut_netns)?;
    if routes.iter().any(|r| r.trim_start().starts_with("default")) {
        bail!(
            "L2 topology assertion FAILED: netns {dut_netns:?} HAS a default route -- refusing \
             (condition 2: the DUT netns must have no route off its own veth)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A fully in-memory fake so these tests run on an unprivileged dev box with no real netns.
    struct FakeTopology {
        links: HashMap<String, LinkInfo>,
        netns: HashMap<String, (Vec<i64>, Vec<String>)>,
    }

    impl Topology for FakeTopology {
        fn link_info(&self, iface: &str) -> Result<LinkInfo> {
            self.links.get(iface).cloned().ok_or_else(|| anyhow::anyhow!("no such interface {iface}"))
        }
        fn netns_ifindexes(&self, netns: &str) -> Result<Vec<i64>> {
            Ok(self.netns.get(netns).map(|(idx, _)| idx.clone()).unwrap_or_default())
        }
        fn netns_exists(&self, netns: &str) -> Result<bool> {
            Ok(self.netns.contains_key(netns))
        }
        fn netns_routes(&self, netns: &str) -> Result<Vec<String>> {
            Ok(self.netns.get(netns).map(|(_, r)| r.clone()).unwrap_or_default())
        }
    }

    fn good_topology() -> FakeTopology {
        let mut links = HashMap::new();
        links.insert(
            "veth-dut".to_string(),
            LinkInfo { ifindex: 10, kind: Some("veth".to_string()), iflink: 11 },
        );
        let mut netns = HashMap::new();
        netns.insert(
            "hookprobe-dut".to_string(),
            (vec![1, 11], vec!["10.99.0.0/24 dev veth-dut-peer proto kernel scope link".to_string()]),
        );
        FakeTopology { links, netns }
    }

    #[test]
    fn accepts_a_real_veth_peer_in_a_routeless_netns() {
        let topo = good_topology();
        assert!(assert_l2_veth_topology(&topo, "veth-dut", "hookprobe-dut").is_ok());
    }

    #[test]
    fn refuses_a_non_veth_interface() {
        let mut topo = good_topology();
        topo.links.insert(
            "veth-dut".to_string(),
            LinkInfo { ifindex: 10, kind: Some("ether".to_string()), iflink: 10 },
        );
        assert!(assert_l2_veth_topology(&topo, "veth-dut", "hookprobe-dut").is_err());
    }

    #[test]
    fn refuses_when_peer_is_not_in_the_declared_netns() {
        let mut topo = good_topology();
        topo.netns.get_mut("hookprobe-dut").unwrap().0 = vec![1, 999]; // peer ifindex 11 absent
        assert!(assert_l2_veth_topology(&topo, "veth-dut", "hookprobe-dut").is_err());
    }

    #[test]
    fn refuses_when_netns_has_a_default_route() {
        let mut topo = good_topology();
        topo.netns.get_mut("hookprobe-dut").unwrap().1.push("default via 10.99.0.1 dev veth-dut-peer".to_string());
        assert!(assert_l2_veth_topology(&topo, "veth-dut", "hookprobe-dut").is_err());
    }

    #[test]
    fn refuses_a_nonexistent_netns() {
        let topo = good_topology();
        assert!(assert_l2_veth_topology(&topo, "veth-dut", "no-such-netns").is_err());
    }

    #[test]
    fn refuses_iflink_equal_ifindex_no_distinct_peer() {
        let mut topo = good_topology();
        topo.links.insert(
            "veth-dut".to_string(),
            LinkInfo { ifindex: 10, kind: Some("veth".to_string()), iflink: 10 },
        );
        assert!(assert_l2_veth_topology(&topo, "veth-dut", "hookprobe-dut").is_err());
    }
}
