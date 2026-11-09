//! Mission Control on the management sub-interface (parity G12-M, ADR 0054 D4).
//!
//! The Mission Control node (smoltcp, `mcserve::McNode`) owns static buffers, so there is exactly one.
//! In the AP image it lives on the Wi-Fi side. To serve it on the management VLAN too, the node is
//! multi-homed (a second address) and these pure helpers move frames across:
//!
//! * ingress — only IPv4 TCP to the management address on port 80/443 (already admitted by the signed
//!   `mgmt in` policy) is handed to the node, re-addressed to the node's MAC;
//! * egress — a node frame whose destination is on the management subnet leaves through the
//!   management VLAN with the management MAC (never on Wi-Fi);
//! * ARP — smoltcp learns neighbours only from ARP; its who-has for a management-subnet address is
//!   answered locally with a placeholder MAC, which egress replaces with the uplink's resolved next hop.

/// Placeholder neighbour MAC handed to the node for management-subnet peers (never put on a wire).
pub const PEER_PLACEHOLDER: [u8; 6] = [0x02, 0, 0, 0, 0, 0xfe];

fn in_net(ip: [u8; 4], net: [u8; 4], prefix: u8) -> bool {
    let m = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix.min(32)) };
    (u32::from_be_bytes(ip) & m) == (u32::from_be_bytes(net) & m)
}

/// A management frame for Mission Control? (IPv4 TCP to `mgmt_ip`, destination port 80 or 443.)
/// On yes, copies it into `out` addressed to `node_mac` and returns its length.
pub fn ingress(frame: &[u8], mgmt_ip: [u8; 4], node_mac: [u8; 6], out: &mut [u8]) -> Option<usize> {
    if frame.len() < 54 || frame.len() > out.len() || frame[12] != 0x08 || frame[13] != 0x00 || frame[23] != 6 {
        return None;
    }
    if frame[30..34] != mgmt_ip {
        return None;
    }
    let l4 = 14 + ((frame[14] & 0x0f) as usize) * 4;
    if l4 + 4 > frame.len() {
        return None;
    }
    let dport = u16::from_be_bytes([frame[l4 + 2], frame[l4 + 3]]);
    if dport != 80 && dport != 443 {
        return None;
    }
    out[..frame.len()].copy_from_slice(frame);
    out[0..6].copy_from_slice(&node_mac);
    Some(frame.len())
}

/// Where a frame the node emitted must go.
#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    /// The Wi-Fi side (unchanged).
    Wifi,
    /// The management VLAN, to this next-hop IPv4 address.
    Mgmt([u8; 4]),
    /// An ARP request for a management-subnet peer: answered locally (see `arp_reply`), never sent.
    ArpLocal,
}

/// Classify one node egress frame. `mgmt` = (management address, prefix), when configured.
pub fn route(frame: &[u8], mgmt: Option<([u8; 4], u8)>) -> Route {
    let Some((mip, prefix)) = mgmt else { return Route::Wifi };
    if frame.len() >= 42 && frame[12] == 0x08 && frame[13] == 0x06 {
        let tip = [frame[38], frame[39], frame[40], frame[41]];
        let sip = [frame[28], frame[29], frame[30], frame[31]];
        if (sip == mip || in_net(tip, mip, prefix)) && tip != mip {
            return Route::ArpLocal;
        }
        return Route::Wifi;
    }
    if frame.len() >= 34 && frame[12] == 0x08 && frame[13] == 0x00 {
        let src = [frame[26], frame[27], frame[28], frame[29]];
        let dst = [frame[30], frame[31], frame[32], frame[33]];
        if src == mip || in_net(dst, mip, prefix) {
            return Route::Mgmt(dst);
        }
    }
    Route::Wifi
}

/// The local answer to the node's ARP who-has (a `Route::ArpLocal` frame): "<target> is at
/// PEER_PLACEHOLDER", addressed back to the node. Returns its length.
pub fn arp_reply(req: &[u8], node_mac: [u8; 6], out: &mut [u8; 64]) -> Option<usize> {
    if req.len() < 42 || req[12] != 0x08 || req[13] != 0x06 || req[20..22] != [0, 1] {
        return None;
    }
    let sip = [req[28], req[29], req[30], req[31]];
    let tip = [req[38], req[39], req[40], req[41]];
    Some(arch_aarch64::mgmtproto::arp_frame(out, 2, &PEER_PLACEHOLDER, &tip, &node_mac, &sip, &node_mac))
}

/// Re-address a `Route::Mgmt` frame for the management wire.
pub fn to_wire(frame: &mut [u8], mgmt_mac: [u8; 6], next_hop_mac: [u8; 6]) {
    frame[0..6].copy_from_slice(&next_hop_mac);
    frame[6..12].copy_from_slice(&mgmt_mac);
}

/// `[P-mcmgmt]`: the four helpers on hand-built frames.
pub fn selftest() -> bool {
    let node = [2, 0x11, 0x22, 0x33, 0x44, 0x55];
    let mgmt_ip = [192, 168, 200, 146];
    let admin = [192, 168, 200, 1];
    // TCP SYN admin:50000 -> mgmt:443
    let mut syn = [0u8; 60];
    syn[0..6].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x02]);
    syn[6..12].copy_from_slice(&[0x00, 0xd0, 0xb4, 0x03, 0xb7, 0x11]);
    syn[12] = 0x08;
    syn[14] = 0x45;
    syn[23] = 6;
    syn[26..30].copy_from_slice(&admin);
    syn[30..34].copy_from_slice(&mgmt_ip);
    syn[34..36].copy_from_slice(&50000u16.to_be_bytes());
    syn[36..38].copy_from_slice(&443u16.to_be_bytes());
    let mut out = [0u8; 128];
    let in_ok = ingress(&syn, mgmt_ip, node, &mut out).is_some_and(|n| n == 60 && out[0..6] == node && out[30..34] == mgmt_ip);
    let mut ssh = syn;
    ssh[36..38].copy_from_slice(&22u16.to_be_bytes());
    let other_port_refused = ingress(&ssh, mgmt_ip, node, &mut out).is_none();
    let mut elsewhere = syn;
    elsewhere[30..34].copy_from_slice(&[192, 168, 200, 9]);
    let other_dst_refused = ingress(&elsewhere, mgmt_ip, node, &mut out).is_none();
    // node reply mgmt:443 -> admin
    let mut reply = syn;
    reply[26..30].copy_from_slice(&mgmt_ip);
    reply[30..34].copy_from_slice(&admin);
    let to_mgmt = route(&reply, Some((mgmt_ip, 24))) == Route::Mgmt(admin);
    // a Wi-Fi client reply stays on Wi-Fi; no management configured = Wi-Fi
    let mut wifi = reply;
    wifi[26..30].copy_from_slice(&[10, 99, 0, 1]);
    wifi[30..34].copy_from_slice(&[10, 99, 0, 12]);
    let stays_wifi = route(&wifi, Some((mgmt_ip, 24))) == Route::Wifi && route(&reply, None) == Route::Wifi;
    // node ARP who-has admin (sender = mgmt ip) -> local answer
    let mut req = [0u8; 64];
    let n = arch_aarch64::mgmtproto::arp_frame(&mut req, 1, &node, &mgmt_ip, &[0; 6], &admin, &[0xff; 6]);
    let arp_local = route(&req[..n], Some((mgmt_ip, 24))) == Route::ArpLocal;
    let mut rep = [0u8; 64];
    let arp_ok = arp_reply(&req[..n], node, &mut rep).is_some_and(|k| {
        k >= 42 && rep[0..6] == node && rep[20..22] == [0, 2] && rep[22..28] == PEER_PLACEHOLDER && rep[28..32] == admin && rep[38..42] == mgmt_ip
    });
    // a Wi-Fi-side who-has (10.99.0.12) is not intercepted
    let n2 = arch_aarch64::mgmtproto::arp_frame(&mut req, 1, &node, &[10, 99, 0, 1], &[0; 6], &[10, 99, 0, 12], &[0xff; 6]);
    let arp_wifi = route(&req[..n2], Some((mgmt_ip, 24))) == Route::Wifi;
    to_wire(&mut reply, [0x02, 0, 0, 0, 0, 0x02], [0x00, 0xd0, 0xb4, 0x03, 0xb7, 0x11]);
    let wire_ok = reply[0..6] == [0x00, 0xd0, 0xb4, 0x03, 0xb7, 0x11] && reply[6..12] == [0x02, 0, 0, 0, 0, 0x02];
    let pass = in_ok && other_port_refused && other_dst_refused && to_mgmt && stays_wifi && arp_local && arp_ok && arp_wifi && wire_ok;
    arch_aarch64::_print(format_args!(
        " [P-mcmgmt] {} — G12-M Mission Control on the management VLAN: ingress only TCP 80/443 to the mgmt address={} (other port refused={} other host refused={}) | egress to the mgmt subnet leaves on mgmt={} Wi-Fi traffic stays on Wi-Fi={} | node ARP for mgmt peers answered locally={}/{} (Wi-Fi ARP untouched={}) | re-addressed for the wire={}\n",
        if pass { "PASS" } else { "FAIL" }, in_ok, other_port_refused, other_dst_refused, to_mgmt, stays_wifi, arp_local, arp_ok, arp_wifi, wire_ok
    ));
    pass
}
