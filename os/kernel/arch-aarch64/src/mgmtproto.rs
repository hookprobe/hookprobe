//! The management sub-interface's IPv4 handling (ARP, ping under policy, hand-up), moved out of the CM5-only
//! `uplink.rs` so the QEMU `[P-fuzz]` phase can drive it (ADR 0050 D3). Pure: transmit is a parameter.

/// The management sub-interface's IPv4 stack (static address; DHCP on management is a follow-up).
#[derive(Clone, Copy, Debug)]
pub struct Mgmt {
    pub ip: [u8; 4],
    pub prefix: u8,
    pub gw: [u8; 4],
    pub gw_mac: Option<[u8; 6]>,
    pub mac: [u8; 6],
    pub last_arp: u64,
    /// Next hops other than the default gateway (routes `via mgmt gw X`): a small ARP cache.
    pub nh: [([u8; 4], [u8; 6]); 4],
    pub nh_last_arp: u64,
    /// `mgmt=dhcp`: the client state. None = static address.
    pub dhcp: Option<MgmtDhcp>,
    /// [ARP answered, gateway ARP sent, ping answered, ping blocked, ping dropped, handed up (NAT), dropped]
    pub stats: [u32; 7],
}

/// DHCP client state of the management sub-interface (`mgmt=dhcp`).
#[derive(Clone, Copy, Debug)]
pub struct MgmtDhcp {
    /// 0 = discovering, 1 = requesting the offer, 2 = bound.
    pub phase: u8,
    pub xid: [u8; 4],
    pub offer: [u8; 4],
    pub server: [u8; 4],
    pub last_tx: u64,
    pub bound_at: u64,
    pub lease_s: u32,
    pub acks: u32,
    pub naks: u32,
}

pub enum MgmtEvent {
    Idle,
    /// An IPv4 frame for the management address the stack does not answer itself (NAT replies for
    /// routes via mgmt): `buf[..n]`, untagged.
    Frame(usize),
}

pub fn arp_frame(o: &mut [u8], op: u16, smac: &[u8; 6], sip: &[u8; 4], tmac: &[u8; 6], tip: &[u8; 4], dst: &[u8; 6]) -> usize {
    o[0..6].copy_from_slice(dst);
    o[6..12].copy_from_slice(smac);
    o[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    o[14..22].copy_from_slice(&[0, 1, 8, 0, 6, 4, 0, op as u8]);
    o[22..28].copy_from_slice(smac);
    o[28..32].copy_from_slice(sip);
    o[32..38].copy_from_slice(tmac);
    o[38..42].copy_from_slice(tip);
    o[42..60].fill(0);
    60
}

/// One received management frame (untagged, `buf[..n]`): ARP, ping under `decide`, else handed up.
pub fn mgmt_frame(m: &mut Mgmt, buf: &mut [u8], n: usize, now: u64, decide: &mut dyn FnMut(&[u8]) -> hal::policy::Act, o: &mut [u8; 1600], mgmt_tx: &mut dyn FnMut(&[u8]) -> bool) -> MgmtEvent {
    use hal::policy::Act;
    if m.gw_mac.is_none() && m.ip != [0; 4] && now.wrapping_sub(m.last_arp) >= 2000 {
        m.last_arp = now;
        let k = arp_frame(o, 1, &m.mac, &m.ip, &[0; 6], &m.gw, &[0xff; 6]);
        let _ = mgmt_tx(&o[..k]);
        m.stats[1] += 1;
    }
    if n >= 42 && buf[12..14] == [0x08, 0x06] {
        let op = u16::from_be_bytes([buf[20], buf[21]]);
        let (smac, sip, tip) = (&buf[22..28], &buf[28..32], &buf[38..42]);
        if op == 1 && tip == m.ip {
            let (mut sm, mut si) = ([0u8; 6], [0u8; 4]);
            sm.copy_from_slice(smac);
            si.copy_from_slice(sip);
            let k = arp_frame(&mut o[..], 2, &m.mac, &m.ip, &sm, &si, &sm);
            let _ = mgmt_tx(&o[..k]);
            m.stats[0] += 1;
        }
        let mut g = [0u8; 6];
        g.copy_from_slice(smac);
        if sip == m.gw && op == 2 {
            m.gw_mac = Some(g); // replies only: unsolicited ARP must not repoint the gateway (peer review L4)
        } else if op == 2 && sip != m.gw {
            // cache an answered next hop on our subnet (LRU-free: replace a matching or the first free slot)
            let mask: u32 = u32::MAX << (32 - m.prefix as u32);
            let si = [sip[0], sip[1], sip[2], sip[3]];
            if u32::from_be_bytes(si) & mask == u32::from_be_bytes(m.ip) & mask {
                let k = m.nh.iter().position(|e| e.0 == si).or_else(|| m.nh.iter().position(|e| e.1 == [0; 6])).unwrap_or(0);
                m.nh[k] = (si, g);
            }
        }
        return MgmtEvent::Idle;
    }
    if n < 34 || buf[12..14] != [0x08, 0x00] || buf[30..34] != m.ip || buf[0..6] != m.mac {
        m.stats[6] += 1;
        return MgmtEvent::Idle;
    }
    let ihl = ((buf[14] & 0x0f) as usize) * 4;
    let tot = u16::from_be_bytes([buf[16], buf[17]]) as usize;
    // Peer review 2026-11-06 H2: a total length < IHL+8 made the echo-reply checksum slice inverted (a
    // remote panic from the management VLAN). Validate the whole header before touching it.
    if buf[14] >> 4 != 4 || ihl < 20 || tot < ihl + 8 || 14 + tot > n {
        m.stats[6] += 1;
        return MgmtEvent::Idle;
    }
    if buf[23] == 1 && buf[14 + ihl] == 8 {
        match decide(&buf[..n]) {
            Act::Allow => {
                // Echo reply: swap MACs/IPs, type 0, fresh checksums.
                o[..n].copy_from_slice(&buf[..n]);
                o[0..6].copy_from_slice(&buf[6..12]);
                o[6..12].copy_from_slice(&m.mac);
                o[26..30].copy_from_slice(&buf[30..34]);
                o[30..34].copy_from_slice(&buf[26..30]);
                o[22] = 64;
                o[24] = 0;
                o[25] = 0;
                let c = hal::inet_csum(&o[14..14 + ihl], 0);
                o[24..26].copy_from_slice(&c.to_be_bytes());
                let ic = 14 + ihl;
                o[ic] = 0;
                o[ic + 2] = 0;
                o[ic + 3] = 0;
                let c = hal::inet_csum(&o[ic..14 + tot], 0);
                o[ic + 2..ic + 4].copy_from_slice(&c.to_be_bytes());
                let _ = mgmt_tx(&o[..14 + tot]);
                m.stats[2] += 1;
            }
            Act::Block => {
                if let Some(k) = crate::reject::reject4(&buf[..n], &m.ip, &m.mac, &mut o[..]) {
                    let _ = mgmt_tx(&o[..k]);
                }
                m.stats[3] += 1;
            }
            Act::Drop => m.stats[4] += 1,
        }
        return MgmtEvent::Idle;
    }
    m.stats[5] += 1;
    MgmtEvent::Frame(n)
}
