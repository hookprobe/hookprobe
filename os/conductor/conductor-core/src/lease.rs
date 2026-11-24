// SPDX-License-Identifier: AGPL-3.0-only
//! The P1 compute segment's data-plane policy (ADR 0071 D4; `KERNEL_REQUESTS.md` KR-3 item 5).
//!
//! The owner's LAN worker sits on a dedicated segment where heqk is the only gateway. This module is the
//! decision heqk makes for every frame on that segment. It is a pure function of the frame bytes, the clock and
//! the segment state: sans-IO, no allocation, no unsafe. HomePods lifts it into the data plane, as the signer is
//! lifted into EL1.
//!
//! What the worker may send:
//! - ARP for the gateway, from its own addresses;
//! - TCP to the gateway's control port (the Conductor channel: pairing, quotes, capabilities, results);
//! - DNS to the gateway only (heqk resolves, under its own policy);
//! - while a lease is active, and only then: TCP or UDP to the exact (address, port, protocol) entries of the
//!   lease's owner-approved egress policy.
//!
//! Everything else is dropped, and the drop is returned as evidence. A worker-originated drop also suspends
//! the worker: from then on every frame is dropped and no lease starts, until the owner resumes it. The one
//! exception is a frame to a destination of a lease that ended less than [`LINGER_MS`] ago (TCP's closing
//! segments): it is dropped and recorded, but it does not suspend an honest worker.
//!
//! Frames heqk would forward INTO the segment pass only as replies from the active lease's destinations.
//!
//! Strict on purpose: no IPv6, no VLAN tags, no IP options, no fragments, no ICMP, no broadcast or multicast
//! except the ARP request. The reference worker (`conductor-worker`) is a heqk node and needs none of them.

use crate::crypto::sha256;

/// Largest Ethernet II frame without FCS (1500-byte payload).
pub const MAX_FRAME: usize = 1514;
/// At most this many destinations in one egress policy.
pub const MAX_DESTS: usize = 8;
/// After a lease ends, frames to its destinations are dropped without suspending for this long.
pub const LINGER_MS: u64 = 2_000;

pub mod proto {
    pub const ICMP: u8 = 1;
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
}

const ETH_ARP: u16 = 0x0806;
const ETH_IPV4: u16 = 0x0800;
const ETH_IPV6: u16 = 0x86dd;
const ETH_VLAN: u16 = 0x8100;
const ETH_QINQ: u16 = 0x88a8;
const BROADCAST: [u8; 6] = [0xff; 6];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dest {
    pub ip: [u8; 4],
    pub port: u16,
    pub proto: u8,
}

/// An owner-approved egress policy (from the owner policy journal), named by the id the pairing record and
/// the capability carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressPolicy {
    pub id: [u8; 16],
    pub dests: [Option<Dest>; MAX_DESTS],
}

impl EgressPolicy {
    /// The policy that allows nothing beyond the gateway (the usual case: inference needs no internet).
    pub const fn none(id: [u8; 16]) -> Self {
        Self { id, dests: [None; MAX_DESTS] }
    }
    fn allows(&self, d: Dest) -> bool {
        self.dests.iter().flatten().any(|x| *x == d)
    }
}

/// Why a frame was dropped. Stable codes: they go into the evidence log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Why {
    NotPaired = 1,
    Suspended = 2,
    Oversize = 3,
    Malformed = 4,
    Vlan = 5,
    Ipv6 = 6,
    OtherEthertype = 7,
    /// Source MAC or IP address is not the paired worker's.
    Spoof = 8,
    /// ARP that is not the worker asking for, or answering, the gateway.
    Arp = 9,
    /// An IP frame not addressed to the gateway's MAC (the worker tried to bypass heqk on L2).
    NotViaGateway = 10,
    Broadcast = 11,
    Fragment = 12,
    IpOptions = 13,
    Icmp = 14,
    OtherProtocol = 15,
    /// To the gateway, but not the control port or DNS.
    GatewayPort = 16,
    /// DNS (53, 853) to anything but the gateway.
    DnsElsewhere = 17,
    NoLease = 18,
    /// Not in the active lease's egress policy.
    OutsideLease = 19,
    /// To a destination of a lease that just ended (does not suspend).
    LeaseEnded = 20,
    /// Into the segment, from something that is not an active lease destination.
    InboundUnsolicited = 21,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    /// Drop and record. `suspended` = this drop suspended the worker.
    Drop { why: Why, suspended: bool },
}

/// One evidence record for a dropped frame: when, why, and a digest of the exact bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub at_ms: u64,
    pub why: Why,
    pub suspended: bool,
    pub frame_digest: [u8; 32],
}

impl Evidence {
    pub const LEN: usize = 8 + 1 + 1 + 32;
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut o = [0u8; Self::LEN];
        let mut w = crate::wire::Writer::new(&mut o);
        // Fixed sizes: these cannot fail.
        let _ = w.u64(self.at_ms);
        let _ = w.u8(self.why as u8);
        let _ = w.u8(u8::from(self.suspended));
        let _ = w.put(&self.frame_digest);
        o
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeaseRefusal {
    NotPaired,
    Suspended,
    /// The capability's epoch is below the device's (the kill switch was used after it was issued).
    Revoked,
    /// The policy is not the one the owner paired this worker with.
    PolicyMismatch,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkerAddr {
    pub mac: [u8; 6],
    pub ip: [u8; 4],
}

#[derive(Clone, Copy, Debug)]
struct Lease {
    until_ms: u64,
    policy: EgressPolicy,
}

/// The segment: the gateway's own addresses, the paired worker, and the lease state.
pub struct Segment {
    pub gateway_mac: [u8; 6],
    pub gateway_ip: [u8; 4],
    pub control_port: u16,
    worker: Option<WorkerAddr>,
    paired_policy: [u8; 16],
    lease: Option<Lease>,
    /// The last lease's policy and when it ended (for [`LINGER_MS`]).
    ended: Option<(EgressPolicy, u64)>,
    epoch: u32,
    suspended: bool,
}

/// What a frame is, as far as the policy cares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum L3 {
    Arp { op: u16, sha: [u8; 6], spa: [u8; 4], tpa: [u8; 4] },
    Ip { src: [u8; 4], dst: [u8; 4], proto: u8, dport: u16 },
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    let s = b.get(i..i.checked_add(2)?)?;
    Some(u16::from_be_bytes([*s.first()?, *s.get(1)?]))
}

fn arr<const N: usize>(b: &[u8], i: usize) -> Option<[u8; N]> {
    let mut a = [0u8; N];
    a.copy_from_slice(b.get(i..i.checked_add(N)?)?);
    Some(a)
}

/// Parse an Ethernet II frame: (dst MAC, src MAC, L3). Anything the policy does not handle is an error with
/// its reason.
fn parse(f: &[u8]) -> Result<([u8; 6], [u8; 6], L3), Why> {
    let m = Why::Malformed;
    let dst_mac: [u8; 6] = arr(f, 0).ok_or(m)?;
    let src_mac: [u8; 6] = arr(f, 6).ok_or(m)?;
    let et = u16_at(f, 12).ok_or(m)?;
    let p = f.get(14..).ok_or(m)?;
    match et {
        ETH_VLAN | ETH_QINQ => Err(Why::Vlan),
        ETH_IPV6 => Err(Why::Ipv6),
        ETH_ARP => {
            // Ethernet/IPv4 ARP only: htype 1, ptype 0x0800, hlen 6, plen 4.
            if u16_at(p, 0) != Some(1) || u16_at(p, 2) != Some(ETH_IPV4) || p.get(4) != Some(&6) || p.get(5) != Some(&4) {
                return Err(m);
            }
            let op = u16_at(p, 6).ok_or(m)?;
            Ok((dst_mac, src_mac, L3::Arp { op, sha: arr(p, 8).ok_or(m)?, spa: arr(p, 14).ok_or(m)?, tpa: arr(p, 24).ok_or(m)? }))
        }
        ETH_IPV4 => {
            let vihl = *p.first().ok_or(m)?;
            if vihl >> 4 != 4 {
                return Err(m);
            }
            let ihl = usize::from(vihl & 0x0f).checked_mul(4).ok_or(m)?;
            if ihl < 20 {
                return Err(m);
            }
            let total = usize::from(u16_at(p, 2).ok_or(m)?);
            if total < ihl || total > p.len() {
                return Err(m);
            }
            if ihl > 20 {
                return Err(Why::IpOptions);
            }
            let frag = u16_at(p, 6).ok_or(m)?;
            // MF set, or a non-zero offset: a fragment.
            if frag & 0x3fff != 0 {
                return Err(Why::Fragment);
            }
            let proto = *p.get(9).ok_or(m)?;
            let src = arr(p, 12).ok_or(m)?;
            let dst = arr(p, 16).ok_or(m)?;
            let l4 = p.get(ihl..total).ok_or(m)?;
            let dport = match proto {
                proto::TCP if l4.len() >= 20 => u16_at(l4, 2).ok_or(m)?,
                proto::UDP if l4.len() >= 8 => u16_at(l4, 2).ok_or(m)?,
                proto::TCP | proto::UDP => return Err(m),
                _ => 0,
            };
            Ok((dst_mac, src_mac, L3::Ip { src, dst, proto, dport }))
        }
        _ => Err(Why::OtherEthertype),
    }
}

fn is_broadcast_or_multicast_ip(ip: [u8; 4]) -> bool {
    let [a, _, _, d] = ip;
    ip == [255; 4] || (224..=239).contains(&a) || d == 255
}

impl Segment {
    pub fn new(gateway_mac: [u8; 6], gateway_ip: [u8; 4], control_port: u16) -> Self {
        Self { gateway_mac, gateway_ip, control_port, worker: None, paired_policy: [0; 16], lease: None, ended: None, epoch: 1, suspended: false }
    }

    /// The owner paired a worker at these addresses, with this egress policy. Replaces any earlier pairing
    /// and ends its lease.
    pub fn pair(&mut self, worker: WorkerAddr, egress_policy_id: [u8; 16]) {
        self.worker = Some(worker);
        self.paired_policy = egress_policy_id;
        self.lease = None;
        self.ended = None;
        self.suspended = false;
    }

    pub fn unpair(&mut self) {
        self.worker = None;
        self.lease = None;
        self.ended = None;
    }

    pub fn is_suspended(&self) -> bool {
        self.suspended
    }

    pub fn lease_active(&self, now_ms: u64) -> bool {
        self.lease.is_some_and(|l| now_ms < l.until_ms)
    }

    /// The owner resumes a suspended worker (an owner action, never automatic).
    pub fn resume(&mut self) {
        self.suspended = false;
    }

    /// `StartLease` from the harness, after the signer issued the capability.
    pub fn start_lease(&mut self, now_ms: u64, until_ms: u64, capability_epoch: u32, policy: &EgressPolicy) -> Result<(), LeaseRefusal> {
        if self.worker.is_none() {
            return Err(LeaseRefusal::NotPaired);
        }
        if self.suspended {
            return Err(LeaseRefusal::Suspended);
        }
        if capability_epoch < self.epoch {
            return Err(LeaseRefusal::Revoked);
        }
        if policy.id != self.paired_policy {
            return Err(LeaseRefusal::PolicyMismatch);
        }
        if until_ms <= now_ms {
            return Err(LeaseRefusal::Expired);
        }
        self.lease = Some(Lease { until_ms, policy: *policy });
        Ok(())
    }

    /// `EndLease` from the harness (job done, cancelled, budget spent).
    pub fn end_lease(&mut self, now_ms: u64) {
        if let Some(l) = self.lease.take() {
            self.ended = Some((l.policy, now_ms.min(l.until_ms)));
        }
    }

    /// The kill switch: a new epoch ends every lease at once and refuses capabilities from before it.
    pub fn on_epoch(&mut self, epoch: u32, now_ms: u64) {
        if epoch > self.epoch {
            self.epoch = epoch;
            self.end_lease(now_ms);
            // Frames to the revoked lease's destinations suspend from now on: no linger after a kill switch.
            self.ended = None;
        }
    }

    fn lapse(&mut self, now_ms: u64) {
        if self.lease.is_some_and(|l| now_ms >= l.until_ms) {
            self.end_lease(now_ms);
        }
    }

    fn drop_suspend(&mut self, why: Why) -> Verdict {
        self.suspended = true;
        self.end_lease(0);
        self.ended = None;
        Verdict::Drop { why, suspended: true }
    }

    /// A frame the worker sent on the segment.
    pub fn egress(&mut self, now_ms: u64, frame: &[u8]) -> Verdict {
        self.lapse(now_ms);
        let Some(w) = self.worker else {
            return Verdict::Drop { why: Why::NotPaired, suspended: false };
        };
        if self.suspended {
            return Verdict::Drop { why: Why::Suspended, suspended: false };
        }
        if frame.len() > MAX_FRAME {
            return self.drop_suspend(Why::Oversize);
        }
        let (dst_mac, src_mac, l3) = match parse(frame) {
            Ok(x) => x,
            Err(why) => return self.drop_suspend(why),
        };
        if src_mac != w.mac {
            return self.drop_suspend(Why::Spoof);
        }
        match l3 {
            L3::Arp { op, sha, spa, tpa } => {
                let to_gateway = dst_mac == BROADCAST || dst_mac == self.gateway_mac;
                if (op == 1 || op == 2) && sha == w.mac && spa == w.ip && tpa == self.gateway_ip && to_gateway {
                    Verdict::Pass
                } else {
                    self.drop_suspend(Why::Arp)
                }
            }
            L3::Ip { src, dst, proto, dport } => {
                if src != w.ip {
                    return self.drop_suspend(Why::Spoof);
                }
                if dst_mac != self.gateway_mac {
                    let why = if dst_mac.first().is_some_and(|b| b & 1 == 1) { Why::Broadcast } else { Why::NotViaGateway };
                    return self.drop_suspend(why);
                }
                if is_broadcast_or_multicast_ip(dst) {
                    return self.drop_suspend(Why::Broadcast);
                }
                if proto == proto::ICMP {
                    return self.drop_suspend(Why::Icmp);
                }
                if proto != proto::TCP && proto != proto::UDP {
                    return self.drop_suspend(Why::OtherProtocol);
                }
                if dst == self.gateway_ip {
                    let control = proto == proto::TCP && dport == self.control_port;
                    let dns = dport == 53;
                    return if control || dns { Verdict::Pass } else { self.drop_suspend(Why::GatewayPort) };
                }
                if dport == 53 || dport == 853 {
                    return self.drop_suspend(Why::DnsElsewhere);
                }
                let d = Dest { ip: dst, port: dport, proto };
                match self.lease {
                    Some(l) if l.policy.allows(d) => Verdict::Pass,
                    Some(_) => self.drop_suspend(Why::OutsideLease),
                    None => match self.ended {
                        Some((p, at)) if p.allows(d) && now_ms < at.saturating_add(LINGER_MS) => Verdict::Drop { why: Why::LeaseEnded, suspended: false },
                        _ => self.drop_suspend(Why::NoLease),
                    },
                }
            }
        }
    }

    /// A packet heqk would forward into the segment (already routed; the gateway's own replies, such as the
    /// control channel and DNS, are not forwarded and do not pass here).
    pub fn ingress(&mut self, now_ms: u64, src: Dest, dst_ip: [u8; 4]) -> Verdict {
        self.lapse(now_ms);
        let ok = !self.suspended && self.worker.is_some_and(|w| w.ip == dst_ip) && self.lease.is_some_and(|l| l.policy.allows(src));
        if ok {
            Verdict::Pass
        } else {
            Verdict::Drop { why: Why::InboundUnsolicited, suspended: false }
        }
    }
}

/// The evidence record for a verdict, if it is a drop.
pub fn evidence(v: Verdict, now_ms: u64, frame: &[u8]) -> Option<Evidence> {
    match v {
        Verdict::Pass => None,
        Verdict::Drop { why, suspended } => Some(Evidence { at_ms: now_ms, why, suspended, frame_digest: sha256(&[frame]) }),
    }
}
