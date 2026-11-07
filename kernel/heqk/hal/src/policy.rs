//! WAN policy engine — pure (no_std, no alloc), QEMU-tested: prefix lists and ACLs ATTACHED to an
//! interface / sub-interface per direction, source+destination routes with gateway and metric, and the
//! encapsulation-stack MTU of a WAN sub-interface.
//!
//! Config is POLICY.TXT (one fixed-size file on the boot partition, like WAN.TXT; a GENERATED artifact
//! — the AEGIS reconciler writes it from intent). Grammar (one per line, `#` comments; first non-empty
//! line `HQPOL1`):
//!
//! ```text
//! prefix-list <NAME> seq <N> permit|deny <prefix> [ge <n>] [le <n>]
//! acl <NAME> seq <N> allow|block|drop <proto> <src> <dst> [<port>|<lo>-<hi>]
//! acl <NAME> default allow|block|drop
//! interface <IF> acl in|out <NAME>
//! interface <IF> prefix-list in|out <NAME>
//! route <dst-prefix> [from <src>] via <IF> [gw <addr>] [metric <n>]
//! ```
//! `<IF>` = lan (the Wi-Fi AP) | eth1 | wan (end0 internet sub-interface) | mgmt (end0 management
//! sub-interface). `<proto>` = any | tcp | udp | icmp | <number>. `<src>`/`<dst>` = any | <prefix> |
//! <host> | pl:<NAME>. IPv4 and IPv6 alike.
//! - An ACL is evaluated first-match by `seq`; with no match its `default` applies — UNSET = drop (the
//!   Cisco implicit deny). `block` REJECTS (TCP RST / ICMP administratively prohibited — the sender
//!   learns at once); `drop` is silent.
//! - STATEFUL: `in` = NEW traffic arriving on the interface (forwarded or to the device); a reply to a
//!   connection the LAN opened (a NAT session, or the IPv6 router's flow table) is admitted without
//!   consulting `in` — as nftables `ct state established` / Cisco reflexive ACLs. `out` = EVERY packet
//!   leaving the interface (so deliveries, replies included, can always be filtered).
//!   (Metal 2026-11-05: a stateless `mgmt in` admin-only ACL dropped the replies of `route … via mgmt`.)
//! - A prefix list on an interface filters addresses: `in` = the SOURCE must be permitted, `out` = the
//!   DESTINATION must be permitted; a miss drops.
//! - Routes: candidates whose destination prefix holds the packet's destination and whose `from` (if any)
//!   holds its source; the longest destination prefix wins; ties go to the lowest metric on an interface
//!   that is UP — so two default routes with different metrics are a failover pair.
//! Policy drops are operator intent, counted apart from IDS threat verdicts (ADR 0023).

pub const PL_MAX: usize = 8;
pub const PL_ENTRIES: usize = 16;
pub const ACL_MAX: usize = 8;
pub const ACL_ENTRIES: usize = 32;
pub const BIND_MAX: usize = 16;
pub const ROUTE_MAX: usize = 16;
pub const NAME_MAX: usize = 16;
pub const POLICY_MAGIC: &[u8] = b"HQPOL1";
/// POLICY.TXT is a fixed 4-KiB file (8 sectors) on the boot partition.
pub const POLICY_FILE_LEN: usize = 4096;

/// An IPv4 (first 4 bytes, `v6 = false`) or IPv6 address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Addr {
    pub v6: bool,
    pub a: [u8; 16],
}

impl Addr {
    pub fn v4(q: [u8; 4]) -> Self {
        let mut a = [0u8; 16];
        a[..4].copy_from_slice(&q);
        Addr { v6: false, a }
    }
    pub fn v6(a: [u8; 16]) -> Self {
        Addr { v6: true, a }
    }
    fn bits(&self) -> u8 {
        if self.v6 { 128 } else { 32 }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Prefix {
    pub addr: Addr,
    pub len: u8,
}

fn prefix_eq_bits(a: &[u8; 16], b: &[u8; 16], len: u8) -> bool {
    let full = (len / 8) as usize;
    if a[..full] != b[..full] {
        return false;
    }
    let rem = len % 8;
    if rem == 0 {
        return true;
    }
    let m = 0xffu8 << (8 - rem);
    a[full] & m == b[full] & m
}

impl Prefix {
    /// Does this prefix contain address `x` (same family)?
    pub fn contains(&self, x: &Addr) -> bool {
        self.addr.v6 == x.v6 && prefix_eq_bits(&self.addr.a, &x.a, self.len)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PlEntry {
    pub seq: u16,
    pub permit: bool,
    pub pfx: Prefix,
    pub ge: u8,
    pub le: u8,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PrefixList {
    pub name: [u8; NAME_MAX],
    pub nlen: usize,
    pub e: [PlEntry; PL_ENTRIES],
    pub n: usize,
}

impl PrefixList {
    /// Cisco semantics for a candidate prefix `p`: the first entry (by seq) whose prefix covers `p`
    /// and whose length window holds `p.len` decides; no match = deny. Without ge/le the window is
    /// exactly the entry's length; `ge` alone = [ge, max]; `le` alone = [len, le].
    pub fn matches_prefix(&self, p: &Prefix) -> bool {
        for e in &self.e[..self.n] {
            if e.pfx.addr.v6 != p.addr.v6 || p.len < e.pfx.len || !prefix_eq_bits(&e.pfx.addr.a, &p.addr.a, e.pfx.len) {
                continue;
            }
            let (lo, hi) = (if e.ge != 0 { e.ge } else { e.pfx.len }, if e.le != 0 { e.le } else if e.ge != 0 { p.addr.bits() } else { e.pfx.len });
            if p.len >= lo && p.len <= hi {
                return e.permit;
            }
        }
        false
    }
    /// Does the list have any entry of this address family? A list of only IPv4 entries does not
    /// apply to IPv6 packets (and vice versa) — like Cisco's separate ip / ipv6 prefix-lists.
    pub fn has_family(&self, v6: bool) -> bool {
        self.e[..self.n].iter().any(|e| e.pfx.addr.v6 == v6)
    }
    /// An address is the host prefix (/32 or /128).
    pub fn matches_addr(&self, a: &Addr) -> bool {
        self.matches_prefix(&Prefix { addr: *a, len: a.bits() })
    }
}


#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum If {
    #[default]
    Lan,
    Eth1,
    Wan,
    Mgmt,
}
pub const IF_N: usize = 4;
impl If {
    pub fn idx(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Dir {
    #[default]
    In,
    Out,
}

/// What a policy decides for a packet.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Act {
    #[default]
    Allow,
    /// Reject: TCP RST / ICMP(v6) administratively prohibited back to the sender.
    Block,
    /// Silent discard.
    Drop,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AddrMatch {
    #[default]
    Any,
    Pfx(Prefix),
    /// Index into the prefix-list table.
    List(u8),
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AclEntry {
    pub seq: u16,
    pub act: Act,
    /// 0 = any; else the IP protocol (6 tcp, 17 udp, 1 icmp — icmp also matches ICMPv6 58).
    pub proto: u8,
    pub src: AddrMatch,
    pub dst: AddrMatch,
    /// Destination port window (0,0 = any).
    pub dport: (u16, u16),
}

#[derive(Clone, Copy, Debug)]
pub struct Acl {
    pub name: [u8; NAME_MAX],
    pub nlen: usize,
    pub e: [AclEntry; ACL_ENTRIES],
    pub n: usize,
    pub hits: [u32; ACL_ENTRIES],
    /// None = unset = Drop (implicit deny).
    pub default: Option<Act>,
    pub default_hits: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindKind {
    Acl(u8),
    Pl(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Binding {
    pub ifc: If,
    pub dir: Dir,
    pub kind: BindKind,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Route {
    pub dst: Prefix,
    pub src: AddrMatch,
    pub via: If,
    pub gw: Option<Addr>,
    pub metric: u16,
}

/// One packet's facts, as the data path sees them.
#[derive(Clone, Copy, Debug)]
pub struct Pkt {
    pub proto: u8,
    pub src: Addr,
    pub dst: Addr,
    pub dport: u16,
}

/// The outcome of the interface bindings for one (interface, direction): the action and which rule
/// decided it (for the log / counters).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decided {
    /// No binding on this interface/direction: allowed, nothing consulted.
    Unbound,
    /// A prefix list refused the address.
    PrefixList(u8),
    /// ACL `.0`, entry seq `.1` (u16::MAX = the ACL's default).
    Acl(u8, u16),
}

#[derive(Clone, Copy, Debug)]
pub struct Policy {
    pub pl: [PrefixList; PL_MAX],
    pub npl: usize,
    pub acl: [Acl; ACL_MAX],
    pub nacl: usize,
    pub bind: [Binding; BIND_MAX],
    pub nbind: usize,
    pub routes: [Route; ROUTE_MAX],
    pub nroutes: usize,
    /// Prefix-list refusals per binding.
    pub pl_drops: [u32; BIND_MAX],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyErr {
    /// ADR 0049 D1: an operator key is set and the signature is missing / invalid / rolled back.
    Unsigned,
    NoMagic,
    /// (1-based line number) — anything malformed rejects the WHOLE file: a policy is never
    /// half-applied (a half-parsed ACL set could open what the operator meant to close). The caller
    /// logs the rejection loudly and runs without operator policy until the file is fixed.
    Line(u16),
    Full(u16),
}

impl Default for Policy {
    fn default() -> Self {
        Self::new()
    }
}

const EMPTY_ACL: Acl = Acl {
    name: [0; NAME_MAX],
    nlen: 0,
    e: [AclEntry { seq: 0, act: Act::Allow, proto: 0, src: AddrMatch::Any, dst: AddrMatch::Any, dport: (0, 0) }; ACL_ENTRIES],
    n: 0,
    hits: [0; ACL_ENTRIES],
    default: None,
    default_hits: 0,
};

impl Policy {
    pub const fn new() -> Self {
        Policy {
            pl: [PrefixList { name: [0; NAME_MAX], nlen: 0, e: [PlEntry { seq: 0, permit: false, pfx: Prefix { addr: Addr { v6: false, a: [0; 16] }, len: 0 }, ge: 0, le: 0 }; PL_ENTRIES], n: 0 }; PL_MAX],
            npl: 0,
            acl: [EMPTY_ACL; ACL_MAX],
            nacl: 0,
            bind: [Binding { ifc: If::Lan, dir: Dir::In, kind: BindKind::Pl(0) }; BIND_MAX],
            nbind: 0,
            routes: [Route { dst: Prefix { addr: Addr { v6: false, a: [0; 16] }, len: 0 }, src: AddrMatch::Any, via: If::Lan, gw: None, metric: 0 }; ROUTE_MAX],
            nroutes: 0,
            pl_drops: [0; BIND_MAX],
        }
    }

    fn addr_ok(&self, m: &AddrMatch, a: &Addr) -> bool {
        match m {
            AddrMatch::Any => true,
            AddrMatch::Pfx(p) => p.contains(a),
            AddrMatch::List(i) => self.pl[*i as usize].matches_addr(a),
        }
    }

    /// Run one ACL (first-match by seq; else its default, unset = Drop). Counts the deciding entry.
    pub fn acl_eval(&mut self, ai: usize, p: &Pkt) -> (Act, u16) {
        // By reference — no per-packet copy of the ~1.8-KB Acl (peer review COR-P3).
        let hit = {
            let a = &self.acl[ai];
            a.e[..a.n].iter().position(|r| {
                (r.proto == 0 || r.proto == p.proto || (r.proto == 1 && p.proto == 58))
                    && (r.dport == (0, 0) || (p.dport >= r.dport.0 && p.dport <= r.dport.1))
                    && self.addr_ok(&r.src, &p.src)
                    && self.addr_ok(&r.dst, &p.dst)
            })
        };
        let a = &mut self.acl[ai];
        match hit {
            Some(k) => {
                a.hits[k] = a.hits[k].wrapping_add(1);
                (a.e[k].act, a.e[k].seq)
            }
            None => {
                a.default_hits = a.default_hits.wrapping_add(1);
                (a.default.unwrap_or(Act::Drop), u16::MAX)
            }
        }
    }

    /// Every binding on (interface, direction), in config order: prefix lists filter the address
    /// (in = source, out = destination), ACLs decide. The first non-Allow outcome wins.
    pub fn check(&mut self, ifc: If, dir: Dir, p: &Pkt) -> (Act, Decided) {
        let mut decided = Decided::Unbound;
        for b in 0..self.nbind {
            let bd = self.bind[b];
            if bd.ifc != ifc || bd.dir != dir {
                continue;
            }
            match bd.kind {
                BindKind::Pl(i) => {
                    let a = if dir == Dir::In { p.src } else { p.dst };
                    let l = &self.pl[i as usize];
                    if l.has_family(a.v6) && !l.matches_addr(&a) {
                        self.pl_drops[b] = self.pl_drops[b].wrapping_add(1);
                        return (Act::Drop, Decided::PrefixList(i));
                    }
                }
                BindKind::Acl(i) => {
                    let (act, seq) = self.acl_eval(i as usize, p);
                    decided = Decided::Acl(i, seq);
                    if act != Act::Allow {
                        return (act, decided);
                    }
                }
            }
        }
        (Act::Allow, decided)
    }

    /// Route for (src, dst): longest destination prefix whose `from` holds `src`, then lowest metric on
    /// an interface `up` reports usable. None = no route (the caller's default path).
    pub fn route(&self, src: &Addr, dst: &Addr, up: &dyn Fn(If) -> bool) -> Option<Route> {
        let mut best: Option<Route> = None;
        for r in &self.routes[..self.nroutes] {
            if !r.dst.contains(dst) || !self.addr_ok(&r.src, src) || !up(r.via) {
                continue;
            }
            best = match best {
                None => Some(*r),
                Some(b) if r.dst.len > b.dst.len || (r.dst.len == b.dst.len && r.metric < b.metric) => Some(*r),
                keep => keep,
            };
        }
        best
    }

    fn list_index(&self, name: &[u8]) -> Option<u8> {
        self.pl[..self.npl].iter().position(|l| &l.name[..l.nlen] == name).map(|i| i as u8)
    }
    fn acl_index(&self, name: &[u8]) -> Option<u8> {
        self.acl[..self.nacl].iter().position(|l| &l.name[..l.nlen] == name).map(|i| i as u8)
    }
}

// ---------------------------------------------------------------- parsing helpers

fn trim(s: &[u8]) -> &[u8] {
    let mut a = 0;
    let mut b = s.len();
    while a < b && (s[a] == b' ' || s[a] == b'\t' || s[a] == b'\r') {
        a += 1;
    }
    while b > a && (s[b - 1] == b' ' || s[b - 1] == b'\t' || s[b - 1] == b'\r') {
        b -= 1;
    }
    &s[a..b]
}

fn num(s: &[u8]) -> Option<u32> {
    if s.is_empty() || s.len() > 9 || !s.iter().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(s.iter().fold(0u32, |a, &c| a * 10 + (c - b'0') as u32))
}

fn parse_v4(s: &[u8]) -> Option<[u8; 4]> {
    let mut q = [0u8; 4];
    let mut i = 0;
    for part in s.split(|&b| b == b'.') {
        if i == 4 {
            return None;
        }
        let v = num(part)?;
        if v > 255 || part.len() > 3 {
            return None;
        }
        q[i] = v as u8;
        i += 1;
    }
    if i == 4 { Some(q) } else { None }
}

fn hexv(s: &[u8]) -> Option<u16> {
    if s.is_empty() || s.len() > 4 {
        return None;
    }
    let mut v = 0u16;
    for &c in s {
        let d = match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => return None,
        };
        v = v << 4 | d as u16;
    }
    Some(v)
}

/// Textual IPv6 (RFC 4291 §2.2 forms 1-2: hex groups with at most one `::`; no embedded IPv4).
pub fn parse_v6(s: &[u8]) -> Option<[u8; 16]> {
    let mut head = [0u16; 8];
    let mut tail = [0u16; 8];
    let (mut nh, mut nt) = (0usize, 0usize);
    let dc = s.windows(2).position(|w| w == b"::");
    let (h, t): (&[u8], &[u8]) = match dc {
        Some(i) => {
            if s[i + 2..].windows(2).any(|w| w == b"::") {
                return None;
            }
            (&s[..i], &s[i + 2..])
        }
        None => (s, &[]),
    };
    if !h.is_empty() {
        for g in h.split(|&b| b == b':') {
            if nh == 8 {
                return None;
            }
            head[nh] = hexv(g)?;
            nh += 1;
        }
    }
    if !t.is_empty() {
        for g in t.split(|&b| b == b':') {
            if nt == 8 {
                return None;
            }
            tail[nt] = hexv(g)?;
            nt += 1;
        }
    }
    if dc.is_none() && nh != 8 || dc.is_some() && nh + nt > 7 {
        return None;
    }
    let mut w = [0u16; 8];
    w[..nh].copy_from_slice(&head[..nh]);
    w[8 - nt..].copy_from_slice(&tail[..nt]);
    let mut a = [0u8; 16];
    for k in 0..8 {
        a[2 * k..2 * k + 2].copy_from_slice(&w[k].to_be_bytes());
    }
    Some(a)
}

pub fn parse_addr(s: &[u8]) -> Option<Addr> {
    if s.contains(&b':') {
        parse_v6(s).map(Addr::v6)
    } else {
        parse_v4(s).map(Addr::v4)
    }
}

/// `<addr>/<len>` or a bare host address (= /32, /128). Host bits must be zero.
pub fn parse_prefix(s: &[u8]) -> Option<Prefix> {
    let (a, len) = match s.iter().position(|&b| b == b'/') {
        Some(i) => {
            let a = parse_addr(&s[..i])?;
            let l = num(&s[i + 1..])?;
            (a, l)
        }
        None => {
            let a = parse_addr(s)?;
            (a, a.bits() as u32)
        }
    };
    if len > a.bits() as u32 {
        return None;
    }
    let p = Prefix { addr: a, len: len as u8 };
    let mut z = a.a;
    let full = (len / 8) as usize;
    if full < 16 {
        let rem = len % 8;
        z[full] &= if rem == 0 { 0 } else { 0xffu8 << (8 - rem) };
        for b in &mut z[full + 1..] {
            *b = 0;
        }
    }
    if z != a.a {
        return None; // host bits set: almost always a typo — refuse rather than guess
    }
    Some(p)
}


fn parse_if(s: &[u8]) -> Option<If> {
    Some(match s {
        b"lan" => If::Lan,
        b"eth1" => If::Eth1,
        b"wan" => If::Wan,
        b"mgmt" => If::Mgmt,
        _ => return None,
    })
}

fn parse_proto(s: &[u8]) -> Option<u8> {
    Some(match s {
        b"any" | b"ip" => 0,
        b"tcp" => 6,
        b"udp" => 17,
        b"icmp" => 1,
        _ => {
            let v = num(s)?;
            if v == 0 || v > 255 {
                return None;
            }
            v as u8
        }
    })
}

fn parse_ports(s: &[u8]) -> Option<(u16, u16)> {
    let (lo, hi) = match s.iter().position(|&b| b == b'-') {
        Some(i) => (num(&s[..i])?, num(&s[i + 1..])?),
        None => {
            let v = num(s)?;
            (v, v)
        }
    };
    if lo == 0 || lo > hi || hi > 65535 {
        return None;
    }
    Some((lo as u16, hi as u16))
}

fn parse_act(s: &[u8]) -> Option<Act> {
    Some(match s {
        b"allow" | b"permit" => Act::Allow,
        b"block" | b"reject" => Act::Block,
        b"drop" | b"deny" => Act::Drop,
        _ => return None,
    })
}

fn addr_match(s: &[u8], p: &Policy) -> Option<AddrMatch> {
    if s == b"any" {
        Some(AddrMatch::Any)
    } else if let Some(n) = s.strip_prefix(b"pl:") {
        p.list_index(n).map(AddrMatch::List)
    } else {
        parse_prefix(s).map(AddrMatch::Pfx)
    }
}

/// Parse POLICY.TXT. Any malformed line rejects the whole file (never half-applied). Names must be
/// defined before they are referenced (lists before ACL entries / bindings that use them).
pub fn parse_policy(buf: &[u8], out: &mut Policy) -> Result<(), PolicyErr> {
    *out = Policy::new();
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let mut magic = false;
    for (ln, raw) in buf[..end].split(|&b| b == b'\n').enumerate() {
        let ln = (ln + 1) as u16;
        let line = trim(raw);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        if !magic {
            if line != POLICY_MAGIC {
                return Err(PolicyErr::NoMagic);
            }
            magic = true;
            continue;
        }
        let mut tok = [&b""[..]; 12];
        let mut nt = 0;
        for t in line.split(|&b| b == b' ' || b == b'\t').filter(|t| !t.is_empty()) {
            if nt == tok.len() {
                return Err(PolicyErr::Line(ln));
            }
            tok[nt] = t;
            nt += 1;
        }
        let t = &tok[..nt];
        let bad = PolicyErr::Line(ln);
        match t[0] {
            b"prefix-list" => {
                // prefix-list NAME seq N permit|deny PFX [ge n] [le n]
                if nt < 6 || t[2] != b"seq" || t[1].len() > NAME_MAX {
                    return Err(bad);
                }
                let seq = num(t[3]).filter(|&v| v <= 65535).ok_or(bad)? as u16;
                let permit = match t[4] {
                    b"permit" => true,
                    b"deny" => false,
                    _ => return Err(bad),
                };
                let pfx = parse_prefix(t[5]).ok_or(bad)?;
                let (mut ge, mut le) = (0u8, 0u8);
                let mut k = 6;
                while k < nt {
                    if k + 1 >= nt {
                        return Err(bad);
                    }
                    let v = num(t[k + 1]).filter(|&v| v <= pfx.addr.bits() as u32 && v >= pfx.len as u32).ok_or(bad)? as u8;
                    match t[k] {
                        b"ge" => ge = v,
                        b"le" => le = v,
                        _ => return Err(bad),
                    }
                    k += 2;
                }
                if ge != 0 && le != 0 && ge > le {
                    return Err(bad);
                }
                let li = match out.list_index(t[1]) {
                    Some(i) => i as usize,
                    None => {
                        if out.npl == PL_MAX {
                            return Err(PolicyErr::Full(ln));
                        }
                        let l = &mut out.pl[out.npl];
                        l.name[..t[1].len()].copy_from_slice(t[1]);
                        l.nlen = t[1].len();
                        out.npl += 1;
                        out.npl - 1
                    }
                };
                let l = &mut out.pl[li];
                if l.n == PL_ENTRIES || l.e[..l.n].iter().any(|e| e.seq == seq) {
                    return Err(PolicyErr::Full(ln));
                }
                let mut at = l.n;
                while at > 0 && l.e[at - 1].seq > seq {
                    l.e[at] = l.e[at - 1];
                    at -= 1;
                }
                l.e[at] = PlEntry { seq, permit, pfx, ge, le };
                l.n += 1;
            }
            b"acl" => {
                if nt < 3 || t[1].len() > NAME_MAX {
                    return Err(bad);
                }
                let ai = match out.acl_index(t[1]) {
                    Some(i) => i as usize,
                    None => {
                        if out.nacl == ACL_MAX {
                            return Err(PolicyErr::Full(ln));
                        }
                        let a = &mut out.acl[out.nacl];
                        a.name[..t[1].len()].copy_from_slice(t[1]);
                        a.nlen = t[1].len();
                        out.nacl += 1;
                        out.nacl - 1
                    }
                };
                if t[2] == b"default" {
                    if nt != 4 {
                        return Err(bad);
                    }
                    out.acl[ai].default = Some(parse_act(t[3]).ok_or(bad)?);
                    continue;
                }
                // acl NAME seq N allow|block|drop PROTO SRC DST [PORTS]
                if (nt != 8 && nt != 9) || t[2] != b"seq" {
                    return Err(bad);
                }
                let seq = num(t[3]).filter(|&v| v <= 65535).ok_or(bad)? as u16;
                let act = parse_act(t[4]).ok_or(bad)?;
                let proto = parse_proto(t[5]).ok_or(bad)?;
                let src = addr_match(t[6], out).ok_or(bad)?;
                let dst = addr_match(t[7], out).ok_or(bad)?;
                let dport = if nt == 9 {
                    if proto != 6 && proto != 17 {
                        return Err(bad); // ports only mean something for TCP/UDP
                    }
                    parse_ports(t[8]).ok_or(bad)?
                } else {
                    (0, 0)
                };
                let a = &mut out.acl[ai];
                if a.n == ACL_ENTRIES || a.e[..a.n].iter().any(|e| e.seq == seq) {
                    return Err(PolicyErr::Full(ln));
                }
                let mut at = a.n;
                while at > 0 && a.e[at - 1].seq > seq {
                    a.e[at] = a.e[at - 1];
                    at -= 1;
                }
                a.e[at] = AclEntry { seq, act, proto, src, dst, dport };
                a.n += 1;
            }
            b"interface" => {
                // interface IF acl|prefix-list in|out NAME
                if nt != 5 {
                    return Err(bad);
                }
                let ifc = parse_if(t[1]).ok_or(bad)?;
                let dir = match t[3] {
                    b"in" => Dir::In,
                    b"out" => Dir::Out,
                    _ => return Err(bad),
                };
                let kind = match t[2] {
                    b"acl" => BindKind::Acl(out.acl_index(t[4]).ok_or(bad)?),
                    b"prefix-list" => BindKind::Pl(out.list_index(t[4]).ok_or(bad)?),
                    _ => return Err(bad),
                };
                let b = Binding { ifc, dir, kind };
                if out.nbind == BIND_MAX || out.bind[..out.nbind].contains(&b) {
                    return Err(PolicyErr::Full(ln));
                }
                out.bind[out.nbind] = b;
                out.nbind += 1;
            }
            b"route" => {
                // route DST [from SRC] via IF [gw ADDR] [metric N]
                if nt < 4 {
                    return Err(bad);
                }
                let dst = parse_prefix(t[1]).ok_or(bad)?;
                let mut r = Route { dst, src: AddrMatch::Any, via: If::Wan, gw: None, metric: 0 };
                let mut via = false;
                let mut k = 2;
                while k < nt {
                    if k + 1 >= nt {
                        return Err(bad);
                    }
                    let v = t[k + 1];
                    match t[k] {
                        b"from" => r.src = addr_match(v, out).ok_or(bad)?,
                        b"via" => {
                            r.via = parse_if(v).ok_or(bad)?;
                            via = true;
                        }
                        b"gw" => {
                            let g = parse_addr(v).ok_or(bad)?;
                            if g.v6 != dst.addr.v6 {
                                return Err(bad);
                            }
                            r.gw = Some(g);
                        }
                        b"metric" => r.metric = num(v).filter(|&m| m <= 65535).ok_or(bad)? as u16,
                        _ => return Err(bad),
                    }
                    k += 2;
                }
                if !via {
                    return Err(bad);
                }
                if out.nroutes == ROUTE_MAX {
                    return Err(PolicyErr::Full(ln));
                }
                out.routes[out.nroutes] = r;
                out.nroutes += 1;
            }
            _ => return Err(bad),
        }
    }
    if magic { Ok(()) } else { Err(PolicyErr::NoMagic) }
}

/// The policy facts of an untagged Ethernet IPv4 / IPv6 frame: protocol, source, destination, and the
/// TCP/UDP destination port (0 otherwise). IPv6 extension headers are not walked: the protocol is the
/// first next-header (an ACL on tcp/udp will not match a packet hiding behind an extension header —
/// the IPv6 router refuses to forward those outbound anyway).
pub fn facts(f: &[u8]) -> Option<Pkt> {
    if f.len() < 14 {
        return None;
    }
    let et = u16::from_be_bytes([f[12], f[13]]);
    let (proto, src, dst, l4) = match et {
        0x0800 => {
            if f.len() < 34 || f[14] >> 4 != 4 {
                return None;
            }
            let ihl = ((f[14] & 0x0f) as usize) * 4;
            let mut s4 = [0u8; 4];
            let mut d4 = [0u8; 4];
            s4.copy_from_slice(&f[26..30]);
            d4.copy_from_slice(&f[30..34]);
            (f[23], Addr::v4(s4), Addr::v4(d4), 14 + ihl)
        }
        0x86dd => {
            if f.len() < 54 || f[14] >> 4 != 6 {
                return None;
            }
            let mut s6 = [0u8; 16];
            let mut d6 = [0u8; 16];
            s6.copy_from_slice(&f[22..38]);
            d6.copy_from_slice(&f[38..54]);
            (f[20], Addr::v6(s6), Addr::v6(d6), 54)
        }
        _ => return None,
    };
    let dport = if (proto == 6 || proto == 17) && f.len() >= l4 + 4 { u16::from_be_bytes([f[l4 + 2], f[l4 + 3]]) } else { 0 };
    Some(Pkt { proto, src, dst, dport })
}

/// uRPF-style MARTIAN check for an IPv4 source arriving on the internet sub-interface (RFC 1812 §5.3.7 +
/// our own addresses). True = the source is impossible from the WAN, i.e. spoofed: `0.0.0.0/8`,
/// `127/8`, multicast / class E / broadcast, OUR WAN address, OUR inside LAN /24, and the management
/// floor `floor_net/floor_len` — unless that floor also covers the WAN address itself (DHCP behind a
/// LAN where the operator genuinely arrives via the WAN). Peer re-review P2: the floor (never enforced
/// against) is keyed on the source IP, so a spoofed floor source from the internet must never get it.
pub fn wan_martian4(src: [u8; 4], wan_ip: [u8; 4], inside: [u8; 3], floor_net: u32, floor_len: u32) -> bool {
    let s = u32::from_be_bytes(src);
    if src[0] == 0 || src[0] == 127 || src[0] >= 224 || src == wan_ip || src[..3] == inside {
        return true;
    }
    if (8..=32).contains(&floor_len) {
        let mask = if floor_len == 32 { u32::MAX } else { u32::MAX << (32 - floor_len) };
        let w = u32::from_be_bytes(wan_ip);
        if s & mask == floor_net & mask && w & mask != floor_net & mask {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------- WAN link encapsulation

/// How a WAN sub-interface is framed on the wire (WAN.TXT `vlan=` / `vlan_outer=` + the mode).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Encap {
    /// 802.1Q customer tag (0 = untagged).
    pub vlan: u16,
    /// 802.1ad service (outer) tag for QinQ (0 = none). Requires `vlan`.
    pub outer: u16,
    /// 802.1p priority for the tags.
    pub pcp: u8,
    pub pppoe: bool,
}

impl Encap {
    /// Bytes of tag added in front of the ethertype.
    pub fn tag_len(&self) -> usize {
        (if self.vlan != 0 { 4 } else { 0 }) + (if self.outer != 0 { 4 } else { 0 })
    }
    /// The IP MTU this stack can carry, from the headers it actually adds: 1500-byte Ethernet
    /// payload, minus PPPoE (6 + PPP 2). 802.1Q/QinQ tags ride OUTSIDE the 1500-byte payload
    /// (IEEE 802.1Q frames are 1522 B; 1526 with an S-tag), so they cost the IP MTU nothing — as long
    /// as the NIC accepts the longer frames, which `frame_max` reports for the driver to configure.
    pub fn ip_mtu(&self) -> u16 {
        1500 - if self.pppoe { 8 } else { 0 }
    }
    /// TCP MSS for IPv4 over this stack (MTU - 40).
    pub fn mss4(&self) -> u16 {
        self.ip_mtu() - 40
    }
    /// Largest frame on the wire (without FCS): 14 + tags + 1500.
    pub fn frame_max(&self) -> usize {
        14 + self.tag_len() + 1500
    }
    /// Write the tag stack after the two MACs (`f[12..]`) for payload ethertype `et`; returns the
    /// offset where the payload ethertype ends (14 + tag_len).
    pub fn push_tags(&self, f: &mut [u8], et: u16) -> usize {
        let mut o = 12;
        if self.outer != 0 {
            f[o..o + 2].copy_from_slice(&0x88a8u16.to_be_bytes());
            f[o + 2..o + 4].copy_from_slice(&(((self.pcp as u16) << 13) | (self.outer & 0x0fff)).to_be_bytes());
            o += 4;
        }
        if self.vlan != 0 {
            f[o..o + 2].copy_from_slice(&0x8100u16.to_be_bytes());
            f[o + 2..o + 4].copy_from_slice(&(((self.pcp as u16) << 13) | (self.vlan & 0x0fff)).to_be_bytes());
            o += 4;
        }
        f[o..o + 2].copy_from_slice(&et.to_be_bytes());
        o + 2
    }
}

/// The VLAN identity of a received frame: (outer S-tag or 0, C-tag or 0, offset of the payload
/// ethertype). Accepts 0x88a8 or 0x8100 as the outer TPID (many access networks use 0x8100 twice).
pub fn rx_tags(f: &[u8]) -> Option<(u16, u16, usize)> {
    if f.len() < 14 {
        return None;
    }
    let tpid = |o: usize| u16::from_be_bytes([f[o], f[o + 1]]);
    let vid = |o: usize| u16::from_be_bytes([f[o + 2], f[o + 3]]) & 0x0fff;
    let t1 = tpid(12);
    if t1 != 0x8100 && t1 != 0x88a8 {
        return Some((0, 0, 12));
    }
    if f.len() < 18 {
        return None;
    }
    let t2 = tpid(16);
    if t2 == 0x8100 {
        if f.len() < 22 {
            return None;
        }
        return Some((vid(12), vid(16), 20));
    }
    Some((0, vid(12), 16))
}
