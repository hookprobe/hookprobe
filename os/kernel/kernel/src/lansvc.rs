//! Kernel side of the EL0 LAN-services server (ADR 0050 D4 step 2): Shield's DNS parsing — every client query and
//! every upstream answer — runs in `el0-lansvc`, one bounded excursion per message. The kernel only rebuilds the
//! result from a fixed record (bounds-checked against its own copy) and keeps every DECISION (Shield, policy).
//! D5: a fault or timeout resets the server and the message is treated as unparseable — a query passes un-inspected
//! exactly as an unparseable one always did (ADR 0023: never a self-inflicted outage), counted and reported.
//! Builds without the EL0 substrate (`mctls` off) parse in-kernel with the same code (`dnswire`).

use crate::dnswire::{Walk, Q};

#[cfg(feature = "mctls")]
mod el0 {
    use hal::lansvcabi::*;

    static LANSVC_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/el0_lansvc.elf"));

    #[cfg(feature = "cm5")]
    pub const BASE: usize = BASE_CM5;
    #[cfg(not(feature = "cm5"))]
    pub const BASE: usize = BASE_QEMU;
    const IO_PAGES: usize = IO_SIZE / 0x1000;
    const STACK_PAGES: usize = STACK_SIZE / 0x1000;
    const RW_MAX: usize = 8;
    #[cfg(feature = "cm5")]
    const BUDGET_US: u64 = 20_000;
    #[cfg(not(feature = "cm5"))]
    const BUDGET_US: u64 = 2_000_000;

    pub struct Server {
        entry: usize,
        sp_top: usize,
        io: [usize; IO_PAGES],
        rw: [(usize, usize, usize); RW_MAX],
        nrw: usize,
        pub calls: u64,
        pub faults: u64,
        pub restarts: u64,
    }
    pub static mut SRV: Option<Server> = None;
    static mut TRIED: bool = false;

    fn alloc() -> usize {
        #[cfg(feature = "cm5")]
        {
            arch_aarch64::mmu_cm5::alloc_frame()
        }
        #[cfg(not(feature = "cm5"))]
        {
            use hal::Mmu as _;
            arch_aarch64::Mmu.alloc_frame()
        }
    }
    fn map(va: usize, pa: usize, exec: bool, write: bool) -> bool {
        #[cfg(feature = "cm5")]
        {
            use arch_aarch64::mmu_cm5 as m;
            if exec {
                m::map_user_code(va, pa);
                true
            } else if write {
                m::map_user_data(va, pa)
            } else {
                m::map_user_data_ro(va, pa)
            }
        }
        #[cfg(not(feature = "cm5"))]
        {
            let m = arch_aarch64::Mmu;
            if exec {
                m.map_user_code_page(va, pa)
            } else if write {
                m.map_user_data_page(va, pa)
            } else {
                m.map_user_data_ro_page(va, pa)
            }
        }
    }

    /// The server, loaded on first use (once; a failed load is reported and the kernel parses in-kernel).
    pub fn server() -> Option<&'static mut Server> {
        unsafe {
            if !TRIED {
                TRIED = true;
                match load() {
                    Ok(s) => {
                        SRV = Some(s);
                        arch_aarch64::_print(format_args!(" [LANSVC] EL0 LAN-services server loaded at {:#x}: Shield's DNS query / answer parsing runs in EL0 (ADR 0050 D4 step 2)\n", BASE));
                    }
                    Err(why) => arch_aarch64::_print(format_args!(" [LANSVC] EL0 server FAILED to load ({}) — DNS parsing stays in-kernel (reported in /api/health)\n", why)),
                }
            }
            (*core::ptr::addr_of_mut!(SRV)).as_mut()
        }
    }

    fn load() -> Result<Server, &'static str> {
        let parsed = crate::elf::parse(LANSVC_ELF).map_err(|_| "ELF parse")?;
        let mut s = Server { entry: parsed.entry, sp_top: BASE + STACK_OFF + STACK_SIZE, io: [0; IO_PAGES], rw: [(0, 0, 0); RW_MAX], nrw: 0, calls: 0, faults: 0, restarts: 0 };
        for g in parsed.segs[..parsed.nsegs].iter() {
            if g.vaddr < BASE || g.vaddr + g.memsz > BASE + IMAGE_MAX {
                return Err("segment outside the window"); // the image must stay inside its own window
            }
            for p in 0..(g.memsz + 0xFFF) >> 12 {
                let f = alloc();
                if f == 0 {
                    return Err("out of frames (image)");
                }
                let voff = p * 0x1000;
                let n = g.filesz.saturating_sub(voff).min(0x1000);
                unsafe { core::ptr::write_bytes(f as *mut u8, 0, 0x1000) };
                if n > 0 {
                    unsafe { core::ptr::copy_nonoverlapping(LANSVC_ELF.as_ptr().add(g.offset + voff), f as *mut u8, n) };
                }
                if g.executable() {
                    arch_aarch64::mmu::sync_instruction_cache(f, 0x1000);
                } else if g.writable() {
                    if s.nrw == RW_MAX {
                        return Err("too many RW pages");
                    }
                    s.rw[s.nrw] = (f, g.offset + voff, n);
                    s.nrw += 1;
                }
                if !map(g.vaddr + voff, f, g.executable(), g.writable()) {
                    return Err("map image page refused");
                }
            }
        }
        for p in 0..STACK_PAGES {
            let f = alloc();
            if f == 0 || !map(BASE + STACK_OFF + p * 0x1000, f, false, true) {
                return Err("map stack refused");
            }
        }
        for p in 0..IO_PAGES {
            let f = alloc();
            if f == 0 || !map(BASE + IO_OFF + p * 0x1000, f, false, true) {
                return Err("map IO refused");
            }
            s.io[p] = f;
        }
        Ok(s)
    }

    impl Server {
        fn write(&mut self, mut off: usize, mut src: &[u8]) {
            while !src.is_empty() && off < IO_SIZE {
                let (pg, po) = (off / 0x1000, off % 0x1000);
                let n = src.len().min(0x1000 - po);
                unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), (self.io[pg] + po) as *mut u8, n) };
                off += n;
                src = &src[n..];
            }
        }
        /// Zero `n` bytes of the shared IO page at `off` (key material: operator 2026-11-11 decision 2A).
        pub fn scrub(&mut self, mut off: usize, mut n: usize) {
            while n > 0 && off < IO_SIZE {
                let (pg, po) = (off / 0x1000, off % 0x1000);
                let k = n.min(0x1000 - po);
                for i in 0..k {
                    unsafe { core::ptr::write_volatile((self.io[pg] + po + i) as *mut u8, 0) };
                }
                off += k;
                n -= k;
            }
        }
        /// Test hook: is this IO range all zero?
        #[allow(dead_code)]
        pub fn is_zero(&self, off: usize, n: usize) -> bool {
            let mut b = [0u8; 64];
            let k = n.min(64);
            self.read(off, &mut b[..k]);
            b[..k].iter().all(|&x| x == 0)
        }
        pub fn read(&self, mut off: usize, mut out: &mut [u8]) {
            while !out.is_empty() && off < IO_SIZE {
                let (pg, po) = (off / 0x1000, off % 0x1000);
                let n = out.len().min(0x1000 - po);
                unsafe { core::ptr::copy_nonoverlapping((self.io[pg] + po) as *const u8, out.as_mut_ptr(), n) };
                off += n;
                out = &mut out[n..];
            }
        }
        fn r32(&self, off: usize) -> u32 {
            let mut b = [0u8; 4];
            self.read(off, &mut b);
            u32::from_le_bytes(b)
        }
        /// One command; `(status, out_len)`. A fault / timeout resets the server and reports ST_PANIC.
        pub fn call(&mut self, cmd: u32, input: &[u8]) -> (u32, usize) {
            let n = input.len().min(IN_MAX);
            self.write(H_MAGIC, &MAGIC.to_le_bytes());
            self.write(H_CMD, &cmd.to_le_bytes());
            self.write(H_IN_LEN, &(n as u32).to_le_bytes());
            self.write(H_STATUS, &ST_PANIC.to_le_bytes());
            self.write(IN_OFF, &input[..n]);
            self.calls += 1;
            let how = crate::excursion_bounded(self.entry, self.sp_top, BUDGET_US);
            let st = if how == crate::Excursion::Exited { self.r32(H_STATUS) } else { ST_PANIC };
            if st == ST_PANIC {
                self.faults += 1;
                self.reset();
                return (ST_PANIC, 0);
            }
            (st, (self.r32(H_OUT_LEN) as usize).min(OUT_MAX))
        }
        /// Fail closed and recover: restore the image's data/bss pages and zero the IO region.
        fn reset(&mut self) {
            self.restarts += 1;
            for i in 0..self.nrw {
                let (f, off, n) = self.rw[i];
                unsafe {
                    core::ptr::write_bytes(f as *mut u8, 0, 0x1000);
                    if n > 0 {
                        core::ptr::copy_nonoverlapping(LANSVC_ELF.as_ptr().add(off), f as *mut u8, n);
                    }
                }
            }
            for f in self.io.iter() {
                unsafe { core::ptr::write_bytes(*f as *mut u8, 0, 0x1000) };
            }
        }
    }
}

static mut IN_KERNEL: u64 = 0;

/// (where, messages parsed in EL0, EL0 faults, EL0 restarts, messages parsed in-kernel)
pub fn stats() -> (&'static str, u64, u64, u64, u64) {
    #[cfg(feature = "mctls")]
    if let Some(s) = unsafe { (*core::ptr::addr_of!(el0::SRV)).as_ref() } {
        return ("el0", s.calls, s.faults, s.restarts, unsafe { IN_KERNEL });
    }
    ("el1", 0, 0, 0, unsafe { IN_KERNEL })
}

/// A client DNS query → its question facts (None = not a standard one-question query, or the parser failed).
pub fn dns_query(dns: &[u8]) -> Option<Q> {
    #[cfg(feature = "mctls")]
    if let Some(s) = el0::server() {
        use hal::lansvcabi::*;
        if dns.len() > IN_MAX {
            return None;
        }
        let (st, n) = s.call(CMD_DNS_QUERY, dns);
        if st != ST_OK || n < Q_REC_HDR {
            return None;
        }
        let mut h = [0u8; Q_REC_HDR];
        s.read(OUT_OFF, &mut h);
        let nl = u16::from_le_bytes([h[0], h[1]]) as usize;
        let qend = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
        if nl > 255 || n != Q_REC_HDR + nl || qend > dns.len() || qend < 12 + 5 {
            return None; // a record that cannot be right: treat as unparseable
        }
        let mut q = Q { name: [0; 256], nl, qtype: u16::from_le_bytes([h[2], h[3]]), qend, edns: h[8] != 0 };
        s.read(OUT_OFF + Q_REC_HDR, &mut q.name[..nl]);
        return Some(q);
    }
    unsafe { IN_KERNEL += 1 };
    crate::dnswire::parse_query(dns)
}

/// An upstream DNS answer → question name + end + CNAME targets (None = malformed: Shield passes it untouched).
pub fn dns_walk(dns: &[u8], w: &mut Walk) -> Option<()> {
    #[cfg(feature = "mctls")]
    if let Some(s) = el0::server() {
        use hal::lansvcabi::*;
        if dns.len() > IN_MAX {
            return None;
        }
        let (st, n) = s.call(CMD_DNS_WALK, dns);
        if st != ST_OK || n < WALK_HDR {
            return None;
        }
        let mut h = [0u8; 8];
        s.read(OUT_OFF, &mut h);
        let qnl = u16::from_le_bytes([h[0], h[1]]) as usize;
        let k = u16::from_le_bytes([h[2], h[3]]) as usize;
        let qend = u32::from_le_bytes([h[4], h[5], h[6], h[7]]) as usize;
        if qnl > 255 || k > WALK_MAX_CNAMES || k > crate::dnswire::MAX_CNAMES || n != WALK_HDR + k * WALK_STRIDE || qend > dns.len() {
            return None;
        }
        w.qnl = qnl;
        w.qend = qend;
        s.read(OUT_OFF + 8, &mut w.qname);
        w.ncname = k;
        for i in 0..k {
            let o = OUT_OFF + WALK_HDR + i * WALK_STRIDE;
            let mut l = [0u8; 2];
            s.read(o, &mut l);
            let len = u16::from_le_bytes(l) as usize;
            if len > 255 {
                return None;
            }
            w.cnl[i] = len;
            s.read(o + 2, &mut w.cnames[i]);
        }
        return Some(());
    }
    unsafe { IN_KERNEL += 1 };
    crate::dnswire::walk_answers(dns, w)
}

/// D4 step 2b: the DHCP server's parse of one client frame, in the EL0 server. `None` = the server faulted (reset,
/// counted): the DHCP server treats the frame as unparseable — no reply, the client retries. Without the EL0 server
/// (load failed / `mctls` off) the same `hal::dhcpwire` parses in-kernel.
#[cfg(feature = "mctls")]
fn dhcp_el0(eth: &[u8]) -> Option<hal::dhcpwire::ClientReq> {
    if let Some(s) = el0::server() {
        use hal::lansvcabi::*;
        if eth.len() > IN_MAX {
            return None;
        }
        let (st, n) = s.call(CMD_DHCP_PARSE, eth);
        if st != ST_OK || n != hal::dhcpwire::REC_LEN {
            return None;
        }
        let mut o = [0u8; hal::dhcpwire::REC_LEN];
        s.read(OUT_OFF, &mut o);
        return Some(hal::dhcpwire::decode(&o));
    }
    unsafe { IN_KERNEL += 1 };
    Some(hal::dhcpwire::parse_client(eth))
}

/// D4 step 3: one WAN-side call. `None` = the server faulted (reset, counted). `Some((status, record))` otherwise.
#[cfg(feature = "mctls")]
fn wan_call<const N: usize>(cmd: u32, pre: &[u8], pkt: &[u8]) -> Option<(u32, [u8; N])> {
    use hal::lansvcabi::*;
    let s = el0::server()?;
    if pre.len() + pkt.len() > IN_MAX {
        return Some((ST_NONE, [0; N]));
    }
    let mut buf = [0u8; IN_MAX];
    buf[..pre.len()].copy_from_slice(pre);
    buf[pre.len()..pre.len() + pkt.len()].copy_from_slice(pkt);
    let (st, n) = s.call(cmd, &buf[..pre.len() + pkt.len()]);
    if st == ST_PANIC {
        return None;
    }
    let mut o = [0u8; N];
    if st == ST_OK && n == N {
        s.read(OUT_OFF, &mut o);
        return Some((ST_OK, o));
    }
    Some((ST_NONE, o))
}
#[cfg(feature = "mctls")]
fn wan_dhcp_reply(eth: &[u8], xid: &[u8; 4], mac: &[u8; 6]) -> Option<hal::dhcpwire::ReplyFacts> {
    if el0::server().is_none() {
        unsafe { IN_KERNEL += 1 };
        return Some(hal::dhcpwire::dhcp_reply_facts(eth, xid, mac));
    }
    let mut pre = [0u8; 10];
    pre[..4].copy_from_slice(xid);
    pre[4..].copy_from_slice(mac);
    let (st, o) = wan_call::<{ hal::dhcpwire::FACTS_LEN }>(hal::lansvcabi::CMD_WAN_DHCP_REPLY, &pre, eth)?;
    Some(if st == hal::lansvcabi::ST_OK { hal::dhcpwire::decode_facts(&o) } else { Default::default() })
}
#[cfg(feature = "mctls")]
fn wan_ra(ip: &[u8]) -> Option<Option<hal::ip6::Ra>> {
    if el0::server().is_none() {
        unsafe { IN_KERNEL += 1 };
        return Some(hal::ip6::parse_ra(ip));
    }
    let (st, o) = wan_call::<{ hal::ip6::RA_LEN }>(hal::lansvcabi::CMD_WAN_RA, &[], ip)?;
    Some((st == hal::lansvcabi::ST_OK).then(|| hal::ip6::decode_ra(&o)))
}
#[cfg(feature = "mctls")]
fn wan_dhcp6(ip: &[u8], xid: u32) -> Option<Option<hal::ip6::Dhcp6>> {
    if el0::server().is_none() {
        unsafe { IN_KERNEL += 1 };
        return Some(hal::ip6::parse_dhcp6(ip, xid));
    }
    let (st, o) = wan_call::<{ hal::ip6::DHCP6_LEN }>(hal::lansvcabi::CMD_WAN_DHCP6, &xid.to_le_bytes(), ip)?;
    Some((st == hal::lansvcabi::ST_OK).then(|| hal::ip6::decode_dhcp6(&o)))
}

#[cfg(feature = "mctls")]
fn wan_pppoe_disc(f: &[u8], plen: usize) -> Option<hal::pppwire::DiscTags> {
    if el0::server().is_none() {
        unsafe { IN_KERNEL += 1 };
        return Some(hal::pppwire::disc_tags(f, plen));
    }
    let (st, o) = wan_call::<{ hal::pppwire::DISC_LEN }>(hal::lansvcabi::CMD_WAN_PPPOE_DISC, &(plen.min(0xffff) as u16).to_le_bytes(), f)?;
    Some(if st == hal::lansvcabi::ST_OK { hal::pppwire::decode_disc(&o) } else { hal::pppwire::DISC0 })
}

#[cfg(feature = "mctls")]
fn wan_lcp(data: &[u8]) -> Option<hal::pppwire::LcpReq> {
    if el0::server().is_none() {
        unsafe { IN_KERNEL += 1 };
        return Some(hal::pppwire::lcp_classify(data));
    }
    let (st, o) = wan_call::<{ hal::pppwire::LCP_LEN }>(hal::lansvcabi::CMD_WAN_LCP_REQ, &[], data)?;
    Some(if st == hal::lansvcabi::ST_OK { hal::pppwire::decode_lcp(&o) } else { hal::pppwire::LcpReq { malformed: true, ..hal::pppwire::LCP0 } })
}

#[cfg(feature = "mctls")]
fn wan_ipcp(code: u8, data: &[u8]) -> Option<hal::pppwire::IpcpFacts> {
    if el0::server().is_none() {
        unsafe { IN_KERNEL += 1 };
        return Some(hal::pppwire::ipcp_facts(code, data));
    }
    let (st, o) = wan_call::<{ hal::pppwire::IPCP_LEN }>(hal::lansvcabi::CMD_WAN_IPCP, &[code], data)?;
    Some(if st == hal::lansvcabi::ST_OK { hal::pppwire::decode_ipcp(&o) } else { hal::pppwire::IpcpFacts { malformed: true, ..hal::pppwire::IPCP0 } })
}

#[cfg(feature = "mctls")]
fn wan_chap(data: &[u8]) -> Option<hal::pppwire::ChapChallenge> {
    if el0::server().is_none() {
        unsafe { IN_KERNEL += 1 };
        return Some(hal::pppwire::chap_challenge(data));
    }
    let (st, o) = wan_call::<{ hal::pppwire::CHAP_LEN }>(hal::lansvcabi::CMD_WAN_CHAP, &[], data)?;
    Some(if st == hal::lansvcabi::ST_OK { hal::pppwire::decode_chap(&o) } else { hal::pppwire::CHAP0 })
}
#[cfg(feature = "mctls")]
fn wan_ip6cp(data: &[u8]) -> Option<hal::pppwire::Ip6cpReq> {
    if el0::server().is_none() {
        unsafe { IN_KERNEL += 1 };
        return Some(hal::pppwire::ip6cp_req(data));
    }
    let (st, o) = wan_call::<{ hal::pppwire::IP6CP_LEN }>(hal::lansvcabi::CMD_WAN_IP6CP, &[], data)?;
    Some(if st == hal::lansvcabi::ST_OK { hal::pppwire::decode_ip6cp(&o) } else { hal::pppwire::Ip6cpReq { malformed: true, ..hal::pppwire::IP6CP0 } })
}

#[cfg(feature = "mctls")]
fn wan_lcp_peer(code: u8, data: &[u8]) -> Option<hal::pppwire::LcpPeer> {
    if el0::server().is_none() {
        unsafe { IN_KERNEL += 1 };
        return Some(hal::pppwire::lcp_peer(code, data));
    }
    let (st, o) = wan_call::<{ hal::pppwire::LCPPEER_LEN }>(hal::lansvcabi::CMD_WAN_LCP_PEER, &[code], data)?;
    Some(if st == hal::lansvcabi::ST_OK { hal::pppwire::decode_lcp_peer(&o) } else { hal::pppwire::LCPPEER0 })
}

#[cfg(feature = "mctls")]
fn sta_m2(pmk: &[u8; 32], aa: &[u8; 6], spa: &[u8; 6], anonce: &[u8; 32], akm8: bool, m2: &[u8]) -> Option<Option<[u8; 48]>> {
    if el0::server().is_none() {
        unsafe { IN_KERNEL += 1 };
        return Some(hal::wpaauth::on_m2(pmk, aa, spa, anonce, akm8, m2));
    }
    // operator 2026-11-11 decision 2A: the PMK reaches EL0 only through this one capability (the M2 command on the
    // LAN-services server's IO page), is never logged nor exposed through the management ABI, and is erased from
    // every copy the kernel controls (stack buffer, the IO page's input and output) as soon as the call returns
    use hal::lansvcabi::*;
    let s = el0::server()?;
    if hal::wpaauth::M2_PRE + m2.len() > IN_MAX {
        return Some(None);
    }
    let mut buf = [0u8; IN_MAX];
    buf[0..32].copy_from_slice(pmk);
    buf[32..38].copy_from_slice(aa);
    buf[38..44].copy_from_slice(spa);
    buf[44..76].copy_from_slice(anonce);
    buf[76] = akm8 as u8;
    let n = hal::wpaauth::M2_PRE + m2.len();
    buf[hal::wpaauth::M2_PRE..n].copy_from_slice(m2);
    let (st, len) = s.call(CMD_STA_M2, &buf[..n]);
    hal::wpaauth::wipe(&mut buf[..hal::wpaauth::M2_PRE]);
    let mut o = [0u8; hal::wpaauth::M2_OUT];
    if st == ST_OK && len == o.len() {
        s.read(OUT_OFF, &mut o);
    }
    s.scrub(IN_OFF, hal::wpaauth::M2_PRE);
    s.scrub(OUT_OFF, hal::wpaauth::M2_OUT);
    if st == ST_PANIC {
        return None;
    }
    let r = (st == ST_OK && o[0] != 0).then(|| {
        let mut p = [0u8; 48];
        p.copy_from_slice(&o[1..49]);
        p
    });
    hal::wpaauth::wipe(&mut o);
    Some(r)
}
#[cfg(feature = "mctls")]
fn sta_m4(kck: &[u8; 16], akm8: bool, m4: &[u8]) -> Option<bool> {
    if el0::server().is_none() {
        unsafe { IN_KERNEL += 1 };
        return Some(hal::wpaauth::on_m4(kck, akm8, m4));
    }
    let mut pre = [0u8; hal::wpaauth::M4_PRE];
    pre[..16].copy_from_slice(kck);
    pre[16] = akm8 as u8;
    let r = wan_call::<1>(hal::lansvcabi::CMD_STA_M4, &pre, m4);
    hal::wpaauth::wipe(&mut pre);
    if let Some(s) = el0::server() {
        s.scrub(hal::lansvcabi::IN_OFF, hal::wpaauth::M4_PRE);
    }
    let (st, o) = r?;
    Some(st == hal::lansvcabi::ST_OK && o[0] != 0)
}

#[cfg(feature = "mctls")]
fn sta_eapol(e: &[u8], sta: &[u8; 6], secure: bool, replay: u64) -> Option<Option<usize>> {
    if el0::server().is_none() {
        unsafe { IN_KERNEL += 1 };
        return Some(hal::eapolwire::eapol_key(e, sta, secure, replay));
    }
    let mut pre = [0u8; 15];
    pre[..6].copy_from_slice(sta);
    pre[6] = secure as u8;
    pre[7..15].copy_from_slice(&replay.to_le_bytes());
    let (st, o) = wan_call::<3>(hal::lansvcabi::CMD_STA_EAPOL, &pre, e)?;
    Some((st == hal::lansvcabi::ST_OK && o[0] != 0).then(|| u16::from_le_bytes([o[1], o[2]]) as usize))
}
#[cfg(feature = "mctls")]
fn sta_mfpc(m2: &[u8], body_off: usize) -> Option<bool> {
    if el0::server().is_none() {
        unsafe { IN_KERNEL += 1 };
        return Some(hal::eapolwire::m2_mfpc(m2, body_off));
    }
    let (st, o) = wan_call::<1>(hal::lansvcabi::CMD_STA_MFPC, &(body_off.min(0xffff) as u16).to_le_bytes(), m2)?;
    Some(st == hal::lansvcabi::ST_OK && o[0] != 0)
}

/// D4 step 5c: one station SAE Authentication frame body → its checked facts, walked in the EL0 server. `None` = the
/// server faulted (the AP rejects the attempt and forgets the station's SAE state). Only public bytes cross: the
/// body the station sent and the AP's H2E flag; the record back holds the station's own scalar / element / confirm.
/// Both IO regions are still scrubbed after the call, so the page never carries one station's frame into the next.
#[cfg(feature = "mctls")]
fn sta_sae(body: &[u8], h2e_ok: bool) -> Option<hal::saewire::Msg> {
    use hal::saewire as w;
    if el0::server().is_none() {
        unsafe { IN_KERNEL += 1 };
        return Some(w::parse(body, h2e_ok));
    }
    // the caller trims to the event's own length; an over-long body is refused whole, never truncated to fit
    if body.len() > w::BODY_MAX {
        return Some(w::dropped(w::R_TOO_LONG));
    }
    let r = wan_call::<{ w::REC_LEN }>(hal::lansvcabi::CMD_STA_SAE, &[h2e_ok as u8], body);
    if let Some(s) = el0::server() {
        s.scrub(hal::lansvcabi::IN_OFF, 1 + body.len());
        s.scrub(hal::lansvcabi::OUT_OFF, w::REC_LEN);
    }
    let (st, mut o) = r?;
    let m = if st == hal::lansvcabi::ST_OK { w::decode(&o) } else { w::dropped(w::R_BAD_RECORD) };
    hal::wpaauth::wipe(&mut o);
    Some(m)
}

/// Route the DHCP server's parse (step 2b) and the WAN control parsers (step 3) through `el0-lansvc` (called once
/// at boot, before any client is served or the uplink comes up).
pub fn install_dhcp() {
    #[cfg(feature = "mctls")]
    unsafe {
        arch_aarch64::dhcpd::EL0_PARSE = Some(dhcp_el0);
        arch_aarch64::wanparse::EL0_DHCP_REPLY = Some(wan_dhcp_reply);
        arch_aarch64::wanparse::EL0_RA = Some(wan_ra);
        arch_aarch64::wanparse::EL0_DHCP6 = Some(wan_dhcp6);
        arch_aarch64::wanparse::EL0_PPPOE_DISC = Some(wan_pppoe_disc);
        arch_aarch64::wanparse::EL0_LCP = Some(wan_lcp);
        arch_aarch64::wanparse::EL0_IPCP = Some(wan_ipcp);
        arch_aarch64::wanparse::EL0_CHAP = Some(wan_chap);
        arch_aarch64::wanparse::EL0_IP6CP = Some(wan_ip6cp);
        arch_aarch64::wanparse::EL0_EAPOL = Some(sta_eapol);
        arch_aarch64::wanparse::EL0_LCP_PEER = Some(wan_lcp_peer);
        arch_aarch64::wanparse::EL0_MFPC = Some(sta_mfpc);
        arch_aarch64::wanparse::EL0_STA_M2 = Some(sta_m2);
        arch_aarch64::wanparse::EL0_STA_M4 = Some(sta_m4);
        arch_aarch64::wanparse::EL0_SAE = Some(sta_sae);
    };
}

/// [P-lansvc] ADR 0050 D4 step 2: Shield's DNS parsing in the EL0 server gives the SAME facts as the in-kernel
/// parser (a query; an answer with a CNAME chain), and a server fault is contained: the server resets, the message
/// reads as unparseable, and the next message parses again.
#[cfg(feature = "mctls")]
pub fn selftest() -> bool {
    use crate::dnswire::{parse_query, walk_answers, WALK0};
    // query: id 0x1234, RD, 1 question "ads.example.com" A, EDNS OPT
    let mut q = [0u8; 64];
    let hdr = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
    q[..12].copy_from_slice(&hdr);
    let mut n = 12;
    for l in [&b"ads"[..], b"example", b"com"] {
        q[n] = l.len() as u8;
        q[n + 1..n + 1 + l.len()].copy_from_slice(l);
        n += 1 + l.len();
    }
    q[n] = 0;
    q[n + 1..n + 5].copy_from_slice(&[0, 1, 0, 1]);
    n += 5;
    q[n..n + 11].copy_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
    n += 11;
    let k = parse_query(&q[..n]);
    let e = dns_query(&q[..n]);
    let same_q = matches!((&k, &e), (Some(a), Some(b)) if a.nl == b.nl && a.name[..a.nl] == b.name[..b.nl] && a.qtype == b.qtype && a.qend == b.qend && a.edns == b.edns);
    // answer: the same question, 2 answers: CNAME -> tracker.bad.example, A
    let mut r = [0u8; 160];
    r[..n - 11].copy_from_slice(&q[..n - 11]);
    r[2] = 0x81;
    r[3] = 0x80;
    r[7] = 2;
    r[11] = 0;
    let mut m = n - 11;
    r[m..m + 12].copy_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 0]);
    let rdl_at = m + 10;
    m += 12;
    let t0 = m;
    for l in [&b"tracker"[..], b"bad", b"example"] {
        r[m] = l.len() as u8;
        r[m + 1..m + 1 + l.len()].copy_from_slice(l);
        m += 1 + l.len();
    }
    r[m] = 0;
    m += 1;
    let rdl = (m - t0) as u16;
    r[rdl_at..rdl_at + 2].copy_from_slice(&rdl.to_be_bytes());
    r[m..m + 16].copy_from_slice(&[0xc0, t0 as u8, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 9]);
    m += 16;
    let mut wk = WALK0;
    let mut we = WALK0;
    let ok_k = walk_answers(&r[..m], &mut wk).is_some();
    let ok_e = dns_walk(&r[..m], &mut we).is_some();
    let same_w = ok_k && ok_e && wk.qnl == we.qnl && wk.qname[..wk.qnl] == we.qname[..we.qnl] && wk.qend == we.qend
        && wk.ncname == 1 && we.ncname == 1 && we.cnames[0][..we.cnl[0]] == *b"tracker.bad.example";
    // a malformed message is unparseable in both
    let bad = dns_query(&[0xff; 7]).is_none() && dns_walk(&[0xc0; 40], &mut we).is_none();
    // fault containment: deliberate EL0 fault -> reset, counted; the next query parses again
    let (where_, _, f0, r0, _) = stats();
    let faulted = match el0::server() {
        Some(s) => s.call(hal::lansvcabi::CMD_SELFTEST_FAULT, &[]).0 == hal::lansvcabi::ST_PANIC,
        None => false,
    };
    let (_, _, f1, r1, _) = stats();
    let recovered = faulted && f1 == f0 + 1 && r1 == r0 + 1 && dns_query(&q[..n]).is_some();
    // D4 step 2b: a DHCP REQUEST (option 50, hostname, vendor, PRL) parses to the same facts in EL0 as in-kernel
    let mut f = [0u8; 400];
    f[12] = 0x08;
    f[14] = 0x45;
    f[23] = 17;
    f[34..38].copy_from_slice(&[0, 68, 0, 67]);
    let b = 42;
    f[b] = 1;
    f[b + 4..b + 8].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    f[b + 28..b + 34].copy_from_slice(&[2, 0, 0, 0, 0, 0x2b]);
    f[b + 236..b + 240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    let opts: &[u8] = &[53, 1, 3, 50, 4, 10, 99, 0, 42, 12, 6, b'p', b'h', b'o', b'n', b'e', b'1', 60, 4, b'a', b'n', b'd', b'r', 55, 3, 1, 3, 6, 255];
    f[b + 240..b + 240 + opts.len()].copy_from_slice(opts);
    let fl = b + 240 + opts.len();
    let kd = hal::dhcpwire::parse_client(&f[..fl]);
    install_dhcp();
    let ed = arch_aarch64::dhcpd::parse_request(&f[..fl]);
    let same_d = kd.mt == 3 && ed.mt == 3 && ed.cmac == kd.cmac && ed.xid == kd.xid && ed.req_ip == [10, 99, 0, 42] && ed.req_ip == kd.req_ip
        && ed.id.host[..ed.id.hlen as usize] == *b"phone1" && ed.id.vendor[..ed.id.vlen as usize] == *b"andr" && ed.id.prl[..ed.id.plen as usize] == [1, 3, 6];
    let bad_d = arch_aarch64::dhcpd::parse_request(&f[..100]).mt == 0;
    // D4 step 3 (WAN control): a DHCP OFFER, a Router Advertisement and junk give the same facts through EL0
    use arch_aarch64::wanparse;
    let (xid, me) = ([1u8, 2, 3, 4], [2u8, 0, 0, 0, 0, 0x77]);
    let mut o = [0u8; 400];
    o[..6].copy_from_slice(&me);
    o[12] = 0x08;
    o[14] = 0x45;
    o[23] = 17;
    o[34..38].copy_from_slice(&[0, 67, 0, 68]);
    o[b] = 2;
    o[b + 4..b + 8].copy_from_slice(&xid);
    o[b + 16..b + 20].copy_from_slice(&[100, 64, 0, 9]);
    o[b + 28..b + 34].copy_from_slice(&me);
    o[b + 236..b + 240].copy_from_slice(&[0x63, 0x82, 0x53, 0x63]);
    let oo: &[u8] = &[53, 1, 2, 54, 4, 100, 64, 0, 1, 3, 4, 100, 64, 0, 1, 1, 4, 255, 255, 255, 0, 6, 4, 1, 1, 1, 1, 51, 4, 0, 0, 14, 16, 255];
    o[b + 240..b + 240 + oo.len()].copy_from_slice(oo);
    let ol = b + 240 + oo.len();
    let mut k1 = arch_aarch64::apparse::DhcpResult::new();
    let mut e1 = arch_aarch64::apparse::DhcpResult::new();
    let mk = hal::dhcpwire::parse_dhcp_reply(&o[..ol], &xid, &me, &mut k1);
    let me1 = wanparse::dhcp_reply(&o[..ol], &xid, &me, &mut e1);
    let same_offer = mk == 2 && me1 == 2 && e1.yiaddr == k1.yiaddr && e1.server == k1.server && e1.router == k1.router
        && e1.mask == k1.mask && e1.dns == k1.dns && e1.lease == 3600 && e1.udp68_seen == 1;
    let other_xid = wanparse::dhcp_reply(&o[..ol], &[9, 9, 9, 9], &me, &mut e1) == 0;
    let rtr = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let all: [u8; 16] = [0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let mut ra = [0u8; 40 + 16 + 32];
    let il = 16 + 32;
    ra[0] = 0x60;
    ra[4..6].copy_from_slice(&(il as u16).to_be_bytes());
    ra[6] = 58;
    ra[7] = 255;
    ra[8..24].copy_from_slice(&rtr);
    ra[24..40].copy_from_slice(&all);
    ra[40] = 134;
    ra[46..48].copy_from_slice(&1800u16.to_be_bytes());
    ra[56] = 3;
    ra[57] = 4;
    ra[58] = 64;
    ra[59] = 0xc0;
    ra[60..64].copy_from_slice(&86400u32.to_be_bytes());
    ra[72..80].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2]);
    let c = hal::ip6::l4_csum(&rtr, &all, 58, &ra[40..40 + il]);
    ra[42..44].copy_from_slice(&c.to_be_bytes());
    let same_ra = matches!((hal::ip6::parse_ra(&ra), wanparse::ra(&ra)), (Some(a), Some(b)) if a == b && b.has_prefix && b.plen == 64 && b.lifetime == 1800);
    let mut rbad = ra;
    rbad[42] ^= 1;
    let junk = wanparse::ra(&rbad).is_none() && wanparse::dhcp6(&ra, 7).is_none() && wanparse::dhcp6(&[0x60; 3], 7).is_none();
    // D4 step 3b: a PADO's tags (host-uniq, cookie, AC-name, an error tag) walk to the same facts in EL0
    let mut pf = [0u8; 120];
    pf[12] = 0x88;
    pf[13] = 0x63;
    pf[14] = 0x11;
    pf[15] = 0x07;
    let tags: &[u8] = &[0x01, 0x03, 0, 4, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x04, 0, 3, b'c', b'k', b'1', 0x01, 0x02, 0, 2, b'A', b'C', 0x02, 0x03, 0, 0];
    pf[20..20 + tags.len()].copy_from_slice(tags);
    pf[18..20].copy_from_slice(&(tags.len() as u16).to_be_bytes());
    let (k, e) = (hal::pppwire::disc_tags(&pf, tags.len()), wanparse::pppoe_disc(&pf, tags.len()));
    let pppoe = k == e && e.hu_len == 4 && e.host_uniq[..4] == [0xde, 0xad, 0xbe, 0xef] && e.cookie[..e.cookie_len as usize] == *b"ck1"
        && e.ac_name[..e.ac_name_len as usize] == *b"AC" && e.err;
    // 3b-ii: an LCP Configure-Request (MRU, auth PAP, an unknown option 0x0d) classifies identically
    let lcp_in: &[u8] = &[1, 4, 0x05, 0xd4, 3, 4, 0xc0, 0x23, 0x0d, 3, 6];
    let (lk, le) = (hal::pppwire::lcp_classify(lcp_in), wanparse::lcp_req(lcp_in));
    let lcp = lk == le && le.auth == 0xc023 && le.nrej == 3 && le.rej[..3] == [0x0d, 3, 6] && wanparse::lcp_req(&[3, 1]).malformed;
    // 3b-iii: an IPCP Configure-Nak (our address, DNS 1 + 2) and a Request with VJ compression (rejected) classify
    // identically
    let nak_in: &[u8] = &[3, 6, 10, 67, 0, 10, 129, 6, 1, 1, 1, 1, 131, 6, 9, 9, 9, 9];
    let req_in: &[u8] = &[2, 6, 0, 0x2d, 0x0f, 1, 3, 6, 10, 67, 0, 1];
    let ipcp = hal::pppwire::ipcp_facts(3, nak_in) == wanparse::ipcp(3, nak_in) && wanparse::ipcp(3, nak_in).dns2 == Some([9, 9, 9, 9])
        && hal::pppwire::ipcp_facts(1, req_in) == wanparse::ipcp(1, req_in) && wanparse::ipcp(1, req_in).nrej == 6
        && wanparse::ipcp(1, req_in).peer == Some([10, 67, 0, 1]);
    // 3b-iv: a CHAP Challenge (16-byte value + name) and an IPv6CP Request (IID + an unknown option) identically
    let ch_in: &[u8] = &[16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, b'A', b'C'];
    let i6_in: &[u8] = &[1, 10, 0, 0, 0, 0, 0, 0, 0, 1, 2, 4, 0, 0];
    let ppp4 = hal::pppwire::chap_challenge(ch_in) == wanparse::chap(ch_in) && wanparse::chap(ch_in).vs == 16 && !wanparse::chap(&[70, 1]).ok
        && hal::pppwire::ip6cp_req(i6_in) == wanparse::ip6cp(i6_in) && wanparse::ip6cp(i6_in).nrej == 4 && wanparse::ip6cp(i6_in).peer_iid[7] == 1;
    let pppoe = pppoe && lcp && ipcp && ppp4;
    // step 5a: an EAPOL-Key M2 (pairwise + MIC, replay 1, RSNE with MFP-capable) classifies identically; another
    // station / a stale replay counter is not ours
    let sta = [2u8, 0, 0, 0, 0, 0x5a];
    let mut ek = [0u8; 160];
    ek[6..12].copy_from_slice(&sta);
    ek[12] = 0x88;
    ek[13] = 0x8e;
    ek[15] = 3;
    ek[16..18].copy_from_slice(&(141u16).to_be_bytes()); // 802.1X body length
    ek[19..21].copy_from_slice(&(0x010au16).to_be_bytes()); // key info: pairwise | MIC, ver 2
    ek[23..31].copy_from_slice(&1u64.to_be_bytes());
    let kd_at = 18 + 93;
    ek[kd_at..kd_at + 2].copy_from_slice(&22u16.to_be_bytes());
    ek[kd_at + 2..kd_at + 24].copy_from_slice(&[0x30, 20, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 4, 1, 0, 0, 0x0f, 0xac, 2, 0x80, 0]);
    let sta_ok = hal::eapolwire::eapol_key(&ek, &sta, false, 1) == wanparse::eapol_key(&ek, &sta, false, 1)
        && wanparse::eapol_key(&ek, &sta, false, 1) == Some(145) && wanparse::eapol_key(&ek, &[9; 6], false, 1).is_none()
        && wanparse::eapol_key(&ek, &sta, false, 2).is_none() && {
            // metal batch 62: the AP hands the rest of its SDPCM buffer, longer than the EL0 input window
            let mut big = [0u8; 3000];
            big[..160].copy_from_slice(&ek);
            wanparse::eapol_key(&big, &sta, false, 1) == Some(145)
        } && wanparse::m2_mfpc(&ek[14..], 4) && hal::eapolwire::m2_mfpc(&ek[14..], 4);
    // 3b-v: the AC's Nak (MRU 1400 + magic) and Reject (MRU + magic) of our LCP request classify identically
    let lnak = [1u8, 4, 0x05, 0x78, 5, 6, 1, 2, 3, 4];
    let lcp_peer_ok = hal::pppwire::lcp_peer(3, &lnak) == wanparse::lcp_peer(3, &lnak)
        && wanparse::lcp_peer(3, &lnak) == hal::pppwire::LcpPeer { mru: Some(1400), magic_nak: true, rej_mru: false, rej_magic: false }
        && wanparse::lcp_peer(4, &lnak) == hal::pppwire::LcpPeer { mru: None, magic_nak: false, rej_mru: true, rej_magic: true }
        && wanparse::lcp_peer(3, &[1, 9, 0]) == hal::pppwire::LCPPEER0;
    // 5b: M2 / M4 crypto in EL0 — for AKM 2 (PRF-SHA1 + HMAC-SHA1 MIC) and AKM 8 (KDF-SHA256 + AES-CMAC, the `sae`
    // crate's KDF as the independent reference): identical PTK, MIC accepted; a flipped MIC bit / another PMK /
    // a truncated frame refused; M4 likewise
    let sta_crypto_ok = {
        let (pmk, aa, spa, an, sn) = ([0x11u8; 32], [2u8, 0, 0, 0, 0, 1], [2u8, 0, 0, 0, 0, 0x5a], [0x22u8; 32], [0x33u8; 32]);
        let mut all = true;
        for akm8 in [false, true] {
            #[cfg(not(feature = "wpa3"))]
            if akm8 {
                continue;
            }
            #[cfg(feature = "wpa3")]
            let reference = if akm8 { sae::ptk_sha256(&pmk, &aa, &spa, &an, &sn) } else { hal::wpa::wpa_ptk(&pmk, &aa, &spa, &an, &sn) };
            #[cfg(not(feature = "wpa3"))]
            let reference = hal::wpa::wpa_ptk(&pmk, &aa, &spa, &an, &sn);
            let mut kck = [0u8; 16];
            kck.copy_from_slice(&reference[..16]);
            let mut f = [0u8; 4 + 95 + 22];
            f[0] = 2;
            f[1] = 3;
            f[2..4].copy_from_slice(&((95 + 22) as u16).to_be_bytes());
            f[4] = 2;
            f[5..7].copy_from_slice(&(if akm8 { 0x0108u16 } else { 0x010au16 }).to_be_bytes());
            f[4 + 13..4 + 45].copy_from_slice(&sn);
            let m = hal::wpaauth::mic(&kck, &f, akm8);
            f[4 + 77..4 + 93].copy_from_slice(&m);
            let good = wanparse::sta_m2(&pmk, &aa, &spa, &an, akm8, &f) == Some(reference);
            let mut bad = f;
            bad[4 + 80] ^= 1;
            let flipped = wanparse::sta_m2(&pmk, &aa, &spa, &an, akm8, &bad).is_none();
            let other_pmk = wanparse::sta_m2(&[0x12; 32], &aa, &spa, &an, akm8, &f).is_none();
            let short = wanparse::sta_m2(&pmk, &aa, &spa, &an, akm8, &f[..60]).is_none();
            let m4 = wanparse::sta_m4(&kck, akm8, &f) && !wanparse::sta_m4(&kck, akm8, &bad) && !wanparse::sta_m4(&[0; 16], akm8, &f);
            // decision 2A: after the calls, the shared IO page holds neither the PMK (input) nor the PTK (output)
            let _ = wanparse::sta_m2(&pmk, &aa, &spa, &an, akm8, &f);
            let wiped = el0::server().is_none_or(|s| s.is_zero(hal::lansvcabi::IN_OFF, hal::wpaauth::M2_PRE) && s.is_zero(hal::lansvcabi::OUT_OFF, hal::wpaauth::M2_OUT));
            all &= good && flipped && other_pmk && short && m4 && wiped;
        }
        all
    };
    let wan_ok_extra = sta_ok && lcp_peer_ok && sta_crypto_ok;
    let wan_ok = same_offer && other_xid && same_ra && junk && pppoe && wan_ok_extra;
    let (_, c_after, _, _, _) = stats();
    let pass = where_ == "el0" && same_q && same_w && bad && recovered && same_d && bad_d && wan_ok && c_after > 0;
    arch_aarch64::_print(format_args!(
        " [P-lansvc] {} — ADR 0050 D4 step 2: Shield DNS parsing in the EL0 LAN-services server (placement={}): a query gives the same facts as the in-kernel parser={} | an answer's CNAME chain is walked identically={} | malformed messages are unparseable in EL0 too={} | a deliberate EL0 fault resets the server (counted) and the next query parses={} | D4 step 2b: a DHCP REQUEST parses to the same facts in EL0 (type, chaddr, xid, option 50, hostname, vendor, PRL)={} a truncated frame is not DHCP={} | D4 step 3 WAN control in EL0: a DHCP OFFER merges identically={} another xid ignored={} an RA parses identically={} a bad-checksum RA / non-DHCPv6 refused={} | 3b PPPoE PADO tags + LCP Configure-Request + IPCP Request / Nak + CHAP Challenge + IPv6CP Request classification identical, 3b-v the AC's LCP Nak/Reject identical, 5a EAPOL-Key M2 + RSNE MFP identical, 5b M2/M4 PTK + MIC (AKM 2 and 8) identical, tampering refused, PMK/PTK wiped from the IO page={}\n",
        if pass { "PASS" } else { "FAIL" }, where_, same_q, same_w, bad, recovered, same_d, bad_d, same_offer, other_xid, same_ra, junk, pppoe
    ));
    pass
}

/// [P-lansvc-sae] ADR 0050 D4 step 5c: the WPA3-SAE station-frame walk runs in `el0-lansvc`; the kernel keeps the
/// state machine and every secret. Proves: the Annex J.10 peer commit decodes in EL0 to values that give the J.10
/// PMK; a full exchange (hunting-and-pecking and H2E) through the EL0 path gives the station's PMK and the SAME AP
/// commit / PMK as the in-kernel walk; malformed commits (another group, scalar = r, element off the curve,
/// truncated, a body over IN_MAX) are refused with no state left; an event buffer far longer than IN_MAX is trimmed
/// to the event's own length and accepted; a server fault rejects that attempt, forgets the station and the next
/// exchange succeeds; the IO page holds no SAE material afterwards (in / out regions zero, neither the PMK nor the
/// passphrase anywhere on the page).
#[cfg(all(feature = "mctls", feature = "wpa3"))]
pub fn sae_selftest() -> bool {
    use arch_aarch64::wanparse;
    use hal::saewire as w;
    fn unhex<const N: usize>(h: &str) -> [u8; N] {
        let b = h.as_bytes();
        let v = |c: u8| match c { b'0'..=b'9' => c - b'0', b'a'..=b'f' => c - b'a' + 10, _ => 0 };
        let mut o = [0u8; N];
        for i in 0..N {
            o[i] = v(b[2 * i]) << 4 | v(b[2 * i + 1]);
        }
        o
    }
    fn commit_body(s: &sae::Sae, h2e: bool) -> [u8; 109] {
        let mut c = [0u8; 109];
        c[0] = 3;
        c[2] = 1;
        c[4] = if h2e { 126 } else { 0 };
        c[6] = 19;
        c[8..40].copy_from_slice(&s.own_scalar);
        c[40..104].copy_from_slice(&s.own_element);
        c[104..109].copy_from_slice(&[255, 3, 92, 20, 0]); // H2E: Rejected Groups = {20}
        c
    }
    /// One station exchange against `tab`; `el0` = through the hook (sae_respond) or the in-kernel walk (on_frame).
    /// Some((AP commit scalar, AP PMK, station PMK)).
    fn exchange(tab: &mut sae::SaeAp, el0: bool, pt: Option<&sae::PT>, ap: &[u8; 6], sta: &[u8; 6], pw: &[u8]) -> Option<([u8; 32], [u8; 32], [u8; 32])> {
        let mut ctr = 0u8;
        let mut rnd = || {
            ctr = ctr.wrapping_add(1);
            Some([ctr; 32])
        };
        let mut st = match pt {
            Some(p) => {
                let mut s = sae::Sae::new_h2e(p, sta, ap, &[0x31; 32], &[0x47; 32]).ok()?;
                s.set_rejected_groups(&[20, 0]);
                s
            }
            None => sae::Sae::new(pw, sta, ap, &[0x31; 32], &[0x47; 32]).ok()?,
        };
        let c = commit_body(&st, pt.is_some());
        let cl = if pt.is_some() { 109 } else { 104 };
        let mut out = [None, None];
        let mut step = |tab: &mut sae::SaeAp, body: &[u8], out: &mut [Option<sae::Out>; 2]| {
            if el0 { wanparse::sae_respond(tab, 0, ap, sta, pt, pw, body, &mut rnd, out) } else { tab.on_frame(0, ap, sta, pt, pw, body, &mut rnd, out) }
        };
        if step(tab, &c[..cl], &mut out) != sae::Event::Committed {
            return None;
        }
        let a = out[0]?;
        let mut asc = [0u8; 32];
        asc.copy_from_slice(&a.body[8..40]);
        st.process_commit(&asc, a.body[40..104].try_into().ok()?).ok()?;
        let (sc, cf) = st.confirm();
        let mut k = [0u8; 40];
        k[0] = 3;
        k[2] = 2;
        k[6..8].copy_from_slice(&sc.to_le_bytes());
        k[8..40].copy_from_slice(&cf);
        if step(tab, &k, &mut out) != sae::Event::Accepted {
            return None;
        }
        let r = out[0]?;
        st.check_confirm(u16::from_le_bytes([r.body[6], r.body[7]]), r.body[8..40].try_into().ok()?).ok()?;
        Some((asc, tab.pmk_for(sta, 1)?, st.pmk))
    }
    fn fault_hook(_: &[u8], _: bool) -> Option<w::Msg> {
        let s = el0::server()?;
        (s.call(hal::lansvcabi::CMD_SELFTEST_FAULT, &[]).0 != hal::lansvcabi::ST_PANIC).then_some(w::MSG0)
    }

    install_dhcp();
    if el0::server().is_none() {
        arch_aarch64::_print(format_args!(" [P-lansvc-sae] FAIL — the EL0 LAN-services server is not loaded\n"));
        return false;
    }
    let (ap, sta) = ([0x76u8, 0x0d, 0x02, 0xf8, 0xd2, 0xda], [0xa8u8, 0x29, 0x48, 0x33, 0x73, 0x52]);
    let pw: &[u8] = b"bench passphrase";

    // (1) Annex J.10: the peer commit walked in EL0 → the J.10 KCK/PMK chain in the kernel
    let kat = (|| {
        let (a1, a2) = ([0x4d, 0x3f, 0x2f, 0xff, 0xe3, 0x87], [0xa5, 0xd8, 0xaa, 0x95, 0x8e, 0x3c]);
        let mut c = [0u8; 104];
        c[0] = 3;
        c[2] = 1;
        c[6] = 19;
        c[8..40].copy_from_slice(&unhex::<32>("591b96f3397fb945100848e7b550543b6720d88337ee93fc49fd6df7e08b5223"));
        c[40..104].copy_from_slice(&unhex::<64>("e71b9bb048d3873f20556953a96c91536fd8ee6ca9b4a68a148b056a909be03e83ae208f60f8ef5537858074db06687032399862999b511e0a1552a5fea317c2"));
        let m = wanparse::sae_parse(&c, false)?;
        if m.kind != w::K_COMMIT || m.scalar[..] != c[8..40] || m.element[..] != c[40..104] {
            return None;
        }
        let mut s = sae::Sae::new(b"mekmitasdigoat", &a1, &a2, &unhex("992465fd3daa3c60aa6565b7f62a2a7f2e12dd12f198faf4fbed89d7ff1ace94"),
            &unhex("9507a90f777a044d6a0830b91ea3d5dd70bece44e1acffb86983b5e1bf9fb322")).ok()?;
        s.process_commit(&m.scalar, &m.element).ok()?;
        Some(s.pmk == unhex::<32>("4e4dfab1a2dd8ac1a91790f953faaa452ae5c6873ab75b63605ba663f8a7fe59")
            && s.pmkid == unhex::<16>("8747a600eea3f9f22475df58ca1e5498"))
    })()
    .unwrap_or(false);

    // (2) full exchanges through EL0 == the in-kernel walk (same AP commit, same PMK, station agrees)
    let (_, c0, _, _, _) = stats();
    let mut ta = sae::SaeAp::new();
    let mut tb = sae::SaeAp::new();
    let e_hnp = exchange(&mut ta, true, None, &ap, &sta, pw);
    let k_hnp = exchange(&mut tb, false, None, &ap, &sta, pw);
    let hnp = matches!((e_hnp, k_hnp), (Some(e), Some(k)) if e == k && e.1 == e.2);
    let (_, c1, _, _, _) = stats();
    let via_el0 = c1 >= c0 + 2; // commit + confirm went through the server
    let pt = sae::derive_pt(b"HookProbe-Setup", pw, None);
    let mut tc = sae::SaeAp::new();
    let h2e = pt.as_ref().and_then(|p| exchange(&mut tc, true, Some(p), &ap, &sta, pw)).is_some_and(|e| e.1 == e.2);
    let pmk = e_hnp.map(|e| e.1).unwrap_or([0; 32]);

    // (3) malformed commits refused, no state left
    let mut ctr = 0x80u8;
    let mut rnd = || {
        ctr = ctr.wrapping_add(1);
        Some([ctr; 32])
    };
    let Ok(st) = sae::Sae::new(pw, &sta, &ap, &[0x31; 32], &[0x47; 32]) else { return false };
    let good = commit_body(&st, false);
    let mut td = sae::SaeAp::new();
    let mut out = [None, None];
    let mut send = |td: &mut sae::SaeAp, body: &[u8], out: &mut [Option<sae::Out>; 2]| wanparse::sae_respond(td, 0, &ap, &sta, None, pw, body, &mut rnd, out);
    let mut g = good;
    g[6] = 20;
    let bad_group = send(&mut td, &g[..104], &mut out) == sae::Event::Refused(77) && out[0].is_some_and(|o| o.body[4..8] == [77, 0, 19, 0]);
    let mut sr = good;
    sr[8..40].copy_from_slice(&unhex::<32>("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"));
    let bad_scalar = send(&mut td, &sr[..104], &mut out) == sae::Event::Dropped(w::reason(w::R_SCALAR));
    let mut eo = good;
    eo[103] ^= 1;
    let off_curve = send(&mut td, &eo[..104], &mut out) == sae::Event::Dropped(w::reason(w::R_ELEMENT));
    let truncated = send(&mut td, &good[..70], &mut out) == sae::Event::Dropped(w::reason(w::R_COMMIT_LEN));
    let mut big = [0u8; 2100];
    big[..104].copy_from_slice(&good[..104]);
    let (_, c2, _, _, _) = stats();
    let oversized = send(&mut td, &big, &mut out) == sae::Event::Dropped(w::reason(w::R_TOO_LONG)) && stats().1 == c2;
    let malformed = bad_group && bad_scalar && off_curve && truncated && oversized && td.active() == 0;

    // (4) the AP hands a 3000-byte receive buffer: trimmed to the event's own length, the commit is accepted
    let mut rx = [0u8; 3000];
    rx[44..48].copy_from_slice(&((24 + 104) as u32).to_be_bytes());
    rx[72] = 0xb0;
    rx[76..82].copy_from_slice(&ap);
    rx[82..88].copy_from_slice(&sta);
    rx[96..200].copy_from_slice(&good[..104]);
    rx[200..260].fill(0xa5); // the rest of the SDPCM buffer: not part of the frame
    let trimmed = match arch_aarch64::apparse::sae_auth_body(&rx, 0, &ap) {
        Ok((s, b0, b1)) => s == sta && b1 - b0 == 104 && send(&mut td, &rx[b0..b1], &mut out) == sae::Event::Committed && td.active() == 1,
        Err(_) => false,
    };
    let untrimmed_refused = send(&mut sae::SaeAp::new(), &rx[96..], &mut out) == sae::Event::Dropped(w::reason(w::R_TOO_LONG));

    // (5) a server fault on the confirm: rejected, nothing sent, the station's state forgotten; then recovered
    let (_, _, f0, _, _) = stats();
    let mut te = sae::SaeAp::new();
    let mut ctr2 = 0u8;
    let mut rnd2 = || {
        ctr2 = ctr2.wrapping_add(1);
        Some([ctr2; 32])
    };
    let committed = wanparse::sae_respond(&mut te, 0, &ap, &sta, None, pw, &good[..104], &mut rnd2, &mut out) == sae::Event::Committed && te.active() == 1;
    let mut k = [0u8; 40];
    k[0] = 3;
    k[2] = 2;
    k[6] = 1;
    unsafe { wanparse::EL0_SAE = Some(fault_hook) };
    let ev = wanparse::sae_respond(&mut te, 0, &ap, &sta, None, pw, &k, &mut rnd2, &mut out);
    unsafe { wanparse::EL0_SAE = Some(sta_sae) };
    let (_, _, f1, _, _) = stats();
    let fault = committed && ev == sae::Event::Dropped(w::reason(w::R_FAULT)) && out[0].is_none() && te.active() == 0
        && te.pmk_for(&sta, 1).is_none() && f1 == f0 + 1;
    let recovered = exchange(&mut te, true, None, &ap, &sta, pw).is_some_and(|e| e.1 == pmk);

    // (6) no SAE material on the IO page: in / out regions zero, neither the PMK nor the passphrase anywhere
    let wiped = el0::server().is_some_and(|s| {
        use hal::lansvcabi::*;
        let zero = |off: usize, n: usize| (0..n).step_by(64).all(|o| s.is_zero(off + o, (n - o).min(64)));
        let mut win = [0u8; 512];
        let mut found = false;
        let mut off = 0;
        while off < IO_SIZE {
            let n = win.len().min(IO_SIZE - off);
            s.read(off, &mut win[..n]);
            found |= win[..n].windows(32).any(|x| x == pmk) || win[..n].windows(pw.len()).any(|x| x == pw);
            off += 448;
        }
        zero(IN_OFF, 1 + w::BODY_MAX) && zero(OUT_OFF, w::REC_LEN) && !found && pmk != [0; 32]
    });

    let pass = kat && hnp && via_el0 && h2e && malformed && trimmed && untrimmed_refused && fault && recovered && wiped;
    arch_aarch64::_print(format_args!(
        " [P-lansvc-sae] {} — ADR 0050 D4 step 5c: the WPA3-SAE station-frame walk (group, scalar range, element on the curve, Rejected Groups, confirm format) runs in el0-lansvc, the state machine and every secret stay in the kernel: Annex J.10 peer commit via EL0 -> J.10 PMK/PMKID={} | hunting-and-pecking exchange via EL0 == in-kernel walk (AP commit + PMK), station agrees={} (EL0 calls made={}) | H2E exchange via EL0={} | refused with no state: other group (77 + group 19), scalar = r, element off the curve, truncated, body over IN_MAX={} | a 3000-B receive buffer trimmed to the event length is accepted={} untrimmed refused={} | server fault -> attempt rejected, nothing sent, station forgotten={} next exchange OK={} | IO page holds no SAE material (in/out zero, no PMK, no passphrase)={}\n",
        if pass { "PASS" } else { "FAIL" }, kat, hnp, via_el0, h2e, malformed, trimmed, untrimmed_refused, fault, recovered, wiped
    ));
    pass
}
