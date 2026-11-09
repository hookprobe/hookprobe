//! Passive LAN discovery (D2): what devices ANNOUNCE about themselves on mDNS (UDP 5353) and SSDP (UDP 1900).
//! heqk already receives these multicast frames on its AP / LAN port; reading them needs no probing (legacy
//! shelled out to avahi + nbtscan). Kept per MAC: a friendly name, a model string, the SSDP SERVER header and
//! a bitmask of advertised services. Every read is bounded; names are sanitised to printable ASCII.

pub const S_CAST: u32 = 1 << 0; // _googlecast, DIAL
pub const S_AIRPLAY: u32 = 1 << 1;
pub const S_RAOP: u32 = 1 << 2; // AirPlay audio
pub const S_COMPANION: u32 = 1 << 3; // Apple phone/tablet/watch
pub const S_HOMEKIT: u32 = 1 << 4; // _hap / _homekit
pub const S_PRINTER: u32 = 1 << 5; // _ipp _printer _pdl-datastream
pub const S_SPOTIFY: u32 = 1 << 6;
pub const S_SONOS: u32 = 1 << 7;
pub const S_AMAZON: u32 = 1 << 8; // _amzn-wplay
pub const S_WORKSTATION: u32 = 1 << 9; // _workstation _smb _ssh _sftp-ssh _device-info (computers)
pub const S_MEDIA_RENDERER: u32 = 1 << 10; // SSDP MediaRenderer
pub const S_MATTER: u32 = 1 << 11; // _matter _matterc

const SVC: &[(&[u8], u32)] = &[
    (b"_googlecast", S_CAST), (b"_airplay", S_AIRPLAY), (b"_raop", S_RAOP), (b"_companion-link", S_COMPANION),
    (b"_hap", S_HOMEKIT), (b"_homekit", S_HOMEKIT), (b"_ipp", S_PRINTER), (b"_ipps", S_PRINTER), (b"_printer", S_PRINTER),
    (b"_pdl-datastream", S_PRINTER), (b"_spotify-connect", S_SPOTIFY), (b"_sonos", S_SONOS), (b"_amzn-wplay", S_AMAZON),
    (b"_workstation", S_WORKSTATION), (b"_smb", S_WORKSTATION), (b"_ssh", S_WORKSTATION), (b"_sftp-ssh", S_WORKSTATION),
    (b"_device-info", S_WORKSTATION), (b"_matter", S_MATTER), (b"_matterc", S_MATTER),
];

#[derive(Clone, Copy)]
pub struct Seen {
    pub mac: [u8; 6],
    pub name: [u8; 32],
    pub nl: u8,
    pub model: [u8; 32],
    pub ml: u8,
    pub server: [u8; 48],
    pub sl: u8,
    pub services: u32,
    pub last_ms: u64,
}
const Z: Seen = Seen { mac: [0; 6], name: [0; 32], nl: 0, model: [0; 32], ml: 0, server: [0; 48], sl: 0, services: 0, last_ms: 0 };
const N: usize = 64;
static mut TAB: [Seen; N] = [Z; N];
static mut FRAMES: u64 = 0;

fn ms() -> u64 {
    let (c, f): (u64, u64);
    unsafe {
        core::arch::asm!("mrs {}, cntpct_el0", out(reg) c, options(nomem, nostack));
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f, options(nomem, nostack));
    }
    c.saturating_mul(1000) / f.max(1)
}

fn put(dst: &mut [u8], len: &mut u8, src: &[u8]) {
    let mut k = 0;
    for &c in src {
        if k >= dst.len() {
            break;
        }
        if (0x20..0x7f).contains(&c) && c != b'"' && c != b'\\' {
            dst[k] = c;
            k += 1;
        }
    }
    if k > 0 {
        *len = k as u8;
    }
}

fn entry(mac: &[u8; 6]) -> &'static mut Seen {
    let t = unsafe { &mut *core::ptr::addr_of_mut!(TAB) };
    let i = t.iter().position(|e| e.last_ms != 0 && e.mac == *mac)
        .or_else(|| t.iter().position(|e| e.last_ms == 0))
        .unwrap_or_else(|| (0..N).min_by_key(|&i| t[i].last_ms).unwrap_or(0));
    if t[i].mac != *mac {
        t[i] = Z;
        t[i].mac = *mac;
    }
    t[i].last_ms = ms().max(1);
    &mut t[i]
}

/// The discovery record for a MAC, if any.
pub fn lookup(mac: &[u8; 6]) -> Option<Seen> {
    let t = unsafe { &*core::ptr::addr_of!(TAB) };
    t.iter().find(|e| e.last_ms != 0 && e.mac == *mac).copied()
}

pub fn frames() -> u64 {
    unsafe { FRAMES }
}

/// A DNS name at `off` (compression-aware, at most 8 jumps), as dotted labels into `out`; returns
/// (length, offset just past the name in the original position).
fn name(p: &[u8], mut off: usize, out: &mut [u8; 128]) -> Option<(usize, usize)> {
    let mut n = 0;
    let mut end = None;
    for _ in 0..40 {
        let l = *p.get(off)? as usize;
        if l == 0 {
            return Some((n, end.unwrap_or(off + 1)));
        }
        if l & 0xc0 == 0xc0 {
            let ptr = ((l & 0x3f) << 8) | *p.get(off + 1)? as usize;
            if end.is_none() {
                end = Some(off + 2);
            }
            if ptr >= off {
                return None; // forward/self pointers: malformed
            }
            off = ptr;
            continue;
        }
        let lab = p.get(off + 1..off + 1 + l)?;
        if n > 0 && n < out.len() {
            out[n] = b'.';
            n += 1;
        }
        for &c in lab {
            if n < out.len() {
                out[n] = c;
                n += 1;
            }
        }
        off += 1 + l;
    }
    None
}

fn first_label(full: &[u8]) -> &[u8] {
    &full[..full.iter().position(|&c| c == b'.').unwrap_or(full.len())]
}

fn mdns(p: &[u8], mac: &[u8; 6]) {
    if p.len() < 12 || p[2] & 0x80 == 0 {
        return; // only responses / announcements carry what a device IS
    }
    let qd = u16::from_be_bytes([p[4], p[5]]) as usize;
    let rr = (u16::from_be_bytes([p[6], p[7]]) as usize + u16::from_be_bytes([p[8], p[9]]) as usize + u16::from_be_bytes([p[10], p[11]]) as usize).min(48);
    let e = entry(mac);
    let mut off = 12;
    let mut nb = [0u8; 128];
    for _ in 0..qd.min(8) {
        let Some((_, o)) = name(p, off, &mut nb) else { return };
        off = o + 4;
    }
    for _ in 0..rr {
        let Some((nl, o)) = name(p, off, &mut nb) else { return };
        let Some(h) = p.get(o..o + 10) else { return };
        let ty = u16::from_be_bytes([h[0], h[1]]);
        let rdl = u16::from_be_bytes([h[8], h[9]]) as usize;
        let rd = o + 10;
        if rd + rdl > p.len() {
            return;
        }
        let owner = &nb[..nl];
        for (svc, bit) in SVC {
            if owner.windows(svc.len()).any(|w| w.eq_ignore_ascii_case(svc)) {
                e.services |= bit;
            }
        }
        match ty {
            12 => {
                // PTR: service type -> instance "Living Room TV._googlecast._tcp.local"
                let mut ib = [0u8; 128];
                if let Some((il, _)) = name(p, rd, &mut ib) {
                    let inst = first_label(&ib[..il]);
                    // avahi's _workstation instances are "<host> [<mac>]": keep the host
                    let inst = &inst[..inst.windows(2).position(|w| w == b" [").unwrap_or(inst.len())];
                    if !inst.starts_with(b"_") && e.nl == 0 {
                        put(&mut e.name, &mut e.nl, inst);
                    }
                }
            }
            16 => {
                // TXT: key=value strings
                let mut i = rd;
                while i < rd + rdl {
                    let l = p[i] as usize;
                    let Some(kv) = p.get(i + 1..i + 1 + l) else { break };
                    for key in [&b"md="[..], b"model=", b"am=", b"ty=", b"usb_MDL="] {
                        if kv.len() > key.len() && kv[..key.len()].eq_ignore_ascii_case(key) {
                            put(&mut e.model, &mut e.ml, &kv[key.len()..]);
                        }
                    }
                    if kv.len() > 3 && kv[..3].eq_ignore_ascii_case(b"fn=") {
                        put(&mut e.name, &mut e.nl, &kv[3..]); // a friendly name the owner set wins
                    }
                    i += 1 + l;
                }
            }
            1 | 28 if e.nl == 0 && owner.len() > 6 && owner.ends_with(b".local") => {
                // A / AAAA "hookprobe-test.local": the host name a device publishes for itself
                put(&mut e.name, &mut e.nl, first_label(owner));
            }
            33 if rdl > 6 && e.nl == 0 => {
                // SRV target host "Johns-iPhone.local"
                let mut tb = [0u8; 128];
                if let Some((tl, _)) = name(p, rd + 6, &mut tb) {
                    put(&mut e.name, &mut e.nl, first_label(&tb[..tl]));
                }
            }
            _ => {}
        }
        off = rd + rdl;
    }
}

fn ssdp(p: &[u8], mac: &[u8; 6]) {
    if !(p.starts_with(b"NOTIFY ") || p.starts_with(b"HTTP/1.1 200")) {
        return;
    }
    let e = entry(mac);
    for line in p.split(|&c| c == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let val = |k: &[u8]| -> Option<&[u8]> {
            (line.len() > k.len() && line[..k.len()].eq_ignore_ascii_case(k)).then(|| {
                let v = &line[k.len()..];
                let s = v.iter().position(|&c| c != b' ').unwrap_or(v.len());
                &v[s..]
            })
        };
        if let Some(v) = val(b"SERVER:") {
            put(&mut e.server, &mut e.sl, v);
        }
        for k in [&b"NT:"[..], b"ST:"] {
            if let Some(v) = val(k) {
                if v.windows(16).any(|w| w.eq_ignore_ascii_case(b"dial-multiscreen")) {
                    e.services |= S_CAST;
                }
                if v.windows(13).any(|w| w.eq_ignore_ascii_case(b"MediaRenderer")) {
                    e.services |= S_MEDIA_RENDERER;
                }
            }
        }
    }
}

/// Every LAN client frame (cheap unless it is UDP to 5353 / 1900): learn what the device announces.
pub fn observe(f: &[u8]) {
    if f.len() < 42 {
        return;
    }
    let (proto, l4) = match (f[12], f[13]) {
        (0x08, 0x00) => (f[23], 14 + ((f[14] & 0x0f) as usize) * 4),
        (0x86, 0xdd) => (f[20], 54), // no extension headers on mDNS in practice
        _ => return,
    };
    if proto != 17 || l4 + 8 > f.len() {
        return;
    }
    let sport = u16::from_be_bytes([f[l4], f[l4 + 1]]);
    let dport = u16::from_be_bytes([f[l4 + 2], f[l4 + 3]]);
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&f[6..12]);
    let pay = &f[l4 + 8..];
    if dport == 5353 || sport == 5353 {
        unsafe { FRAMES += 1 };
        mdns(pay, &mac);
    } else if dport == 1900 || sport == 1900 {
        unsafe { FRAMES += 1 };
        ssdp(pay, &mac);
    }
}

/// A category from advertised services ("" when nothing tells).
pub fn category(s: u32) -> &'static str {
    if s & S_PRINTER != 0 {
        "printer"
    } else if s & (S_CAST | S_MEDIA_RENDERER) != 0 && s & S_WORKSTATION == 0 {
        "tv"
    } else if s & (S_SONOS | S_SPOTIFY | S_RAOP) != 0 && s & (S_WORKSTATION | S_COMPANION) == 0 {
        "speaker"
    } else if s & S_AMAZON != 0 {
        "voice_assistant"
    } else if s & (S_HOMEKIT | S_MATTER) != 0 && s & (S_WORKSTATION | S_COMPANION) == 0 {
        "smart_home"
    } else if s & S_COMPANION != 0 {
        "phone"
    } else if s & S_WORKSTATION != 0 {
        "computer"
    } else {
        ""
    }
}

/// `[P-discovery]`: a Chromecast mDNS announcement (PTR + TXT md/fn, compressed names), an iPhone
/// companion-link SRV, an SSDP NOTIFY, and hostile input.
pub fn selftest() -> bool {
    fn lab(out: &mut [u8], n: &mut usize, s: &[u8]) {
        out[*n] = s.len() as u8;
        out[*n + 1..*n + 1 + s.len()].copy_from_slice(s);
        *n += 1 + s.len();
    }
    // mDNS response: answer PTR _googlecast._tcp.local -> "Living Room TV" (compressed), additional TXT
    let mut p = [0u8; 256];
    p[2] = 0x84; // QR + AA
    p[7] = 1; // ancount 1
    p[11] = 1; // arcount 1
    let mut n = 12;
    let svc_at = n;
    lab(&mut p, &mut n, b"_googlecast");
    lab(&mut p, &mut n, b"_tcp");
    lab(&mut p, &mut n, b"local");
    p[n] = 0;
    n += 1;
    p[n..n + 10].copy_from_slice(&[0, 12, 0, 1, 0, 0, 0x11, 0x94, 0, 0]);
    let rdl_at = n + 8;
    n += 10;
    let inst_at = n;
    lab(&mut p, &mut n, b"Living Room TV");
    p[n] = 0xc0;
    p[n + 1] = svc_at as u8;
    n += 2;
    let rdl = n - inst_at;
    p[rdl_at..rdl_at + 2].copy_from_slice(&(rdl as u16).to_be_bytes());
    // TXT owned by the instance name (pointer), md=Chromecast fn=Living Room TV
    p[n] = 0xc0;
    p[n + 1] = inst_at as u8;
    n += 2;
    p[n..n + 10].copy_from_slice(&[0, 16, 0x80, 1, 0, 0, 0x11, 0x94, 0, 0]);
    let trdl_at = n + 8;
    n += 10;
    let t0 = n;
    lab(&mut p, &mut n, b"md=Chromecast");
    lab(&mut p, &mut n, b"fn=Living Room TV");
    p[trdl_at..trdl_at + 2].copy_from_slice(&((n - t0) as u16).to_be_bytes());
    let mut f = [0u8; 400];
    f[0..6].copy_from_slice(&[0x01, 0x00, 0x5e, 0, 0, 0xfb]);
    f[6..12].copy_from_slice(&[0xf4, 0xf5, 0xd8, 1, 2, 3]);
    f[12] = 0x08;
    f[14] = 0x45;
    f[23] = 17;
    f[34..36].copy_from_slice(&5353u16.to_be_bytes());
    f[36..38].copy_from_slice(&5353u16.to_be_bytes());
    f[42..42 + n].copy_from_slice(&p[..n]);
    observe(&f[..42 + n]);
    let cc = lookup(&[0xf4, 0xf5, 0xd8, 1, 2, 3]).is_some_and(|e| &e.name[..e.nl as usize] == b"Living Room TV" && &e.model[..e.ml as usize] == b"Chromecast" && e.services & S_CAST != 0 && category(e.services) == "tv");
    // SSDP NOTIFY from a TV
    let notify = b"NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: urn:dial-multiscreen-org:service:dial:1\r\nSERVER: Linux/4.9 UPnP/1.0 Roku/11.5\r\n\r\n";
    let mut g = [0u8; 300];
    g[6..12].copy_from_slice(&[0xb0, 0xa7, 0x37, 4, 5, 6]);
    g[12] = 0x08;
    g[14] = 0x45;
    g[23] = 17;
    g[36..38].copy_from_slice(&1900u16.to_be_bytes());
    g[42..42 + notify.len()].copy_from_slice(notify);
    observe(&g[..42 + notify.len()]);
    let ss = lookup(&[0xb0, 0xa7, 0x37, 4, 5, 6]).is_some_and(|e| e.server[..e.sl as usize].starts_with(b"Linux/4.9 UPnP/1.0 Roku") && e.services & S_CAST != 0);
    // hostile: every truncation of the mDNS frame, a pointer loop, garbage — no panic
    for cut in 0..42 + n {
        observe(&f[..cut]);
    }
    let mut lp = f;
    lp[42 + 12] = 0xc0;
    lp[42 + 13] = 12; // pointer to itself
    observe(&lp[..42 + n]);
    observe(&[0xff; 300]);
    let pass = cc && ss;
    arch_aarch64::_print(format_args!(
        " [P-discovery] {} — passive mDNS/SSDP discovery (D2): Chromecast announcement -> name 'Living Room TV', model 'Chromecast', category tv={} | SSDP NOTIFY SERVER + DIAL={} | truncations, pointer loop, garbage survived\n",
        if pass { "PASS" } else { "FAIL" }, cc, ss
    ));
    // leave the table clean for the device
    unsafe { *core::ptr::addr_of_mut!(TAB) = [Z; N] };
    pass
}
