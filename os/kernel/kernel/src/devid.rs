//! Device identification (discovery D1) — legacy V1 Fingerbank parity, run on the DHCP evidence heqk already
//! holds per lease (option 12 hostname, 55 parameter-request list, 60 vendor class, the MAC). Tables are
//! generated from the legacy module (`fpdb.rs`, os/build/fpgen); the waterfall is legacy's, minus its cloud
//! API (never on-device) and with every answer carrying its source and confidence.
//!
//! Identity linking for rotating private MACs: one key per device across MAC changes —
//!   hostname + option-55 shape (both present)  -> "high"
//!   a globally unique (non-randomised) MAC      -> "high"
//!   option-55 shape alone, >= 5 options         -> "low"  (legacy's own correlator rated this 0.30)
//!   nothing                                     -> the MAC itself, "none"

use crate::fpdb;

#[derive(Clone, Copy)]
pub struct Ident {
    pub model: &'static str,
    pub vendor: &'static str,
    pub category: &'static str,
    pub os: &'static str,
    /// 0..=100
    pub confidence: u8,
    /// "vendor-class" | "pinned-oui" | "option-55" | "hostname" | "oui" | "os-guess" | ""
    pub source: &'static str,
    pub identity: u64,
    /// "high" | "low" | "none"
    pub identity_basis: &'static str,
}

fn fnv(h: &mut u64, b: &[u8]) {
    for &x in b {
        *h ^= x.to_ascii_lowercase() as u64;
        *h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
}

/// Comma-joined decimal option list (the legacy key format), into `out`; returns its length.
fn prl_key(prl: &[u8], out: &mut [u8; 128]) -> usize {
    let mut n = 0;
    for (i, &o) in prl.iter().enumerate() {
        if i > 0 && n < out.len() {
            out[n] = b',';
            n += 1;
        }
        let mut d = [0u8; 3];
        let mut k = 0;
        let mut v = o;
        loop {
            d[k] = b'0' + v % 10;
            k += 1;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        for j in (0..k).rev() {
            if n < out.len() {
                out[n] = d[j];
                n += 1;
            }
        }
    }
    n
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.len() >= needle.len() && hay.windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle))
}

/// Hostname conventions (legacy unified-engine hostname rules, trimmed to unambiguous ones).
fn by_hostname(h: &[u8]) -> Option<(&'static str, &'static str, &'static str, &'static str, u8)> {
    const R: &[(&[u8], &str, &str, &str, &str, u8)] = &[
        (b"iphone", "iPhone", "Apple", "phone", "iOS", 85),
        (b"ipad", "iPad", "Apple", "tablet", "iPadOS", 85),
        (b"macbook", "MacBook", "Apple", "laptop", "macOS", 85),
        (b"imac", "iMac", "Apple", "desktop", "macOS", 80),
        (b"apple-tv", "Apple TV", "Apple", "tv", "tvOS", 85),
        (b"appletv", "Apple TV", "Apple", "tv", "tvOS", 85),
        (b"homepod", "HomePod", "Apple", "voice_assistant", "audioOS", 85),
        (b"galaxy", "Galaxy", "Samsung", "phone", "Android", 75),
        (b"pixel", "Pixel", "Google", "phone", "Android", 75),
        (b"android", "Android device", "", "phone", "Android", 70),
        (b"desktop-", "Windows PC", "", "desktop", "Windows", 75),
        (b"laptop-", "Windows laptop", "", "laptop", "Windows", 75),
        (b"chromecast", "Chromecast", "Google", "tv", "Cast OS", 85),
        (b"roku", "Roku", "Roku", "tv", "Roku OS", 85),
        (b"firetv", "Fire TV", "Amazon", "tv", "Fire OS", 85),
        (b"echo", "Echo", "Amazon", "voice_assistant", "Fire OS", 70),
        (b"google-home", "Google Home", "Google", "voice_assistant", "Cast OS", 85),
        (b"nest", "Nest", "Google", "smart_home", "", 70),
        (b"playstation", "PlayStation", "Sony", "gaming", "", 85),
        (b"ps5", "PlayStation 5", "Sony", "gaming", "", 80),
        (b"xbox", "Xbox", "Microsoft", "gaming", "", 85),
        (b"nintendo", "Nintendo Switch", "Nintendo", "gaming", "", 80),
        (b"raspberrypi", "Raspberry Pi", "Raspberry Pi", "sbc", "Linux", 85),
        (b"printer", "Printer", "", "printer", "", 70),
        (b"shelly", "Shelly", "Shelly", "iot", "", 85),
        (b"tasmota", "Tasmota device", "", "iot", "", 85),
        (b"esp-", "ESP device", "Espressif", "iot", "", 70),
        (b"espressif", "ESP device", "Espressif", "iot", "", 75),
    ];
    R.iter().find(|r| contains(h, r.0)).map(|r| (r.1, r.2, r.3, r.4, r.5))
}

pub fn oui_vendor(mac: &[u8; 6]) -> &'static str {
    if mac[0] & 0x02 != 0 {
        return ""; // a randomised MAC has no vendor
    }
    let k = [mac[0], mac[1], mac[2]];
    fpdb::OUI.binary_search_by(|e| e.0.cmp(&k)).map_or("", |i| fpdb::VENDORS.get(fpdb::OUI[i].1 as usize).copied().unwrap_or(""))
}

/// Identify one device from its lease evidence.
pub fn classify(mac: &[u8; 6], host: &[u8], vendor_class: &[u8], prl: &[u8]) -> Ident {
    let private = mac[0] & 0x02 != 0;
    let mut kb = [0u8; 128];
    let kl = prl_key(prl, &mut kb);
    let key = &kb[..kl];
    // identity
    let (identity, basis) = if !host.is_empty() && prl.len() >= 3 {
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        fnv(&mut h, host);
        fnv(&mut h, b"|");
        fnv(&mut h, key);
        (h, "high")
    } else if !private {
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        fnv(&mut h, mac);
        (h, "high")
    } else if prl.len() >= 5 {
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        fnv(&mut h, b"prl|");
        fnv(&mut h, key);
        (h, "low")
    } else {
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        fnv(&mut h, mac);
        (h, "none")
    };
    // D2: what the device announced (mDNS / SSDP) — an mDNS name is the strongest identity across private-MAC
    // rotations (legacy rule 2); an advertised model names the product better than any DHCP fingerprint.
    let disc = crate::discovery::lookup(mac);
    let (identity, basis) = match &disc {
        Some(d) if d.nl > 0 => {
            let mut h = 0xcbf2_9ce4_8422_2325u64;
            fnv(&mut h, b"mdns|");
            fnv(&mut h, &d.name[..d.nl as usize]);
            (h, "high")
        }
        _ => (identity, basis),
    };
    let disc_cat = disc.map_or("", |d| crate::discovery::category(d.services));
    let mk = |f: fpdb::Fp, src: &'static str| Ident { model: f.0, vendor: f.1, category: if f.2.is_empty() { disc_cat } else { f.2 }, os: f.3, confidence: f.4, source: src, identity, identity_basis: basis };
    // 0. vendor class (option 60): explicit, highest priority
    let osg = arch_aarch64::dhcpd::os_guess(vendor_class, prl);
    if !vendor_class.is_empty() && !osg.is_empty() && (vendor_class.starts_with(b"MSFT") || vendor_class.starts_with(b"android-dhcp")) {
        let cat = if osg == "Android" { "phone" } else { "desktop" };
        return mk(("", "", cat, osg, 90), "vendor-class");
    }
    // 1. an OUI that pins a specific device (never for a randomised MAC)
    if !private {
        let k = [mac[0], mac[1], mac[2]];
        if let Ok(i) = fpdb::OUI_DEV.binary_search_by(|e| e.0.cmp(&k)) {
            return mk(fpdb::OUI_DEV[i].1, "pinned-oui");
        }
    }
    // 2. exact option-55 fingerprint
    if !key.is_empty() {
        if let Ok(i) = fpdb::OPT55.binary_search_by(|e| e.0.as_bytes().cmp(key)) {
            let f = fpdb::OPT55[i].1;
            if f.4 >= 75 {
                return mk(f, "option-55");
            }
        }
    }
    // 3. hostname conventions (+ the OUI vendor when the hostname does not name one)
    if let Some((m, v, c, o, conf)) = by_hostname(host) {
        let v = if v.is_empty() { oui_vendor(mac) } else { v };
        return mk((m, v, c, o, conf), "hostname");
    }
    // 4. OUI vendor alone
    let v = oui_vendor(mac);
    if !v.is_empty() {
        return mk(("", v, "", osg, 50), "oui");
    }
    // 5. heqk's OS-family guess
    if !osg.is_empty() {
        return mk(("", "", "", osg, 40), "os-guess");
    }
    mk(("", "", "", "", 0), "")
}

/// `[P-devid]`: the generated tables are sorted + non-empty, the waterfall picks the right source, and
/// identity linking holds across a private-MAC rotation.
pub fn selftest() -> bool {
    let sorted = fpdb::OPT55.windows(2).all(|w| w[0].0 < w[1].0) && fpdb::OUI.windows(2).all(|w| w[0].0 < w[1].0)
        && fpdb::OUI_DEV.windows(2).all(|w| w[0].0 < w[1].0) && fpdb::OPT55.len() >= 50 && fpdb::OUI.len() >= 500;
    // an exact iPhone option-55 string from the table must resolve to it
    let (k0, f0) = fpdb::OPT55.iter().find(|e| e.1 .2 == "phone" && e.1 .1 == "Apple" && e.1 .4 >= 75).copied().unwrap_or(("", ("", "", "", "", 0)));
    let mut prl = [0u8; 64];
    let mut pn = 0;
    for t in k0.split(',') {
        if let Ok(v) = t.parse::<u8>() {
            if pn < prl.len() {
                prl[pn] = v;
                pn += 1;
            }
        }
    }
    let rot1 = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    let rot2 = [0x06, 0x99, 0x88, 0x77, 0x66, 0x55];
    let a = classify(&rot1, b"Johns-iPhone", b"", &prl[..pn]);
    let b = classify(&rot2, b"Johns-iPhone", b"", &prl[..pn]);
    let exact = !k0.is_empty() && a.source == "option-55" && a.model == f0.0;
    let linked = a.identity == b.identity && a.identity_basis == "high";
    // Windows by vendor class; a hostname-only device; a randomised MAC never gets an OUI vendor
    let w = classify(&[0x02, 1, 2, 3, 4, 5], b"DESKTOP-AB12", b"MSFT 5.0", &[1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252]);
    let win = w.source == "vendor-class" && w.os == "Windows";
    let r = classify(&[0x02, 1, 2, 3, 4, 6], b"living-room-roku", b"", &[]);
    let host = r.source == "hostname" && r.category == "tv" && r.vendor == "Roku";
    let anon = classify(&[0x02, 9, 9, 9, 9, 9], b"", b"", &[1, 3, 6]);
    let honest = anon.identity_basis == "none" && anon.vendor.is_empty();
    // a real vendor OUI (first entry of the table, made non-random)
    let (o, _) = fpdb::OUI[0];
    let ov = !oui_vendor(&[o[0], o[1], o[2], 0, 0, 1]).is_empty();
    let pass = sorted && exact && linked && win && host && honest && ov;
    arch_aarch64::_print(format_args!(
        " [P-devid] {} — device identification (legacy Fingerbank tables: {} option-55 fingerprints, {} OUIs, {} pinned OUIs): tables sorted={} exact option-55 -> '{}'={} private-MAC rotation linked (hostname+opt55)={} Windows by vendor class={} hostname rule (Roku TV)={} unknown device stays unknown={} OUI vendor={}\n",
        if pass { "PASS" } else { "FAIL" }, fpdb::OPT55.len(), fpdb::OUI.len(), fpdb::OUI_DEV.len(), sorted, a.model, exact, linked, win, host, honest, ov
    ));
    pass
}
