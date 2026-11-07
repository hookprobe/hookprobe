//! `WIFI.TXT` — the AP's network settings from the boot partition (parity gap G20). Until now the SSID
//! was hard-coded ("heqk-ap") and the PSK a build-time env var, so changing either meant a rebuild.
//!
//! Operator-signed (`WIFI.SIG`, magic HQWSIG1 / tag HQWIF1 — never interchangeable with the other signed
//! files) so a stolen or swapped card cannot repoint the network. Format, one `key=value` per line:
//!   ssid=Home Network          1..32 bytes, printable (spaces allowed, no control characters)
//!   psk=correct horse battery  WPA2: 8..63 printable ASCII, or exactly 64 hex digits (a raw PMK)
//!   channel=40                 2.4 GHz 1..13, 5 GHz 36/40/44/48 (UNII-1 — DFS channels fail on this
//!                              firmware's stock CLM, see the Wi-Fi capability notes); default: auto
//! Anything invalid → the file is refused whole and the build-time defaults stay (never half-applied).
//! Honest limitation: the PSK sits on the boot partition in the clear, like any WPA2 appliance config;
//! physical possession of the card is the same exposure as the build-time PSK in the image.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WifiCfg {
    pub ssid: [u8; 32],
    pub ssid_len: u8,
    pub psk: [u8; 64],
    pub psk_len: u8,
    /// 0 = automatic.
    pub channel: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CfgErr {
    Missing(&'static str),
    BadSsid,
    BadPsk,
    BadChannel,
    UnknownKey,
    Duplicate,
}

pub fn parse(text: &[u8]) -> Result<WifiCfg, CfgErr> {
    let mut c = WifiCfg { ssid: [0; 32], ssid_len: 0, psk: [0; 64], psk_len: 0, channel: 0 };
    let (mut have_ssid, mut have_psk, mut have_ch) = (false, false, false);
    for raw in text.split(|&b| b == b'\n') {
        let line = raw.strip_suffix(b"\r").unwrap_or(raw);
        let line = line.split(|&b| b == 0).next().unwrap_or(&[]);
        if line.iter().all(|b| b.is_ascii_whitespace()) || line.first() == Some(&b'#') {
            continue;
        }
        let eq = line.iter().position(|&b| b == b'=').ok_or(CfgErr::UnknownKey)?;
        let (k, v) = (&line[..eq], &line[eq + 1..]);
        match k {
            b"ssid" => {
                if have_ssid {
                    return Err(CfgErr::Duplicate);
                }
                if v.is_empty() || v.len() > 32 || !v.iter().all(|&b| (0x20..0x7f).contains(&b)) {
                    return Err(CfgErr::BadSsid);
                }
                c.ssid[..v.len()].copy_from_slice(v);
                c.ssid_len = v.len() as u8;
                have_ssid = true;
            }
            b"psk" => {
                if have_psk {
                    return Err(CfgErr::Duplicate);
                }
                let hex64 = v.len() == 64 && v.iter().all(|b| b.is_ascii_hexdigit());
                let pass = (8..=63).contains(&v.len()) && v.iter().all(|&b| (0x20..0x7f).contains(&b));
                if !hex64 && !pass {
                    return Err(CfgErr::BadPsk);
                }
                c.psk[..v.len()].copy_from_slice(v);
                c.psk_len = v.len() as u8;
                have_psk = true;
            }
            b"channel" => {
                if have_ch {
                    return Err(CfgErr::Duplicate);
                }
                let ch = if v == b"auto" {
                    0
                } else {
                    core::str::from_utf8(v).ok().and_then(|s| s.parse::<u8>().ok()).ok_or(CfgErr::BadChannel)?
                };
                if !(ch == 0 || (1..=13).contains(&ch) || matches!(ch, 36 | 40 | 44 | 48)) {
                    return Err(CfgErr::BadChannel);
                }
                c.channel = ch;
                have_ch = true;
            }
            _ => return Err(CfgErr::UnknownKey),
        }
    }
    if !have_ssid {
        return Err(CfgErr::Missing("ssid"));
    }
    if !have_psk {
        return Err(CfgErr::Missing("psk"));
    }
    Ok(c)
}

fn signed_message(gen: u64, len: u64, digest: &[u8; 32]) -> [u8; 54] {
    let mut m = [0u8; 54];
    m[..6].copy_from_slice(b"HQWIF1");
    m[6..14].copy_from_slice(&gen.to_le_bytes());
    m[14..22].copy_from_slice(&len.to_le_bytes());
    m[22..].copy_from_slice(digest);
    m
}

/// Verify WIFI.SIG over `body` with the operator key. Returns (generation, signed length).
pub fn check_sig(sig: &[u8], key: &[u8; 32], body: &[u8]) -> Option<(u64, usize)> {
    if sig.len() < 120 || &sig[..8] != b"HQWSIG1\0" {
        return None;
    }
    let gen = u64::from_le_bytes(sig[8..16].try_into().ok()?);
    let len = u64::from_le_bytes(sig[16..24].try_into().ok()?) as usize;
    if len > body.len() {
        return None;
    }
    let d = boot_abi::sha256::digest(&body[..len]);
    if d[..] != sig[24..56] {
        return None;
    }
    let pk = ed25519_compact::PublicKey::from_slice(key).ok()?;
    let s = ed25519_compact::Signature::from_slice(&sig[56..120]).ok()?;
    pk.verify(&signed_message(gen, len as u64, &d)[..], &s).ok()?;
    Some((gen, len))
}

/// Boot: WIFI.TXT (≤ 1 KiB) [+ WIFI.SIG when an operator key is compiled in]. None = no file (defaults).
pub fn load<D: hal::BlockDev>(dev: &D) -> Option<Result<WifiCfg, CfgErr>> {
    let mut sec = [0u8; 512];
    dev.read_block(0, &mut sec).ok()?;
    let p1 = crate::store::parse_mbr(&sec)[0].start;
    if p1 == 0 {
        return None;
    }
    let (lba, n) = crate::fat::locate_contiguous(dev, p1, b"WIFI    TXT")?;
    let mut buf = [0u8; 1024];
    for k in 0..(n as usize).min(2) {
        dev.read_block(lba + k as u64, &mut sec).ok()?;
        buf[k * 512..k * 512 + 512].copy_from_slice(&sec);
    }
    let mut body: &[u8] = &buf;
    if let Some(key) = crate::policysig::POLICY_PUBKEY {
        let mut sig = [0u8; 512];
        let ok = crate::fat::locate_contiguous(dev, p1, b"WIFI    SIG").and_then(|(l, _)| dev.read_block(l, &mut sig).ok()).and_then(|_| check_sig(&sig, &key, &buf));
        match ok {
            Some((_, len)) => body = &buf[..len],
            None => return Some(Err(CfgErr::Missing("valid WIFI.SIG"))),
        }
    }
    Some(parse(body))
}

/// `[P-wificfg]`
pub fn selftest() -> bool {
    use ed25519_compact::{KeyPair, Seed};
    let good = parse(b"# home\nssid=Home Network\npsk=correct horse battery\nchannel=40\n");
    let good_ok = good.map_or(false, |c| &c.ssid[..c.ssid_len as usize] == b"Home Network" && &c.psk[..c.psk_len as usize] == b"correct horse battery" && c.channel == 40);
    let auto = parse(b"ssid=x\npsk=12345678\r\n").map_or(false, |c| c.channel == 0) && parse(b"ssid=x\npsk=12345678\nchannel=auto\n").is_ok();
    let hex = parse(b"ssid=x\npsk=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n").is_ok();
    let refused = parse(b"ssid=x\npsk=short\n") == Err(CfgErr::BadPsk)
        && parse(b"ssid=x\npsk=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg\n") == Err(CfgErr::BadPsk)
        && parse(b"ssid=\npsk=12345678\n") == Err(CfgErr::BadSsid)
        && parse(b"ssid=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\npsk=12345678\n") == Err(CfgErr::BadSsid)
        && parse(b"ssid=x\x01y\npsk=12345678\n") == Err(CfgErr::BadSsid)
        && parse(b"ssid=x\npsk=12345678\nchannel=52\n") == Err(CfgErr::BadChannel)
        && parse(b"ssid=x\npsk=12345678\nchannel=14\n") == Err(CfgErr::BadChannel)
        && parse(b"ssid=x\nssid=y\npsk=12345678\n") == Err(CfgErr::Duplicate)
        && parse(b"ssid=x\npsk=12345678\nmode=open\n") == Err(CfgErr::UnknownKey)
        && parse(b"psk=12345678\n") == Err(CfgErr::Missing("ssid"))
        && parse(b"ssid=x\n") == Err(CfgErr::Missing("psk"));
    let kp = KeyPair::from_seed(Seed::new([0x91; 32]));
    let pk: [u8; 32] = *kp.pk;
    let body: &[u8] = b"ssid=Home\npsk=correct horse battery\n";
    let d = boot_abi::sha256::digest(body);
    let mut sig = [0u8; 512];
    sig[..8].copy_from_slice(b"HQWSIG1\0");
    sig[8..16].copy_from_slice(&1u64.to_le_bytes());
    sig[16..24].copy_from_slice(&(body.len() as u64).to_le_bytes());
    sig[24..56].copy_from_slice(&d);
    sig[56..120].copy_from_slice(kp.sk.sign(&signed_message(1, body.len() as u64, &d)[..], None).as_ref());
    let sig_ok = check_sig(&sig, &pk, body) == Some((1, body.len()));
    let mut t = [0u8; 64];
    t[..body.len()].copy_from_slice(body);
    t[6] ^= 1;
    let sig_t = check_sig(&sig, &pk, &t[..body.len()]).is_none();
    let mut x = sig;
    x[..8].copy_from_slice(b"HQBSIG1\0");
    let sig_x = check_sig(&x, &pk, body).is_none();
    let pass = good_ok && auto && hex && refused && sig_ok && sig_t && sig_x;
    arch_aarch64::_print(format_args!(
        " [P-wificfg] {} — WIFI.TXT (parity G20: SSID/PSK/channel without a rebuild): valid file={} auto channel={} raw 64-hex PMK={} | refused whole: short/long/non-hex PSK, empty/33-byte/control-char SSID, DFS ch 52 + ch 14, duplicates, unknown keys, missing keys ={} | WIFI.SIG ok={} tampered refused={} other-file signature refused={}\n",
        if pass { "PASS" } else { "FAIL" }, good_ok, auto, hex, refused, sig_ok, sig_t, sig_x
    ));
    pass
}
