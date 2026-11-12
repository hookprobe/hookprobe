//! Pure parsers for frames the Wi-Fi AP / WAN DHCP paths receive from untrusted peers: the WAN DHCP
//! client's reply parser, the AP DHCP server's request parser, CYW43455 firmware event decoding and the
//! WPA2 authenticator's EAPOL matcher. No MMIO — built on EVERY target so the QEMU `[P-fuzz]` phase can
//! reach them (ADR 0050 D3); `cyw43.rs` / `uplink.rs` use them via re-exports.

// brcmf event codes the authenticator reacts to (bcmevent.h).
pub const WLC_E_DEAUTH_IND: u32 = 6;
pub const WLC_E_ASSOC_IND: u32 = 8;
pub const WLC_E_REASSOC_IND: u32 = 10;
pub const WLC_E_DISASSOC_IND: u32 = 12;

pub use hal::dhcpwire::{apply_reply, dhcp_reply_facts, parse_dhcp_reply, DhcpResult, ReplyFacts};

pub use hal::dhcpwire::parse_client_dhcp;

/// Decode a channel-1 event at `doff`: (event type @ev+28, status @ev+32, station addr
/// @ev+48). None if the frame is too short to hold a brcmf_event_msg_be.
pub fn parse_ap_event(rx: &[u8], doff: usize) -> Option<(u32, u32, [u8; 6])> {
    let ev = doff + 4 + (*rx.get(doff + 3)? as usize) * 4;
    if ev + 54 > rx.len() {
        return None;
    }
    let et = u32::from_be_bytes([rx[ev + 28], rx[ev + 29], rx[ev + 30], rx[ev + 31]]);
    let st = u32::from_be_bytes([rx[ev + 32], rx[ev + 33], rx[ev + 34], rx[ev + 35]]);
    let mut sta = [0u8; 6];
    sta.copy_from_slice(&rx[ev + 48..ev + 54]);
    Some((et, st, sta))
}

/// Outcome of one bounded wait for an EAPOL-Key reply from the station.
pub enum KeyWait {
    Got(usize), // an EAPOL-Key frame matching the filter + replay is in the buffer (802.1X len)
    Dry,        // `dry_limit` consecutive dry reads (~1.5 s each): the caller retransmits
    Reassoc,    // the station (re)associated: the caller restarts the handshake
    Deauth,     // the station left
}

/// One SDPCM frame vs the authenticator's wait: `Some` = terminal for this wait (our EAPOL reply —
/// copied into `out` when given — or this station's deauth / reassoc event), `None` = not ours.
pub fn eapol_match(rx: &[u8], ch: u8, doff: usize, sta: &[u8; 6], secure: bool, replay: u64, out: Option<&mut [u8]>) -> Option<KeyWait> {
    let body = 18usize;
    if ch == 1 {
        if let Some((et, _st, who)) = parse_ap_event(rx, doff) {
            if who == *sta {
                if et == WLC_E_DEAUTH_IND || et == WLC_E_DISASSOC_IND {
                    return Some(KeyWait::Deauth);
                }
                if et == WLC_E_ASSOC_IND || et == WLC_E_REASSOC_IND {
                    return Some(KeyWait::Reassoc);
                }
            }
        }
        return None;
    }
    if ch != 2 || doff + 4 > rx.len() {
        return None;
    }
    let eth = doff + 4 + (rx[doff + 3] as usize) * 4;
    if eth + body + 95 > rx.len() {
        return None;
    }
    // ADR 0050 D4 step 5a: the EAPOL-Key classification runs in EL0 (el0-lansvc) when it is loaded; the length it
    // returns is re-checked here against this buffer before anything is copied
    let n = crate::wanparse::eapol_key(&rx[eth..], sta, secure, replay)?;
    if eth + 14 + n > rx.len() {
        return None;
    }
    match out {
        Some(buf) => {
            if n > buf.len() {
                return None; // skipped, never truncated (a truncated MIC span reads as "wrong PSK")
            }
            buf[..n].copy_from_slice(&rx[eth + 14..eth + 14 + n]);
            Some(KeyWait::Got(n))
        }
        None => Some(KeyWait::Got(n)),
    }
}

/// Event 188 (EXT_AUTH_FRAME_RX) at event-message offset `ev`: the 802.11 Authentication frame addressed to `ap`.
/// Fixed-offset header reads only (event datalen, the optional 16-byte rx metadata, frame control, addr1/addr2).
/// Returns (station, body start, body end): the body is trimmed to the EVENT's own data length, never the rest of
/// the SDPCM buffer (metal batch 62 lesson), so the SAE walk sees exactly the frame the station sent.
pub fn sae_auth_body(rx: &[u8], ev: usize, ap: &[u8; 6]) -> Result<([u8; 6], usize, usize), &'static str> {
    if ev + 72 > rx.len() {
        return Err("short event");
    }
    let dl = u32::from_be_bytes([rx[ev + 44], rx[ev + 45], rx[ev + 46], rx[ev + 47]]) as usize;
    let d = ev + 72;
    let end = d.saturating_add(dl).min(rx.len());
    // 16-byte rx metadata (version, chanspec, rssi, mactime, rate) then the 802.11 frame
    let f = if end >= d + 16 + 24 && rx[d + 16] & 0xfc == 0xb0 {
        d + 16
    } else if end >= d + 24 && rx[d] & 0xfc == 0xb0 {
        d
    } else {
        return Err("no auth frame");
    };
    let mut sta = [0u8; 6];
    sta.copy_from_slice(&rx[f + 10..f + 16]);
    if rx[f + 4..f + 10] != ap[..] || sta[0] & 1 != 0 {
        return Err("not addressed to this AP");
    }
    Ok((sta, f + 24, end))
}
