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
    if u16::from_be_bytes([rx[eth + 12], rx[eth + 13]]) != 0x888E || &rx[eth + 6..eth + 12] != &sta[..] {
        return None;
    }
    let ki = u16::from_be_bytes([rx[eth + body + 1], rx[eth + body + 2]]);
    let pairwise_mic_noack = ki & 0x0008 != 0 && ki & 0x0100 != 0 && ki & 0x0080 == 0;
    if !pairwise_mic_noack || (ki & 0x0200 != 0) != secure {
        return None;
    }
    let mut rc = [0u8; 8];
    rc.copy_from_slice(&rx[eth + body + 5..eth + body + 13]);
    if u64::from_be_bytes(rc) != replay {
        return None; // stale (previous session / previous retransmit)
    }
    let x1 = u16::from_be_bytes([rx[eth + 16], rx[eth + 17]]) as usize;
    let n = 4 + x1;
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
