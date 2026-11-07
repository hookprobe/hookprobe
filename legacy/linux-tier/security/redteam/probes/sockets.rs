//! Raw AF_PACKET send socket — the ONLY place in the probes tree that touches `unsafe`, mirroring
//! `modules/napse-capture/loader/src/bin/napse-dpi.rs`'s `open_afpacket` (same libc calls, checked
//! the same way, no blanket crate-level forbid — see that file's doc comment for the convention
//! this crate deliberately matches). A socket is opened LAZILY, per already-`ValidatedTarget`/
//! `ValidatedL2Scope` token (ADR 0020 D3 contract #2: "no raw socket without a validated target") —
//! every public function here takes a `&str` interface name that the CALLER must already have
//! obtained from `target_guard`; this module does not itself consult the ROE (that would be a
//! layering violation — a probe that could open a socket without going through `target_guard` first
//! would defeat contract #2 even if every *caller* happened to behave).
use anyhow::{bail, Context, Result};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Open an AF_PACKET/SOCK_RAW TX socket bound to `iface`. Needs CAP_NET_RAW (or root); the caller
/// (the CLI) surfaces a plain, honest error — never a silent no-op — when that capability is
/// absent, so a campaign run without privilege fails loudly instead of reporting a fabricated pass.
pub fn open_afpacket_tx(iface: &str) -> Result<OwnedFd> {
    let eth_p_all = (libc::ETH_P_ALL as u16).to_be() as i32;
    // SAFETY: standard AF_PACKET/SOCK_RAW socket creation, return value checked immediately below.
    let fd: RawFd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, eth_p_all) };
    if fd < 0 {
        bail!(
            "socket(AF_PACKET) failed (need CAP_NET_RAW / root): {}",
            std::io::Error::last_os_error()
        );
    }
    // SAFETY: fd is a valid, just-created, exclusively-owned descriptor.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    let ifindex: i32 = std::fs::read_to_string(format!("/sys/class/net/{iface}/ifindex"))
        .with_context(|| format!("ifindex for {iface}"))?
        .trim()
        .parse()?;
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = eth_p_all as u16;
    sll.sll_ifindex = ifindex;
    // SAFETY: sockaddr_ll is correctly sized/zeroed above; bind() return value checked.
    let rc = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            &sll as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ll>() as u32,
        )
    };
    if rc < 0 {
        bail!("bind({iface}) failed: {}", std::io::Error::last_os_error());
    }
    Ok(sock)
}

/// Read the interface's own MAC (source address for crafted frames) from sysfs — never guessed.
pub fn iface_mac(iface: &str) -> Result<[u8; 6]> {
    let text = std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .with_context(|| format!("read MAC for {iface}"))?;
    parse_mac(text.trim())
}

pub fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let mut out = [0u8; 6];
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        bail!("{s:?} is not a MAC address");
    }
    for (i, p) in parts.iter().enumerate() {
        out[i] = u8::from_str_radix(p, 16).with_context(|| format!("bad MAC octet {p:?}"))?;
    }
    Ok(out)
}

/// Send one raw frame. Returns the frame's byte length on success (the caller feeds this straight
/// into `Limiter::admit` bookkeeping BEFORE calling this — never after; see each probe's send loop).
pub fn send_frame(sock: &OwnedFd, frame: &[u8]) -> Result<usize> {
    // SAFETY: fd is a valid bound AF_PACKET socket (from `open_afpacket_tx`); buffer/len are a
    // valid Rust slice passed by pointer+length, matching `libc::send`'s contract.
    let n = unsafe { libc::send(sock.as_raw_fd(), frame.as_ptr() as *const libc::c_void, frame.len(), 0) };
    if n < 0 {
        bail!("send() failed: {}", std::io::Error::last_os_error());
    }
    Ok(n as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mac_accepts_well_formed_address() {
        assert_eq!(parse_mac("02:00:00:00:00:01").unwrap(), [0x02, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn parse_mac_rejects_malformed_input() {
        assert!(parse_mac("not-a-mac").is_err());
        assert!(parse_mac("02:00:00:00:00").is_err()); // only 5 octets
    }
}
