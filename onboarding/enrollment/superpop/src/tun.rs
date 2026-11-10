//! Minimal Linux TUN device (IFF_TUN | IFF_NO_PI): one read() = one inner IP packet.
//! Address/route/NAT setup is the operator's (see `superpop-net.sh`), so this needs only
//! CAP_NET_ADMIN to create the interface.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

#[repr(C)]
struct IfReq {
    name: [u8; libc::IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

pub fn open(name: &str) -> io::Result<File> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad interface name"));
    }
    let f = OpenOptions::new().read(true).write(true).open("/dev/net/tun")?;
    let mut req = IfReq { name: [0; libc::IFNAMSIZ], flags: IFF_TUN | IFF_NO_PI, _pad: [0; 22] };
    req.name[..name.len()].copy_from_slice(name.as_bytes());
    // SAFETY: TUNSETIFF takes a pointer to an ifreq-sized struct that lives for the call.
    let rc = unsafe { libc::ioctl(f.as_raw_fd(), TUNSETIFF as _, &mut req as *mut IfReq) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(f)
}
