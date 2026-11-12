//! The kernel <-> EL0 LAN-services server ABI (ADR 0050 D4 step 2). One shared IO region; every bounded
//! excursion carries ONE command. Shared by `el0-lansvc` and the kernel so the two cannot drift.
//!
//! Address space: the server image is linked at `base`; the kernel maps the stack and IO region at the fixed
//! offsets below. QEMU base `0xB000_0000`; CM5 base `USER_VA_BASE + 0x20_0000` — the GB5 window's second 2 MiB
//! block (the Wasm and TLS hosts fill the first). No heap: the server is allocation-free.

pub const BASE_QEMU: usize = 0xB000_0000;
pub const BASE_CM5: usize = 0x1_4020_0000;
pub const IMAGE_MAX: usize = 0x4_0000; // 256 KiB text+rodata+data+bss
pub const STACK_OFF: usize = 0x4_0000;
pub const STACK_SIZE: usize = 0x1_0000;
pub const IO_OFF: usize = 0x5_0000;
pub const IO_SIZE: usize = 0x4000;

// IO header (all little-endian).
pub const H_MAGIC: usize = 0; // u32 "HQLS"
pub const H_CMD: usize = 4; // u32 (in)
pub const H_IN_LEN: usize = 8; // u32 (in)
pub const H_STATUS: usize = 12; // u32 (out)
pub const H_OUT_LEN: usize = 16; // u32 (out)
pub const MAGIC: u32 = u32::from_le_bytes(*b"HQLS");

pub const IN_OFF: usize = 0x40;
pub const IN_MAX: usize = 0x7C0; // 1984 B: one DNS message in a 1500-B frame, or one whole client Ethernet frame
pub const OUT_OFF: usize = 0x800;
pub const OUT_MAX: usize = IO_SIZE - OUT_OFF;

/// IN = a client DNS query (UDP payload). OUT = `[u16 nl][u16 qtype][u32 qend][u8 edns][3 pad][name; nl]`.
pub const CMD_DNS_QUERY: u32 = 1;
pub const Q_REC_HDR: usize = 12;
/// IN = an upstream DNS response (UDP payload). OUT = `[u16 qnl][u16 ncname][u32 qend][qname; 256]` then
/// `ncname` × `[u16 len][name; 256]` (fixed stride `WALK_STRIDE`).
pub const CMD_DNS_WALK: u32 = 2;
pub const WALK_HDR: usize = 8 + 256;
pub const WALK_STRIDE: usize = 2 + 256;
pub const WALK_MAX_CNAMES: usize = 32;
/// D4 step 2b: IN = a client Ethernet frame to the DHCP server (<= 1514 B). OUT = `hal::dhcpwire::REC_LEN` bytes
/// (`dhcpwire::encode`): message type, chaddr, xid, requested IP, and the identity options (hostname, vendor, PRL).
pub const CMD_DHCP_PARSE: u32 = 3;
/// D4 step 3 (WAN control). IN = `xid[4] mac[6]` + a WAN Ethernet frame. OUT = `dhcpwire::FACTS_LEN`.
pub const CMD_WAN_DHCP_REPLY: u32 = 4;
/// IN = a bare IPv6 packet. OUT = `ip6::RA_LEN` (ST_NONE = not a valid RA).
pub const CMD_WAN_RA: u32 = 5;
/// IN = `xid[4] LE` + a bare IPv6 packet. OUT = `ip6::DHCP6_LEN` (ST_NONE = not ours / invalid).
pub const CMD_WAN_DHCP6: u32 = 6;
/// D4 step 3b: IN = `plen u16 LE` + a PPPoE discovery frame (PADO / PADS). OUT = `pppwire::DISC_LEN`.
pub const CMD_WAN_PPPOE_DISC: u32 = 7;
/// D4 step 3b-ii: IN = an LCP Configure-Request's option bytes. OUT = `pppwire::LCP_LEN`.
pub const CMD_WAN_LCP_REQ: u32 = 8;
/// D4 step 3b-iii: IN = `code u8` + IPCP option bytes. OUT = `pppwire::IPCP_LEN`.
pub const CMD_WAN_IPCP: u32 = 9;
/// D4 step 3b-iv: IN = a CHAP Challenge's bytes after code/id/length. OUT = `pppwire::CHAP_LEN`.
pub const CMD_WAN_CHAP: u32 = 10;
/// IN = an IPv6CP Configure-Request's option bytes. OUT = `pppwire::IP6CP_LEN`.
pub const CMD_WAN_IP6CP: u32 = 11;
/// D4 step 3b-v: IN = `code u8` + the AC's LCP Nak / Reject data. OUT = `pppwire::encode_lcp_peer`.
pub const CMD_WAN_LCP_PEER: u32 = 14;
/// D4 step 5b: IN = `wpaauth::M2_PRE` prefix + the M2 802.1X frame. OUT = `[ok u8][ptk 48]`.
pub const CMD_STA_M2: u32 = 15;
/// IN = `wpaauth::M4_PRE` prefix + the M4 frame. OUT = `[ok u8]`.
pub const CMD_STA_M4: u32 = 16;
/// D4 step 5a: IN = `sta[6] secure u8 replay u64 LE` + an Ethernet frame. OUT = `[ok u8][n u16 LE]`.
pub const CMD_STA_EAPOL: u32 = 12;
/// IN = `body_off u16 LE` + an M2 802.1X frame. OUT = `[mfpc u8]`.
pub const CMD_STA_MFPC: u32 = 13;
/// D4 step 5c: IN = `h2e_ok u8` + one SAE Authentication frame body (<= `saewire::BODY_MAX`). OUT = `saewire::REC_LEN`
/// (`saewire::encode`): the checked Commit / Confirm facts. Public bytes only — no SAE secret crosses.
pub const CMD_STA_SAE: u32 = 17;
/// Self-test only (kernel-issued at boot): the server faults on purpose, proving the D5 reset path.
pub const CMD_SELFTEST_FAULT: u32 = 99;

pub const ST_OK: u32 = 0;
/// The parser rejected the message (the kernel treats it exactly like the in-kernel `None`).
pub const ST_NONE: u32 = 1;
pub const ST_BAD_CMD: u32 = 2;
/// Written by the kernel before every call; a clean exit overwrites it.
pub const ST_PANIC: u32 = 6;
