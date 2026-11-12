//! The EL0 LAN-services server (ADR 0050 D4 step 2). Each bounded excursion runs ONE command from the shared IO
//! region (`hal::lansvcabi`) and exits back to the kernel with `SYS_EXIT_USER`. It parses what every Wi-Fi client
//! and the upstream resolver send to Shield — a DNS query, a DNS answer — with the kernel's own `dnswire.rs`, so a
//! parser bug costs this server (the kernel resets it and passes the message, ADR 0050 D5), never the kernel.
//! D4 step 2b: the DHCP server's client-frame parse (`hal::dhcpwire`) runs here too; step 3: the WAN control
//! parsers (DHCPv4 replies, Router Advertisements, DHCPv6) — bytes from the ISP side.
//! Step 5c: the WPA3-SAE responder's walk over a station's Commit / Confirm (`hal::saewire`).
//! Allocation-free; no state survives a command.
#![no_std]
#![no_main]

#[path = "../../kernel/src/dnswire.rs"]
#[allow(dead_code)]
mod dnswire;

use core::ptr::{read_volatile, write_volatile};
use hal::lansvcabi::*;

#[cfg(not(feature = "cm5"))]
const BASE: usize = BASE_QEMU;
#[cfg(feature = "cm5")]
const BASE: usize = BASE_CM5;
const IO: usize = BASE + IO_OFF;
const SYS_EXIT_USER: u64 = 6;

fn rd32(off: usize) -> u32 {
    unsafe { read_volatile((IO + off) as *const u32) }
}
fn wr32(off: usize, v: u32) {
    unsafe { write_volatile((IO + off) as *mut u32, v) }
}
fn io(off: usize, len: usize) -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut((IO + off) as *mut u8, len) }
}
fn exit(status: u32, out_len: usize) -> ! {
    wr32(H_STATUS, status);
    wr32(H_OUT_LEN, out_len as u32);
    unsafe { core::arch::asm!("svc #0", in("x8") SYS_EXIT_USER, options(noreturn)) }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(ST_PANIC, 0)
}

/// The response walk result lives in .bss (8 KiB+; the stack stays small).
static mut WALK: dnswire::Walk = dnswire::WALK0;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    if rd32(H_MAGIC) != MAGIC {
        exit(ST_BAD_CMD, 0);
    }
    let n = (rd32(H_IN_LEN) as usize).min(IN_MAX);
    let mut msg = [0u8; IN_MAX];
    msg[..n].copy_from_slice(&io(IN_OFF, n)[..]);
    let dns = &msg[..n];
    let out = io(OUT_OFF, OUT_MAX);
    match rd32(H_CMD) {
        CMD_DNS_QUERY => match dnswire::parse_query(dns) {
            Some(q) => {
                let nl = q.nl.min(255);
                out[0..2].copy_from_slice(&(nl as u16).to_le_bytes());
                out[2..4].copy_from_slice(&q.qtype.to_le_bytes());
                out[4..8].copy_from_slice(&(q.qend as u32).to_le_bytes());
                out[8] = q.edns as u8;
                out[Q_REC_HDR..Q_REC_HDR + nl].copy_from_slice(&q.name[..nl]);
                exit(ST_OK, Q_REC_HDR + nl)
            }
            None => exit(ST_NONE, 0),
        },
        CMD_DNS_WALK => {
            #[allow(static_mut_refs)]
            let w = unsafe { &mut WALK };
            if dnswire::walk_answers(dns, w).is_none() {
                exit(ST_NONE, 0);
            }
            let k = w.ncname.min(WALK_MAX_CNAMES);
            out[0..2].copy_from_slice(&(w.qnl.min(255) as u16).to_le_bytes());
            out[2..4].copy_from_slice(&(k as u16).to_le_bytes());
            out[4..8].copy_from_slice(&(w.qend as u32).to_le_bytes());
            out[8..8 + 256].copy_from_slice(&w.qname);
            for i in 0..k {
                let o = WALK_HDR + i * WALK_STRIDE;
                out[o..o + 2].copy_from_slice(&(w.cnl[i].min(255) as u16).to_le_bytes());
                out[o + 2..o + 2 + 256].copy_from_slice(&w.cnames[i]);
            }
            exit(ST_OK, WALK_HDR + k * WALK_STRIDE)
        }
        CMD_DHCP_PARSE => {
            let r = hal::dhcpwire::parse_client(dns);
            let mut rec = [0u8; hal::dhcpwire::REC_LEN];
            hal::dhcpwire::encode(&r, &mut rec);
            out[..rec.len()].copy_from_slice(&rec);
            exit(ST_OK, rec.len())
        }
        CMD_WAN_DHCP_REPLY if n >= 10 => {
            let xid: [u8; 4] = [dns[0], dns[1], dns[2], dns[3]];
            let mac: [u8; 6] = [dns[4], dns[5], dns[6], dns[7], dns[8], dns[9]];
            let rec = hal::dhcpwire::encode_facts(&hal::dhcpwire::dhcp_reply_facts(&dns[10..], &xid, &mac));
            out[..rec.len()].copy_from_slice(&rec);
            exit(ST_OK, rec.len())
        }
        CMD_WAN_RA => match hal::ip6::parse_ra(dns) {
            Some(r) => {
                let rec = hal::ip6::encode_ra(&r);
                out[..rec.len()].copy_from_slice(&rec);
                exit(ST_OK, rec.len())
            }
            None => exit(ST_NONE, 0),
        },
        CMD_WAN_DHCP6 if n >= 4 => match hal::ip6::parse_dhcp6(&dns[4..], u32::from_le_bytes([dns[0], dns[1], dns[2], dns[3]])) {
            Some(d) => {
                let rec = hal::ip6::encode_dhcp6(&d);
                out[..rec.len()].copy_from_slice(&rec);
                exit(ST_OK, rec.len())
            }
            None => exit(ST_NONE, 0),
        },
        CMD_WAN_PPPOE_DISC if n >= 2 => {
            let plen = u16::from_le_bytes([dns[0], dns[1]]) as usize;
            let rec = hal::pppwire::encode_disc(&hal::pppwire::disc_tags(&dns[2..], plen));
            out[..rec.len()].copy_from_slice(&rec);
            exit(ST_OK, rec.len())
        }
        CMD_WAN_LCP_REQ => {
            let rec = hal::pppwire::encode_lcp(&hal::pppwire::lcp_classify(dns));
            out[..rec.len()].copy_from_slice(&rec);
            exit(ST_OK, rec.len())
        }
        CMD_WAN_IPCP if n >= 1 => {
            let rec = hal::pppwire::encode_ipcp(&hal::pppwire::ipcp_facts(dns[0], &dns[1..]));
            out[..rec.len()].copy_from_slice(&rec);
            exit(ST_OK, rec.len())
        }
        CMD_WAN_CHAP => {
            let rec = hal::pppwire::encode_chap(&hal::pppwire::chap_challenge(dns));
            out[..rec.len()].copy_from_slice(&rec);
            exit(ST_OK, rec.len())
        }
        CMD_WAN_IP6CP => {
            let rec = hal::pppwire::encode_ip6cp(&hal::pppwire::ip6cp_req(dns));
            out[..rec.len()].copy_from_slice(&rec);
            exit(ST_OK, rec.len())
        }
        CMD_WAN_LCP_PEER if n >= 1 => {
            let rec = hal::pppwire::encode_lcp_peer(&hal::pppwire::lcp_peer(dns[0], &dns[1..]));
            out[..rec.len()].copy_from_slice(&rec);
            exit(ST_OK, rec.len())
        }
        CMD_STA_M2 if n >= hal::wpaauth::M2_PRE => {
            let a = |r: core::ops::Range<usize>| -> &[u8] { &dns[r] };
            let pmk: [u8; 32] = a(0..32).try_into().unwrap();
            let aa: [u8; 6] = a(32..38).try_into().unwrap();
            let spa: [u8; 6] = a(38..44).try_into().unwrap();
            let anonce: [u8; 32] = a(44..76).try_into().unwrap();
            let mut pmk = pmk;
            let mut r = hal::wpaauth::on_m2(&pmk, &aa, &spa, &anonce, dns[76] != 0, &dns[hal::wpaauth::M2_PRE..n]);
            out[0] = r.is_some() as u8;
            out[1..49].copy_from_slice(&r.unwrap_or([0; 48]));
            // operator 2026-11-11 (2A): the PMK and the PTK do not outlive this call in the server
            hal::wpaauth::wipe(&mut pmk);
            if let Some(p) = r.as_mut() {
                hal::wpaauth::wipe(p);
            }
            hal::wpaauth::wipe(io(IN_OFF, hal::wpaauth::M2_PRE));
            hal::wpaauth::wipe(&mut msg[..hal::wpaauth::M2_PRE]);
            exit(ST_OK, hal::wpaauth::M2_OUT)
        }
        CMD_STA_M4 if n >= hal::wpaauth::M4_PRE => {
            let mut kck: [u8; 16] = dns[0..16].try_into().unwrap();
            out[0] = hal::wpaauth::on_m4(&kck, dns[16] != 0, &dns[hal::wpaauth::M4_PRE..n]) as u8;
            hal::wpaauth::wipe(&mut kck);
            hal::wpaauth::wipe(io(IN_OFF, 16));
            hal::wpaauth::wipe(&mut msg[..16]);
            exit(ST_OK, 1)
        }
        CMD_STA_EAPOL if n >= 15 => {
            let sta: [u8; 6] = [dns[0], dns[1], dns[2], dns[3], dns[4], dns[5]];
            let replay = u64::from_le_bytes([dns[7], dns[8], dns[9], dns[10], dns[11], dns[12], dns[13], dns[14]]);
            let r = hal::eapolwire::eapol_key(&dns[15..], &sta, dns[6] != 0, replay);
            out[0] = r.is_some() as u8;
            out[1..3].copy_from_slice(&(r.unwrap_or(0).min(0xffff) as u16).to_le_bytes());
            exit(ST_OK, 3)
        }
        CMD_STA_MFPC if n >= 2 => {
            out[0] = hal::eapolwire::m2_mfpc(&dns[2..], u16::from_le_bytes([dns[0], dns[1]]) as usize) as u8;
            exit(ST_OK, 1)
        }
        // D4 step 5c: a station's SAE Commit / Confirm (public bytes only: no password, PWE, rand, KCK or PMK here)
        CMD_STA_SAE if n >= 1 && n - 1 <= hal::saewire::BODY_MAX => {
            let mut rec = hal::saewire::encode(&hal::saewire::parse(&dns[1..n], dns[0] != 0));
            out[..rec.len()].copy_from_slice(&rec);
            hal::wpaauth::wipe(&mut rec);
            hal::wpaauth::wipe(&mut msg[..n]);
            exit(ST_OK, hal::saewire::REC_LEN)
        }
        CMD_SELFTEST_FAULT => unsafe { core::ptr::read_volatile(0x10 as *const u32) as usize as *const u8; core::ptr::write_volatile(0x8 as *mut u32, 1); exit(ST_OK, 0) },
        _ => exit(ST_BAD_CMD, 0),
    }
}
