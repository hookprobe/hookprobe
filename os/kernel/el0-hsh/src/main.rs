//! hsh — the HEQK native management shell (ADR 0059 step 4a; docs/design/hsh-native-management-shell.md §0 wins).
//!
//! An EL0 EXCURSION server (R1): each excursion runs ONE command from the shared IO region (`hal::hshabi`) and exits
//! with `SYS_EXIT_USER`. Two-phase per shell command: a line comes in; the shell answers with text, or with ONE
//! bounded management request (`hal::mgmtabi`) that the kernel authorises and serves from the same producers as
//! `GET /api/*`; then the kernel re-enters with the reply and the shell formats it. The shell parses untrusted input
//! (a fault here costs only this command — ADR 0050 D5), never decides trust, keeps no state, allocates nothing.
//! Step 4a = foundation + read-only views; configuration (4b) and owner (4c) commands say "not supported" until then.
#![no_std]
#![no_main]

use core::fmt::Write;
use core::ptr::{read_volatile, write_volatile};
use hal::hshabi::*;
use hal::mgmtabi as m;

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

/// Bounded text writer over the OUT region (never overflows; truncates).
struct Out {
    buf: &'static mut [u8],
    n: usize,
}
impl Write for Out {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let b = s.as_bytes();
        let k = b.len().min(self.buf.len() - self.n);
        self.buf[self.n..self.n + k].copy_from_slice(&b[..k]);
        self.n += k;
        Ok(())
    }
}

// ---- parser (spec §9) ----------------------------------------------------------------------------------------

pub enum Parsed<'a> {
    Empty,
    Tokens([&'a [u8]; TOKENS_MAX], usize),
    Bad(&'static str),
}

/// `command := token (SP token)*`, token = printable ASCII 0x21-0x7E; no quoting, no escapes, no operators.
pub fn parse(line: &[u8]) -> Parsed<'_> {
    if line.len() > LINE_MAX {
        return Parsed::Bad("ERROR: Invalid argument. (line longer than 255 bytes)");
    }
    if line.iter().any(|&c| c != b' ' && !(0x21..=0x7e).contains(&c)) {
        return Parsed::Bad("ERROR: Invalid argument. (only printable ASCII)");
    }
    let mut t = [&b""[..]; TOKENS_MAX];
    let mut n = 0;
    for tok in line.split(|&c| c == b' ').filter(|s| !s.is_empty()) {
        if n == TOKENS_MAX {
            return Parsed::Bad("ERROR: Invalid argument. (more than 12 tokens)");
        }
        if tok.len() > TOKEN_MAX {
            return Parsed::Bad("ERROR: Invalid argument. (a token longer than 64 bytes)");
        }
        // §9.3: pipes, redirection, chaining, substitution, wildcards, quoting / escapes — never
        if tok.iter().any(|c| b"|;&<>$`'\"\\*?(){}[]!~".contains(c)) {
            return Parsed::Bad("ERROR: Invalid argument. (shell operators are not supported)");
        }
        t[n] = tok;
        n += 1;
    }
    if n == 0 { Parsed::Empty } else { Parsed::Tokens(t, n) }
}

// ---- registry (spec §4; step 4a) ------------------------------------------------------------------------------

enum Act {
    Text(&'static str),
    Req(u16),
    ReqArg(u16, u64),
    Help,
    Unsupported,
}

/// (words, what it does, help line). Read-only commands map to exactly ONE management message.
const CMDS: &[(&[&str], u8, &str)] = &[
    (&["help"], 0, "help                  this list (only what this build supports)"),
    (&["version"], 1, "version               HEQK build"),
    (&["info"], 1, "info                  platform, counters, configuration + ownership state"),
    (&["uptime"], 1, "uptime                time since boot"),
    (&["interface", "show", "wan"], 2, "interface show wan    WAN state, address, mode, counters"),
    (&["wan", "status"], 2, "wan status            (same as interface show wan)"),
    (&["qsecbit", "status"], 3, "qsecbit status        the latest risk score and band"),
    (&["config", "status"], 4, "config status         configuration lifecycle (cfgd) + generation floors"),
    (&["owner", "status"], 5, "owner status          which keys verify what (fingerprints only)"),
    (&["security", "posture"], 6, "security posture      where the network parsers run (ADR 0050) + EL0 health"),
    (&["config", "confirm"], 20, "config confirm        commit the configuration on trial (owner-signed envelope)"),
    (&["config", "rollback"], 21, "config rollback       the previous configuration (owner-signed envelope)"),
    (&["owner", "challenge"], 30, "owner challenge       what an owner-signed envelope must bind (signed off-device)"),
];
/// Spec commands that exist in the command set but not yet in this build (4b / 4c / backends pending).
const LATER: &[&[&str]] = &[
    &["memory"], &["cpu"], &["boot"], &["reboot"], &["interface", "list"], &["interface", "stats"], &["ip"], &["route"],
    &["vlan"], &["pppoe"], &["dhcp"], &["dns"], &["firewall"], &["acl"], &["prefix"], &["audit"], &["diagnostics"],
    &["config"], &["owner"], &["recovery"],
];

/// An upload id as Mission Control shows it (16 hex digits) or decimal.
fn parse_id(t: &[u8]) -> Option<u64> {
    let s = core::str::from_utf8(t).ok()?;
    if s.len() == 16 { u64::from_str_radix(s, 16).ok() } else { s.parse().ok() }
}

fn lookup(t: &[&[u8]]) -> Act {
    if t.len() == 3 && t[0] == b"config" && t[1] == b"stage" {
        return match parse_id(t[2]) {
            Some(id) => Act::ReqArg(hal::mgmtabi::CFG_STAGE, id),
            None => Act::Text("ERROR: Invalid argument. (config stage <upload-id>)"),
        };
    }
    for (words, what, _) in CMDS {
        if words.len() == t.len() && words.iter().zip(t).all(|(w, x)| w.as_bytes() == *x) {
            return match *what {
                0 => Act::Help,
                1 => Act::Req(m::GET_INFO),
                2 => Act::Req(m::GET_WAN),
                3 => Act::Req(m::GET_QSECBIT),
                4 => Act::Req(m::GET_CONFIG),
                5 => Act::Req(m::GET_ANCHOR),
                6 => Act::Req(m::GET_PARSERS),
                20 => Act::Req(m::CFG_CONFIRM),
                21 => Act::Req(m::CFG_ROLLBACK),
                30 => Act::Req(m::OWNER_CHALLENGE),
                _ => Act::Unsupported,
            };
        }
    }
    if LATER.iter().any(|w| w.len() <= t.len() && w.iter().zip(t).all(|(a, b)| a.as_bytes() == *b)) {
        return Act::Unsupported;
    }
    Act::Text("ERROR: Unknown command. (type help)")
}

// ---- formatting (spec §10: never print success before the ABI reply confirms it) ------------------------------

fn ip(o: &mut Out, a: [u8; 4]) {
    let _ = write!(o, "{}.{}.{}.{}", a[0], a[1], a[2], a[3]);
}
fn fp(o: &mut Out, f: Option<[u8; 8]>) {
    match f {
        Some(f) => {
            for b in f {
                let _ = write!(o, "{:02x}", b);
            }
            let _ = o.write_str("…");
        }
        None => {
            let _ = o.write_str("NONE");
        }
    }
}
const CFG_STATE: [&str; 5] = ["NONE (per-file configuration)", "COMMITTED", "TRIAL", "REVERTED", "REFUSED (per-file configuration)"];

fn format(o: &mut Out, msg: u16, cmd0: u8, rec: &[u8]) -> bool {
    match msg {
        m::GET_INFO => {
            let Ok(r) = rec.try_into() else { return false };
            let i = m::Info::decode(r);
            let build = core::str::from_utf8(&i.build).unwrap_or("?").trim_end_matches('\0');
            match cmd0 {
                b'v' => {
                    let _ = writeln!(o, "HEQK {}", build);
                }
                b'u' => {
                    let _ = writeln!(o, "up {} d {:02}:{:02}:{:02}", i.uptime_s / 86400, i.uptime_s / 3600 % 24, i.uptime_s / 60 % 60, i.uptime_s % 60);
                }
                _ => {
                    let _ = writeln!(o, "HEQK Management Environment\nBuild:          {}\nPlatform:       Raspberry Pi CM5 (AArch64), shell at EL0, kernel at EL1", build);
                    let _ = writeln!(o, "Uptime:         {} s   clock: {}", i.uptime_s, if i.clock_synced { "NTP" } else { "unsynced" });
                    let _ = writeln!(o, "Detection:      {} rules armed, {} detections; seen {} forwarded {} dropped {}", i.rules_active, i.detections, i.seen, i.forwarded, i.dropped);
                    let _ = writeln!(o, "Configuration:  {} (generation {})   Security: {}", CFG_STATE[i.cfg_state as usize], i.cfg_gen, if i.config_protected { "CONFIG PROTECTED" } else { "CONFIG UNPROTECTED" });
                    let _ = writeln!(o, "Owner key:      {}", if i.owner_enrolled { "ENROLLED" } else { "NONE" });
                }
            }
        }
        m::GET_WAN => {
            let Ok(r) = rec.try_into() else { return false };
            let w = m::Wan::decode(r);
            if !w.present {
                let _ = writeln!(o, "wan: no uplink state (this build / no WAN port)");
                return true;
            }
            let _ = write!(o, "wan: {}  mode {}  address ", if w.up { "UP" } else { "DOWN" }, ["dhcp", "static", "pppoe"][w.mode as usize]);
            ip(o, w.ip);
            let _ = writeln!(o, "  ipv6 {}", if w.ipv6 { "yes" } else { "no" });
            let _ = writeln!(o, "     clients {}  packets out {} in {}  dns inspected {} blocked {}", w.clients, w.pkts_out, w.pkts_in, w.dns_inspected, w.dns_blocked);
        }
        m::GET_QSECBIT => {
            let Ok(r) = rec.try_into() else { return false };
            let q = m::Qs::decode(r);
            if !q.present {
                let _ = writeln!(o, "qsecbit: no sample yet");
            } else {
                let band = core::str::from_utf8(&q.band).unwrap_or("?").trim_end_matches('\0');
                let _ = writeln!(o, "qsecbit: {}.{:03}  band {}  ({} samples)", q.score_milli / 1000, q.score_milli % 1000, band, q.samples);
            }
        }
        m::GET_CONFIG => {
            let Ok(r) = rec.try_into() else { return false };
            let c = m::Cfg::decode(r);
            let _ = writeln!(o, "config: {}  generation {}  bundle floor {}", CFG_STATE[c.state as usize], c.generation, c.floor);
            if c.on_trial {
                let _ = writeln!(o, "        ON TRIAL {}/{} s — {}", c.elapsed_s, c.window_s, if c.needs_confirm { "owner confirm REQUIRED (management-plane change)" } else { "commits when the WAN is usable, reverts otherwise" });
            }
            let _ = writeln!(o, "floors: wan {} (floor {})  wifi {} (floor {})  policy floor {}", c.wan_cur, c.wan_floor, c.wifi_cur, c.wifi_floor, c.policy_floor);
        }
        m::GET_ANCHOR => {
            let Ok(r) = rec.try_into() else { return false };
            let a = m::Anchor::decode(r);
            let _ = write!(o, "security: {}\nvendor key: ", if a.protected { "CONFIG PROTECTED" } else { "CONFIG UNPROTECTED" });
            fp(o, a.vendor);
            let _ = write!(o, "\nowner key:  ");
            fp(o, a.owner);
            let _ = writeln!(o, "{}", if a.owner.is_some() { "  (verifies WAN / Wi-Fi / POLICY)" } else { "" });
            if a.owner.is_some() {
                let _ = writeln!(o, "owner generation {}", a.owner_gen);
            }
        }
        m::GET_PARSERS => {
            let Ok(r) = rec.try_into() else { return false };
            let p = m::Parsers::decode(r);
            let _ = writeln!(o, "HTTP request parser:  {}  requests {} faults {}", if p.http_el0 { "EL0 (el0-tlshost)" } else { "EL1" }, p.http_requests, p.http_faults);
            let _ = writeln!(o, "LAN/WAN parsers:      {}  calls {} faults {} restarts {} in-kernel {}", if p.lan_el0 { "EL0 (el0-lansvc)" } else { "EL1" }, p.lan_calls, p.lan_faults, p.lan_restarts, p.lan_in_kernel);
        }
        m::OWNER_CHALLENGE => {
            let Ok(r) = rec.try_into() else { return false };
            let c = m::Challenge::decode(r);
            if !c.owner_enrolled {
                let _ = writeln!(o, "No owner key is enrolled on this device: enroll it in Mission Control first.");
                return true;
            }
            let _ = write!(o, "A privileged command needs an HQMGMT1 envelope signed off-device by the owner key:\n  device_id  ");
            for b in c.device_id {
                let _ = write!(o, "{:02x}", b);
            }
            let _ = write!(o, "\n  epoch      ");
            for b in c.epoch {
                let _ = write!(o, "{:02x}", b);
            }
            let _ = write!(o, "\n  sequence   >= {}\n  generation {}{}\n  digest     ", c.next_seq, c.generation, if c.on_trial { " (on trial)" } else { "" });
            for b in c.digest {
                let _ = write!(o, "{:02x}", b);
            }
            let _ = writeln!(o, "\n(policy-sign.py mgmt-sign; the carrier sends the envelope with the command)");
        }
        m::CFG_CONFIRM | m::CFG_ROLLBACK | m::CFG_STAGE => {
            let Ok(r) = rec.try_into() else { return false };
            let a = m::Act::decode(r);
            if a.ok {
                let _ = match msg {
                    m::CFG_CONFIRM => writeln!(o, "Configuration committed: generation {} (the bundle floor rose).", a.generation),
                    m::CFG_ROLLBACK => writeln!(o, "Rollback done: generation {} at the next boot.", a.generation),
                    _ => writeln!(o, "Configuration staged: generation {} — it runs as a TRIAL at the next boot.", a.generation),
                };
            } else {
                let _ = writeln!(o, "ERROR: Configuration rejected. ({})", a.reason_str());
            }
        }
        _ => return false,
    }
    true
}

/// The request record: [msg u16][first byte of the command, for the formatter][rsv][arg u64].
fn request(msg: u16, cmd0: u8, arg: u64, payload: &[u8]) -> ! {
    let out = io(OUT_OFF, REQ_LEN);
    out.fill(0);
    out[..2].copy_from_slice(&msg.to_le_bytes());
    out[2] = cmd0;
    let n = payload.len().min(64);
    out[3] = n as u8;
    out[4..12].copy_from_slice(&arg.to_le_bytes());
    out[12..12 + n].copy_from_slice(&payload[..n]);
    exit(ST_REQUEST, REQ_LEN)
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    if rd32(H_MAGIC) != MAGIC {
        exit(ST_BAD_CMD, 0);
    }
    let n = (rd32(H_IN_LEN) as usize).min(IN_MAX);
    let mut inb = [0u8; IN_MAX];
    inb[..n].copy_from_slice(&io(IN_OFF, n)[..]);
    let mut o = Out { buf: io(OUT_OFF, OUT_MAX), n: 0 };
    match rd32(H_CMD) {
        CMD_LINE => match parse(&inb[..n]) {
            Parsed::Empty => exit(ST_TEXT, 0),
            Parsed::Bad(e) => {
                let _ = writeln!(o, "{}", e);
                exit(ST_TEXT, o.n)
            }
            Parsed::Tokens(t, k) => match lookup(&t[..k]) {
                Act::Text(s) => {
                    let _ = writeln!(o, "{}", s);
                    exit(ST_TEXT, o.n)
                }
                Act::Unsupported => {
                    let _ = writeln!(o, "ERROR: Operation not supported. (not in this build yet — ADR 0059 step 4b/4c)");
                    exit(ST_TEXT, o.n)
                }
                Act::Help => {
                    let role = rd32(H_ROLE) as u8;
                    for (_, what, h) in CMDS {
                        let need = match *what {
                            0 => 0,
                            20 => m::role_for(m::CFG_CONFIRM),
                            21 => m::role_for(m::CFG_ROLLBACK),
                            30 => m::role_for(m::OWNER_CHALLENGE),
                            _ => m::ROLE_VIEW,
                        };
                        if role >= need {
                            let _ = writeln!(o, "{}", h);
                        }
                    }
                    exit(ST_TEXT, o.n)
                }
                Act::Req(msg) => request(msg, t[0][0], 0, &[]),
                Act::ReqArg(msg, arg) => request(msg, t[0][0], arg, &[]),
            },
        },
        CMD_REPLY if n >= 4 => {
            let msg = u16::from_le_bytes([inb[0], inb[1]]);
            let res = inb[2];
            let cmd0 = inb[3];
            match res {
                m::R_OK => {}
                m::R_DENIED => {
                    let _ = writeln!(o, "ERROR: Permission denied.");
                    exit(ST_TEXT, o.n)
                }
                m::R_UNAVAILABLE => {
                    let _ = writeln!(o, "ERROR: Management service unavailable.");
                    exit(ST_TEXT, o.n)
                }
                _ => {
                    let _ = writeln!(o, "ERROR: Operation not supported.");
                    exit(ST_TEXT, o.n)
                }
            }
            let rec = &inb[4..n];
            if m::reply_len(msg) != Some(rec.len()) || !format(&mut o, msg, cmd0, rec) {
                o.n = 0;
                let _ = writeln!(o, "ERROR: Management service unavailable. (malformed reply)");
            }
            exit(ST_TEXT, o.n)
        }
        CMD_SELFTEST_FAULT => unsafe {
            core::ptr::write_volatile(0x8 as *mut u32, 1);
            exit(ST_TEXT, 0)
        },
        _ => exit(ST_BAD_CMD, 0),
    }
}
