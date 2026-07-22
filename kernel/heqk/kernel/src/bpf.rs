//! P6 — AI Runtime: a small RFC 9669 BPF virtual machine (interpreter).
//!
//! Runs standard BPF bytecode (a *subset* of the RFC 9669 ISA — enough for a
//! packet-filter threat rule) against a packet, returning a verdict. This
//! replaces the native stand-in that P5's Packet Engine used: the ring's verdict
//! IS this VM now. v1 is a signed-first-party interpreter with a runtime memory
//! bounds check (Layer-2 software sandbox); a JIT + a full verifier are the next
//! increments (see BPF_THREAT_PLANE.md). The moat: this same bytecode runs on
//! the Linux/FreeBSD/QNX HookProbe substrates too.

use core::ptr::read_volatile;

pub const PASS: u64 = 1;
pub const DROP: u64 = 2;
pub const INVALID: u64 = 0; // OOB / unknown op / step limit — caller fails safe

// BPF instruction encoding: u8 opcode | u4 dst | u4 src | i16 off | i32 imm.
const fn insn(op: u8, dst: u8, src: u8, off: i16, imm: i32) -> u64 {
    (op as u64)
        | ((dst as u64) << 8)
        | ((src as u64) << 12)
        | (((off as u16) as u64) << 16)
        | (((imm as u32) as u64) << 32)
}

// Opcodes used (RFC 9669 encoding):
//   0x71 LDX_B (dst = *(u8*)(src+off))   0x67 LSH64_K   0x4f OR64_X
//   0xb7 MOV64_K   0x55 JNE_K   0x95 EXIT
/// The signed first-party threat rule. R1 points at the **L4 (TCP/UDP) header**
/// (the parser in `net.rs` locates it); the dst port is the big-endian field at
/// L4 offset 2..4 (src port is 0..2). DROP if dst-port == 4444, else PASS.
pub const THREAT_RULE: [u64; 9] = [
    insn(0x71, 2, 1, 2, 0),    // R2 = *(u8*)(R1+2)   dst-port high byte
    insn(0x67, 2, 0, 0, 8),    // R2 <<= 8
    insn(0x71, 3, 1, 3, 0),    // R3 = *(u8*)(R1+3)   dst-port low byte
    insn(0x4f, 2, 3, 0, 0),    // R2 |= R3            (R2 = dst_port)
    insn(0x55, 2, 0, 2, 4444), // if R2 != 4444 goto +2
    insn(0xb7, 0, 0, 0, 2),    // R0 = DROP
    insn(0x95, 0, 0, 0, 0),    // EXIT
    insn(0xb7, 0, 0, 0, 1),    // R0 = PASS
    insn(0x95, 0, 0, 0, 0),    // EXIT
];

/// A dst-port DROP rule (same L4-header shape as THREAT_RULE) for `port`. Used to
/// build the P8 rule corpus — the mechanism that lets the SAME bytecode rules run
/// on the Linux/FreeBSD/QNX HookProbe substrates and here, unchanged.
pub const fn port_block_rule(port: i32) -> [u64; 9] {
    [
        insn(0x71, 2, 1, 2, 0),   // R2 = *(u8*)(R1+2)   dst-port high byte
        insn(0x67, 2, 0, 0, 8),   // R2 <<= 8
        insn(0x71, 3, 1, 3, 0),   // R3 = *(u8*)(R1+3)   dst-port low byte
        insn(0x4f, 2, 3, 0, 0),   // R2 |= R3            (R2 = dst_port)
        insn(0x55, 2, 0, 2, port), // if R2 != port goto +2
        insn(0xb7, 0, 0, 0, 2),   // R0 = DROP
        insn(0x95, 0, 0, 0, 0),   // EXIT
        insn(0xb7, 0, 0, 0, 1),   // R0 = PASS
        insn(0x95, 0, 0, 0, 0),   // EXIT
    ]
}
/// P8 corpus (beyond the signed 4444 rule): telnet + a common backdoor port.
pub const BLOCK_TELNET: [u64; 9] = port_block_rule(23);
pub const BLOCK_BACKDOOR: [u64; 9] = port_block_rule(31337);

// --- L2 tier: parity with HookProbe `napse-l2guard` (Ring-0 malformed-frame /
// malformed-ARP / ARP-spoof drop). These rules take R1 = the L2 FRAME start and
// mirror `dpi::ArpObs::is_malformed` / `eth_mismatch` field-for-field. Values are
// little-endian (HEQK's LDX_H/W assemble bytes LE); wire fields are big-endian,
// so 16-bit constants are byte-swapped (ARP EtherType 0x0806 -> 0x0608, etc.).

/// Malformed-ARP drop — mirrors `ArpObs::is_malformed`: a frame that IS ARP but
/// whose fixed header isn't the standard Ethernet/IPv4 shape (htype=1, ptype=
/// 0x0800, hlen=6, plen=4) or isn't a complete 42-byte packet → DROP. Non-ARP →
/// PASS. Ethernet@0, EtherType@12; ARP header@14 (htype,ptype,hlen,plen); the
/// LDX_W@38 forces the verifier's min_len to 42 (the "complete body" check).
pub const ARP_MALFORMED: [u64; 16] = [
    insn(0x69, 2, 1, 12, 0),      // 0  R2 = *(u16*)(R1+12)  EtherType
    insn(0xb7, 0, 0, 0, 1),       // 1  R0 = PASS
    insn(0x55, 2, 0, 10, 0x0608), // 2  if R2 != ARP goto 13 (PASS EXIT)
    insn(0x61, 6, 1, 38, 0),      // 3  R6 = *(u32*)(R1+38)  target_ip -> min_len=42
    insn(0x69, 3, 1, 14, 0),      // 4  R3 = *(u16*)(R1+14)  htype
    insn(0x55, 3, 0, 8, 0x0100),  // 5  if htype != 1 goto 14 (DROP)
    insn(0x69, 4, 1, 16, 0),      // 6  R4 = *(u16*)(R1+16)  ptype
    insn(0x55, 4, 0, 6, 0x0008),  // 7  if ptype != 0x0800 goto 14
    insn(0x71, 5, 1, 18, 0),      // 8  R5 = *(u8*)(R1+18)   hlen
    insn(0x55, 5, 0, 4, 6),       // 9  if hlen != 6 goto 14
    insn(0x71, 7, 1, 19, 0),      // 10 R7 = *(u8*)(R1+19)   plen
    insn(0x55, 7, 0, 2, 4),       // 11 if plen != 4 goto 14
    insn(0xb7, 0, 0, 0, 1),       // 12 R0 = PASS (well-formed ARP)
    insn(0x95, 0, 0, 0, 0),       // 13 EXIT (PASS)
    insn(0xb7, 0, 0, 0, 2),       // 14 R0 = DROP
    insn(0x95, 0, 0, 0, 0),       // 15 EXIT (DROP)
];

// --- TCP scan tier: stateless anomalous-flag detection (Nmap/Suricata-style).
// R1 = the TCP header; the flags byte is at TCP offset 13 (FIN=0x01 SYN=0x02
// RST=0x04 PSH=0x08 ACK=0x10 URG=0x20). These run ONLY on TCP (classify gates on
// ip_proto). A normal SYN(0x02)/ACK(0x10)/PSH-ACK(0x18) never matches, so there
// are no false positives on legitimate traffic.

/// Build a "DROP iff flags == `flags`" TCP rule (R1 = TCP header, flags @13).
pub const fn tcp_flag_eq_rule(flags: i32) -> [u64; 5] {
    [
        insn(0x71, 2, 1, 13, 0),     // R2 = *(u8*)(R1+13)  TCP flags
        insn(0xb7, 0, 0, 0, 1),      // R0 = PASS
        insn(0x55, 2, 0, 1, flags),  // if flags != `flags` goto EXIT (PASS)
        insn(0xb7, 0, 0, 0, 2),      // R0 = DROP
        insn(0x95, 0, 0, 0, 0),      // EXIT
    ]
}
/// NULL scan — no flags set (illegal). Nmap `-sN`.
pub const TCP_NULL_SCAN: [u64; 5] = tcp_flag_eq_rule(0x00);
/// FIN scan — lone FIN with no connection. Nmap `-sF`.
pub const TCP_FIN_SCAN: [u64; 5] = tcp_flag_eq_rule(0x01);
/// Xmas scan — FIN|PSH|URG lit up "like a Christmas tree". Nmap `-sX`.
pub const TCP_XMAS_SCAN: [u64; 5] = tcp_flag_eq_rule(0x29);
/// SYN+FIN — an illegal combination (open+close at once); scanner/IDS-evasion.
/// DROP iff BOTH the SYN(0x02) and FIN(0x01) bits are set: (flags & 0x03) == 0x03.
pub const TCP_SYNFIN: [u64; 6] = [
    insn(0x71, 2, 1, 13, 0),     // R2 = TCP flags
    insn(0x57, 2, 0, 0, 0x03),   // R2 &= (SYN|FIN)
    insn(0xb7, 0, 0, 0, 1),      // R0 = PASS
    insn(0x55, 2, 0, 1, 0x03),   // if (flags & 3) != 3 goto EXIT (PASS)
    insn(0xb7, 0, 0, 0, 2),      // R0 = DROP
    insn(0x95, 0, 0, 0, 0),      // EXIT
];

/// SYN-flood rate-limit threshold (lone SYNs per ~1 s window). Tunable per policy.
pub const SYN_LIMIT: i32 = 32;

/// SYN-flood — the first STATEFUL rule (uses the `CALL` helper + the kernel rate
/// limiter). A lone SYN (`flags==0x02`) bumps a windowed counter; once the rate
/// exceeds `SYN_LIMIT` in the window it DROPs, otherwise PASS. Non-SYN → PASS.
/// R1 = TCP header. NB (v1): the key is a global bucket, so this proves the
/// stateful primitive but is NOT wired into the live datapath — per-source keying
/// (needs the IP src, i.e. run on the full frame) is the follow-up before it can
/// enforce inline without false-positiving legitimate connection setups.
pub const TCP_SYN_FLOOD: [u64; 10] = [
    insn(0x71, 2, 1, 13, 0),         // 0  R2 = TCP flags
    insn(0x55, 2, 0, 6, 0x02),       // 1  if flags != SYN goto 8 (PASS)
    insn(0xb7, 1, 0, 0, 0),          // 2  R1 = 0        (rate key: global bucket v1)
    insn(0xb7, 2, 0, 0, SYN_LIMIT),  // 3  R2 = SYN_LIMIT
    insn(0x85, 0, 0, 0, 1),          // 4  R0 = call helper#1 syn_rate_over(R1,R2)
    insn(0x15, 0, 0, 2, 0),          // 5  if R0 == 0 goto 8 (under limit -> PASS)
    insn(0xb7, 0, 0, 0, 2),          // 6  R0 = DROP
    insn(0x95, 0, 0, 0, 0),          // 7  EXIT (DROP)
    insn(0xb7, 0, 0, 0, 1),          // 8  R0 = PASS  (not-SYN or under-limit)
    insn(0x95, 0, 0, 0, 0),          // 9  EXIT (PASS)
];

/// ARP-spoof drop — mirrors `ArpObs::eth_mismatch`: an ARP frame whose payload
/// sender-MAC (@22, 6 bytes) disagrees with the Ethernet source-MAC (@6) → DROP
/// (a spoofed sender). Non-ARP → PASS. Compared as 4 bytes (LDX_W) + 2 bytes
/// (LDX_H); byte order is irrelevant since both sides use the same widths.
pub const ARP_SPOOF: [u64; 13] = [
    insn(0x69, 2, 1, 12, 0),      // 0  R2 = EtherType
    insn(0xb7, 0, 0, 0, 1),       // 1  R0 = PASS
    insn(0x55, 2, 0, 7, 0x0608),  // 2  if not ARP goto 10 (PASS EXIT)
    insn(0x61, 3, 1, 6, 0),       // 3  R3 = *(u32*)(R1+6)   eth src_mac[0..4]
    insn(0x61, 4, 1, 22, 0),      // 4  R4 = *(u32*)(R1+22)  arp sender_mac[0..4]
    insn(0x5d, 3, 4, 5, 0),       // 5  if R3 != R4 goto 11 (DROP)
    insn(0x69, 5, 1, 10, 0),      // 6  R5 = *(u16*)(R1+10)  eth src_mac[4..6]
    insn(0x69, 6, 1, 26, 0),      // 7  R6 = *(u16*)(R1+26)  arp sender_mac[4..6]
    insn(0x5d, 5, 6, 2, 0),       // 8  if R5 != R6 goto 11 (DROP)
    insn(0xb7, 0, 0, 0, 1),       // 9  R0 = PASS (MACs agree)
    insn(0x95, 0, 0, 0, 0),       // 10 EXIT (PASS)
    insn(0xb7, 0, 0, 0, 2),       // 11 R0 = DROP
    insn(0x95, 0, 0, 0, 0),       // 12 EXIT (DROP)
];

// --- P8 verifier test vectors: adversarial "third-party" rules ---------------
/// UNSAFE: loads from an arbitrary (scalar) address, not the packet. A runtime
/// bounds check might catch some of these; the STATIC verifier rejects it flat.
pub const EVIL_WILD_LOAD: [u64; 3] = [
    insn(0xb7, 2, 0, 0, 0x41414141), // R2 = 0x41414141 (a scalar)
    insn(0x71, 3, 2, 0, 0),          // R3 = *(u8*)(R2+0)  — load from arbitrary addr
    insn(0x95, 0, 0, 0, 0),          // EXIT
];
/// UNSAFE: a backward jump — a loop that could run forever.
pub const EVIL_LOOP: [u64; 3] = [
    insn(0xb7, 0, 0, 0, 1),  // R0 = 1
    insn(0x55, 0, 0, -1, 5), // if R0 != 5 goto -1  (BACKWARD)
    insn(0x95, 0, 0, 0, 0),  // EXIT
];
/// UNSAFE: EXITs without ever setting R0 — returns an uninitialized verdict.
pub const EVIL_NO_VERDICT: [u64; 2] = [
    insn(0x71, 2, 1, 0, 0), // R2 = *(u8*)(R1+0)
    insn(0x95, 0, 0, 0, 0), // EXIT — R0 never written
];

/// A realistic rule exercising the EXPANDED ISA: walk to the Ethernet EtherType
/// via pointer arithmetic (MOV_X + ADD_K), read it with a 16-bit load (LDX_H),
/// read the first 4 bytes with a 32-bit load (LDX_W), and DROP IPv4 frames
/// (EtherType 0x0800 → little-endian 0x0008) via JEQ. The verifier proves it
/// needs min_len = 14 (offset 12 + 2-byte load). R1 = packet start (L2).
pub const PARSE_RULE: [u64; 9] = [
    insn(0xbf, 2, 1, 0, 0),      // R2 = R1               (MOV64_X)
    insn(0x07, 2, 0, 0, 12),     // R2 += 12              (-> EtherType)
    insn(0x69, 3, 2, 0, 0),      // R3 = *(u16*)(R2+0)    EtherType (LE)
    insn(0x61, 4, 1, 0, 0),      // R4 = *(u32*)(R1+0)    first 4 bytes
    insn(0xb7, 0, 0, 0, 1),      // R0 = PASS
    insn(0x15, 3, 0, 1, 0x0008), // if R3 == 0x0008 (IPv4) goto +1
    insn(0x95, 0, 0, 0, 0),      // EXIT (non-IPv4 -> PASS)
    insn(0xb7, 0, 0, 0, 2),      // R0 = DROP
    insn(0x95, 0, 0, 0, 0),      // EXIT
];

/// Static verifier — gate a program before it runs (v1: signed first-party, so
/// this is a safety net; a full PREVAIL-style abstract-interpretation verifier
/// is for opening the plane to third-party rules). Checks: known opcodes, valid
/// registers, **no backward jumps** (termination — no loops), forward jump
/// targets in range, and a reachable EXIT. Returns true if the program is safe.
pub fn verify(prog: &[u64]) -> bool {
    if prog.is_empty() {
        return false;
    }
    let mut has_exit = false;
    for (i, &ins) in prog.iter().enumerate() {
        let op = (ins & 0xff) as u8;
        let dst = ((ins >> 8) & 0xf) as usize;
        let src = ((ins >> 12) & 0xf) as usize;
        let off = ((ins >> 16) & 0xffff) as u16 as i16;
        if dst >= 11 || src >= 11 {
            return false; // register out of range
        }
        match op {
            0x71 | 0x67 | 0x4f | 0xb7 => {} // LDX_B / LSH64 / OR64 / MOV64 — ok
            0x55 => {
                // JNE: forward-only (no loops), target within [0, len].
                if off < 0 {
                    return false;
                }
                let target = i as i64 + 1 + off as i64;
                if target < 0 || target as usize >= prog.len() {
                    return false; // must land on a real instruction
                }
            }
            0x95 => has_exit = true, // EXIT
            _ => return false,       // unknown opcode
        }
    }
    has_exit
}

// ---------------------------------------------------------------------------
// P8 — PREVAIL-style abstract-interpretation verifier for THIRD-PARTY rules.
//
// The v1 `verify` above is a structural safety net that trusts the runtime
// bounds check. To open the plane to UNTRUSTED third-party rules we must PROVE,
// statically, before a single instruction runs, that the rule is memory-safe.
// This verifier abstract-interprets the program: each register is tracked as
// Uninit / Scalar / Pkt{offset-interval}. It proves:
//   * every load is PACKET-RELATIVE (base is a Pkt pointer) — a load from an
//     arbitrary/scalar address is REJECTED (the key third-party guarantee),
//   * no UNINITIALIZED register is ever read,
//   * control flow is a forward DAG (terminates), no unreachable code.
// It returns `Ok(min_len)`: the minimum packet length for which every load is
// in-bounds. The packet engine runs the rule only when `len >= min_len`, so
// memory safety is a STATIC property — the runtime check becomes defense-in-depth.
// ---------------------------------------------------------------------------

use alloc::vec;
use alloc::vec::Vec;

#[derive(Clone, Copy, PartialEq)]
enum Abs {
    Uninit,
    Scalar { lo: i64, hi: i64 }, // value interval — NOT a valid load base
    Pkt { lo: i64, hi: i64 },    // packet base + byte offset in [lo, hi]
}
/// A scalar of fully-unknown value (loads from it rejected; adding it to a
/// pointer makes the pointer offset unbounded ⇒ its loads rejected too).
const S_TOP: Abs = Abs::Scalar { lo: i64::MIN, hi: i64::MAX };
#[inline]
fn sat_add(a: i64, b: i64) -> i64 {
    a.saturating_add(b)
}

fn join(a: Abs, b: Abs) -> Abs {
    match (a, b) {
        (Abs::Uninit, Abs::Uninit) => Abs::Uninit,
        // Init on one path, uninit on another ⇒ treat as uninit (reading is unsafe).
        (Abs::Uninit, _) | (_, Abs::Uninit) => Abs::Uninit,
        (Abs::Pkt { lo: l1, hi: h1 }, Abs::Pkt { lo: l2, hi: h2 }) => {
            Abs::Pkt { lo: l1.min(l2), hi: h1.max(h2) }
        }
        (Abs::Scalar { lo: l1, hi: h1 }, Abs::Scalar { lo: l2, hi: h2 }) => {
            Abs::Scalar { lo: l1.min(l2), hi: h1.max(h2) }
        }
        // Any mix of Pkt/Scalar loses pointer-ness ⇒ unknown scalar.
        _ => S_TOP,
    }
}

/// Merge `src` state into `in_st[pc]`, marking progress. Returns Err on a
/// register-count issue (shouldn't happen — guarded earlier).
fn merge_into(slot: &mut Option<[Abs; 11]>, src: &[Abs; 11]) {
    match slot {
        None => *slot = Some(*src),
        Some(cur) => {
            for i in 0..11 {
                cur[i] = join(cur[i], src[i]);
            }
        }
    }
}

pub fn verify_prevail(prog: &[u64]) -> Result<u64, &'static str> {
    let n = prog.len();
    if n == 0 {
        return Err("empty program");
    }
    // Entry state: R1 = packet pointer at offset 0; everything else uninitialized.
    let mut entry = [Abs::Uninit; 11];
    entry[1] = Abs::Pkt { lo: 0, hi: 0 };
    let mut in_st: Vec<Option<[Abs; 11]>> = vec![None; n];
    in_st[0] = Some(entry);

    let mut min_len: u64 = 0;
    let mut has_exit = false;

    for pc in 0..n {
        let st = match in_st[pc] {
            Some(s) => s,
            None => return Err("unreachable code"), // dead code ⇒ reject (PREVAIL policy)
        };
        let ins = prog[pc];
        let op = (ins & 0xff) as u8;
        let dst = ((ins >> 8) & 0xf) as usize;
        let src = ((ins >> 12) & 0xf) as usize;
        let off = ((ins >> 16) & 0xffff) as u16 as i16;
        if dst >= 11 || src >= 11 {
            return Err("register out of range");
        }
        let imm = ((ins >> 32) & 0xffff_ffff) as u32 as i32 as i64;
        let mut out = st;

        match op {
            // LDX_B/H/W dst = *(uW*)(src+off): src MUST be a packet pointer; the
            // accessed range [off, off+W) must be non-negative + statically bounded.
            0x71 | 0x69 | 0x61 => {
                let w: i64 = match op {
                    0x71 => 1,
                    0x69 => 2,
                    _ => 4,
                };
                match st[src] {
                    Abs::Pkt { lo, hi } => {
                        if sat_add(lo, off as i64) < 0 {
                            return Err("load below packet start");
                        }
                        let need_i = sat_add(sat_add(hi, off as i64), w);
                        if need_i < 0 || need_i > 65536 {
                            return Err("load offset unbounded / exceeds max packet");
                        }
                        if need_i as u64 > min_len {
                            min_len = need_i as u64;
                        }
                        let maxv = if w >= 8 { i64::MAX } else { (1i64 << (8 * w)) - 1 };
                        out[dst] = Abs::Scalar { lo: 0, hi: maxv };
                    }
                    Abs::Uninit => return Err("load base uninitialized"),
                    Abs::Scalar { .. } => return Err("load from non-packet (scalar) address"),
                }
            }
            0xb7 => out[dst] = Abs::Scalar { lo: imm, hi: imm }, // MOV64_K
            0xbf => {
                // MOV64_X: reg copy — propagates the abstract value (incl. Pkt-ness).
                if st[src] == Abs::Uninit {
                    return Err("MOV from uninitialized register");
                }
                out[dst] = st[src];
            }
            0x07 => {
                // ADD64_K: pointer OR scalar arithmetic with a constant.
                out[dst] = match st[dst] {
                    Abs::Pkt { lo, hi } => Abs::Pkt { lo: sat_add(lo, imm), hi: sat_add(hi, imm) },
                    Abs::Scalar { lo, hi } => {
                        Abs::Scalar { lo: sat_add(lo, imm), hi: sat_add(hi, imm) }
                    }
                    Abs::Uninit => return Err("ADD to uninitialized register"),
                };
            }
            0x0f => {
                // ADD64_X: pointer+scalar (widen the offset by the scalar interval).
                out[dst] = match (st[dst], st[src]) {
                    (Abs::Uninit, _) | (_, Abs::Uninit) => {
                        return Err("ADD of uninitialized register")
                    }
                    (Abs::Pkt { lo, hi }, Abs::Scalar { lo: a, hi: b }) => {
                        Abs::Pkt { lo: sat_add(lo, a), hi: sat_add(hi, b) }
                    }
                    (Abs::Scalar { lo, hi }, Abs::Scalar { lo: a, hi: b }) => {
                        Abs::Scalar { lo: sat_add(lo, a), hi: sat_add(hi, b) }
                    }
                    _ => return Err("ADD yields a non-scalar (pointer+pointer?)"),
                };
            }
            0x57 => {
                // AND64_K masking: x & m (m>=0) ∈ [0, m].
                if st[dst] == Abs::Uninit {
                    return Err("AND of uninitialized register");
                }
                out[dst] = if imm >= 0 {
                    Abs::Scalar { lo: 0, hi: imm }
                } else {
                    S_TOP
                };
            }
            0x67 => {
                if st[dst] == Abs::Uninit {
                    return Err("LSH of uninitialized register");
                }
                out[dst] = S_TOP;
            }
            0x4f => {
                if st[dst] == Abs::Uninit || st[src] == Abs::Uninit {
                    return Err("OR of uninitialized register");
                }
                out[dst] = S_TOP;
            }
            // Conditional jumps (forward-only, no loops): JEQ/JGT/JGE/JSET/JNE, K + X.
            0x15 | 0x25 | 0x35 | 0x45 | 0x55 | 0x1d | 0x2d | 0x3d | 0x4d | 0x5d => {
                if st[dst] == Abs::Uninit {
                    return Err("jump on uninitialized register");
                }
                if op & 0x08 != 0 && st[src] == Abs::Uninit {
                    return Err("jump on uninitialized src register");
                }
                if off < 0 {
                    return Err("backward jump (would not terminate)");
                }
                let target = pc as i64 + 1 + off as i64;
                if target < 0 || target as usize >= n {
                    return Err("jump target out of range");
                }
                merge_into(&mut in_st[target as usize], &out);
            }
            0x85 => {
                // CALL helper: R0 = helper(imm)(R1, R2). The helper id must be a
                // known, signed helper; args R1/R2 must be initialized; R0 becomes
                // a scalar result and R1..R5 are clobbered (caller-saved ABI).
                if (imm as u32) == 0 || (imm as u32) > crate::ratelimit::MAX_HELPER_ID {
                    return Err("CALL to unknown helper id");
                }
                if st[1] == Abs::Uninit || st[2] == Abs::Uninit {
                    return Err("CALL with uninitialized argument register");
                }
                out[0] = Abs::Scalar { lo: 0, hi: 1 };
                for k in 1..=5 {
                    out[k] = Abs::Uninit; // args clobbered by the call
                }
            }
            0x95 => {
                // EXIT: returns R0 — it must be initialized (a real verdict).
                if st[0] == Abs::Uninit {
                    return Err("EXIT with uninitialized R0 (no verdict)");
                }
                has_exit = true;
                continue; // no fall-through successor
            }
            _ => return Err("unknown opcode"),
        }

        // Fall-through to pc+1 (all ops except EXIT).
        if pc + 1 < n {
            merge_into(&mut in_st[pc + 1], &out);
        }
    }

    if !has_exit {
        return Err("no reachable EXIT");
    }
    Ok(min_len)
}

/// Execute `prog` against the packet `[pkt, pkt+len)`. R1 = packet pointer.
/// Returns the verdict in R0, or INVALID on any safety violation.
pub fn run(prog: &[u64], pkt: *const u8, len: usize) -> u64 {
    let mut r = [0u64; 11];
    r[1] = pkt as u64;
    let pbase = pkt as u64;
    // Saturating: an absurd `len` must not wrap `pend` below `pbase` and defeat
    // the LDX_B bounds check. (Packet path caps len at u16 today; defensive.)
    let pend = pbase.saturating_add(len as u64);
    let mut pc: usize = 0;
    let mut steps: u32 = 0;

    while pc < prog.len() {
        steps += 1;
        if steps > 10_000 {
            return INVALID; // termination bound — no infinite loops
        }
        let ins = prog[pc];
        let op = (ins & 0xff) as u8;
        let dst = ((ins >> 8) & 0xf) as usize;
        let src = ((ins >> 12) & 0xf) as usize;
        let off = ((ins >> 16) & 0xffff) as u16 as i16;
        let imm = ((ins >> 32) & 0xffff_ffff) as u32 as i32;
        if dst >= 11 || src >= 11 {
            return INVALID; // register out of range
        }

        match op {
            // LDX_B/H/W: dst = *(uW*)(src+off), runtime bounds check + byte-assembled
            // (little-endian, native — avoids misaligned-read UB on odd offsets).
            0x71 | 0x69 | 0x61 => {
                let w = match op {
                    0x71 => 1u64,
                    0x69 => 2,
                    _ => 4,
                };
                let addr = r[src].wrapping_add(off as i64 as u64);
                let end = addr.wrapping_add(w);
                if addr < pbase || end > pend || end < addr {
                    return INVALID; // OOB / wrap — the software sandbox
                }
                let mut v = 0u64;
                for k in 0..w {
                    v |= (unsafe { read_volatile((addr + k) as *const u8) } as u64) << (8 * k);
                }
                r[dst] = v;
            }
            0xbf => r[dst] = r[src],                                 // MOV64_X
            0x07 => r[dst] = r[dst].wrapping_add(imm as i64 as u64), // ADD64_K
            0x0f => r[dst] = r[dst].wrapping_add(r[src]),            // ADD64_X
            0x57 => r[dst] &= imm as i64 as u64,                     // AND64_K
            0x67 => r[dst] = r[dst].wrapping_shl((imm as u32) & 63), // LSH64_K
            0x4f => r[dst] |= r[src],                                // OR64_X
            0xb7 => r[dst] = imm as i64 as u64,                      // MOV64_K
            // Conditional jumps (branch relative to next instruction): K + X.
            0x15 | 0x1d | 0x25 | 0x2d | 0x35 | 0x3d | 0x45 | 0x4d | 0x55 | 0x5d => {
                let a = r[dst];
                let b = if op & 0x08 != 0 { r[src] } else { imm as i64 as u64 };
                let take = match op & 0xf0 {
                    0x10 => a == b, // JEQ
                    0x20 => a > b,  // JGT (unsigned)
                    0x30 => a >= b, // JGE (unsigned)
                    0x40 => (a & b) != 0, // JSET
                    _ => a != b,    // JNE (0x50)
                };
                if take {
                    pc = (pc as i64 + off as i64) as usize;
                }
            }
            0x85 => {
                // CALL helper: R0 = helper(imm)(R1, R2). (Args clobbered per ABI;
                // the verifier forbids reading them after, so we needn't scrub.)
                r[0] = crate::ratelimit::call_helper(imm as u32, r[1], r[2]);
            }
            0x95 => return r[0], // EXIT
            _ => return INVALID, // unknown opcode
        }
        pc = pc.wrapping_add(1);
    }
    INVALID
}
