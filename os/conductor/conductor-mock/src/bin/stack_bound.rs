// SPDX-License-Identifier: AGPL-3.0-only
//! Static worst-case stack bound for an aarch64 EL0 server, from a disassembly listing
//! (`llvm-objdump -d --no-show-raw-insn ELF > x.dis`; `stack-bound x.dis`).
//! Frame sizes come from the prologues, call edges from `bl`/`b`, the bound is the deepest path from
//! `_start`. Valid only when the binary has no indirect calls and no register-based sp adjustment; both
//! are counted and reported, and a non-zero count makes the tool exit with an error. Jump tables from
//! `match` (adr + ldrsw + br) stay inside their function, so they are counted separately and allowed.
use std::collections::{HashMap, HashSet};

fn num(s: &str) -> Option<u64> {
    match s.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

fn depth(f: &str, frame: &HashMap<String, u64>, calls: &HashMap<String, HashSet<String>>, memo: &mut HashMap<String, u64>, path: &mut Vec<String>) -> u64 {
    if let Some(v) = memo.get(f) {
        return *v;
    }
    if path.iter().any(|p| p == f) {
        eprintln!("recursion through {f}: no static bound");
        std::process::exit(2);
    }
    path.push(f.to_string());
    let below = calls.get(f).map_or(0, |cs| cs.iter().filter(|c| *c != f).map(|c| depth(c, frame, calls, memo, path)).max().unwrap_or(0));
    path.pop();
    let v = frame.get(f).copied().unwrap_or(0) + below;
    memo.insert(f.to_string(), v);
    v
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: stack-bound LISTING.dis");
    let text = std::fs::read_to_string(&path).expect("read listing");
    let (mut frame, mut calls) = (HashMap::<String, u64>::new(), HashMap::<String, HashSet<String>>::new());
    let (mut cur, mut indirect, mut sp_reg, mut fp_simd) = (None::<String>, 0u32, 0u32, 0u32);
    // A compiled `match`: `adr base; ldrsw off, [table, idx, lsl #2]; add; br` stays inside its function.
    let (mut jump_tables, mut recent) = (0u32, std::collections::VecDeque::<String>::new());
    for line in text.lines() {
        if let (Some(a), true) = (line.find(" <"), line.ends_with(">:")) {
            if !line.starts_with(' ') {
                let name = line[a + 2..line.len() - 2].to_string();
                frame.insert(name.clone(), 0);
                calls.insert(name.clone(), HashSet::new());
                cur = Some(name);
                recent.clear();
                continue;
            }
        }
        let Some(f) = &cur else { continue };
        let ins = line.split_once(':').map_or("", |x| x.1).trim();
        let (op, args) = ins.split_once(char::is_whitespace).map_or((ins, ""), |(o, a)| (o, a.trim()));
        // Pre-indexed pushes: `[sp, #-N]!`
        if let Some(i) = args.find("[sp, #-") {
            if let Some(n) = args[i + 7..].split(']').next().and_then(num) {
                if args[i..].contains("]!") {
                    *frame.get_mut(f).unwrap() += n;
                }
            }
        }
        if op == "sub" && args.starts_with("sp, sp, ") {
            let rest = &args[8..];
            if let Some(imm) = rest.strip_prefix('#') {
                let (v, shift) = imm.split_once(", lsl #12").map_or((imm, false), |(v, _)| (v, true));
                if let Some(n) = num(v.trim()) {
                    *frame.get_mut(f).unwrap() += if shift { n << 12 } else { n };
                }
            } else {
                sp_reg += 1;
            }
        }
        if (op == "mov" || op == "add") && args.starts_with("sp, ") && !args.contains('#') && !args.starts_with("sp, sp, #") && op == "mov" {
            sp_reg += 1;
        }
        if op == "bl" || op == "b" {
            if let (Some(a), Some(b)) = (args.find('<'), args.rfind('>')) {
                let target = args[a + 1..b].split('+').next().unwrap_or("").to_string();
                if !target.is_empty() {
                    calls.get_mut(f).unwrap().insert(target);
                }
            }
        }
        if op == "blr" {
            indirect += 1;
        } else if op == "br" {
            if recent.iter().any(|o| o == "adr") && recent.iter().any(|o| o == "ldrsw") {
                jump_tables += 1;
            } else {
                indirect += 1;
            }
        }
        recent.push_back(op.to_string());
        if recent.len() > 6 {
            recent.pop_front();
        }
        let simd_reg = args.split(|c: char| !c.is_ascii_alphanumeric()).any(|t| t.len() >= 2 && (t.starts_with('q') || t.starts_with('v') || t.starts_with('d')) && t[1..].chars().all(|c| c.is_ascii_digit()));
        if matches!(op, "fmov" | "fadd" | "fmul" | "fdiv" | "scvtf" | "ucvtf" | "ld1" | "st1" | "movi" | "dup") || (matches!(op, "ldr" | "str" | "ldp" | "stp") && simd_reg) {
            fp_simd += 1;
        }
    }
    if !frame.contains_key("_start") {
        eprintln!("no _start in the listing: nothing was measured");
        std::process::exit(3);
    }
    let mut memo = HashMap::new();
    let bound = depth("_start", &frame, &calls, &mut memo, &mut Vec::new());
    println!("functions: {}", frame.len());
    println!("indirect calls or jumps: {indirect}");
    println!("jump tables (intra-function match): {jump_tables}");
    println!("register-based sp adjustments: {sp_reg}");
    println!("FP/SIMD instructions: {fp_simd}");
    println!("max stack from _start (bytes): {bound}");
    if indirect != 0 || sp_reg != 0 {
        eprintln!("the bound is NOT valid: indirect control flow or dynamic stack present");
        std::process::exit(1);
    }
}
