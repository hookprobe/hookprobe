// SPDX-License-Identifier: AGPL-3.0-only
//! Guard G and the grounding checks against Neuro's own functions.
//! - Drift gate: `src/attack_ids.rs` equals what `docs/research/neuro/data/attack-ids.json` says (every id, every
//!   revoked/deprecated flag). `ATTACK_IDS_REGEN=1` rewrites the table from the JSON.
//! - Vectors: `tests/data/grounding_vectors.rs` holds Neuro's outputs (`guard_ground.apply`,
//!   `grounding.technique_check`, `grounding.service_check`) on hand-written edge cases and 1,500 random ones.
//!   How they were made is in `tests/data/GROUNDING_VECTORS.md`; nothing here runs Python.
use neuro_contract::attack_ids::ATTACK_IDS;
use neuro_contract::grounding::*;

#[path = "data/grounding_vectors.rs"]
mod vectors;

fn root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// (id, stale) from the JSON, one field per line as Neuro writes it.
fn json_ids() -> (Vec<(String, bool)>, String, String) {
    let p = root().join("docs/research/neuro/data/attack-ids.json");
    let s = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()));
    let field = |k: &str| s.lines().find(|l| l.starts_with(&format!("\"{k}\": "))).map(|l| l.split('"').nth(3).unwrap().to_string()).unwrap();
    let mut out = vec![];
    let mut lines = s.lines().skip_while(|l| !l.starts_with("\"ids\": {")).skip(1);
    while let Some(l) = lines.next() {
        let Some(id) = l.strip_prefix('"').and_then(|r| r.strip_suffix("\": {")) else { continue };
        let (mut rev, mut dep) = (None, None);
        for l in lines.by_ref() {
            if let Some(v) = l.strip_prefix("\"revoked\": ") {
                rev = Some(v.trim_end_matches(',') == "true");
            }
            if let Some(v) = l.strip_prefix("\"deprecated\": ") {
                dep = Some(v.trim_end_matches(',') == "true");
            }
            if l.starts_with('}') {
                break;
            }
        }
        out.push((id.to_string(), rev.expect("revoked") || dep.expect("deprecated")));
    }
    (out, field("version"), field("source_sha256"))
}

fn key(id: &str) -> u32 {
    let b = &id.as_bytes()[1..];
    assert!(b.len() == 4 || (b.len() == 8 && b[4] == b'.'), "attack-ids.json has an id of a new shape: {id}; update grounding::attack_id");
    let base: u32 = id[1..5].parse().unwrap();
    let sub: u32 = if b.len() == 8 { id[6..9].parse().unwrap() } else { 0 };
    assert!(b.len() == 4 || sub != 0);
    base * 1000 + sub
}

#[test]
fn attack_id_table_equals_neuros_json() {
    let (ids, version, sha) = json_ids();
    assert!(ids.len() > 800, "parsed only {} ids", ids.len());
    let mut want: Vec<u32> = ids.iter().map(|(id, st)| key(id) | (u32::from(*st) << 31)).collect();
    want.sort_by_key(|v| v & 0x7fff_ffff);
    if std::env::var("ATTACK_IDS_REGEN").is_ok() {
        let mut s = format!("// SPDX-License-Identifier: AGPL-3.0-only\n// GENERATED from docs/research/neuro/data/attack-ids.json (ATT&CK {version}, source sha256 {sha}).\n// Do not edit: tests/grounding.rs re-derives this table from the JSON and fails on any difference;\n// run it with ATTACK_IDS_REGEN=1 to rewrite this file.\n// ATT&CK(R) (C) The MITRE Corporation. Reproduced with permission; ATT&CK is a registered trademark of The MITRE Corporation.\n\n/// `T<base>[.<sub>]` as `base * 1000 + sub` (sub 0 = no sub-technique), with bit 31 set when the id is revoked or\n/// deprecated. Sorted by key.\npub static ATTACK_IDS: [u32; {}] = [\n", want.len());
        for c in want.chunks(9) {
            s += "   ";
            for v in c {
                s += &format!(" 0x{v:08x},");
            }
            s += "\n";
        }
        s += "];\n";
        std::fs::write(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/attack_ids.rs"), s).unwrap();
        return;
    }
    assert_eq!(ATTACK_IDS.to_vec(), want, "src/attack_ids.rs differs from attack-ids.json: rerun with ATTACK_IDS_REGEN=1");
    let src = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/attack_ids.rs")).unwrap();
    assert!(src.contains(&format!("ATT&CK {version}, source sha256 {sha}")), "the table's header must name the JSON's version and source");
    // Lookups by string agree with the JSON, including near misses.
    for (id, st) in &ids {
        assert_eq!(attack_id(id.as_bytes()), Some(*st), "{id}");
    }
    for bad in ["T1059.000", "T1059.01", "T01059", "T105", "T1059.0010", "t1059", "T9999", "T1059.999"] {
        assert_eq!(attack_id(bad.as_bytes()), None, "{bad}");
    }
    println!("attack-ids drift gate: {} ids (ATT&CK {version}) equal Neuro's JSON", ids.len());
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn guard_g_and_checks_equal_neuros_python() {
    let (mut n, mut edited, mut survivors) = (0, 0, 0);
    for line in vectors::VECTORS.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        let (t, c, g) = (unhex(f[0]), unhex(f[1]), unhex(f[2]));
        let num = |i: usize| f[i].parse::<usize>().unwrap();
        let (rem, unk, stale, cve, svc, unk_after) = (num(3), num(4), num(5), num(6), num(7), num(8));
        let show = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        let mut buf = t.clone();
        let r = guard_g(&mut buf, t.len(), &[&c]);
        assert!(!r.overflow);
        assert_eq!(show(&buf[..r.len]), show(&g), "guard G on {:?} (context {:?})", show(&t), show(&c));
        assert_eq!(r.removed, rem, "removed count on {:?}", show(&t));
        let tc = technique_check(&t);
        assert_eq!(tc.unknown > 0, unk > 0, "unknown ids in {:?}", show(&t));
        assert_eq!(tc.stale > 0, stale > 0, "stale ids in {:?}", show(&t));
        assert_eq!(ungrounded_cves(&t, &[&c]) > 0, cve > 0, "ungrounded CVEs in {:?}", show(&t));
        assert_eq!(services_without_port(&t, &[&c]), svc, "services in {:?} vs {:?}", show(&t), show(&c));
        // After G, no invented technique may remain (Neuro: "after G, an invented id cannot remain").
        assert_eq!(technique_check(&buf[..r.len]).unknown > 0, unk_after > 0);
        assert_eq!(technique_check(&buf[..r.len]).unknown, 0, "G left an invented id in {:?}", show(&buf[..r.len]));
        // Neuro's G can leave an unreturned CVE when the id's last group is longer than 7 digits: the detector
        // matches the first 7, the removal pattern then needs a non-alphanumeric after them. The device keeps G
        // byte-exact with Neuro, so the verifier's REJECTED check is what catches these. Count them.
        if ungrounded_cves(&buf[..r.len], &[&c]) > 0 {
            survivors += 1;
            assert!(buf[..r.len].windows(4).any(|w| w.eq_ignore_ascii_case(b"CVE-")), "{:?}", show(&buf[..r.len]));
        }
        n += 1;
        edited += usize::from(rem > 0);
    }
    assert!(n > 1500);
    assert!(survivors > 0, "the vectors include the over-long CVE case");
    println!("grounding vectors: {n} cases equal Neuro's guard_ground.apply and grounding checks ({edited} edited by G; {survivors} unreturned CVEs survive Neuro's G and are left to the verifier)");
}

#[test]
fn too_many_bad_tokens_is_refused_not_half_filtered() {
    let mut t: Vec<u8> = (0..20).flat_map(|i| format!("T9{i:03} ").into_bytes()).collect();
    let len = t.len();
    let r = guard_g(&mut t, len, &[]);
    assert!(r.overflow);
    assert_eq!(r.len, len);
}
