// SPDX-License-Identifier: AGPL-3.0-only
//! Evidence cards against Neuro's Python reference (`semantic_compression.rep_cards` + `fill`, and the `REST`
//! rule of `e2e_neuro.py`).
//!
//! - Vectors: `tests/data/card_vectors.rs` holds the contexts Neuro's own functions produced for generated
//!   windows; `tests/data/CARD_VECTORS.md` says how they were made. Set `NEURO_CARD_VECTORS` to more files in
//!   that format (colon-separated) to check more windows.
//! - Neuro's own vectors: set `NEURO_CARD_CONTRACT` to its `card_contract.json` (22 windows of the E2E fixture;
//!   it holds the fixture's real addresses and is not in the repository).
//! - Drift gate: the constants and format strings this module mirrors are read from Neuro's sources as text.
use neuro_contract::cards::*;
use neuro_contract::{ContractError, Out};

#[path = "data/card_vectors.rs"]
mod data;

struct Window {
    budget: u32,
    want: String,
    baseline: Vec<(String, String)>,
    flows: Vec<(u32, String, String, u32, u64, bool)>,
    dets: Vec<[String; 8]>,
}

fn unhex(s: &str) -> String {
    let b: Vec<u8> = (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|_| panic!("not hex: {s}"))).collect();
    String::from_utf8(b).expect("utf-8")
}

fn parse(text: &str) -> Vec<Window> {
    let mut ws: Vec<Window> = Vec::new();
    for line in text.lines().filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let f: Vec<&str> = line.split(' ').collect();
        let dash = |s: &str| if s == "-" { String::new() } else { s.to_string() };
        match f[0] {
            "V" => ws.push(Window { budget: f[1].parse().unwrap(), want: unhex(f.get(2).copied().unwrap_or("")), baseline: vec![], flows: vec![], dets: vec![] }),
            "b" => ws.last_mut().unwrap().baseline.push((f[1].into(), f[2].into())),
            "f" => ws.last_mut().unwrap().flows.push((f[1].parse().unwrap(), f[2].into(), f[3].into(), f[4].parse().unwrap(), f[5].parse().unwrap(), f[6] == "1")),
            "d" => ws.last_mut().unwrap().dets.push([f[1].into(), f[2].into(), dash(f[3]), f[4].into(), f[5].into(), dash(f[6]), f[7].into(), unhex(f.get(8).copied().unwrap_or(""))]),
            other => panic!("unknown line kind {other}"),
        }
    }
    ws
}

fn build(w: &Window) -> Result<(String, Built), ContractError> {
    let mut flows: Vec<Flow> = w.flows.iter().map(|(t, s, d, p, b, r)| Flow::new(*t, s, d, *p, *b, *r)).collect();
    let dets: Vec<Detection> = w
        .dets
        .iter()
        .map(|d| Detection { id: &d[0], src: &d[1], dst: &d[2], port: d[3].parse().unwrap(), category: &d[4], mitre: &d[5], severity: d[6].parse().unwrap(), rule_msg: &d[7] })
        .collect();
    let baseline: Vec<(&str, &str)> = w.baseline.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    let (mut cards, mut fans, mut aliases) = (vec![Card::EMPTY; 4096], vec![Fan::EMPTY; 256], vec![Alias::EMPTY; 8192]);
    let mut scratch = Scratch { cards: &mut cards, fans: &mut fans, aliases: &mut aliases };
    let mut buf = vec![0u8; 1 << 16];
    let mut o = Out::new(&mut buf);
    let b = build_context(&mut flows, &dets, &baseline, w.budget, &mut scratch, &mut o)?;
    Ok((String::from_utf8(o.buf[..o.n].to_vec()).expect("utf-8"), b))
}

/// Checks every window; returns (windows, with a fan-out, periodic, with a detection note, with dropped cards).
fn check(ws: &[Window], origin: &str) -> [usize; 5] {
    let mut seen = [0usize; 5];
    for (k, w) in ws.iter().enumerate() {
        let (got, b) = build(w).unwrap_or_else(|e| panic!("{origin} window {k}: {e:?}"));
        assert_eq!(got, w.want, "{origin} window {k} (budget {}): the context differs from Neuro's", w.budget);
        seen[0] += 1;
        seen[1] += usize::from(got.contains("fanout_hosts="));
        seen[2] += usize::from(got.contains("periodic="));
        seen[3] += usize::from(got.contains(" det="));
        seen[4] += usize::from(b.kept < b.cards);
    }
    seen
}

#[test]
fn contexts_equal_neuros_python() {
    let ws = parse(data::VECTORS);
    let s = check(&ws, "card_vectors.rs");
    assert!(s[0] >= 100 && s[1] >= 10 && s[2] >= 10 && s[3] >= 40 && s[4] >= 10, "the vectors no longer exercise the builder: {s:?}");
    println!("card vectors: {} windows equal Neuro's rep_cards + fill + REST ({} with a fan-out, {} periodic, {} with a detection, {} with dropped cards)", s[0], s[1], s[2], s[3], s[4]);
    if let Ok(p) = std::env::var("NEURO_CARD_VECTORS") {
        for p in p.split(':').filter(|p| !p.is_empty()) {
            let s = check(&parse(&std::fs::read_to_string(p).unwrap_or_else(|e| panic!("cannot read {p}: {e}"))), p);
            println!("extra vectors {p}: {} windows equal ({} with a fan-out, {} periodic, {} with a detection, {} with dropped cards)", s[0], s[1], s[2], s[3], s[4]);
        }
    }
}

#[test]
fn one_dropped_card_gives_one_rest_line() {
    // `fill` returns the kept lines plus its REST line; with exactly one card dropped that is as many lines as there
    // are cards. `e2e_neuro.py` appended the REST line again until Neuro's d65431e5c; now it checks the last line.
    let ws = parse(data::VECTORS);
    let w = ws.iter().find(|w| w.want.contains("REST 1 more cards omitted; omitted cards carry detections: port_scan x1;")).expect("the hand-built window");
    let (got, b) = build(w).unwrap();
    assert_eq!(got, w.want);
    assert_eq!(b.cards - b.kept, 1);
    assert_eq!(got.matches("REST ").count(), 1, "one REST line:\n{got}");
    assert!(got.lines().last().is_some_and(|l| l.starts_with("REST 1 more cards omitted")));
}

#[test]
fn neuros_fixture_vectors_when_present() {
    let Ok(path) = std::env::var("NEURO_CARD_CONTRACT") else {
        println!("NEURO_CARD_CONTRACT is not set: Neuro's 22 fixture windows were not checked in this run");
        return;
    };
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {path}: {e}"))).expect("json");
    let s = |x: &serde_json::Value| x.as_str().unwrap_or("").to_string();
    let mut ws = Vec::new();
    for vec in v["vectors"].as_array().expect("vectors") {
        assert_eq!(vec["tokenizer"], "ESTIMATE (bytes/4)", "the mirror counts as the estimate does");
        let mut w = Window { budget: vec["budget"].as_u64().unwrap() as u32, want: s(&vec["context"]), baseline: vec![], flows: vec![], dets: vec![] };
        for p in vec["baseline_pairs"].as_array().unwrap() {
            w.baseline.push((s(&p[0]), s(&p[1])));
        }
        for e in vec["events"].as_array().unwrap() {
            match e["type"].as_str().unwrap() {
                "flow" => {
                    let t = e["ts"].as_str().unwrap();
                    let n = |a: usize, b: usize| t[a..b].parse::<u32>().unwrap();
                    let ms = n(11, 13) * 3_600_000 + n(14, 16) * 60_000 + n(17, 19) * 1000 + n(20, 23);
                    w.flows.push((ms, s(&e["src_ip"]), s(&e["dst_ip"]), e["dst_port"].as_u64().unwrap() as u32, e["bytes_out"].as_u64().unwrap(), e["state"] == "rst"));
                }
                "detection" => w.dets.push([s(&e["id"]), s(&e["src_ip"]), s(&e["dst_ip"]), e["dst_port"].to_string(), s(&e["category"]), s(&e["mitre"]), e["severity"].to_string(), s(&e["rule_msg"])]),
                other => panic!("event type {other} is not mirrored"),
            }
        }
        ws.push(w);
    }
    let st = check(&ws, "card_contract.json");
    let cardless = ws.iter().filter(|w| !w.want.starts_with("F1 ")).count();
    println!("Neuro's fixture: {} windows equal byte for byte ({} with a detection, {} with no fact card)", st[0], st[3], cardless);
}

#[test]
fn small_cases_by_hand() {
    let w = |flows: Vec<(u32, &str, &str, u32, u64, bool)>, dets: Vec<[&str; 8]>, budget| Window {
        budget,
        want: String::new(),
        baseline: vec![],
        flows: flows.into_iter().map(|(t, s, d, p, b, r)| (t, s.to_string(), d.to_string(), p, b, r)).collect(),
        dets: dets.into_iter().map(|d| d.map(String::from)).collect(),
    };
    // Nothing at all: the REST line alone. This is the window the harness refuses to send to a model.
    assert_eq!(build(&w(vec![], vec![], 512)).unwrap().0, "REST 0 more cards omitted; omitted cards carry no detections; plus 0 ordinary flow pairs and 0 ordinary dns groups with no detections");
    // One small pair is ordinary: no card.
    let one = build(&w(vec![(0, "192.168.1.10", "198.51.100.1", 443, 100, false)], vec![], 512)).unwrap();
    assert_eq!((one.1.cards, one.1.ordinary_pairs), (0, 1));
    assert!(one.0.starts_with("REST 0 more cards") && one.0.contains("plus 1 ordinary flow pairs"));
    // A detection with no flow is kept as its own card, with the text after the rule's last bracket.
    let det = ["det:0", "192.168.1.10", "198.51.100.1", "443", "ioc_match", "T1071", "1", "Known C2 address (DROP, block)"];
    assert_eq!(build(&w(vec![], vec![det], 512)).unwrap().0.lines().next().unwrap(), "F1 H1=192.168.1.10->R1=198.51.100.1:443 det=ioc_match[T1071,sev1,DROP, block]");
    // 172.16/12 is the site, 172.32 is not; the classification reads the text.
    assert!(is_site("172.16.0.1") && is_site("172.31.255.1") && is_site("10.1.1.1") && is_site("192.168.0.9"));
    assert!(!is_site("172.32.0.1") && !is_site("172.15.0.1") && !is_site("172.160.0.1") && !is_site("100.64.0.1") && !is_site("1172.16.0.1"));
}

#[test]
fn refusals() {
    let mk = |src: &'static str| vec![Flow::new(0, src, "198.51.100.1", 443, 1, false)];
    let run = |flows: &mut [Flow<'static>], dets: &[Detection<'static>], cards: usize, buf: usize| {
        let (mut c, mut f, mut a) = (vec![Card::EMPTY; cards], vec![Fan::EMPTY; 4], vec![Alias::EMPTY; 16]);
        let mut b = vec![0u8; buf];
        build_context(flows, dets, &[], 512, &mut Scratch { cards: &mut c, fans: &mut f, aliases: &mut a }, &mut Out::new(&mut b)).map(|_| ())
    };
    // Text that could forge a line or a placeholder is refused, never written.
    for bad in ["192.168.1.1\nF9 x", "h\u{1}", "", "é"] {
        assert_eq!(run(&mut mk(bad), &[], 8, 4096), Err(ContractError::Invalid), "{bad:?}");
    }
    let det = |msg: &'static str| Detection { id: "d", src: "192.168.1.1", dst: "", port: 0, category: "c", mitre: "", severity: 2, rule_msg: msg };
    assert_eq!(run(&mut [], &[det("line\nbreak")], 8, 4096), Err(ContractError::Invalid));
    // No room is an error, never a shorter context.
    assert_eq!(run(&mut [], &[det("ok")], 0, 4096), Err(ContractError::Space));
    assert_eq!(run(&mut [], &[det("ok")], 8, 10), Err(ContractError::Space));
    assert_eq!(run(&mut [], &vec![det("ok"); MAX_DETECTIONS + 1], 80, 4096), Err(ContractError::Space));
}

// ------------------------------------------------------------------------------------------- drift gate

fn source(rel: &str) -> String {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tools/neuro-research").join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))
}

#[test]
fn cards_match_neuros_sources() {
    let sc = source("semantic_compression.py");
    let e2e = source("e2e_neuro.py");
    let want: Vec<String> = vec![
        "SEV_WEIGHT = {1: 8.0, 2: 6.0, 3: 3.0, 4: 1.0, 5: 0.2}".into(),
        "n = max(1, len(text.encode()) // 4)".into(),
        "JITTER = 0.0 ".into(),
        format!("sample = \"\\n\".join(lines[:{RATIO_SAMPLE_LINES}])"),
        "return self.count(sample) / max(1, len(sample.encode()))".into(),
        "c = len(l.encode()) * r + 1".into(),
        "if est + c > budget:".into(),
        "while n > budget and kept:".into(),
        "if residual is not None and len(k) < len(lines):".into(),
        "if ip.startswith((\"10.\", \"192.168.\")) or re.match(r\"172\\.(1[6-9]|2\\d|3[01])\\.\", ip):".into(),
        "t_of = lambda ts: int(ts[11:13]) * 3600 + int(ts[14:16]) * 60 + float(ts[17:23])".into(),
        "hits = [d for d in dets.get(src, []) if d[\"dst_ip\"] == dst]".into(),
        "hits = [d for d in hits if d[\"dst_port\"] in (0, port, 53)]".into(),
        "best = min(hits, key=lambda d: d[\"severity\"])".into(),
        "return (\" det=%s[%s,sev%d,%s]\" % (best[\"category\"], best[\"mitre\"] or \"-\", best[\"severity\"],".into(),
        "best[\"rule_msg\"].split(\"(\")[-1].rstrip(\")\"))), w, hits".into(),
        format!("if len(dsts) >= {FANOUT_HOSTS}:"),
        "fail = 100 * fail_sport[(src, port)] // max(1, n)".into(),
        "hits = [d for d in dets.get(src, []) if d[\"dst_port\"] in (0, port)]".into(),
        "cards.append((4.0 + dw + min(3.0, len(dsts) / 500.0),".into(),
        "\"%s->*:%d n=%d fanout_hosts=%d fail=%d%%%s\" % (I(src, kind_of(src)), port, n, len(dsts), fail, note),".into(),
        "if all((src, r[1]) in fanned for r in rows):".into(),
        format!("if len(ports) >= {FANOUT_PORTS}:\n            flags.append(\"fanout_ports=%d\" % len(ports))\n            w += 4"),
        format!("if n >= {PERIODIC_MIN_FLOWS}:"),
        format!("if round(mu, 3) >= {PERIODIC_MIN_GAP_S}:"),
        "cv = statistics.pstdev(gaps) / mu\n                if cv < 0.1:\n                    flags.append(\"periodic=%ds cv=%.2f\" % (round(mu), cv))\n                    w += 3".into(),
        "if out_b >= 100_000_000:\n            flags.append(\"out=%.1fGB\" % (out_b / 1e9))\n            w += 4".into(),
        "if rst > n / 2 and n > 20:\n            flags.append(\"rst=%d%%\" % (100 * rst // n))".into(),
        "novel = (src, dst) not in baseline[\"pairs\"]".into(),
        "note, dw, hits = det_note(src, dst, None if len(ports) > 3 else min(ports))".into(),
        "w += dw + (1.0 if novel else 0.0)".into(),
        format!("if not flags and not note and n < {ORDINARY_MAX_FLOWS}:"),
        "port_s = (\"%d ports\" % len(ports)) if len(ports) > 3 else \",\".join(str(p) for p in sorted(ports))".into(),
        "text = \"%s->%s:%s n=%d %s%s%s\" % (I(src, kind_of(src)), I(dst, kind_of(dst)), port_s, n,".into(),
        "\" \".join(flags), \" novel\" if novel else \"\", note)".into(),
        "w = SEV_WEIGHT.get(d[\"severity\"], 1.0) + (2.0 if d[\"category\"] == \"ioc_match\" else 0.0)".into(),
        "text = \"%s->%s:%s det=%s[%s,sev%d,%s]\" % (I(src, kind_of(src)), I(d[\"dst_ip\"], kind_of(d[\"dst_ip\"])) if d[\"dst_ip\"] else \"-\",".into(),
        "ranked = [c for c in sorted(cards, key=lambda c: -c[0]) if c[1]]".into(),
        "lines = I.materialize([\"F%d %s\" % (i + 1, c[1]) for i, c in enumerate(ranked)])".into(),
        "seen[ent] = \"%s%d\" % (kind, counters[kind])\n                return \"%s=%s\" % (seen[ent], ent)".into(),
        "cats = collections.Counter(m for l in dropped_lines for m in re.findall(r\"det=(\\w+)\", l))".into(),
        "dets_s = (\"; omitted cards carry detections: \" + \", \".join(\"%s x%d\" % kv for kv in cats.most_common())) \\".into(),
        "if cats else \"; omitted cards carry no detections\"".into(),
        "return \"REST %d more cards omitted%s; plus %d ordinary flow pairs and %d ordinary dns groups with no detections\" % (".into(),
    ];
    for f in &want {
        assert!(sc.contains(f.as_str()), "semantic_compression.py no longer contains:\n  {f}\nUpdate neuro_contract::cards to match Neuro's change.");
    }
    for f in [
        format!("lines, used = sc.fill(cards, {BUDGET}, tok, residual)"),
        "if len(lines) == len(cards) and not (lines and lines[-1].startswith(\"REST \")):".to_string(),
        "lines = lines + [residual([])]".to_string(),
        "st = {\"S0\": \"rst\", \"REJ\": \"rst\", \"SF\": \"fin\"}".to_string(),
    ] {
        assert!(e2e.contains(f.as_str()), "e2e_neuro.py no longer contains:\n  {f}\nUpdate neuro_contract::cards to match Neuro's change.");
    }
    println!("drift gate: neuro_contract::cards equals semantic_compression.py ({} fragments) and e2e_neuro.py's REST rule", want.len());
}
