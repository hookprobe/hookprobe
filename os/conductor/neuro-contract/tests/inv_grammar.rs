// SPDX-License-Identifier: AGPL-3.0-only
//! `inv::ToolMachine` against the grammar llama-server itself reports for Neuro's investigation request
//! (`tools/neuro-research/inv_contract_gen.json`, `server_grammar`). The test reads the GBNF text from that file
//! and interprets it with a small, independent matcher, so the automaton is compared with the server's grammar
//! and not with a hand copy of it. A change of the grammar on the Neuro side fails here.
use neuro_contract::inv::*;
use neuro_contract::{context_ids, IdList};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};

fn gen() -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../tools/neuro-research/inv_contract_gen.json");
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("cannot read {}: {e}", p.display()))).expect("inv_contract_gen.json")
}

// ------------------------------------------------------------------------------------------- a GBNF matcher

#[derive(Debug, Clone)]
enum Node {
    Lit(Vec<u8>),
    Class(Vec<(u8, u8)>, bool),
    Rule(String),
    Seq(Vec<Node>),
    Alt(Vec<Node>),
    Rep(Box<Node>, usize, Option<usize>),
}

struct Gbnf<'a> {
    s: &'a [u8],
    i: usize,
}

impl Gbnf<'_> {
    fn blanks(&mut self) {
        while matches!(self.s.get(self.i), Some(b' ' | b'\t')) {
            self.i += 1;
        }
    }
    /// One character of a literal or a class, with GBNF's escapes.
    fn ch(&mut self) -> u8 {
        let c = self.s[self.i];
        self.i += 1;
        if c != b'\\' {
            return c;
        }
        let e = self.s[self.i];
        self.i += 1;
        match e {
            b'n' => b'\n',
            b't' => b'\t',
            b'r' => b'\r',
            b'x' => {
                let v = u8::from_str_radix(std::str::from_utf8(&self.s[self.i..self.i + 2]).unwrap(), 16).unwrap();
                self.i += 2;
                v
            }
            other => other,
        }
    }
    fn alt(&mut self) -> Node {
        let mut alts = vec![];
        loop {
            let mut seq = vec![];
            loop {
                self.blanks();
                match self.s.get(self.i) {
                    None | Some(b'|' | b')' | b'\n') => break,
                    _ => seq.push(self.item()),
                }
            }
            alts.push(Node::Seq(seq));
            if self.s.get(self.i) == Some(&b'|') {
                self.i += 1;
            } else {
                break;
            }
        }
        Node::Alt(alts)
    }
    fn item(&mut self) -> Node {
        let mut n = match self.s[self.i] {
            b'"' => {
                self.i += 1;
                let mut v = vec![];
                while self.s[self.i] != b'"' {
                    v.push(self.ch());
                }
                self.i += 1;
                Node::Lit(v)
            }
            b'[' => {
                self.i += 1;
                let neg = self.s[self.i] == b'^';
                self.i += usize::from(neg);
                let mut ranges = vec![];
                while self.s[self.i] != b']' {
                    let a = self.ch();
                    if self.s[self.i] == b'-' && self.s[self.i + 1] != b']' {
                        self.i += 1;
                        let b = self.ch();
                        ranges.push((a, b));
                    } else {
                        ranges.push((a, a));
                    }
                }
                self.i += 1;
                Node::Class(ranges, neg)
            }
            b'(' => {
                self.i += 1;
                let n = self.alt();
                assert_eq!(self.s[self.i], b')');
                self.i += 1;
                n
            }
            _ => {
                let st = self.i;
                while self.s.get(self.i).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'-') {
                    self.i += 1;
                }
                assert!(self.i > st, "GBNF: unexpected {:?}", self.s[st] as char);
                Node::Rule(String::from_utf8(self.s[st..self.i].to_vec()).unwrap())
            }
        };
        loop {
            match self.s.get(self.i) {
                Some(b'?') => n = Node::Rep(Box::new(n), 0, Some(1)),
                Some(b'*') => n = Node::Rep(Box::new(n), 0, None),
                Some(b'+') => n = Node::Rep(Box::new(n), 1, None),
                Some(b'{') => {
                    let end = self.i + self.s[self.i..].iter().position(|&c| c == b'}').unwrap();
                    let body = std::str::from_utf8(&self.s[self.i + 1..end]).unwrap();
                    let (lo, hi) = match body.split_once(',') {
                        Some((a, b)) => (a.parse().unwrap(), if b.is_empty() { None } else { Some(b.parse().unwrap()) }),
                        None => (body.parse().unwrap(), Some(body.parse().unwrap())),
                    };
                    n = Node::Rep(Box::new(n), lo, hi);
                    self.i = end;
                }
                _ => return n,
            }
            self.i += 1;
        }
    }
}

struct Grammar {
    rules: HashMap<String, Node>,
}

impl Grammar {
    fn parse(text: &str) -> Self {
        let mut rules = HashMap::new();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let (name, body) = line.split_once("::=").unwrap_or_else(|| panic!("GBNF line without ::= : {line}"));
            let mut p = Gbnf { s: body.as_bytes(), i: 0 };
            let n = p.alt();
            assert_eq!(p.i, body.len(), "GBNF: could not read all of rule {name}");
            rules.insert(name.trim().to_string(), n);
        }
        Self { rules }
    }
    /// Every position where `n` can end when it starts at `at`.
    fn ends(&self, n: &Node, t: &[u8], at: usize, memo: &mut HashMap<(String, usize), BTreeSet<usize>>) -> BTreeSet<usize> {
        match n {
            Node::Lit(l) => t[at..].starts_with(l).then_some(at + l.len()).into_iter().collect(),
            Node::Class(r, neg) => match t.get(at) {
                Some(&c) if r.iter().any(|&(a, b)| (a..=b).contains(&c)) != *neg => [at + 1].into(),
                _ => BTreeSet::new(),
            },
            Node::Rule(name) => {
                if let Some(e) = memo.get(&(name.clone(), at)) {
                    return e.clone();
                }
                let e = self.ends(self.rules.get(name).unwrap_or_else(|| panic!("GBNF: no rule {name}")), t, at, memo);
                memo.insert((name.clone(), at), e.clone());
                e
            }
            Node::Seq(items) => {
                let mut cur: BTreeSet<usize> = [at].into();
                for it in items {
                    cur = cur.iter().flat_map(|&p| self.ends(it, t, p, memo)).collect();
                }
                cur
            }
            Node::Alt(alts) => alts.iter().flat_map(|a| self.ends(a, t, at, memo)).collect(),
            Node::Rep(inner, lo, hi) => {
                let (mut out, mut cur): (BTreeSet<usize>, BTreeSet<usize>) = (BTreeSet::new(), [at].into());
                let mut k = 0usize;
                loop {
                    if k >= *lo {
                        out.extend(cur.iter().copied());
                    }
                    if hi.is_some_and(|h| k >= h) {
                        break;
                    }
                    let next: BTreeSet<usize> = cur.iter().flat_map(|&p| self.ends(inner, t, p, memo)).filter(|e| !out.contains(e) || k < *lo).collect();
                    if next.is_empty() || next == cur {
                        break;
                    }
                    cur = next;
                    k += 1;
                }
                out
            }
        }
    }
    fn accepts(&self, t: &[u8]) -> bool {
        self.ends(&Node::Rule("root".into()), t, 0, &mut HashMap::new()).contains(&t.len())
    }
}

// ------------------------------------------------------------------------------------------- the comparison

/// The automaton's verdict on a whole answer that starts at the trigger.
fn machine_accepts(t: &[u8]) -> bool {
    let mut m = ToolMachine::new();
    m.feed(t) && m.triggered() && m.accepting()
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// A random answer the automaton accepts, built byte by byte from what it allows. Structure bytes are preferred
/// so that walks finish; `allowed_seen` collects how many bytes each step allowed.
fn walk(rng: &mut Rng) -> Vec<u8> {
    let mut m = ToolMachine::new();
    let mut t = TRIGGER.as_bytes().to_vec();
    assert!(m.feed(&t));
    for step in 0..4000 {
        if m.accepting() && (rng.below(3) == 0 || step > 600) {
            return t;
        }
        let allowed: Vec<u8> = (0u8..=255).filter(|&b| m.accepts(&[b])).collect();
        assert!(!allowed.is_empty() || m.accepting(), "dead end after {:?}", String::from_utf8_lossy(&t));
        if allowed.is_empty() {
            return t;
        }
        // Inside a string almost every byte is allowed: mostly pick something that moves on.
        let b = if allowed.len() > 100 && rng.below(4) != 0 { *b"\"R1\\ua".get(rng.below(6)).unwrap() } else { allowed[rng.below(allowed.len())] };
        let b = if m.accepts(&[b]) { b } else { allowed[rng.below(allowed.len())] };
        assert!(m.step(b));
        t.push(b);
    }
    panic!("a walk did not finish: {:?}", String::from_utf8_lossy(&t));
}

#[test]
fn tool_machine_equals_the_servers_grammar() {
    let g = gen();
    let sg = &g["server_grammar"];
    // What the automaton assumes about how the server applies the grammar.
    assert_eq!(sg["grammar_lazy"], true);
    assert_eq!(sg["grammar_triggers"], serde_json::json!([{"type": 1, "value": TRIGGER}]), "the trigger changed");
    assert_eq!(sg["preserved_tokens"].as_array().map(Vec::len), Some(PRESERVED_TOKENS.len()));
    let grammar = Grammar::parse(sg["grammar"].as_str().expect("grammar"));

    // The reference matcher itself, on cases worked out by hand from the GBNF text.
    for (t, want) in [
        ("<tool_call>\n{\"name\": \"lookup_reputation\", \"arguments\": {\"entity\": \"R1\"}}\n</tool_call>", true),
        ("<tool_call>\n{\"name\":\"query_dns\",\"arguments\":{\"entity\":\"x\",\"minutes\":-0}}</tool_call>", true),
        ("<tool_call>\n{\"name\":\"query_dns\",\"arguments\":{\"entity\":\"x\" ,\"minutes\":5}}</tool_call>", false),
        ("<tool_call>\n{\"name\":\"propose_policy_change\",\"arguments\":{\"entity\":\"x\"}}</tool_call>", false),
        ("<tool_call>\n{\"name\":\"lookup_exposure\",\"arguments\":{\"entity\":\"x\"}}</tool_call> \n\t ", true),
        ("<tool_call>\n{\"name\":\"lookup_exposure\",\"arguments\":{\"entity\":\"x\"}}</tool_call> \t", false),
        ("<tool_call>\n{\"name\":\"lookup_exposure\",\"arguments\":{\"entity\":\"x\"}}", false),
    ] {
        assert_eq!(grammar.accepts(t.as_bytes()), want, "reference matcher on {t:?}");
    }

    // Neuro's recorded generations.
    let ents = |ctx: &str| {
        let (mut f, mut e) = (IdList::new(), IdList::new());
        context_ids(ctx.as_bytes(), &mut f, &mut e).unwrap();
        e
    };
    let mut calls = 0;
    for v in g["vectors"].as_array().expect("vectors") {
        let raw = v["raw_text"].as_str().expect("raw_text").as_bytes();
        let mut m = ToolMachine::new();
        assert!(m.feed(raw) && m.accepting(), "{}: the automaton refuses what the server generated", v["id"]);
        if m.triggered() {
            assert!(grammar.accepts(raw));
            assert!(matches!(parse_answer(raw, &ents("H1 R1")), Ok(Answer::Call(_))), "{}", v["id"]);
            calls += 1;
        } else {
            assert_eq!(parse_answer(raw, &ents("H1 R1")), Ok(Answer::NoTool));
        }
    }
    assert!(calls >= 2);

    // Random answers the automaton accepts are in the grammar; one-byte changes of them agree both ways.
    let mut rng = Rng(0x2026_1124_0bad_cafe);
    let (mut walks, mut mutants, mut mutants_ok) = (0, 0, 0);
    for _ in 0..1500 {
        let t = walk(&mut rng);
        assert!(machine_accepts(&t));
        assert!(grammar.accepts(&t), "the automaton accepts, the server's grammar does not: {:?}", String::from_utf8_lossy(&t));
        walks += 1;
        for _ in 0..12 {
            let mut u = t.clone();
            let at = TRIGGER.len() + rng.below(u.len() - TRIGGER.len() + 1);
            const ALPHABET: &[u8] = b"\"{}:,<>/ \n\t\\-0159aenu_RtlcZ";
            let b = ALPHABET[rng.below(ALPHABET.len())];
            match rng.below(3) {
                0 if at < u.len() => {
                    u.remove(at);
                }
                1 if at < u.len() => u[at] = b,
                _ => u.insert(at, b),
            }
            let (a, r) = (machine_accepts(&u), grammar.accepts(&u));
            assert_eq!(a, r, "automaton {a}, server grammar {r}: {:?}", String::from_utf8_lossy(&u));
            mutants += 1;
            mutants_ok += usize::from(a);
        }
    }
    assert!(mutants_ok > 500 && mutants - mutants_ok > 5000, "the mutants no longer exercise both verdicts: {mutants_ok} of {mutants}");
    println!("tool-call grammar: {walks} random answers accepted by both; {mutants} one-byte changes agree ({mutants_ok} accepted, {} refused)", mutants - mutants_ok);
}

#[test]
fn before_the_trigger_everything_is_allowed() {
    let mut m = ToolMachine::new();
    assert!(m.accepting() && !m.triggered());
    assert!(m.feed("Nothing to check. <tool_call> is not a call without its newline, <tool_call>x neither.".as_bytes()));
    assert!(m.accepting() && !m.triggered());
    assert!(m.feed(b"<<tool_call>\n"));
    assert!(m.triggered() && !m.accepting(), "the grammar starts where the generated text contains the trigger");
    assert!(!m.accepts(b"x") && m.accepts(b"{") && m.accepts(b" {\"name\""));
    // What the device's strict reader refuses can still be inside the server's grammar: it mirrors the server.
    let wide = "<tool_call>\n{\"name\": \"query_flows\", \"arguments\": {\"entity\": \"203.0.113.9\", \"minutes\": -7}} , {\"name\": \"lookup_exposure\", \"arguments\": {\"entity\": \"\"}}</tool_call>";
    assert!(machine_accepts(wide.as_bytes()));
    assert!(parse_answer(wide.as_bytes(), &IdList::new()).is_err());
}
