// SPDX-License-Identifier: AGPL-3.0-only
//! The device tokenizer (`neuro_lm::tok`) against references, on the build host:
//! - its hand-written pre-tokenizer against the model's own regex (fancy-regex), on random Unicode;
//! - the whole encoder against HF `tokenizers` on the real Qwen3 `tokenizer.json`
//!   (set `QWEN3_TOKENIZER_JSON`; pinned file SHA-256 aeb13307…dae4);
//! - malformed blobs refused.
use neuro_lm::tok::{TokError, Tokenizer};
use std::sync::OnceLock;
use tok_build::*;

const PATTERN: &str = r"(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+";

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn pick<T: Copy>(&mut self, v: &[T]) -> T {
        v[(self.next() % v.len() as u64) as usize]
    }
}

fn ranges() -> &'static Vec<(u32, u32, u32)> {
    static R: OnceLock<Vec<(u32, u32, u32)>> = OnceLock::new();
    R.get_or_init(unicode_ranges)
}

type Nfc = (Vec<(u32, Vec<u32>)>, Vec<(u32, u32, u32)>);
fn nfc() -> &'static Nfc {
    static N: OnceLock<Nfc> = OnceLock::new();
    N.get_or_init(nfc_tables)
}

/// Random text from pools that hit every branch of the pattern and its edges.
fn random_text(r: &mut Rng, max: usize) -> String {
    let pools: &[&[char]] = &[
        &['a', 'b', 'Z', 'é', 'ß', 'Ω', 'ж', 'ا', 'न', '你', 'ſ', 'K', 's', 't', 'r', 'e', 'v', 'm', 'l', 'd', 'S', 'T', 'E', 'L'],
        &['0', '7', '٣', '½', '²', 'Ⅻ', '៣'],
        &[' ', ' ', ' ', '\t', '\n', '\r', '\u{a0}', '\u{3000}', '\u{2028}', '\u{b}', '\u{c}', '\u{85}'],
        &['\'', '\'', '.', ',', '!', '-', '"', '{', '}', ':', '/', '_', '@', '😀', '→', '\u{301}', '\u{94d}', '\u{200d}', '\u{0}', '\u{7f}'],
    ];
    let n = (r.next() % max as u64) as usize;
    let mut s = String::new();
    for _ in 0..n {
        let p = pools[(r.next() % 4) as usize];
        s.push(r.pick(p));
    }
    s
}

fn tiny_blob() -> Vec<u8> {
    let tokens: Vec<Vec<u8>> = (0..=255u8).map(|b| vec![b]).collect();
    blob(&Source { tokens, merges: vec![], added: vec![] }, ranges(), nfc()).unwrap()
}

#[test]
fn pretokenizer_equals_the_model_regex() {
    let b = tiny_blob();
    let t = Tokenizer::new(&b).unwrap();
    let re = fancy_regex::Regex::new(PATTERN).unwrap();
    let mut r = Rng(0x5eed);
    let mut texts: Vec<String> = [
        "", "a", " ", "  ", "\n", " \n ", "a  b", "a \n\n  b", "x   ", "It's", "IT'S", "we'll've", "'re", "'", "''s", "'ſ", "don't stop",
        "1234", " 12", "a1b2", "!!!\n\n", " !?", "  !", "\t\tif x:\n\t\treturn", "x\r\n\r\ny", "a\u{a0}b", "é", "e\u{301}", "😀😀 ok",
    ].iter().map(|s| s.to_string()).collect();
    for _ in 0..40_000 {
        texts.push(random_text(&mut r, 40));
    }
    for s in &texts {
        let want: Vec<(usize, usize)> = re.find_iter(s).map(|m| m.unwrap()).map(|m| (m.start(), m.end())).collect();
        let mut got = vec![];
        t.pretokenize(s, |a, b| {
            got.push((a, b));
            Ok(())
        }).unwrap();
        assert_eq!(got, want, "text {s:?}");
    }
    println!("pre-tokenizer: {} texts split exactly as the model's regex", texts.len());
}

fn qwen() -> Option<(tokenizers::Tokenizer, Vec<u8>)> {
    let path = std::env::var("QWEN3_TOKENIZER_JSON").ok()?;
    let json = std::fs::read_to_string(&path).unwrap();
    let src = from_hf_json(&json).unwrap();
    let b = blob(&src, ranges(), nfc()).unwrap();
    Some((tokenizers::Tokenizer::from_file(&path).unwrap(), b))
}

#[test]
fn qwen3_encoding_equals_hf_tokenizers() {
    let Some((hf, b)) = qwen() else {
        println!("SKIPPED: set QWEN3_TOKENIZER_JSON to the Qwen3 tokenizer.json");
        return;
    };
    let t0 = std::time::Instant::now();
    let t = Tokenizer::new(&b).unwrap();
    println!("blob: {} bytes, {} ids, validated in {:?}", b.len(), t.vocab(), t0.elapsed());
    assert_eq!(t.vocab(), 151_669);
    assert_eq!(t.added_id(b"<|im_start|>"), Some(151_644));
    let mut r = Rng(42);
    let mut texts: Vec<String> = vec![
        "Hello world".into(),
        "<|im_start|>system\nYou are Neuro, the explainer of HookProbe OS.<|im_end|>\n<|im_start|>user\nWhy was 198.51.100.7 blocked?<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n".into(),
        "<tool_call>\n{\"name\": \"lookup_exposure\", \"arguments\": {\"device\": \"slot-3\", \"port\": 443}}\n</tool_call>".into(),
        "{\"verdict\":\"malicious\",\"cites\":[\"ev:1\",\"ev:12\"],\"summary\":\"Port scan from 198.51.100.7 (TCP/22, 23, 80, 443) at 2026-11-24T09:12:03Z.\"}".into(),
        "fn main() {\n    let x: Vec<u32> = (0..10).collect();\n    println!(\"{x:?}\");\n}\n".into(),
        "It's naïve to think we'll've DONE it — café, Ωmega, 你好，世界！ مرحبا नमस्ते 😀👍🏽 ½ ² Ⅻ".into(),
        "   leading and trailing   \r\n\r\n\t\ttabs\u{a0}nbsp\u{3000}ideographic  ".into(),
        "<|im_start|><|im_end|><tool_call></tool_call><|endoftext|>".into(),
        "<|im_start".into(),
        "a<think>b</think>c<|fim_prefix|>".into(),
        "cafe\u{301} e\u{301}\u{323} \u{1e9b}\u{323} \u{958}\u{93c} \u{1100}\u{1161}\u{11a8} 한국어 \u{212b} \u{2126}hm \u{f900}".into(),
    ];
    for _ in 0..20_000 {
        texts.push(random_text(&mut r, 60));
    }
    // Texts made of real tokens' text, glued: exercises long merges.
    for _ in 0..5_000 {
        let mut s = String::new();
        for _ in 0..(1 + r.next() % 12) {
            let id = (r.next() % 151_643) as usize;
            if let Ok(p) = std::str::from_utf8(t.bytes(id).unwrap()) {
                s.push_str(p);
            }
        }
        texts.push(s);
    }
    let (mut same, mut refused, mut ids_total, mut bytes_total, mut changed) = (0usize, 0usize, 0usize, 0usize, 0usize);
    let mut out = vec![0u32; 1 << 16];
    let mut back = vec![0u8; 1 << 16];
    let (mut cps, mut buf) = (vec![0u32; 1 << 18], vec![0u8; 1 << 18]);
    let t1 = std::time::Instant::now();
    for s in &texts {
        let want = hf.encode(s.as_str(), false).unwrap().get_ids().to_vec();
        match t.encode_nfc(s.as_bytes(), &mut out, &mut cps, &mut buf) {
            Ok(n) => {
                assert_eq!(&out[..n], &want[..], "text {s:?}");
                let m = t.decode(&out[..n], &mut back).unwrap();
                use unicode_normalization::UnicodeNormalization;
                let norm: String = s.nfc().collect();
                assert_eq!(&back[..m], norm.as_bytes(), "round trip {s:?}");
                changed += usize::from(norm != *s);
                same += 1;
                ids_total += n;
                bytes_total += s.len();
            }
            Err(TokError::NotNfc) => {
                // Only text NFC might change: it contains a quick-check No/Maybe character or out-of-order marks.
                use unicode_normalization::{is_nfc_quick, IsNormalized};
                assert_ne!(is_nfc_quick(s.chars()), IsNormalized::Yes, "refused NFC text {s:?}");
                refused += 1;
            }
            Err(e) => panic!("{e:?} on {s:?}"),
        }
    }
    println!(
        "qwen3 tokenizer: {same} texts encode to exactly HF's ids and decode to their NFC form ({changed} were not NFC); {refused} refused; {ids_total} ids from {bytes_total} bytes in {:?}",
        t1.elapsed()
    );
    assert_eq!(refused, 0);
}

#[test]
fn malformed_blobs_are_refused() {
    let b = tiny_blob();
    assert!(Tokenizer::new(&b).is_ok());
    let mut bad = b.clone();
    bad[0] = b'X';
    assert_eq!(Tokenizer::new(&bad).err(), Some(TokError::Table));
    assert_eq!(Tokenizer::new(&b[..b.len() - 1]).err(), Some(TokError::Table));
    let mut longer = b.clone();
    longer.push(0);
    assert_eq!(Tokenizer::new(&longer).err(), Some(TokError::Table));
    // A byte token that is not its byte.
    let mut bad = b.clone();
    bad[32..36].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(Tokenizer::new(&bad).err(), Some(TokError::Table));
    // A merge whose result is not the concatenation of its parts.
    let mut tokens: Vec<Vec<u8>> = (0..=255u8).map(|x| vec![x]).collect();
    tokens.push(b"ab".to_vec());
    tokens.push(b"abc".to_vec());
    let good = blob(&Source { tokens: tokens.clone(), merges: vec![(97, 98), (256, 99)], added: vec![] }, ranges(), nfc()).unwrap();
    let t = Tokenizer::new(&good).unwrap();
    let mut out = [0u32; 8];
    let n = t.encode(b"xabcab", &mut out).unwrap();
    assert_eq!(&out[..n], &[120, 257, 256]);
    let merges_at = 32 + 256 * 4;
    let mut bad = good.clone();
    bad[merges_at + 12..merges_at + 16].copy_from_slice(&257u32.to_le_bytes()); // (97,98) → "abc"
    assert_eq!(Tokenizer::new(&bad).err(), Some(TokError::Table));
    // Unsorted merges.
    let mut bad = good.clone();
    let (m0, m1) = (bad[merges_at..merges_at + 16].to_vec(), bad[merges_at + 16..merges_at + 32].to_vec());
    bad[merges_at..merges_at + 16].copy_from_slice(&m1);
    bad[merges_at + 16..merges_at + 32].copy_from_slice(&m0);
    assert_eq!(Tokenizer::new(&bad).err(), Some(TokError::Table));
    // Errors at run time: bad UTF-8, small output, unknown id.
    assert_eq!(t.encode(&[0xff, 0x41], &mut out), Err(TokError::Utf8));
    assert_eq!(t.encode(b"hello world", &mut [0u32; 3]), Err(TokError::Space));
    assert_eq!(t.decode(&[258], &mut [0u8; 8]), Err(TokError::Token));
    // 200,000 random single-bit corruptions: never a panic. (Integrity is the HNX signature and Merkle
    // root; this validation only guarantees the blob is internally consistent and safe to run.)
    let mut r = Rng(9);
    let mut accepted = 0;
    for _ in 0..200_000 {
        let mut x = good.clone();
        let i = (r.next() % x.len() as u64) as usize;
        x[i] ^= 1 << (r.next() % 8);
        if let Ok(t) = Tokenizer::new(&x) {
            accepted += 1;
            let _ = t.encode(b"xabcab 12 \n", &mut out);
        }
    }
    println!("200,000 corrupted blobs: {accepted} still valid (flips in unused class bits or pool bytes of unused tokens), none panicked");
}

#[test]
fn device_nfc_equals_unicode_normalization() {
    use unicode_normalization::UnicodeNormalization;
    let b = tiny_blob();
    let t = Tokenizer::new(&b).unwrap();
    let mut r = Rng(77);
    let pool: Vec<char> = "aeiouAEOUnNcCsSzZ\u{301}\u{300}\u{302}\u{303}\u{308}\u{323}\u{327}\u{328}\u{30a}\u{331}\u{345}\u{344}\u{340}\u{1e9b}\u{1ff3}\u{3b1}\u{3c9}\u{399}\u{958}\u{915}\u{93c}\u{94d}\u{b47}\u{b3e}\u{b57}\u{1100}\u{1161}\u{11a8}\u{ac00}\u{d7a3}\u{1112}\u{1175}\u{11c2}\u{212b}\u{2126}\u{f900}\u{2f800}\u{fb1d}\u{5b4}\u{5bf}\u{1d15e}\u{1d165}\u{1d16e} x".chars().collect();
    let (mut cps, mut buf) = (vec![0u32; 1024], vec![0u8; 1024]);
    let mut changed = 0;
    for _ in 0..200_000 {
        let n = (r.next() % 12) as usize;
        let s: String = (0..n).map(|_| r.pick(&pool)).collect();
        let want: String = s.nfc().collect();
        let m = t.nfc(&s, &mut cps, &mut buf).unwrap();
        assert_eq!(std::str::from_utf8(&buf[..m]).unwrap(), want, "nfc({s:?})");
        changed += usize::from(want != s);
    }
    // Every non-Hangul character with a decomposition, on its own and after a base letter.
    for (cp, _) in &nfc().0 {
        for s in [char::from_u32(*cp).unwrap().to_string(), format!("a{}", char::from_u32(*cp).unwrap())] {
            let m = t.nfc(&s, &mut cps, &mut buf).unwrap();
            assert_eq!(std::str::from_utf8(&buf[..m]).unwrap(), s.nfc().collect::<String>(), "nfc({s:?})");
        }
    }
    println!("nfc: 200,000 random combining-heavy texts ({changed} changed by NFC) and all {} decomposable characters equal unicode-normalization; {} compositions", nfc().0.len(), nfc().1.len());
}

#[test]
fn long_pieces_match_and_stay_bounded() {
    let Some((hf, b)) = qwen() else {
        println!("SKIPPED: set QWEN3_TOKENIZER_JSON");
        return;
    };
    let t = Tokenizer::new(&b).unwrap();
    let mut out = vec![0u32; 1 << 16];
    for (name, s) in [
        ("16 KB of spaces", " ".repeat(16_384)),
        ("16 KB of one letter", "a".repeat(16_384)),
        ("16 KB of punctuation", "!?".repeat(8_192)),
        ("16 KB of mixed punctuation", "{}[]<>()=;:,.!?-_+*/\\|&^%$#@~`".repeat(546)),
        ("16 KB of CJK", "你好世界".repeat(1_365)),
    ] {
        let t0 = std::time::Instant::now();
        let n = t.encode(s.as_bytes(), &mut out).unwrap();
        let dt = t0.elapsed();
        assert_eq!(&out[..n], hf.encode(s.as_str(), false).unwrap().get_ids(), "{name}");
        println!("{name}: {n} ids in {dt:?} (equal to HF)");
    }
}
