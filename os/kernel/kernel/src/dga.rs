//! DGA / lookalike / tunnelling scoring for Shield queries (parity gap G8). DETECTION ONLY — a high score
//! raises an observe-only `dns_dga` detection, it never blocks (ADR 0023, ADR 0052 D4).
//!
//! A no_std, integer port of the Linux-tier dnsxai lexical scorer (`legacy/linux-tier/modules/dnsxai`,
//! weights from V1 `detect_dga`): Shannon entropy, vowel ratio, 5+ consonant cluster, label length,
//! digit ratio, suspicious TLD, long / high-entropy subdomain (tunnelling), lookalike brands. Scores the
//! REGISTRABLE label (V1 scored `parts[0]`, so `www.<dga>.com` scored "www"). Scores are milli (0..1000).

/// A query at or above this score raises a detection.
pub const DGA_THRESHOLD: u32 = 600;

/// log2(x) in 1/256 units for x ≥ 1 (integer: msb + a linear mantissa term; error < 0.09 bits).
fn log2_q8(x: u32) -> u32 {
    if x == 0 {
        return 0;
    }
    let msb = 31 - x.leading_zeros();
    let frac = if msb >= 8 { (x >> (msb - 8)) & 0xff } else { (x << (8 - msb)) & 0xff };
    (msb << 8) + frac
}

/// Shannon entropy of `s` in bits × 256.
fn entropy_q8(s: &[u8]) -> u32 {
    let n = s.len() as u32;
    if n == 0 {
        return 0;
    }
    let mut c = [0u16; 256];
    for &b in s {
        c[b as usize] += 1;
    }
    // H = log2 n - (1/n) Σ c_i log2 c_i
    let mut sum = 0u64;
    for &k in c.iter() {
        if k > 0 {
            sum += k as u64 * log2_q8(k as u32) as u64;
        }
    }
    log2_q8(n).saturating_sub((sum / n as u64) as u32)
}

/// Two-label public suffixes we know (registrable = the label before them).
const SUFFIX2: &[&[u8]] = &[b"co.uk", b"org.uk", b"ac.uk", b"com.au", b"net.au", b"co.jp", b"com.br", b"co.in", b"com.cn", b"co.nz", b"com.tr", b"co.za", b"com.mx", b"com.ro"];
const SUS_TLD: &[&[u8]] = &[b"xyz", b"top", b"tk", b"ml", b"ga", b"cf", b"gq", b"pw", b"click", b"loan", b"work", b"zip", b"mov", b"cyou", b"rest", b"buzz"];
const BRANDS: &[&[u8]] = &[b"google", b"paypal", b"microsoft", b"apple", b"amazon", b"facebook", b"netflix", b"instagram", b"whatsapp", b"outlook", b"office", b"icloud", b"binance", b"coinbase", b"linkedin", b"dropbox"];
const PHISH: &[&[u8]] = &[b"secure", b"login", b"signin", b"verify", b"account", b"update", b"support", b"wallet", b"billing"];

/// (registrable label, the subdomain part before it, tld).
fn split(name: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let name = name.strip_suffix(b".").unwrap_or(name);
    let last = name.iter().rposition(|&c| c == b'.')?;
    let tld = &name[last + 1..];
    let mut end = last;
    for s in SUFFIX2 {
        if name.len() > s.len() && name.ends_with(s) && name[name.len() - s.len() - 1] == b'.' {
            end = name.len() - s.len() - 1;
        }
    }
    let start = name[..end].iter().rposition(|&c| c == b'.').map_or(0, |p| p + 1);
    let sub = if start > 0 { &name[..start - 1] } else { &name[..0] };
    Some((&name[start..end], sub, tld))
}

fn leet(c: u8) -> u8 {
    match c {
        b'0' => b'o',
        b'1' => b'l',
        b'3' => b'e',
        b'4' => b'a',
        b'5' => b's',
        b'7' => b't',
        b'@' => b'a',
        _ => c,
    }
}

fn contains(h: &[u8], n: &[u8]) -> bool {
    n.len() <= h.len() && h.windows(n.len()).any(|w| w == n)
}

/// A lookalike of a curated brand: a digit-substituted brand ("goog1e", "micros0ft") or a brand +
/// phishing-keyword compound ("paypal-secure"). The brand's own label ("google") is never flagged.
fn lookalike(label: &[u8]) -> bool {
    let mut norm = [0u8; 64];
    let mut lower = [0u8; 64];
    let n = label.len().min(64);
    let mut has_digit = false;
    for i in 0..n {
        has_digit |= label[i].is_ascii_digit();
        lower[i] = label[i].to_ascii_lowercase();
        norm[i] = leet(lower[i]);
    }
    let norm = &norm[..n];
    for b in BRANDS {
        if label == *b {
            return false;
        }
        if has_digit && contains(norm, b) && !contains(&lower[..n], b) {
            return true; // a digit REPLACES a brand letter (gates `shopify`≈`spotify` and `office365`)
        }
        if contains(label, b) && PHISH.iter().any(|p| contains(label, p)) {
            return true;
        }
    }
    false
}

/// The score (0..1000) for a query name.
pub fn score(name: &[u8]) -> u32 {
    let Some((label, sub, tld)) = split(name) else { return 0 };
    let mut s = 0u32;
    if lookalike(label) {
        s += 650;
    }
    let l = label.len() as u32;
    if l >= 4 {
        let e = entropy_q8(label); // bits × 256
        if e >= 4 * 256 {
            s += 300;
        } else if e > 3 * 256 + 128 {
            s += 150;
        }
        let letters = label.iter().filter(|c| c.is_ascii_alphabetic()).count() as u32;
        let vowels = label.iter().filter(|c| matches!(c.to_ascii_lowercase(), b'a' | b'e' | b'i' | b'o' | b'u' | b'y')).count() as u32;
        if letters > 0 {
            let vr = vowels * 100 / l;
            if vr < 10 {
                s += 250;
            } else if vr < 20 {
                s += 150;
            }
        }
        let mut run = 0;
        let mut cluster = false;
        for &c in label {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_alphabetic() && !matches!(c, b'a' | b'e' | b'i' | b'o' | b'u' | b'y') {
                run += 1;
                cluster |= run >= 5;
            } else {
                run = 0;
            }
        }
        if cluster {
            s += 200;
        }
        if l >= 20 {
            s += 150;
        } else if l >= 15 {
            s += 80;
        }
        let digits = label.iter().filter(|c| c.is_ascii_digit()).count() as u32;
        let dr = digits * 100 / l;
        if dr > 40 {
            s += 150;
        } else if dr > 25 {
            s += 80;
        }
        if SUS_TLD.iter().any(|t| tld.eq_ignore_ascii_case(t)) {
            s += 100;
        }
    }
    // tunnelling: a long / high-entropy subdomain label
    let mut maxl = 0usize;
    let mut maxe = 0u32;
    for part in sub.split(|&c| c == b'.') {
        if part.len() > maxl {
            maxl = part.len();
            maxe = entropy_q8(part);
        }
    }
    // a long label alone is common (hex CDN hashes, ≤ 4.0 bits); length AND > 4.1 bits (base32/64) is the tunnel shape
    if maxl > 30 && maxe > 4 * 256 + 32 {
        s += 650;
    } else if maxl > 30 {
        s += 250;
    } else if maxl > 15 && maxe >= 4 * 256 {
        s += 150;
    }
    s.min(1000)
}

/// `[P-dga]` — known DGA/lookalike/tunnel names score ≥ threshold; a benign popular-domain set scores
/// below it (the false-positive guard V1's keyword rules never had).
pub fn selftest() -> bool {
    let bad: &[&[u8]] = &[
        b"xjw3kq9vzt2lmpr8.com", b"qzkxjvbnmwrtpl.net", b"a1b2c3d4e5f6g7h8i9.top", b"goog1e.com", b"paypal-secure-login.com",
        b"micros0ft-update.com", b"www.xjw3kq9vzt2lmpr8.com", b"aGVsbG8gd29ybGQgdGhpcyBpcyBhIHR1bm5lbA.data.example.com",
    ];
    let good: &[&[u8]] = &[
        b"google.com", b"www.google.com", b"accounts.google.com", b"facebook.com", b"apple.com", b"icloud.com",
        b"microsoft.com", b"login.microsoftonline.com", b"amazon.co.uk", b"netflix.com", b"wikipedia.org", b"github.com",
        b"stackoverflow.com", b"cloudflare.com", b"spotify.com", b"shopify.com", b"bbc.co.uk", b"nytimes.com",
        b"youtube.com", b"instagram.com", b"whatsapp.net", b"linkedin.com", b"dropbox.com", b"hookprobe.com",
        b"example.org", b"mozilla.org", b"ubuntu.com", b"debian.org", b"geometric.example", b"collection.example",
        b"pixelmator.com", b"metrics.icloud.com", b"captive.apple.com", b"time.windows.com", b"office.com",
        b"outlook.office365.com", b"d1af033869koo7.cloudfront.net", b"rr3---sn-4g5e6nsz.googlevideo.com",
    ];
    let mut worst_good = 0u32;
    let mut worst_name: &[u8] = b"";
    for g in good {
        let v = score(g);
        if v > worst_good {
            worst_good = v;
            worst_name = g;
        }
    }
    let mut min_bad = 1000u32;
    for b in bad {
        min_bad = min_bad.min(score(b));
    }
    let split_ok = split(b"www.xjw3k.co.uk").map(|(l, s, _)| (l, s)) == Some((&b"xjw3k"[..], &b"www"[..]));
    let ent_ok = entropy_q8(b"aaaa") == 0 && (entropy_q8(b"abcd") as i32 - 512).abs() <= 24;
    let pass = min_bad >= DGA_THRESHOLD && worst_good < DGA_THRESHOLD && split_ok && ent_ok && score(b"") == 0 && score(b"com") == 0;
    arch_aarch64::_print(format_args!(
        " [P-dga] {} — Shield DGA/lookalike/tunnel scoring (parity G8, detect-only): {} DGA/lookalike/tunnel names min score {} (≥ {}), {} benign popular domains max score {} ({}) — registrable-label split={} integer entropy={}\n",
        if pass { "PASS" } else { "FAIL" }, bad.len(), min_bad, DGA_THRESHOLD, good.len(), worst_good,
        core::str::from_utf8(worst_name).unwrap_or("?"), split_ok, ent_ok
    ));
    pass
}
