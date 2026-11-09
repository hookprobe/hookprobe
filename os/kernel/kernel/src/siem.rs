//! Local SIEM export (parity gap G15 — beats both legacy tiers, which had no syslog/CEF export).
//!
//! Each new detection is sent once, as one UDP datagram, to the collector named in the operator-signed
//! POLICY.TXT (`export syslog <ip> <port> via wan|mgmt [json]`). Format RFC 5424 with structured data
//! (`[hookprobe@32473 …]`, PEN-style SD-ID) — or one OCSF-style JSON object per datagram (`json`).
//! Fire-and-forget by design: a lost datagram is counted, never retried (the on-device ring and
//! /api/detections stay the source of truth); nothing is exported until the operator asks for it.

use core::fmt::Write;

/// RFC 5424 SD-ID enterprise number placeholder (32473 = RFC 5612 documentation PEN).
pub const SD_PEN: u32 = 32473;

pub struct Det<'a> {
    pub seq: u64,
    /// Unix ms, 0 = clock not set (timestamp sent as NILVALUE "-").
    pub ts_ms: u64,
    pub rule_id: u32,
    pub msg: &'a str,
    pub category: &'a str,
    pub mitre: &'a str,
    /// catalogue severity 1 critical … 5 info
    pub severity: u8,
    pub src: u32,
    pub dst: u32,
    pub dport: u16,
    /// "dropped" | "rate_limited" | "observed"
    pub action: &'a str,
}

struct W<'b> {
    b: &'b mut [u8],
    n: usize,
    over: bool,
}
impl Write for W<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bs = s.as_bytes();
        if self.n + bs.len() > self.b.len() {
            self.over = true;
            return Err(core::fmt::Error);
        }
        self.b[self.n..self.n + bs.len()].copy_from_slice(bs);
        self.n += bs.len();
        Ok(())
    }
}

/// Civil date from Unix days (Howard Hinnant's algorithm).
fn civil(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn rfc3339(w: &mut W, ms: u64) {
    if ms == 0 {
        let _ = w.write_str("-");
        return;
    }
    let s = (ms / 1000) as i64;
    let (y, mo, d) = civil(s.div_euclid(86_400));
    let t = s.rem_euclid(86_400);
    let _ = write!(w, "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", y, mo, d, t / 3600, (t / 60) % 60, t % 60, ms % 1000);
}

fn ip(w: &mut W, a: u32) {
    let _ = write!(w, "{}.{}.{}.{}", a >> 24, (a >> 16) & 0xff, (a >> 8) & 0xff, a & 0xff);
}

/// RFC 5424 SD-PARAM value escaping: `"`, `\` and `]` are escaped.
fn sd_val(w: &mut W, v: &str) {
    for c in v.chars() {
        if matches!(c, '"' | '\\' | ']') {
            let _ = w.write_char('\\');
        }
        if c.is_control() {
            continue;
        }
        let _ = w.write_char(c);
    }
}

/// JSON string escaping.
fn js(w: &mut W, v: &str) {
    let _ = w.write_char('"');
    for c in v.chars() {
        match c {
            '"' => { let _ = w.write_str("\\\""); }
            '\\' => { let _ = w.write_str("\\\\"); }
            c if c.is_control() => { let _ = write!(w, "\\u{:04x}", c as u32); }
            c => { let _ = w.write_char(c); }
        }
    }
    let _ = w.write_char('"');
}

/// syslog severity from the catalogue severity (1 critical → 2 crit, 2 high → 3 err, 3 → 4 warning,
/// 4 → 5 notice, else 6 info); facility local0 (16).
fn pri(sev: u8) -> u8 {
    16 * 8 + match sev { 1 => 2, 2 => 3, 3 => 4, 4 => 5, _ => 6 }
}

/// One RFC 5424 message. Returns the length (0 = did not fit).
pub fn rfc5424(d: &Det, host: &str, out: &mut [u8]) -> usize {
    let mut w = W { b: out, n: 0, over: false };
    let _ = write!(w, "<{}>1 ", pri(d.severity));
    rfc3339(&mut w, d.ts_ms);
    let _ = write!(w, " {} heqk - DET{} [hookprobe@{} rule=\"{}\" category=\"", host, d.seq % 1_000_000, SD_PEN, d.rule_id);
    sd_val(&mut w, d.category);
    let _ = w.write_str("\" mitre=\"");
    sd_val(&mut w, d.mitre);
    let _ = write!(w, "\" severity=\"{}\" action=\"{}\" src=\"", d.severity, d.action);
    ip(&mut w, d.src);
    let _ = w.write_str("\" dst=\"");
    ip(&mut w, d.dst);
    let _ = write!(w, "\" dport=\"{}\" seq=\"{}\"] ", d.dport, d.seq);
    let _ = w.write_str("\u{feff}"); // BOM: MSG is UTF-8 (RFC 5424 §6.4)
    let _ = w.write_str(d.msg);
    if w.over { 0 } else { w.n }
}

/// One OCSF-style (Detection Finding, class 2004) JSON object.
pub fn ocsf_json(d: &Det, host: &str, out: &mut [u8]) -> usize {
    let mut w = W { b: out, n: 0, over: false };
    let _ = write!(w, "{{\"class_uid\":2004,\"category_uid\":2,\"severity_id\":{},\"time\":{},\"metadata\":{{\"product\":{{\"name\":\"HookProbe OS\",\"vendor_name\":\"HookProbe\"}},\"uid\":\"det:heqk:{}\"}},\"device\":{{\"hostname\":",
        match d.severity { 1 => 5, 2 => 4, 3 => 3, 4 => 2, _ => 1 }, d.ts_ms, d.seq);
    js(&mut w, host);
    let _ = write!(w, "}},\"finding_info\":{{\"uid\":\"{}\",\"title\":", d.rule_id);
    js(&mut w, d.msg);
    let _ = w.write_str(",\"types\":[");
    js(&mut w, d.category);
    let _ = w.write_str("],\"attacks\":[{\"technique\":{\"uid\":");
    js(&mut w, d.mitre);
    let _ = w.write_str("}}]},\"src_endpoint\":{\"ip\":\"");
    ip(&mut w, d.src);
    let _ = w.write_str("\"},\"dst_endpoint\":{\"ip\":\"");
    ip(&mut w, d.dst);
    let _ = write!(w, "\",\"port\":{}}},\"disposition\":", d.dport);
    js(&mut w, d.action);
    let _ = w.write_str("}");
    if w.over { 0 } else { w.n }
}

/// `[P-siem]`
pub fn selftest() -> bool {
    let d = Det {
        seq: 42, ts_ms: 1_800_000_000_123, rule_id: 1_200_113, msg: "Port scan (answered probes)", category: "port_scan",
        mitre: "T1046", severity: 2, src: 0x0A64_004D, dst: 0x0A64_0087, dport: 22, action: "dropped",
    };
    let mut b = [0u8; 600];
    let n = rfc5424(&d, "heqk-ap", &mut b);
    let s = core::str::from_utf8(&b[..n]).unwrap_or("");
    let r_ok = s.starts_with("<131>1 2027-01-15T08:00:00.123Z heqk-ap heqk - DET42 [hookprobe@32473 rule=\"1200113\" category=\"port_scan\" mitre=\"T1046\" severity=\"2\" action=\"dropped\" src=\"10.100.0.77\" dst=\"10.100.0.135\" dport=\"22\" seq=\"42\"] ")
        && s.ends_with("Port scan (answered probes)");
    let nil = { let d2 = Det { ts_ms: 0, ..d }; let n2 = rfc5424(&d2, "h", &mut b); core::str::from_utf8(&b[..n2]).unwrap_or("").starts_with("<131>1 - h heqk") };
    let esc = { let d3 = Det { category: "a\"b]c\\d", ..d }; let n3 = rfc5424(&d3, "h", &mut b); core::str::from_utf8(&b[..n3]).unwrap_or("").contains("category=\"a\\\"b\\]c\\\\d\"") };
    let n4 = ocsf_json(&d, "heqk-ap", &mut b);
    let j = core::str::from_utf8(&b[..n4]).unwrap_or("");
    let j_ok = j.starts_with("{\"class_uid\":2004,\"category_uid\":2,\"severity_id\":4,\"time\":1800000000123,") && j.contains("\"src_endpoint\":{\"ip\":\"10.100.0.77\"}")
        && j.contains("\"technique\":{\"uid\":\"T1046\"}") && j.ends_with("\"disposition\":\"dropped\"}");
    let jesc = { let d5 = Det { msg: "x\"y\n", ..d }; let n5 = ocsf_json(&d5, "h", &mut b); core::str::from_utf8(&b[..n5]).unwrap_or("").contains("\"title\":\"x\\\"y\\u000a\"") };
    let small = rfc5424(&d, "heqk-ap", &mut [0u8; 40]) == 0 && ocsf_json(&d, "heqk-ap", &mut [0u8; 40]) == 0;
    let leap = civil(19_782) == (2024, 2, 29) && civil(0) == (1970, 1, 1);
    let pass = r_ok && nil && esc && j_ok && jesc && small && leap;
    arch_aarch64::_print(format_args!(
        " [P-siem] {} — local SIEM export formats (parity G15): RFC 5424 with structured data + RFC 3339 UTC time + UTF-8 BOM={} unset clock -> NILVALUE={} SD-PARAM escaping={} | OCSF Detection Finding JSON={} JSON escaping={} | too-small buffer -> 0 (never truncated)={} civil date incl. leap day={}\n",
        if pass { "PASS" } else { "FAIL" }, r_ok, nil, esc, j_ok, jesc, small, leap
    ));
    pass
}
