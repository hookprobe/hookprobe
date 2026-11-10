//! Pure HTTP/1.1 request + form parsing for Mission Control — every byte here comes from the network. Kept free of
//! kernel state (no `crate::` paths) so the same code is compiled into the host libFuzzer harness
//! (`tools/fuzz/heqk-kernel`, release gate SEC-02). `http.rs` / `actionapi.rs` re-export it unchanged.

/// The raw-chunk upload route's body cap (ADR 0056); `upload::CHUNK_MAX` is this value.
pub const UPLOAD_CHUNK_MAX: usize = 2048;
/// The session cookie name; `mcauth::COOKIE` is this value.
pub const SESSION_COOKIE: &str = "hq_session";

#[derive(Debug, PartialEq, Eq)]
pub struct Req<'a> {
    pub get: bool,
    pub post: bool,
    pub path: &'a str,
    pub query: &'a str,
    /// The `hq_session` cookie value, if sent.
    pub session: Option<&'a str>,
    /// Request body (POST only; bounded by `MAX_BODY`).
    pub body: &'a [u8],
    /// The `Host` header (for the :80 -> https redirect); empty if absent or not a plain host[:port].
    pub host: &'a str,
    /// The client wants the connection kept open (HTTP/1.1 without `Connection: close`).
    pub keep_alive: bool,
    /// Bytes of the input this request occupies (header block + body) — anything after it is the next
    /// (pipelined) request and must be kept.
    pub consumed: usize,
    /// The `Origin` header (ADR 0053: writes must come from this device's own pages).
    pub origin: &'a str,
    /// The client's IPv4 address (set by the server loop from the socket; 0.0.0.0 if unknown) — the login
    /// throttle is per source, so one LAN host cannot lock the owner out.
    pub peer: [u8; 4],
    /// The `X-HQ-CSRF` header (ADR 0053 per-session token).
    pub csrf: &'a str,
}

/// Largest accepted request body (the login form and ADR 0053 action forms).
pub const MAX_BODY: usize = 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum ParseErr {
    /// Headers not complete yet — read more.
    Incomplete,
    /// Not an HTTP/1.x request line (or headers over the cap) — answer 400 and close.
    Bad,
}

/// Parse the request line once the header block (`\r\n\r\n`) is complete. The body (none for
/// GET) and headers are ignored — nothing here depends on them.
pub fn parse(buf: &[u8]) -> Result<Req<'_>, ParseErr> {
    let end = match buf.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(e) => e,
        None => return Err(if buf.len() >= 4096 { ParseErr::Bad } else { ParseErr::Incomplete }),
    };
    let head = core::str::from_utf8(&buf[..end]).map_err(|_| ParseErr::Bad)?;
    let line = head.split("\r\n").next().ok_or(ParseErr::Bad)?;
    let mut parts = line.split(' ');
    let method = parts.next().ok_or(ParseErr::Bad)?;
    let target = parts.next().ok_or(ParseErr::Bad)?;
    let version = parts.next().ok_or(ParseErr::Bad)?;
    if !version.starts_with("HTTP/1.") || !target.starts_with('/') {
        return Err(ParseErr::Bad);
    }
    let (path, query) = match target.find('?') {
        Some(i) => (&target[..i], &target[i + 1..]),
        None => (target, ""),
    };
    let mut session = None;
    let mut host = "";
    let mut conn_close = false;
    let mut clen = 0usize;
    let mut origin = "";
    let mut csrf = "";
    for h in head.split("\r\n").skip(1) {
        let Some((k, v)) = h.split_once(':') else { continue };
        let v = v.trim();
        if k.eq_ignore_ascii_case("cookie") {
            for c in v.split(';') {
                if let Some((ck, cv)) = c.trim().split_once('=') {
                    if ck == SESSION_COOKIE {
                        session = Some(cv);
                    }
                }
            }
        } else if k.eq_ignore_ascii_case("host") {
            let h = v.trim();
            // Only a plain host / IPv4 / [IPv6] with an optional port — never anything that could split
            // the Location header we echo it into.
            if !h.is_empty() && h.len() <= 255 && h.bytes().all(|c| c.is_ascii_alphanumeric() || b".-:[]".contains(&c)) {
                host = h;
            }
        } else if k.eq_ignore_ascii_case("content-length") {
            clen = v.parse().map_err(|_| ParseErr::Bad)?;
        } else if k.eq_ignore_ascii_case("origin") {
            origin = v;
        } else if k.eq_ignore_ascii_case("x-hq-csrf") {
            csrf = v;
        } else if k.eq_ignore_ascii_case("connection") {
            conn_close = v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close"));
        }
    }
    // ADR 0056: upload chunks carry raw bytes (still inside the 4 KiB request buffer)
    let cap = if path == "/api/upload/chunk" { UPLOAD_CHUNK_MAX } else { MAX_BODY };
    if clen > cap {
        return Err(ParseErr::Bad);
    }
    let body_start = end + 4;
    if buf.len() < body_start + clen {
        return Err(ParseErr::Incomplete);
    }
    let body = &buf[body_start..body_start + clen];
    let keep_alive = version == "HTTP/1.1" && !conn_close;
    Ok(Req { get: method == "GET", post: method == "POST", path, query, session, body, host, keep_alive, consumed: body_start + clen, origin, csrf, peer: [0; 4] })
}

/// `key=<u32>` from a query string.
pub fn query_u32(query: &str, key: &str) -> Option<u32> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        if k == key { v.parse().ok() } else { None }
    })
}

/// A query value, percent-decoded into `buf` (bounded; a malformed escape → None).
pub fn query_str<'b>(query: &str, key: &str, buf: &'b mut [u8; 96]) -> Option<&'b str> {
    let v = query.split('&').find_map(|kv| kv.split_once('=').filter(|(k, _)| *k == key).map(|(_, v)| v))?;
    let b = v.as_bytes();
    let (mut i, mut n) = (0usize, 0usize);
    while i < b.len() {
        let c = if b[i] == b'%' {
            let h = |x: u8| (x as char).to_digit(16);
            let (hi, lo) = (h(*b.get(i + 1)?)?, h(*b.get(i + 2)?)?);
            i += 3;
            (hi * 16 + lo) as u8
        } else {
            i += 1;
            b[i - 1]
        };
        *buf.get_mut(n)? = c;
        n += 1;
    }
    core::str::from_utf8(&buf[..n]).ok()
}

/// One form field, percent/plus-decoded into `buf`.
pub fn form_get<'b>(body: &[u8], key: &str, buf: &'b mut [u8; 192]) -> Option<&'b str> {
    let s = core::str::from_utf8(body).ok()?;
    let v = s.split('&').find_map(|kv| kv.split_once('=').filter(|(k, _)| *k == key).map(|(_, v)| v))?;
    let b = v.as_bytes();
    let (mut i, mut n) = (0usize, 0usize);
    while i < b.len() {
        let c = match b[i] {
            b'%' => {
                let h = |x: u8| (x as char).to_digit(16);
                let v = h(*b.get(i + 1)?)? * 16 + h(*b.get(i + 2)?)?;
                i += 3;
                v as u8
            }
            b'+' => {
                i += 1;
                b' '
            }
            c => {
                i += 1;
                c
            }
        };
        *buf.get_mut(n)? = c;
        n += 1;
    }
    core::str::from_utf8(&buf[..n]).ok()
}
