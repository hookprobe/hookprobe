// SPDX-License-Identifier: AGPL-3.0-only
//! A deliberately small HTTP/1.1 client for ONE purpose: talking to an inference engine on loopback.
//!
//! It refuses any address that is not loopback (the engine must never be reachable from the network; the
//! worker is its only client), sends one request with `Connection: close`, and streams the body through a
//! bounded reader that understands `Transfer-Encoding: chunked`. Every size is capped; malformed input is an
//! error, never a panic.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::Duration;

pub const MAX_HEADER: usize = 16 * 1024;
pub const MAX_BODY: usize = 8 * 1024 * 1024;

#[derive(Debug)]
pub enum HttpError {
    NotLoopback,
    BadUrl,
    Io(io::Error),
    Status(u16),
    Malformed(&'static str),
    TooLarge,
}

impl From<io::Error> for HttpError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// `http://127.0.0.1:8080/prefix` → (addr, prefix). Only `http`, only loopback literals or `localhost`.
pub fn parse_loopback_url(url: &str) -> Result<(SocketAddr, String), HttpError> {
    let rest = url.strip_prefix("http://").ok_or(HttpError::BadUrl)?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].trim_end_matches('/').to_string()),
        None => (rest, String::new()),
    };
    let (host, port) = if let Some(h) = hostport.strip_prefix('[') {
        let (h, p) = h.split_once("]:").ok_or(HttpError::BadUrl)?;
        (h, p)
    } else {
        hostport.rsplit_once(':').ok_or(HttpError::BadUrl)?
    };
    let port: u16 = port.parse().map_err(|_| HttpError::BadUrl)?;
    let ip: IpAddr = if host == "localhost" { IpAddr::from([127, 0, 0, 1]) } else { host.parse().map_err(|_| HttpError::BadUrl)? };
    if !ip.is_loopback() {
        return Err(HttpError::NotLoopback);
    }
    Ok((SocketAddr::new(ip, port), path))
}

/// The response body as a bounded byte stream (chunked or length-delimited or until close).
pub struct Body {
    r: BufReader<TcpStream>,
    chunked: bool,
    left_in_chunk: usize,
    content_left: Option<usize>,
    total: usize,
    done: bool,
}

impl Read for Body {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.done || out.is_empty() {
            return Ok(0);
        }
        let n = if self.chunked {
            if self.left_in_chunk == 0 {
                let mut line = String::new();
                read_line_bounded(&mut self.r, &mut line, 64)?;
                let size = usize::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16)
                    .map_err(|_| io::Error::other("bad chunk size"))?;
                if size == 0 {
                    self.done = true;
                    return Ok(0);
                }
                self.left_in_chunk = size;
            }
            let want = out.len().min(self.left_in_chunk);
            let n = self.r.read(&mut out[..want])?;
            if n == 0 {
                return Err(io::Error::other("truncated chunk"));
            }
            self.left_in_chunk -= n;
            if self.left_in_chunk == 0 {
                let mut crlf = [0u8; 2];
                self.r.read_exact(&mut crlf)?;
                if &crlf != b"\r\n" {
                    return Err(io::Error::other("bad chunk terminator"));
                }
            }
            n
        } else {
            let want = match self.content_left {
                Some(0) => {
                    self.done = true;
                    return Ok(0);
                }
                Some(l) => out.len().min(l),
                None => out.len(),
            };
            let n = self.r.read(&mut out[..want])?;
            if let Some(l) = self.content_left.as_mut() {
                *l -= n;
            }
            if n == 0 {
                self.done = true;
            }
            n
        };
        self.total += n;
        if self.total > MAX_BODY {
            return Err(io::Error::other("body too large"));
        }
        Ok(n)
    }
}

fn read_line_bounded(r: &mut impl BufRead, line: &mut String, max: usize) -> io::Result<()> {
    line.clear();
    let mut b = Vec::new();
    r.by_ref().take(max as u64 + 1).read_until(b'\n', &mut b)?;
    if b.len() > max || !b.ends_with(b"\n") {
        return Err(io::Error::other("line too long or truncated"));
    }
    *line = String::from_utf8(b).map_err(|_| io::Error::other("non-UTF-8 header"))?;
    Ok(())
}

/// POST a JSON body to a loopback engine; return the response body stream (status 200 only).
pub fn post_json(addr: SocketAddr, path: &str, body: &[u8], timeout: Duration) -> Result<Body, HttpError> {
    if !addr.ip().is_loopback() {
        return Err(HttpError::NotLoopback);
    }
    let mut s = TcpStream::connect_timeout(&addr, timeout)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nAccept: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes())?;
    s.write_all(body)?;
    let mut r = BufReader::new(s);
    let mut line = String::new();
    read_line_bounded(&mut r, &mut line, 256)?;
    let mut parts = line.split_whitespace();
    if !parts.next().is_some_and(|v| v.starts_with("HTTP/1.")) {
        return Err(HttpError::Malformed("status line"));
    }
    let status: u16 = parts.next().and_then(|c| c.parse().ok()).ok_or(HttpError::Malformed("status code"))?;
    let (mut chunked, mut content_left, mut seen) = (false, None, 0usize);
    loop {
        read_line_bounded(&mut r, &mut line, 4096)?;
        seen += line.len();
        if seen > MAX_HEADER {
            return Err(HttpError::TooLarge);
        }
        let l = line.trim_end();
        if l.is_empty() {
            break;
        }
        let (k, v) = l.split_once(':').ok_or(HttpError::Malformed("header"))?;
        match k.trim().to_ascii_lowercase().as_str() {
            "transfer-encoding" => chunked = v.trim().eq_ignore_ascii_case("chunked"),
            "content-length" => content_left = Some(v.trim().parse::<usize>().map_err(|_| HttpError::Malformed("content-length"))?),
            _ => {}
        }
    }
    if status != 200 {
        return Err(HttpError::Status(status));
    }
    if content_left.is_some_and(|l| l > MAX_BODY) {
        return Err(HttpError::TooLarge);
    }
    Ok(Body { r, chunked, left_in_chunk: 0, content_left: if chunked { None } else { content_left }, total: 0, done: false })
}

/// Split a byte stream into Server-Sent-Events `data:` payloads, bounded per event.
pub struct SseLines<R: Read> {
    r: BufReader<R>,
}

impl<R: Read> SseLines<R> {
    pub fn new(r: R) -> Self {
        Self { r: BufReader::new(r) }
    }
    /// Next `data:` payload, or None at end of stream.
    pub fn next_data(&mut self) -> io::Result<Option<String>> {
        let mut line = String::new();
        loop {
            line.clear();
            let mut b = Vec::new();
            let n = self.r.by_ref().take(64 * 1024 + 1).read_until(b'\n', &mut b)?;
            if n == 0 {
                return Ok(None);
            }
            if b.len() > 64 * 1024 {
                return Err(io::Error::other("SSE line too long"));
            }
            line.push_str(std::str::from_utf8(&b).map_err(|_| io::Error::other("non-UTF-8 SSE"))?);
            let l = line.trim_end_matches(['\r', '\n']);
            if let Some(d) = l.strip_prefix("data:") {
                return Ok(Some(d.trim_start().to_string()));
            }
        }
    }
}
