//! The EL0 TLS server (ADR 0050 D2 / ADR 0051). Each bounded excursion runs ONE command from the shared
//! IO region (`hal::tlsabi`) and exits back to the kernel with `SYS_EXIT_USER`. Connection state lives in
//! statics + the talc heap, which stay mapped between excursions. The kernel keeps TCP; this server only
//! ever sees ciphertext in and returns ciphertext / plaintext out — a bug here costs the HTTPS service,
//! never forwarding or the IPS (bounded excursion, contained faults, ADR 0050 D5).
#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ptr::{read_volatile, write_volatile};
use hal::tlsabi::*;
use rustls::pki_types::CertificateDer;
use rustls::server::{ClientHello, ResolvesServerCert, UnbufferedServerConnection};
use rustls::sign::CertifiedKey;
use rustls::unbuffered::ConnectionState;

#[cfg(not(feature = "cm5"))]
const BASE: usize = BASE_QEMU;
#[cfg(feature = "cm5")]
const BASE: usize = BASE_CM5;
const IO: usize = BASE + IO_OFF;
const SYS_EXIT_USER: u64 = 6;

// ------------------------------------------------------------------ heap (talc over the mapped window)

#[global_allocator]
static ALLOC: talc::Talck<spin::Mutex<()>, talc::ClaimOnOom> = talc::Talc::new(unsafe {
    talc::ClaimOnOom::new(talc::Span::from_base_size((BASE + HEAP_OFF) as *mut u8, HEAP_SIZE))
})
.lock();

// ------------------------------------------------------------------ IO helpers

fn rd32(off: usize) -> u32 {
    unsafe { read_volatile((IO + off) as *const u32) }
}
fn wr32(off: usize, v: u32) {
    unsafe { write_volatile((IO + off) as *mut u32, v) }
}
fn rd64(off: usize) -> u64 {
    unsafe { read_volatile((IO + off) as *const u64) }
}
fn io(off: usize, len: usize) -> &'static mut [u8] {
    unsafe { core::slice::from_raw_parts_mut((IO + off) as *mut u8, len) }
}

fn exit(status: u32, out_tls: usize, out_plain: usize, flags: u32) -> ! {
    wr32(H_STATUS, status);
    wr32(H_OUT_TLS, out_tls as u32);
    wr32(H_OUT_PLAIN, out_plain as u32);
    wr32(H_FLAGS, flags);
    unsafe { core::arch::asm!("svc #0", in("x8") SYS_EXIT_USER, options(noreturn)) }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    exit(ST_PANIC, 0, 0, 0)
}

// ------------------------------------------------------------------ entropy: the kernel's per-call pool

static mut ENT_POS: usize = 0;

/// Draw from the kernel-refreshed pool; when it is exhausted the handshake fails (fail-closed) — the
/// kernel refills it from the hardware TRNG on the next call.
fn pool_rng(buf: &mut [u8]) -> bool {
    let avail = (rd32(H_ENT_LEN) as usize).min(ENT_MAX);
    let pos = unsafe { ENT_POS };
    if pos + buf.len() > avail {
        return false;
    }
    let src = io(H_ENT + pos, buf.len());
    buf.copy_from_slice(src);
    src.fill(0); // never reuse a byte
    unsafe { ENT_POS = pos + buf.len() };
    true
}

#[derive(Debug)]
struct KernelTime;
impl rustls::time_provider::TimeProvider for KernelTime {
    fn current_time(&self) -> Option<rustls::pki_types::UnixTime> {
        let s = rd64(H_UNIX_SECS);
        (s != 0).then(|| rustls::pki_types::UnixTime::since_unix_epoch(core::time::Duration::from_secs(s)))
    }
}

// ------------------------------------------------------------------ server state

#[derive(Debug)]
struct OneCert(Arc<CertifiedKey>);
impl ResolvesServerCert for OneCert {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

struct Slot {
    conn: UnbufferedServerConnection,
    inbuf: Vec<u8>,
    done: bool,
}

static mut CONFIG: Option<Arc<rustls::ServerConfig>> = None;
static mut SLOTS_: [Option<Slot>; SLOTS] = [const { None }; SLOTS];

#[allow(static_mut_refs)]
fn slot(i: usize) -> Option<&'static mut Option<Slot>> {
    unsafe { SLOTS_.get_mut(i) }
}

/// INIT: build the key from the scalar, ALWAYS publish its SEC1 public point (65 B at OUT_TLS — the
/// provisioning step, ADR 0051 D3), and build the server config only when a certificate chain is given.
/// Returns whether TLS is now ready to serve.
fn init(input: &[u8]) -> Result<bool, u32> {
    if input.len() < 34 {
        return Err(ST_BAD_INIT);
    }
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&input[..32]);
    let key = heqk_tlsprov::signing_key_from_scalar(&scalar).ok_or(ST_BAD_INIT)?;
    let pubpt = heqk_tlsprov::public_point_from_scalar(&scalar).ok_or(ST_BAD_INIT)?;
    scalar.fill(0);
    io(OUT_TLS_OFF, 65).copy_from_slice(&pubpt);
    let n = u16::from_le_bytes([input[32], input[33]]) as usize;
    let mut p = 34;
    let mut chain = Vec::new();
    for _ in 0..n.min(4) {
        if p + 2 > input.len() {
            return Err(ST_BAD_INIT);
        }
        let l = u16::from_le_bytes([input[p], input[p + 1]]) as usize;
        p += 2;
        if p + l > input.len() {
            return Err(ST_BAD_INIT);
        }
        chain.push(CertificateDer::from(input[p..p + l].to_vec()));
        p += l;
    }
    if chain.is_empty() {
        return Ok(false); // key published, no certificate yet: TLS stays off
    }
    heqk_tlsprov::set_rng(pool_rng);
    let cfg = rustls::ServerConfig::builder_with_details(Arc::new(heqk_tlsprov::provider()), Arc::new(KernelTime))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| ST_BAD_INIT)?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(OneCert(Arc::new(CertifiedKey::new(chain, key)))));
    let mut cfg = cfg;
    cfg.alpn_protocols = alloc::vec![b"http/1.1".to_vec()];
    cfg.send_tls13_tickets = 0; // no resumption state to keep
    unsafe { CONFIG = Some(Arc::new(cfg)) };
    Ok(true)
}

/// Drive one connection: process buffered ciphertext, emit handshake/app records, collect plaintext,
/// optionally encrypt `send` and/or queue close_notify. Returns (out_tls, out_plain, flags).
fn pump(s: &mut Slot, mut send: Option<&[u8]>, mut close: bool) -> Result<(usize, usize, u32), u32> {
    let out_tls = io(OUT_TLS_OFF, OUT_TLS_MAX);
    let out_plain = io(OUT_PLAIN_OFF, OUT_PLAIN_MAX);
    let (mut nt, mut np, mut flags) = (0usize, 0usize, 0u32);
    let pq = s.conn.negotiated_key_exchange_group().map_or(false, |g| g.name() == rustls::NamedGroup::X25519MLKEM768);
    for _ in 0..64 {
        let st = s.conn.process_tls_records(&mut s.inbuf);
        let mut discard = st.discard;
        let mut stop = false;
        match st.state.map_err(|_| ST_TLS_ERROR)? {
            ConnectionState::ReadTraffic(mut r) => {
                while let Some(rec) = r.next_record() {
                    let rec = rec.map_err(|_| ST_TLS_ERROR)?;
                    discard += rec.discard;
                    if np + rec.payload.len() > out_plain.len() {
                        return Err(ST_TOO_BIG);
                    }
                    out_plain[np..np + rec.payload.len()].copy_from_slice(rec.payload);
                    np += rec.payload.len();
                }
            }
            ConnectionState::EncodeTlsData(mut e) => {
                nt += e.encode(&mut out_tls[nt..]).map_err(|_| ST_TOO_BIG)?;
            }
            ConnectionState::TransmitTlsData(t) => t.done(), // the kernel transmits OUT_TLS after we exit
            ConnectionState::BlockedHandshake => stop = true, // need more ciphertext
            ConnectionState::WriteTraffic(mut w) => {
                flags |= F_HANDSHAKE_DONE;
                if pq {
                    flags |= F_PQ;
                }
                s.done = true;
                if let Some(d) = send.take() {
                    nt += w.encrypt(d, &mut out_tls[nt..]).map_err(|_| ST_TOO_BIG)?;
                }
                if close {
                    close = false;
                    nt += w.queue_close_notify(&mut out_tls[nt..]).map_err(|_| ST_TOO_BIG)?;
                }
                stop = true;
            }
            ConnectionState::PeerClosed => flags |= F_PEER_CLOSED,
            ConnectionState::Closed => {
                flags |= F_CLOSED;
                stop = true;
            }
            _ => stop = true, // early data is not enabled; anything else: wait for more input
        }
        if discard > 0 {
            s.inbuf.drain(..discard.min(s.inbuf.len()));
        }
        if stop {
            break;
        }
    }
    if send.is_some() {
        return Err(ST_NOT_READY); // asked to send before the handshake finished
    }
    Ok((nt, np, flags))
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    if rd32(H_MAGIC) != MAGIC {
        exit(ST_BAD_CMD, 0, 0, 0);
    }
    unsafe { ENT_POS = 0 };
    let cmd = rd32(H_CMD);
    let conn = rd32(H_CONN) as usize;
    let n = (rd32(H_IN_LEN) as usize).min(IN_MAX);
    let input = io(IN_OFF, n);
    if cmd == CMD_INIT {
        let r = init(input);
        input.fill(0); // the key scalar leaves the shared region
        match r {
            Ok(ready) => exit(ST_OK, 65, 0, if ready { F_HANDSHAKE_DONE } else { 0 }),
            Err(e) => exit(e, 0, 0, 0),
        }
    }
    #[allow(static_mut_refs)]
    let Some(cfg) = (unsafe { CONFIG.clone() }) else { exit(ST_NOT_INIT, 0, 0, 0) };
    let Some(sl) = slot(conn) else { exit(ST_NO_SLOT, 0, 0, 0) };
    match cmd {
        CMD_OPEN => match UnbufferedServerConnection::new(cfg) {
            Ok(c) => {
                *sl = Some(Slot { conn: c, inbuf: Vec::with_capacity(4096), done: false });
                exit(ST_OK, 0, 0, 0)
            }
            Err(_) => exit(ST_TLS_ERROR, 0, 0, 0),
        },
        CMD_RECV => {
            let Some(s) = sl.as_mut() else { exit(ST_NO_SLOT, 0, 0, 0) };
            if s.inbuf.len() + n > IN_MAX * 2 {
                *sl = None;
                exit(ST_TOO_BIG, 0, 0, F_CLOSED);
            }
            s.inbuf.extend_from_slice(input);
            match pump(s, None, false) {
                Ok((t, p, f)) => {
                    if f & F_CLOSED != 0 {
                        *sl = None;
                    }
                    exit(ST_OK, t, p, f)
                }
                Err(e) => {
                    *sl = None; // a TLS error ends the session (fail closed)
                    exit(e, 0, 0, F_CLOSED)
                }
            }
        }
        CMD_SEND => {
            let Some(s) = sl.as_mut() else { exit(ST_NO_SLOT, 0, 0, 0) };
            if n > SEND_CHUNK {
                exit(ST_TOO_BIG, 0, 0, 0);
            }
            let data: Vec<u8> = input.to_vec();
            match pump(s, Some(&data), false) {
                Ok((t, p, f)) => exit(ST_OK, t, p, f),
                Err(e) => exit(e, 0, 0, 0),
            }
        }
        CMD_CLOSE => {
            let r = sl.as_mut().map(|s| pump(s, None, true));
            *sl = None;
            match r {
                Some(Ok((t, _, _))) => exit(ST_OK, t, 0, F_CLOSED),
                _ => exit(ST_OK, 0, 0, F_CLOSED),
            }
        }
        _ => exit(ST_BAD_CMD, 0, 0, 0),
    }
}
