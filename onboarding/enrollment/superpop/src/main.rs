//! heqk super-PoP (G19) — operator-run SASE tunnel endpoint.
//!
//!   superpop keygen --key-file F           create the PoP static key (0600); print its public blob
//!   superpop pub    --key-file F           print the public blob (x25519 pk ‖ ML-KEM ek, hex) to bake
//!                                          into device images as the pinned PoP key
//!   superpop run    --key-file F --devices FILE [--tenant HEX] [--dns IP] [--mtu N] [--pool CIDR]
//!                   [--tun NAME] [--bind IP]
//!   superpop selftest                      in-process device↔PoP end-to-end (no network, no TUN)
//!   superpop devsim …                      a device simulator over real UDP (test tooling; see devsim.rs)
//!
//! Devices file: one device per line, `name  <ed25519-pk-hex, 64 chars>  <inner-ipv4>`; `#` comments.
//! The pk is the one the device prints at boot (`[NETCP] device identity (SRK-derived) pk=…`).
//! Networking (TUN address, forwarding, NAT) is set up by `superpop-net.sh`.

#[path = "../../responder-sim/src/entropy.rs"]
#[allow(dead_code)]
mod entropy;
#[path = "../../../../os/kernel/kernel/src/securechannel.rs"]
#[allow(dead_code)]
mod securechannel;
mod pop;
mod tun;
#[allow(dead_code)] // CLOSE_* reasons: protocol constants the device side mirrors
mod wire;

use ed25519_compact::PublicKey as EdPub;
use entropy::{EntropySource, OsEntropy};
use pop::{Config, Device, Out, Pop};
use securechannel::ResponderStatic;
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn parse_ip4(s: &str) -> Option<[u8; 4]> {
    s.parse::<std::net::Ipv4Addr>().ok().map(|a| a.octets())
}

/// The key file holds three 32-byte seeds (hex, one per line): x25519, ML-KEM d, ML-KEM z.
fn load_key(path: &str) -> Result<ResponderStatic, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{path}: {e}"))?;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(format!("{path}: refusing a key file readable by group/other (chmod 600)"));
    }
    let txt = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let seeds: Vec<[u8; 32]> = txt
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| unhex(l).and_then(|v| <[u8; 32]>::try_from(v).ok()))
        .collect::<Option<_>>()
        .ok_or(format!("{path}: malformed seed line"))?;
    if seeds.len() != 3 {
        return Err(format!("{path}: expected 3 seed lines, found {}", seeds.len()));
    }
    Ok(ResponderStatic::from_seeds(&seeds[0], &seeds[1], &seeds[2]))
}

fn keygen(path: &str) -> Result<(), String> {
    let mut ent = OsEntropy;
    let mut lines = String::from("# heqk super-PoP static key seeds (x25519, ML-KEM d, ML-KEM z). SECRET.\n");
    for _ in 0..3 {
        let s = ent.fill_32().map_err(|e| format!("entropy: {e:?}"))?;
        lines.push_str(&hex(&s));
        lines.push('\n');
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{path}: {e} (refusing to overwrite an existing key)"))?;
    f.write_all(lines.as_bytes()).map_err(|e| e.to_string())?;
    print_pub(&load_key(path)?);
    Ok(())
}

fn print_pub(k: &ResponderStatic) {
    let p = k.public();
    println!("PoP public blob (x25519 pk ‖ ML-KEM-768 ek, {} B):", 32 + p.k_ek_bytes().len());
    println!("{}{}", hex(&p.x_pk()[..]), hex(&p.k_ek_bytes()[..]));
}

fn load_devices(path: &str) -> Result<Vec<Device>, String> {
    let txt = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let mut out = Vec::new();
    for (i, l) in txt.lines().enumerate() {
        let l = l.split('#').next().unwrap_or("").trim();
        if l.is_empty() {
            continue;
        }
        let f: Vec<&str> = l.split_whitespace().collect();
        let bad = || format!("{path}:{}: expected `name pk-hex inner-ipv4`", i + 1);
        if f.len() != 3 {
            return Err(bad());
        }
        let pk = unhex(f[1]).and_then(|v| EdPub::from_slice(&v).ok()).ok_or_else(bad)?;
        let inner = parse_ip4(f[2]).ok_or_else(bad)?;
        out.push(Device::new(f[0], pk, inner));
    }
    if out.is_empty() {
        return Err(format!("{path}: no devices"));
    }
    Ok(out)
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn run(args: &[String]) -> Result<(), String> {
    let key = load_key(&arg(args, "--key-file").ok_or("--key-file required")?)?;
    let devices = load_devices(&arg(args, "--devices").ok_or("--devices required")?)?;
    let mut cfg = Config::default();
    if let Some(t) = arg(args, "--tenant") {
        cfg.tenant = u64::from_str_radix(t.trim_start_matches("0x"), 16).map_err(|_| "bad --tenant")?;
    }
    if let Some(d) = arg(args, "--dns") {
        cfg.dns = parse_ip4(&d).ok_or("bad --dns")?;
    }
    if let Some(pl) = arg(args, "--pool") {
        // e.g. 198.18.0.0/15 for a bench host whose own WAN sits in 100.64.0.0/10 (CGNAT)
        let (net, len) = pl.split_once('/').ok_or("bad --pool (want a.b.c.d/len)")?;
        let len: u8 = len.parse().map_err(|_| "bad --pool length")?;
        if !(8..=30).contains(&len) {
            return Err("--pool length must be 8..=30".into());
        }
        cfg.pool = (parse_ip4(net).ok_or("bad --pool address")?, len);
    }
    if let Some(m) = arg(args, "--mtu") {
        cfg.mtu = m.parse().map_err(|_| "bad --mtu")?;
        if !(576..=1420).contains(&cfg.mtu) {
            return Err("--mtu must be 576..=1420".into());
        }
    }
    let ifname = arg(args, "--tun").unwrap_or_else(|| "hqpop0".into());
    let bind = arg(args, "--bind").unwrap_or_else(|| "0.0.0.0".into());
    let ndev = devices.len();
    print_pub(&key);
    let pop = Arc::new(Mutex::new(Pop::new(key, cfg, devices)?));

    let hs = Arc::new(UdpSocket::bind((bind.as_str(), wire::HS_PORT)).map_err(|e| format!("bind :7654: {e}"))?);
    let data = Arc::new(UdpSocket::bind((bind.as_str(), wire::DATA_PORT)).map_err(|e| format!("bind :7655: {e}"))?);
    let tun_r = tun::open(&ifname).map_err(|e| format!("tun {ifname}: {e} (needs CAP_NET_ADMIN)"))?;
    let tun_w = Arc::new(Mutex::new(tun_r.try_clone().map_err(|e| e.to_string())?));
    println!("superpop: {ndev} device(s) allowed; handshake {bind}:7654, data {bind}:7655, tun {ifname}");
    println!("superpop: now run `superpop-net.sh {ifname}` (address, forwarding, NAT) if not done");

    let t0 = Instant::now();
    let now = move || t0.elapsed().as_millis() as u64;
    let dispatch = {
        let (hs, data, tun_w) = (hs.clone(), data.clone(), tun_w.clone());
        move |outs: Vec<Out>| {
            for o in outs {
                let _ = match o {
                    Out::Hs(to, b) => hs.send_to(&b, to).map(|_| ()),
                    Out::Data(to, b) => data.send_to(&b, to).map(|_| ()),
                    Out::Tun(p) => tun_w.lock().unwrap().write_all(&p),
                };
            }
        }
    };

    // Handshake socket.
    {
        let (pop, hs, dispatch) = (pop.clone(), hs.clone(), dispatch.clone());
        std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            let mut ent = OsEntropy;
            loop {
                let Ok((n, from)) = hs.recv_from(&mut buf) else { continue };
                let outs = pop.lock().unwrap().on_hs(from, &buf[..n], now(), &mut ent);
                dispatch(outs);
            }
        });
    }
    // Data socket.
    {
        let (pop, data, dispatch) = (pop.clone(), data.clone(), dispatch.clone());
        std::thread::spawn(move || {
            let mut buf = vec![0u8; wire::MAX_DGRAM + 64];
            loop {
                let Ok((n, from)) = data.recv_from(&mut buf) else { continue };
                let outs = pop.lock().unwrap().on_data(from, &buf[..n], now());
                dispatch(outs);
            }
        });
    }
    // TUN → devices.
    {
        let (pop, dispatch) = (pop.clone(), dispatch.clone());
        let mut tun_r = tun_r;
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 2048];
            loop {
                let Ok(n) = tun_r.read(&mut buf) else { continue };
                if n == 0 {
                    continue;
                }
                let outs = pop.lock().unwrap().on_tun(&buf[..n]);
                dispatch(outs);
            }
        });
    }
    // Housekeeping + stats.
    let mut last_stats = Instant::now();
    loop {
        std::thread::sleep(Duration::from_secs(5));
        let mut p = pop.lock().unwrap();
        p.gc(now());
        if last_stats.elapsed() >= Duration::from_secs(60) {
            last_stats = Instant::now();
            println!("superpop: sessions={} {:?}", p.session_count(), p.stats);
        }
    }
}

fn selftest() -> bool {
    match e2e_selftest::run() {
        Ok(()) => {
            println!("superpop selftest: PASS — handshake, ASSIGN, DATA both ways, anti-spoof, replay, rebind, in-session rekey (W4)");
            true
        }
        Err(e) => {
            eprintln!("superpop selftest: FAIL — {e}");
            false
        }
    }
}

mod e2e_selftest {
    //! The same scenario as the unit e2e tests, runnable on an operator host (`superpop selftest`).
    pub fn run() -> Result<(), String> {
        crate::e2e_harness::scenario()?;
        crate::e2e_harness::rekey_scenario()
    }
}
mod e2e_harness;
mod devsim;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let res = match args.get(1).map(String::as_str) {
        Some("keygen") => keygen(&arg(&args, "--key-file").unwrap_or_default()),
        Some("pub") => load_key(&arg(&args, "--key-file").unwrap_or_default()).map(|k| print_pub(&k)),
        Some("run") => run(&args),
        Some("devsim") => devsim::run(&args),
        Some("selftest") => {
            std::process::exit(if selftest() { 0 } else { 1 });
        }
        _ => Err("usage: superpop keygen|pub|run|selftest (see source header)".into()),
    };
    if let Err(e) = res {
        eprintln!("superpop: {e}");
        std::process::exit(2);
    }
}
