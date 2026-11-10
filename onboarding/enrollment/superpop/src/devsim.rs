//! `superpop devsim` — a DEVICE simulator over REAL UDP (test tooling, like responder-sim).
//! It is provisioned exactly like a device: it holds only the PoP's PUBLIC blob.
//!
//!   superpop devsim --seed TAG --print-pk                 the simulated device's ed25519 pk (allowlist it)
//!   superpop devsim --seed TAG --pop IP --pop-pub HEX --ping DST
//!       handshake → ADDR_REQ/ASSIGN → ICMP echo to DST through the tunnel → wait for the reply.

use crate::e2e_harness::{dev_kp, Dev};
use crate::entropy::OsEntropy;
use crate::securechannel::{hs_chunk, initiator_read_msg2, initiator_write_msg1, HsReasm, InitiatorRandomness, ResponderPub};
use crate::wire::{self, Msg};
use boot_abi::sha256;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

fn csum(b: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for c in b.chunks(2) {
        s += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

/// A checksummed IPv4 ICMP echo request.
pub fn icmp_echo(src: [u8; 4], dst: [u8; 4], id: u16, seq: u16) -> Vec<u8> {
    let mut icmp = vec![8u8, 0, 0, 0, (id >> 8) as u8, id as u8, (seq >> 8) as u8, seq as u8];
    icmp.extend_from_slice(b"heqk-g19-devsim-ping");
    let c = csum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    let total = 20 + icmp.len();
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64;
    p[9] = 1;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    let c = csum(&p);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(&icmp);
    p
}

fn arg(args: &[String], n: &str) -> Option<String> {
    args.iter().position(|a| a == n).and_then(|i| args.get(i + 1)).cloned()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    (s.len() % 2 == 0).then_some(())?;
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

pub fn run(args: &[String]) -> Result<(), String> {
    let seed = arg(args, "--seed").ok_or("--seed required")?;
    let kp = dev_kp(seed.as_bytes());
    if args.iter().any(|a| a == "--print-pk") {
        println!("{}", kp.pk.as_ref().iter().map(|b| format!("{b:02x}")).collect::<String>());
        return Ok(());
    }
    let pop = arg(args, "--pop").ok_or("--pop required")?;
    let blob = unhex(&arg(args, "--pop-pub").ok_or("--pop-pub required")?).ok_or("bad --pop-pub hex")?;
    if blob.len() < 33 {
        return Err("--pop-pub too short".into());
    }
    let resp_pub = ResponderPub::from_provisioned(blob[..32].try_into().unwrap(), &blob[32..]).ok_or("bad PoP public blob")?;
    let dst: [u8; 4] = arg(args, "--ping")
        .ok_or("--ping required")?
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| "bad --ping")?
        .octets();

    // Handshake over UDP to <pop>:7654.
    let hs = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    hs.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut ent = OsEntropy;
    let rnd = InitiatorRandomness::from_entropy(&mut ent).map_err(|e| format!("{e:?}"))?;
    let fp = sha256::digest(kp.pk.as_ref());
    let (msg1, pend) = initiator_write_msg1(&kp, &resp_pub, &rnd, &fp).ok_or("msg1")?;
    hs_chunk(msg1.as_slice(), |c| hs.send_to(c, (pop.as_str(), wire::HS_PORT)).is_ok());
    let mut re = HsReasm::new();
    let mut buf = [0u8; 2048];
    let total = loop {
        let (n, _) = hs.recv_from(&mut buf).map_err(|e| format!("no msg2 from PoP: {e}"))?;
        if let Some(t) = re.feed(&buf[..n]).map_err(|_| "msg2 reassembly")? {
            break t;
        }
    };
    let (session, tenant) = initiator_read_msg2(pend, &re.message()[..total]).map_err(|e| format!("msg2: {e:?}"))?;
    println!("devsim: ESTABLISHED (tenant payload {:02x?})", tenant.as_slice());
    let mut dev = Dev::from_session(session);

    // Data over UDP 7655.
    let data = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    data.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let to = (pop.as_str(), wire::DATA_PORT);
    data.send_to(&dev.seal(&Msg::AddrReq), to).map_err(|e| e.to_string())?;
    let (n, _) = data.recv_from(&mut buf).map_err(|e| format!("no ASSIGN: {e}"))?;
    let inner = match wire::decode(&dev.open(&buf[..n])?) {
        Some(Msg::Assign(a)) => {
            println!("devsim: ASSIGN inner={:?}/{} dns={:?} mtu={}", a.inner, a.plen, a.dns, a.mtu);
            a.inner
        }
        other => return Err(format!("expected ASSIGN, got {other:?}")),
    };
    let ping = icmp_echo(inner, dst, 0x4851, 1);
    data.send_to(&dev.seal(&Msg::Data(&ping)), to).map_err(|e| e.to_string())?;
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_secs(3) {
        let Ok((n, _)) = data.recv_from(&mut buf) else { break };
        if let Some(Msg::Data(p)) = wire::decode(&dev.open(&buf[..n])?) {
            if let Some((s, d)) = wire::ipv4_src_dst(p) {
                if s == dst && d == inner && p[9] == 1 && p.get(20) == Some(&0) {
                    println!("devsim: ICMP echo reply from {:?} through the tunnel — PASS", s);
                    return Ok(());
                }
            }
        }
    }
    Err("no echo reply through the tunnel".into())
}
